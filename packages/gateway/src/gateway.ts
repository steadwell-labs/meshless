/**
 * The provider (§8, §11, §12).
 *
 * `Gateway` is transport-independent: it takes a method, a path, headers, and
 * the exact body bytes, and returns a status, body, and headers. The HTTP server
 * in `server.ts` is a thin adapter. That split is deliberate — the conformance
 * suite drives this object directly, so no test depends on a socket, and an
 * alternative transport can reuse the same policy code.
 */

import { canonicalBytes, isJsonObject, parseJsonStrict, type JsonObject, JsonError } from '../../core/src/json.ts';
import { MlpError, asMlpError, invalidGrant, invalidProof, invalidRequest } from '../../core/src/errors.ts';
import { isUuidV4, randomToken } from '../../core/src/bytes.ts';
import { isKeyId } from '../../core/src/jwk.ts';
import { parseJws } from '../../core/src/jws.ts';
import { buildProof, verifyProof } from '../../core/src/proof.ts';
import { buildReceipt } from '../../core/src/receipt.ts';
import { parseGrant, verifyChain, type VerifiedChain } from '../../core/src/grant.ts';
import { parseResourceId } from '../../core/src/ids.ts';
import { verifyDescriptor, type DescriptorRecord } from '../../core/src/descriptor.ts';
import { type SigningKey, type PublicJwk } from '../../core/src/jwk.ts';
import { type HandlerRegistry, type InvocationContext } from './handlers.ts';
import { type Ledger } from './ledger.ts';

export interface RawRequest {
  readonly method: string;
  /** Path only, never a full URL: the origin is fixed by the descriptor. */
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: Uint8Array;
  readonly remoteAddress?: string;
}

export interface RawResponse {
  readonly status: number;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export interface LogEvent {
  readonly level: 'info' | 'warn' | 'error';
  readonly event: string;
  readonly rid?: string;
  readonly subject?: string;
  readonly action?: string;
  readonly requestId?: string;
  readonly detail?: string;
}

export interface GatewayOptions {
  /** Compact descriptor JWS, signed by the owner. */
  descriptor: string;
  providerKey: SigningKey;
  ownerKeyId: string;
  ledger: Ledger;
  registry: HandlerRegistry;
  now?: () => number;
  /** §11.1: 1 MiB, lower if a profile says so. */
  maxBodyBytes?: number;
  maxResponseBytes?: number;
  /** §11.3: 15 minutes. */
  sessionTtlSeconds?: number;
  /** §11.2: 60 seconds. */
  nonceTtlSeconds?: number;
  /** §8.1: public listing is opt-in and off by default. */
  discovery?: boolean;
  /** Challenge issuance rate limit per source address, per minute. */
  rateLimitPerMinute?: number;
  logger?: (event: LogEvent) => void;
}

const PATHS = {
  challenge: '/mlp/v1/challenge',
  sessions: '/mlp/v1/sessions',
  invoke: '/mlp/v1/invoke',
  close: '/mlp/v1/sessions/close',
  revoke: '/mlp/v1/revoke',
  wellKnown: '/.well-known/meshless',
};

const DEFAULT_MAX_BODY = 1024 * 1024;

/**
 * Record an owner's enrollment.
 *
 * §6.2 requires an independently trusted channel. This function is that channel
 * when the caller is an operator with local access; an implementation that
 * enrolls over the network has to do better than this.
 */
export function enrollResource(
  ledger: Ledger,
  options: { descriptor: string; now: number },
): DescriptorRecord {
  const record = verifyDescriptor(options.descriptor, { now: options.now });
  const rid = record.claims.rid;
  const existing = ledger.enrollment(rid);
  if (existing && (existing.owner !== record.claims.iss || existing.provider !== record.claims.provider)) {
    throw new Error('resource is already enrolled with a different owner or provider');
  }
  ledger.enroll({
    rid,
    owner: record.claims.iss,
    provider: record.claims.provider,
    enrolledAt: options.now,
  });
  ledger.setHighWaterSeq(rid, record.claims.seq);
  return record;
}

export class Gateway {
  readonly descriptor: DescriptorRecord;
  readonly rid: string;
  readonly origin: string;
  readonly providerKeyId: string;
  readonly ownerKeyId: string;

  private readonly providerKey: SigningKey;
  private readonly ledger: Ledger;
  private readonly registry: HandlerRegistry;
  private readonly now: () => number;
  private readonly maxBodyBytes: number;
  private readonly maxResponseBytes: number;
  private readonly sessionTtlSeconds: number;
  private readonly nonceTtlSeconds: number;
  private readonly discovery: boolean;
  private readonly rateLimitPerMinute: number;
  private readonly logger: (event: LogEvent) => void;
  private readonly limiter = new WindowLimiter();

  constructor(options: GatewayOptions) {
    this.providerKey = options.providerKey;
    this.ledger = options.ledger;
    this.registry = options.registry;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.maxResponseBytes = options.maxResponseBytes ?? options.maxBodyBytes ?? DEFAULT_MAX_BODY;
    this.sessionTtlSeconds = options.sessionTtlSeconds ?? 900;
    this.nonceTtlSeconds = options.nonceTtlSeconds ?? 60;
    this.discovery = options.discovery ?? false;
    this.rateLimitPerMinute = options.rateLimitPerMinute ?? 120;
    this.logger = options.logger ?? (() => {});

    const now = this.now();
    this.descriptor = verifyDescriptor(options.descriptor, {
      now,
      expectedOwnerKeyId: options.ownerKeyId,
      expectedProviderKeyId: options.providerKey.keyId,
    });
    this.rid = this.descriptor.claims.rid;
    this.origin = this.descriptor.origin;
    this.providerKeyId = this.descriptor.claims.provider;
    this.ownerKeyId = this.descriptor.claims.iss;

    const enrollment = this.ledger.enrollment(this.rid);
    if (!enrollment) throw new Error(`resource ${this.rid} is not enrolled with this provider`);
    if (enrollment.owner !== this.ownerKeyId) throw new Error('enrollment owner does not match the descriptor owner');
    if (enrollment.provider !== this.providerKeyId) throw new Error('enrollment provider does not match the descriptor provider');

    for (const action of this.registry.list()) {
      if (!this.descriptor.actions.has(action.name)) {
        this.logger({ level: 'warn', event: 'handler-not-in-descriptor', action: action.name, rid: this.rid });
      }
    }
  }

  /** The descriptor this provider serves, for exchange out of band or via §8.1. */
  descriptorCompact(): string {
    return this.descriptor.compact;
  }

  async handle(request: RawRequest): Promise<RawResponse> {
    const started = performance.now();
    let requestId: string | undefined;
    try {
      if (request.body.byteLength > this.maxBodyBytes) {
        throw new MlpError('too_large', 'request body exceeds the provider limit');
      }
      const method = request.method.toUpperCase();
      const path = request.path === '' ? '/' : request.path;

      if (method === 'GET' && path === PATHS.wellKnown) {
        return await this.handleDiscovery(request);
      }
      if (method !== 'POST') throw new MlpError('unknown_resource', 'no such endpoint');

      switch (path) {
        case PATHS.challenge:
          return this.handleChallenge(request);
        case PATHS.sessions:
          return this.handleSessions(request);
        case PATHS.invoke: {
          const response = await this.handleInvoke(request, (id) => {
            requestId = id;
          });
          return response;
        }
        case PATHS.close:
          return this.handleClose(request);
        case PATHS.revoke:
          return this.handleRevoke(request);
        default:
          throw new MlpError('unknown_resource', 'no such endpoint');
      }
    } catch (error) {
      return this.errorResponse(error, requestId, started);
    }
  }

  // ---------------------------------------------------------------- endpoints

  private handleChallenge(request: RawRequest): RawResponse {
    const body = this.parseBody(request);
    const rid = body.rid;
    const subject = body.subject;
    if (typeof rid !== 'string' || !isKeyId(subject)) throw invalidRequest('challenge requires rid and subject');
    // Concealment: an unknown resource answers exactly like a known one would
    // answer to an unauthorized caller.
    if (rid !== this.rid) throw new MlpError('unknown_resource', 'no such resource');

    const now = this.now();
    if (!this.limiter.hit(`challenge:${request.remoteAddress ?? 'unknown'}`, now, this.rateLimitPerMinute)) {
      throw new MlpError('quota_exceeded', 'too many challenge requests');
    }
    const { nonce, expiresAt } = this.ledger.issueNonce(rid, subject, now, this.nonceTtlSeconds);
    this.log({ level: 'info', event: 'challenge', rid, subject });
    return this.json(200, { nonce, expires_at: expiresAt });
  }

  private handleSessions(request: RawRequest): RawResponse {
    const body = this.parseBody(request);
    const chain = body.chain;
    if (!Array.isArray(chain) || chain.length === 0 || !chain.every((item) => typeof item === 'string')) {
      throw invalidRequest('sessions requires a chain array of compact grants');
    }
    const compacts = chain as string[];

    // Proof first, grant evaluation second (§11.1). The leaf's subject key is a
    // claim inside a signed object, so reading it before verifying the chain is
    // safe: an attacker can only name a key they hold, and the chain check
    // immediately afterwards decides whether that key was ever authorized.
    const leaf = parseGrant(compacts[compacts.length - 1]!);
    const subject = leaf.claims.sub;
    const now = this.now();
    const proof = this.requireProof(request);
    const claims = verifyProof(proof, {
      subject,
      aud: this.providerKeyId,
      method: 'POST',
      uri: this.origin + PATHS.sessions,
      body: request.body,
      grantHash: leaf.hash,
      now,
      subjectJwk: leaf.subject.jwk,
    });
    this.ledger.consumeNonce(claims.nonce, this.rid, subject, now);

    const verified = verifyChain(compacts, {
      now,
      descriptor: this.descriptor,
      providerKeyId: this.providerKeyId,
      ownerKeyId: this.ownerKeyId,
      isRevoked: (jti) => this.ledger.isRevoked(jti),
    });
    if (verified.leafHash !== leaf.hash) throw invalidGrant('chain changed between proof and verification');

    for (const record of verified.grants) this.ledger.rememberSubject(record.subject.jwk);
    this.ledger.rememberSubject(this.descriptor.owner.jwk);

    const sid = randomToken(32);
    const expiresAt = Math.min(verified.leaf.claims.exp, now + this.sessionTtlSeconds);
    this.ledger.putSession(sid, {
      rid: this.rid,
      subject,
      leafHash: verified.leafHash,
      exp: expiresAt,
      chain: compacts,
    });
    this.prune();
    this.log({ level: 'info', event: 'session-open', rid: this.rid, subject });
    return this.json(200, { sid, expires_at: expiresAt });
  }

  private async handleInvoke(request: RawRequest, noteRequestId: (id: string) => void): Promise<RawResponse> {
    const body = this.parseBody(request);
    const sid = body.sid;
    const requestIdValue = body.request_id;
    const rid = body.rid;
    const action = body.action;
    const input = body.input;

    if (typeof sid !== 'string' || !isUuidV4(requestIdValue) || typeof action !== 'string') {
      throw invalidRequest('invoke requires sid, request_id, rid, action and input');
    }
    noteRequestId(requestIdValue);
    if (rid !== this.rid) throw new MlpError('unknown_resource', 'no such resource');
    if (!isJsonObject(input)) throw invalidRequest('invoke.input must be an object');

    const now = this.now();
    const session = this.ledger.getSession(sid);
    if (!session) throw invalidGrant('session is unknown or has been closed');
    if (session.exp <= now) {
      this.ledger.deleteSession(sid);
      throw invalidGrant('session has expired');
    }
    if (session.rid !== this.rid) throw invalidGrant('session was opened for a different resource');

    const subject = session.subject;
    const proof = this.requireProof(request);
    const proofClaims = verifyProof(proof, {
      subject,
      aud: this.providerKeyId,
      method: 'POST',
      uri: this.origin + PATHS.invoke,
      body: request.body,
      grantHash: session.leafHash,
      now,
      subjectJwk: this.subjectJwk(subject),
    });
    this.ledger.consumeNonce(proofClaims.nonce, this.rid, subject, now);

    // Re-validate the whole chain on every invocation. A session is a
    // convenience, not an authorization decision (§11.4).
    const verified = verifyChain(session.chain, {
      now,
      descriptor: this.descriptor,
      providerKeyId: this.providerKeyId,
      ownerKeyId: this.ownerKeyId,
      isRevoked: (jti) => this.ledger.isRevoked(jti),
    });
    if (verified.leafHash !== session.leafHash) throw invalidGrant('session chain does not match the leaf grant');

    if (!verified.leaf.actions.has(action)) throw new MlpError('denied', 'action is not granted', action);
    if (!this.registry.has(action)) throw new MlpError('denied', 'action is not implemented by this provider', action);

    if (this.ledger.hasRequest(this.rid, subject, requestIdValue)) {
      throw new MlpError('duplicate_request', 'request_id has already been processed', requestIdValue);
    }

    const normalizedInput = this.registry.validate(action, input);
    const requestBytes = canonicalBytes(normalizedInput).byteLength;
    const links = verified.grants.map((grant) => ({ jti: grant.claims.jti, limits: grant.claims.limits }));
    this.ledger.reserve(links, requestBytes);
    this.ledger.markRequest(this.rid, subject, requestIdValue, verified.leaf.claims.exp);

    const deadlineMs = verified.limits.max_ms;
    const startedAt = performance.now();
    let result: JsonObject;
    try {
      result = await this.dispatch(action, normalizedInput, {
        rid: this.rid,
        action,
        subject,
        requestId: requestIdValue,
        now,
        deadlineMs,
      });
    } catch (error) {
      // A failure still consumed a call (§9.5). It gets no receipt: Draft 00
      // has no delivery path for a failed-invocation receipt (see open issues).
      this.log({
        level: 'warn',
        event: 'invoke-failed',
        rid: this.rid,
        subject,
        action,
        requestId: requestIdValue,
        detail: asMlpError(error).detail ?? asMlpError(error).publicMessage,
      });
      throw error;
    }

    const elapsedMs = Math.round(performance.now() - startedAt);
    const resultBytes = canonicalBytes(result).byteLength;
    if (resultBytes > this.maxResponseBytes) {
      throw new MlpError('too_large', 'response exceeds the provider limit');
    }
    this.ledger.chargeBytes(links, resultBytes);

    const receipt = buildReceipt(
      {
        rid: this.rid,
        sub: subject,
        jti: verified.leaf.claims.jti,
        requestId: requestIdValue,
        action,
        iat: this.now(),
        request: normalizedInput,
        result,
        usage: { calls: 1, bytes: requestBytes + resultBytes, elapsed_ms: elapsedMs },
      },
      this.providerKey,
    );

    this.log({
      level: 'info',
      event: 'invoke',
      rid: this.rid,
      subject,
      action,
      requestId: requestIdValue,
      detail: `bytes=${requestBytes + resultBytes} elapsed_ms=${elapsedMs}`,
    });
    return this.json(200, { request_id: requestIdValue, result, receipt });
  }

  private handleClose(request: RawRequest): RawResponse {
    const body = this.parseBody(request);
    const sid = body.sid;
    if (typeof sid !== 'string') throw invalidRequest('close requires sid');

    const now = this.now();
    const session = this.ledger.getSession(sid);
    if (!session) throw invalidGrant('session is unknown');
    const subject = session.subject;
    const proof = this.requireProof(request);
    const claims = verifyProof(proof, {
      subject,
      aud: this.providerKeyId,
      method: 'POST',
      uri: this.origin + PATHS.close,
      body: request.body,
      grantHash: session.leafHash,
      now,
      subjectJwk: this.subjectJwk(subject),
    });
    this.ledger.consumeNonce(claims.nonce, this.rid, subject, now);
    this.ledger.deleteSession(sid);
    this.log({ level: 'info', event: 'session-close', rid: this.rid, subject });
    return this.json(200, { closed: true });
  }

  private handleRevoke(request: RawRequest): RawResponse {
    const body = this.parseBody(request);
    const rid = body.rid;
    const jti = body.jti;
    if (rid !== this.rid) throw new MlpError('unknown_resource', 'no such resource');
    if (typeof jti !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(jti)) {
      throw invalidRequest('revoke requires a grant jti');
    }

    const now = this.now();
    const owner = this.ownerKeyId;
    const proof = this.requireProof(request);
    const claims = verifyProof(proof, {
      subject: owner,
      aud: this.providerKeyId,
      method: 'POST',
      uri: this.origin + PATHS.revoke,
      body: request.body,
      // §11.6: owner-only operation, empty grant hash.
      grantHash: '',
      now,
      subjectJwk: this.descriptor.owner.jwk,
    });
    this.ledger.consumeNonce(claims.nonce, this.rid, owner, now);

    // Persist before answering. The order is the whole point of the endpoint.
    this.ledger.revoke(jti, now);
    this.log({ level: 'info', event: 'revoke', rid: this.rid, subject: owner, detail: jti });
    return this.json(200, { revoked: true });
  }

  private handleDiscovery(request: RawRequest): RawResponse {
    if (!this.discovery) throw new MlpError('unknown_resource', 'no such endpoint');

    const proof = this.requireProof(request);
    const parsed = parseJws(proof, 'mlp-proof+jwt');
    const subject = parsed.kid;
    const jwk = this.ledger.subjectKey(subject);
    if (!jwk) throw invalidProof('discovery requires a previously authorized subject');

    const now = this.now();
    const claims = verifyProof(proof, {
      subject,
      aud: this.providerKeyId,
      method: 'GET',
      uri: this.origin + PATHS.wellKnown,
      body: request.body,
      grantHash: '',
      now,
      subjectJwk: jwk,
    });
    this.ledger.consumeNonce(claims.nonce, this.rid, subject, now);
    return this.json(200, { v: 1, descriptors: [this.descriptor.compact] });
  }

  // ------------------------------------------------------------------ helpers

  private async dispatch(
    action: string,
    input: JsonObject,
    base: Omit<InvocationContext, 'signal' | 'deadlineMs'> & { deadlineMs: number },
  ): Promise<JsonObject> {
    const controller = new AbortController();
    const deadline = Math.max(1, Math.min(base.deadlineMs, 600_000));
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new MlpError('deadline_exceeded', 'handler exceeded its deadline', `max_ms=${deadline}`));
      }, deadline);
      timer.unref?.();
    });
    try {
      return await Promise.race([
        this.registry.invoke(action, input, {
          rid: base.rid,
          action: base.action,
          subject: base.subject,
          requestId: base.requestId,
          now: base.now,
          deadlineMs: deadline,
          signal: controller.signal,
        }),
        timeout,
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private subjectJwk(subject: string): PublicJwk {
    const known = this.ledger.subjectKey(subject);
    if (known) return known;
    // Sessions always record their subjects, so an unknown subject here means
    // the ledger lost state; refuse rather than guess.
    throw invalidProof('subject key is not known to this provider');
  }

  private requireProof(request: RawRequest): string {
    const value = request.headers['meshless-proof'];
    if (typeof value !== 'string' || value.length === 0) throw invalidProof('Meshless-Proof header is required');
    if (value.length > 16384) throw invalidProof('Meshless-Proof header is too large');
    return value;
  }

  private parseBody(request: RawRequest): JsonObject {
    if (request.body.byteLength === 0) throw invalidRequest('request body is required');
    let parsed: unknown;
    try {
      parsed = parseJsonStrict(request.body);
    } catch (error) {
      if (error instanceof JsonError) throw invalidRequest(`body rejected: ${error.message}`);
      throw invalidRequest('body is not valid JSON');
    }
    if (!isJsonObject(parsed)) throw invalidRequest('body must be a JSON object');
    return parsed;
  }

  private json(status: number, payload: JsonObject): RawResponse {
    return {
      status,
      body: JSON.stringify(payload),
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      },
    };
  }

  private errorResponse(error: unknown, requestId: string | undefined, started: number): RawResponse {
    const mlp = asMlpError(error);
    const status = mlp.status;
    if (status >= 500) {
      this.log({ level: 'error', event: 'internal-error', detail: mlp.detail ?? mlp.message });
      const sanitized = new MlpError('unavailable', 'provider could not complete the request');
      return this.json(sanitized.status, sanitized.toWire(requestId));
    }
    this.log({ level: 'warn', event: 'reject', detail: `${mlp.code}: ${mlp.detail ?? mlp.publicMessage}`, requestId });
    void started;
    return this.json(status, mlp.toWire(requestId));
  }

  private prune(): void {
    this.ledger.prune(this.now());
  }

  private log(event: LogEvent): void {
    // Never log bodies, proofs, or keys. The event shape is the whole record.
    this.logger(event);
  }
}

/**
 * Fixed-window limiter keyed by source address.
 *
 * §11.2 requires challenge issuance to be rate limited. A fixed window is
 * crude; it is also cheap, has no unbounded state, and cannot be used to make
 * the provider allocate memory on demand.
 */
export class WindowLimiter {
  private readonly buckets = new Map<string, { start: number; count: number }>();

  hit(key: string, now: number, limitPerMinute: number): boolean {
    const windowStart = Math.floor(now / 60) * 60;
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.start !== windowStart) {
      this.buckets.set(key, { start: windowStart, count: 1 });
      if (this.buckets.size > 10_000) this.sweep(windowStart);
      return true;
    }
    bucket.count += 1;
    return bucket.count <= limitPerMinute;
  }

  private sweep(windowStart: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.start !== windowStart) this.buckets.delete(key);
    }
  }
}

/** Parse a resource ID for a gateway URL, used by the CLI. */
export function describeResource(rid: string): { ownerThumbprint: string; uuid: string } {
  return parseResourceId(rid);
}

/** Build a proof for a provider request. Exported for adapters and tests. */
export function proofFor(input: Parameters<typeof buildProof>[0]): string {
  return buildProof(input);
}

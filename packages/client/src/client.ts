/**
 * The consumer (§11, §12).
 *
 * The client is where the "grant is not a bearer credential" property becomes
 * visible: every request is a fresh challenge, a fresh proof over the exact
 * bytes about to be sent, and a signature by the leaf subject's own key.
 *
 * Transport is `node:https` rather than `fetch` because MLP/1 requires an
 * explicit trust anchor or a pinned certificate (§5.1), and a fetch
 * implementation cannot express that without an extra dependency.
 */

import { request as httpsRequest } from 'node:https';
import { checkServerIdentity as tlsCheckServerIdentity, type PeerCertificate } from 'node:tls';
import { createHash } from 'node:crypto';
import { sha256b64u, uuidv4 } from '../../core/src/bytes.ts';
import { MlpError } from '../../core/src/errors.ts';
import { buildProof } from '../../core/src/proof.ts';
import { verifyReceipt, type ReceiptClaims } from '../../core/src/receipt.ts';
import { verifyDescriptor, type DescriptorRecord } from '../../core/src/descriptor.ts';
import { compactHash } from '../../core/src/jws.ts';
import { PublicKeyRef, type PublicJwk, type SigningKey } from '../../core/src/jwk.ts';
import { parseJsonStrict, type JsonObject } from '../../core/src/json.ts';

export const PATHS = {
  challenge: '/mlp/v1/challenge',
  sessions: '/mlp/v1/sessions',
  invoke: '/mlp/v1/invoke',
  close: '/mlp/v1/sessions/close',
  revoke: '/mlp/v1/revoke',
  wellKnown: '/.well-known/meshless',
} as const;

export interface ClientOptions {
  /** HTTPS origin, e.g. `https://127.0.0.1:8443`. No path. */
  origin: string;
  rid: string;
  /** The consumer's own key. */
  key: SigningKey;
  /** Provider key identifier, learned from the descriptor or enrollment. */
  providerKeyId: string;
  /** Provider public key, for receipt verification. */
  providerJwk: PublicJwk;
  /** PEM trust anchor(s). Required unless `pinnedCertSha256` is set. */
  ca?: string | string[];
  /** SHA-256 of the DER certificate, hex or base64url. Pins replace `ca`. */
  pinnedCertSha256?: string;
  /** Reject responses after this many milliseconds. Default 30s. */
  timeoutMs?: number;
  /** Highest descriptor `seq` already accepted for this resource. */
  descriptorHighWaterSeq?: number;
  /**
   * Clock source for proof timestamps, in Unix seconds. Defaults to the system
   * clock. Tests and deterministic fixtures supply their own; a client whose
   * clock is wrong by more than 30 seconds cannot produce a usable proof, and
   * that failure should be visible rather than papered over.
   */
  now?: () => number;
}

export interface SessionHandle {
  readonly sid: string;
  readonly expiresAt: number;
  readonly leafHash: string;
  readonly chain: readonly string[];
}

export interface InvocationResult {
  readonly request_id: string;
  readonly result: JsonObject;
  readonly receipt: string;
  readonly receiptClaims: ReceiptClaims;
}

export class MeshlessClient {
  private readonly options: ClientOptions;
  private readonly provider: PublicKeyRef;
  private readonly now: () => number;
  private descriptorRecord?: DescriptorRecord;

  constructor(options: ClientOptions) {
    if (!options.origin.startsWith('https://')) throw new Error('MLP/1 client requires an https origin');
    // An origin never has a trailing slash, and the proof binds this string
    // exactly, so normalize once here rather than at every call site.
    options = { ...options, origin: options.origin.replace(/\/+$/, '') };
    if (!options.ca && !options.pinnedCertSha256) {
      throw new Error('MLP/1 requires an explicit trust anchor (ca) or a pinned certificate');
    }
    this.options = options;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.provider = new PublicKeyRef(options.providerJwk);
    if (this.provider.keyId !== options.providerKeyId) {
      throw new Error('providerJwk does not match providerKeyId');
    }
  }

  get rid(): string {
    return this.options.rid;
  }

  get origin(): string {
    return this.options.origin;
  }

  get subject(): string {
    return this.options.key.keyId;
  }

  /** Verify and remember a descriptor received out of band (§8). */
  acceptDescriptor(compact: string, now = this.now()): DescriptorRecord {
    const record = verifyDescriptor(compact, {
      now,
      expectedProviderKeyId: this.provider.keyId,
      highWaterSeq: this.options.descriptorHighWaterSeq,
    });
    if (record.claims.rid !== this.options.rid) throw new Error('descriptor is for a different resource');
    if (record.origin !== this.options.origin) throw new Error('descriptor endpoint does not match the client origin');
    this.descriptorRecord = record;
    this.options.descriptorHighWaterSeq = record.claims.seq;
    return record;
  }

  /** `GET /.well-known/meshless` with a proof (§8.1). */
  async discover(): Promise<DescriptorRecord[]> {
    const response = await this.post(PATHS.wellKnown, undefined, '', 'GET');
    const descriptors = response.descriptors;
    if (!Array.isArray(descriptors)) throw new MlpError('invalid_request', 'discovery response is malformed');
    return (descriptors as string[]).map((compact) => this.acceptDescriptor(compact, this.now()));
  }

  async openSession(chain: string[]): Promise<SessionHandle> {
    if (chain.length === 0) throw new Error('chain must contain at least the root grant');
    const leaf = chain[chain.length - 1]!;
    const leafHash = compactHash(leaf);
    const body = await this.post(PATHS.sessions, { chain }, leafHash, 'POST');
    const sid = body.sid;
    const expiresAt = body.expires_at;
    if (typeof sid !== 'string' || typeof expiresAt !== 'number') {
      throw new MlpError('invalid_request', 'session response is malformed');
    }
    return { sid, expiresAt, leafHash, chain };
  }

  async invoke(session: SessionHandle, action: string, input: JsonObject, requestId = uuidv4()): Promise<InvocationResult> {
    if (session.expiresAt <= this.now()) throw new MlpError('invalid_grant', 'session has expired; open a new one');
    const body = await this.post(
      PATHS.invoke,
      { sid: session.sid, request_id: requestId, rid: this.options.rid, action, input },
      session.leafHash,
      'POST',
    );
    const result = body.result;
    const receipt = body.receipt;
    if (typeof receipt !== 'string' || body.request_id !== requestId) {
      throw new MlpError('invalid_request', 'invoke response is malformed');
    }
    const receiptClaims = verifyReceipt(receipt, {
      provider: this.provider,
      rid: this.options.rid,
      sub: this.subject,
      jti: leafJti(session.chain),
      requestId,
      action,
      request: input,
      result: typeof result === 'object' && result !== null ? (result as JsonObject) : undefined,
    });
    if (typeof result !== 'object' || result === null) throw new MlpError('invalid_request', 'invoke result is not an object');
    return { request_id: requestId, result: result as JsonObject, receipt, receiptClaims };
  }

  async close(session: SessionHandle): Promise<void> {
    await this.post(PATHS.close, { sid: session.sid }, session.leafHash, 'POST');
  }

  /** Owner-only. Requires this client's key to be the enrolled owner key. */
  async revoke(jti: string): Promise<void> {
    await this.post(PATHS.revoke, { rid: this.options.rid, jti }, '', 'POST');
  }

  private async post(path: string, payload: JsonObject | undefined, grantHash: string, method: 'POST' | 'GET'): Promise<JsonObject> {
    const body = payload === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(payload), 'utf8');
    const nonce = await this.challenge();
    const proof = buildProof({
      key: this.options.key,
      aud: this.options.providerKeyId,
      nonce,
      method,
      uri: this.options.origin + path,
      body,
      grantHash,
      iat: this.now(),
    });

    const response = await this.transport({
      method,
      path,
      headers: {
        'meshless-proof': proof,
        ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': String(body.byteLength) }),
      },
      body,
    });

    let parsed: unknown;
    try {
      parsed = response.body.byteLength === 0 ? {} : parseJsonStrict(response.body);
    } catch {
      throw new MlpError('invalid_request', 'provider returned malformed JSON');
    }
    if (typeof parsed !== 'object' || parsed === null) throw new MlpError('invalid_request', 'provider returned a non-object');
    const object = parsed as JsonObject;

    if (response.status >= 400) {
      const error = object.error;
      if (typeof error === 'object' && error !== null && typeof (error as JsonObject).code === 'string') {
        const wire = error as JsonObject;
        const code = wire.code as MlpError['code'];
        const message = typeof wire.message === 'string' ? wire.message : 'request rejected';
        throw new MlpError(code, message, `HTTP ${response.status}`);
      }
      throw new MlpError('invalid_request', `provider returned HTTP ${response.status}`);
    }
    if (response.status >= 300) throw new MlpError('unavailable', 'provider returned a redirect; MLP/1 forbids following it');
    return object;
  }

  /** A fresh nonce per request (§11.4). */
  private async challenge(): Promise<string> {
    const body = Buffer.from(JSON.stringify({ rid: this.options.rid, subject: this.subject }), 'utf8');
    const response = await this.transport({
      method: 'POST',
      path: PATHS.challenge,
      headers: { 'content-type': 'application/json', 'content-length': String(body.byteLength) },
      body,
    });
    const parsed = parseJsonStrict(response.body);
    if (typeof parsed !== 'object' || parsed === null) throw new MlpError('invalid_request', 'challenge response is malformed');
    const nonce = (parsed as JsonObject).nonce;
    if (typeof nonce !== 'string') throw new MlpError('invalid_request', 'challenge response is missing a nonce');
    return nonce;
  }

  private transport(request: { method: string; path: string; headers: Record<string, string>; body: Buffer }): Promise<{
    status: number;
    body: Buffer;
  }> {
    const url = new URL(this.options.origin);
    const timeoutMs = this.options.timeoutMs ?? 30_000;
    const pin = this.options.pinnedCertSha256;

    return new Promise((resolve, reject) => {
      const req = httpsRequest(
        {
          protocol: 'https:',
          host: url.hostname,
          port: url.port === '' ? 443 : Number(url.port),
          path: request.path,
          method: request.method,
          headers: request.headers,
          // Always on. There is no option in this client to disable it.
          rejectUnauthorized: true,
          ...(this.options.ca === undefined ? {} : { ca: this.options.ca }),
          ...(pin === undefined
            ? {}
            : {
                checkServerIdentity: (hostname: string, cert: PeerCertificate) => {
                  const hostnameError = tlsCheckServerIdentity(hostname, cert);
                  if (hostnameError) return hostnameError;
                  const raw = cert.raw;
                  if (!raw) return new Error('server certificate is unavailable');
                  const digest = createHash('sha256').update(raw).digest();
                  const expected = normalizePin(pin);
                  if (!digest.equals(expected)) return new Error('server certificate does not match the pin');
                  return undefined;
                },
              }),
          timeout: timeoutMs,
          // No keep-alive: one request, one connection. A pooled socket that
          // outlives a session is state a consumer does not need to reason about.
          agent: false,
        },
        (response) => {
          const chunks: Buffer[] = [];
          let size = 0;
          response.on('data', (chunk: Buffer) => {
            size += chunk.byteLength;
            if (size > 8 * 1024 * 1024) {
              response.destroy(new Error('response exceeds client limit'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', () => {
            resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks) });
          });
          response.on('error', reject);
        },
      );
      req.on('timeout', () => req.destroy(new MlpError('deadline_exceeded', 'request timed out')));
      req.on('error', reject);
      req.end(request.body);
    });
  }
}

function normalizePin(pin: string): Buffer {
  if (/^[0-9a-fA-F]{64}$/.test(pin)) return Buffer.from(pin, 'hex');
  return Buffer.from(pin, 'base64url');
}

/** Leaf grant `jti`, needed to bind a receipt to the session that produced it. */
function leafJti(chain: readonly string[]): string {
  const leaf = chain[chain.length - 1];
  if (!leaf) throw new Error('chain is empty');
  const payload = leaf.split('.')[1];
  if (!payload) throw new Error('leaf grant is not a compact JWS');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as JsonObject;
  const jti = claims.jti;
  if (typeof jti !== 'string') throw new Error('leaf grant has no jti');
  return jti;
}

/** Re-exported so a consumer can hash bytes the same way the protocol does. */
export { sha256b64u };

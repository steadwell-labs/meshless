/**
 * Capability grants and delegation chains (§9).
 *
 * A grant is a signed, scoped, expiring authorization. The properties that make
 * it safe are all arithmetic: delegation may only narrow, time may only shrink,
 * limits may only decrease, and the chain may not grow past four links. Every
 * one of those is checked here, on every link, on every request.
 */

import { uuidv4, sha256b64u, utf8 } from './bytes.ts';
import { invalidGrant, MlpError } from './errors.ts';
import { compactHash, checkJwsSignature, parseJws, signJws } from './jws.ts';
import { isJsonObject, type JsonObject } from './json.ts';
import {
  isKeyId,
  isPublicJwk,
  keyIdFromJwk,
  normalizePublicJwk,
  PublicKeyRef,
  type PublicJwk,
  type SigningKey,
} from './jwk.ts';
import { isResourceId } from './ids.ts';
import { parseActions, type DescriptorRecord } from './descriptor.ts';

export const GRANT_TYP = 'mlp-grant+jwt';

/** §9.1 ceiling on how far a grant may be delegated. */
export const MAX_DEPTH = 3;

/** §9.4: a chain is a root plus at most three delegations. */
export const MAX_CHAIN_LENGTH = 4;

/** §9.1: no grant may be issued for more than 24 hours. */
export const MAX_GRANT_LIFETIME_SECONDS = 86400;

const LIMIT_MEMBERS = ['calls', 'bytes', 'max_ms'] as const;

export interface GrantLimits {
  calls: number;
  bytes: number;
  max_ms: number;
}

export interface GrantClaims {
  readonly v: 1;
  readonly jti: string;
  readonly iss: string;
  readonly sub: string;
  readonly sub_jwk: PublicJwk;
  readonly aud: string;
  readonly rid: string;
  readonly actions: string[];
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
  readonly delegate: boolean;
  readonly depth: number;
  readonly limits: GrantLimits;
  readonly parent: string | null;
}

export interface GrantRecord {
  readonly claims: GrantClaims;
  readonly compact: string;
  /** base64url SHA-256 of the compact JWS exactly as received. */
  readonly hash: string;
  /** The subject's key, recovered from `sub_jwk` and checked against `sub`. */
  readonly subject: PublicKeyRef;
  readonly actions: ReadonlySet<string>;
}

/** Top-level claims MLP/1 defines. Anything else is rejected as unsupported. */
const KNOWN_CLAIMS = new Set([
  'v',
  'jti',
  'iss',
  'sub',
  'sub_jwk',
  'aud',
  'rid',
  'actions',
  'iat',
  'nbf',
  'exp',
  'delegate',
  'depth',
  'limits',
  'parent',
]);

/**
 * Parse and structurally validate one grant.
 *
 * Does not verify the signature, because the issuer's key depends on the
 * position in the chain: a root is signed by the owner, a child by its parent's
 * subject. `verifyChain` supplies the keys.
 */
export function parseGrant(compact: string): GrantRecord {
  const parsed = parseJws(compact, GRANT_TYP);
  const payload = parsed.payload;

  for (const member of Object.keys(payload)) {
    if (!KNOWN_CLAIMS.has(member)) throw invalidGrant(`grant carries unsupported claim ${member}`);
  }

  const jti = payload.jti;
  if (typeof jti !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(jti)) {
    throw invalidGrant('grant jti must be a lowercase UUIDv4');
  }

  const iss = payload.iss;
  const sub = payload.sub;
  const aud = payload.aud;
  if (!isKeyId(iss)) throw invalidGrant('grant iss must be a key identifier');
  if (!isKeyId(sub)) throw invalidGrant('grant sub must be a key identifier');
  if (!isKeyId(aud)) throw invalidGrant('grant aud must be a key identifier');

  if (!isPublicJwk(payload.sub_jwk)) throw invalidGrant('grant sub_jwk is not an Ed25519 public JWK');
  const subjectJwk = normalizePublicJwk(payload.sub_jwk);
  const subjectKeyId = keyIdFromJwk(subjectJwk);
  if (subjectKeyId !== sub) throw invalidGrant('grant sub_jwk does not match sub');

  const rid = payload.rid;
  if (!isResourceId(rid)) throw invalidGrant('grant rid is not a resource identifier');

  const actions = parseActions(payload.actions, 'grant actions');

  const iat = requireNonNegativeInteger(payload, 'iat');
  const nbf = requireNonNegativeInteger(payload, 'nbf');
  const exp = requireNonNegativeInteger(payload, 'exp');
  if (nbf < iat) throw invalidGrant('grant nbf must not precede iat');
  if (exp <= nbf) throw invalidGrant('grant exp must be after nbf');
  if (exp - iat > MAX_GRANT_LIFETIME_SECONDS) throw invalidGrant('grant lifetime exceeds 24 hours');

  const delegate = payload.delegate;
  if (typeof delegate !== 'boolean') throw invalidGrant('grant delegate must be a boolean');

  const depth = payload.depth;
  if (typeof depth !== 'number' || !Number.isInteger(depth) || depth < 0 || depth > MAX_DEPTH) {
    throw invalidGrant(`grant depth must be an integer between 0 and ${MAX_DEPTH}`);
  }
  if (delegate !== depth > 0) throw invalidGrant('grant delegate must equal depth > 0');

  const limits = parseLimits(payload.limits);

  const parent = payload.parent;
  if (parent !== null) {
    if (typeof parent !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(parent)) {
      throw invalidGrant('grant parent must be null or a base64url SHA-256 digest');
    }
  }

  return {
    claims: payload as unknown as GrantClaims,
    compact,
    hash: compactHash(compact),
    subject: new PublicKeyRef(subjectJwk),
    actions,
  };
}

/** Parse the `limits` object. All three are needed; a missing limit is not "unbounded". */
export function parseLimits(value: unknown): GrantLimits {
  if (!isJsonObject(value)) throw invalidGrant('grant limits must be an object');
  for (const member of Object.keys(value)) {
    if (!(LIMIT_MEMBERS as readonly string[]).includes(member)) {
      throw invalidGrant(`grant limits carries unsupported member ${member}`);
    }
  }
  const limits = {} as GrantLimits;
  for (const member of LIMIT_MEMBERS) {
    const raw = value[member];
    if (typeof raw !== 'number' || !Number.isInteger(raw) || raw <= 0 || !Number.isSafeInteger(raw)) {
      throw invalidGrant(`grant limits.${member} must be a positive safe integer`);
    }
    limits[member] = raw;
  }
  return limits;
}

export interface BuildGrantInput {
  rid: string;
  aud: string;
  subject: PublicKeyRef;
  actions: string[];
  iat: number;
  nbf: number;
  exp: number;
  limits: GrantLimits;
  depth: number;
  jti?: string;
}

/**
 * Build a root grant (`parent` = `null`), signed by the resource owner.
 *
 * The caller is responsible for checking that `actions` is a subset of the
 * descriptor's actions and that `aud` is the descriptor's provider; a provider
 * re-checks both on every request, but the issuing tool should refuse to create
 * a grant it knows is unusable.
 */
export function buildRootGrant(input: BuildGrantInput, ownerKey: SigningKey): string {
  assertGrantTimes(input);
  if (!isResourceId(input.rid)) throw new Error('rid must be an mlp:res identifier');
  if (!input.rid.startsWith(`mlp:res:${ownerKey.keyId.slice('mlp:key:'.length)}:`)) {
    throw new Error('root grant must be issued by the resource owner');
  }
  const payload: JsonObject = {
    v: 1,
    jti: input.jti ?? uuidv4(),
    iss: ownerKey.keyId,
    sub: input.subject.keyId,
    sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: input.subject.jwk.x },
    aud: input.aud,
    rid: input.rid,
    actions: [...new Set(input.actions)].sort(),
    iat: input.iat,
    nbf: input.nbf,
    exp: input.exp,
    delegate: input.depth > 0,
    depth: input.depth,
    limits: { calls: input.limits.calls, bytes: input.limits.bytes, max_ms: input.limits.max_ms },
    parent: null,
  };
  return signJws(payload, ownerKey, GRANT_TYP);
}

/**
 * Build a child grant from an existing parent.
 *
 * Refuses locally what a provider would refuse remotely: a parent that cannot
 * delegate, a wider action set, a longer window, or a larger limit. Failing at
 * issue time is cheaper than failing at invocation time.
 */
export function buildChildGrant(
  parent: GrantRecord,
  input: {
    subject: PublicKeyRef;
    actions: string[];
    nbf?: number;
    exp?: number;
    limits?: Partial<GrantLimits>;
    depth?: number;
    iat?: number;
    jti?: string;
  },
  issuerKey: SigningKey,
): string {
  const parentClaims = parent.claims;
  if (issuerKey.keyId !== parentClaims.sub) throw new Error('child grant must be signed by the parent subject');
  if (!parentClaims.delegate || parentClaims.depth < 1) throw new Error('parent grant does not permit delegation');

  const depth = input.depth ?? parentClaims.depth - 1;
  if (!Number.isInteger(depth) || depth < 0 || depth > parentClaims.depth - 1) {
    throw new Error('child depth must be at most parent depth minus one');
  }

  const actions = [...new Set(input.actions)].sort();
  for (const action of actions) {
    if (!parent.actions.has(action)) throw new Error(`child grant widens actions with ${action}`);
  }

  const nbf = input.nbf ?? parentClaims.nbf;
  const exp = input.exp ?? parentClaims.exp;
  if (nbf < parentClaims.nbf) throw new Error('child grant starts before parent');
  if (exp > parentClaims.exp) throw new Error('child grant ends after parent');

  const limits: GrantLimits = {
    calls: input.limits?.calls ?? parentClaims.limits.calls,
    bytes: input.limits?.bytes ?? parentClaims.limits.bytes,
    max_ms: input.limits?.max_ms ?? parentClaims.limits.max_ms,
  };
  for (const member of LIMIT_MEMBERS) {
    if (limits[member] > parentClaims.limits[member]) throw new Error(`child grant widens limit ${member}`);
  }

  const payload: JsonObject = {
    v: 1,
    jti: input.jti ?? uuidv4(),
    iss: issuerKey.keyId,
    sub: input.subject.keyId,
    sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: input.subject.jwk.x },
    aud: parentClaims.aud,
    rid: parentClaims.rid,
    actions,
    iat: input.iat ?? nbf,
    nbf,
    exp,
    delegate: depth > 0,
    depth,
    limits: { calls: limits.calls, bytes: limits.bytes, max_ms: limits.max_ms },
    parent: parent.hash,
  };
  const compact = signJws(payload, issuerKey, GRANT_TYP);
  assertGrantTimes({ iat: payload.iat as number, nbf, exp });
  return compact;
}

export interface ChainVerifyOptions {
  now: number;
  descriptor: DescriptorRecord;
  /** This provider's key identifier. */
  providerKeyId: string;
  /** The owner key enrolled for this resource. */
  ownerKeyId: string;
  /** Revocation lookup. Called for every link; ancestor revocation invalidates the chain. */
  isRevoked?: (jti: string) => boolean;
  /** No grace period is permitted for grant windows (§10.3). */
  skewSeconds?: number;
}

export interface VerifiedChain {
  readonly grants: GrantRecord[];
  readonly leaf: GrantRecord;
  readonly leafHash: string;
  /** Subject key identifier for each link, root first. */
  readonly subjects: string[];
  /** Effective limits: the minimum of every link in the chain. */
  readonly limits: GrantLimits;
}

/**
 * Verify a full chain from root to leaf.
 *
 * Every rule in §9.4 is checked here. A caller must treat a returned chain as a
 * verified fact only for the `now` it supplied; the provider re-checks on every
 * invocation rather than caching the decision.
 */
export function verifyChain(chain: string[], options: ChainVerifyOptions): VerifiedChain {
  if (!Array.isArray(chain) || chain.length === 0) throw invalidGrant('chain must contain at least a root grant');
  if (chain.length > MAX_CHAIN_LENGTH) throw invalidGrant(`chain exceeds ${MAX_CHAIN_LENGTH} grants`);

  const records = chain.map((compact) => parseGrant(compact));

  // Root: issued by the enrolled owner for this resource, and signed by the key
  // the descriptor names as owner.
  const root = records[0]!;
  if (root.claims.parent !== null) throw invalidGrant('first grant in chain must be a root grant');
  if (root.claims.iss !== options.ownerKeyId) throw invalidGrant('root grant issuer is not the enrolled owner');
  if (root.claims.iss !== options.descriptor.claims.iss) throw invalidGrant('root grant issuer is not the descriptor owner');
  if (root.claims.rid !== options.descriptor.claims.rid) throw invalidGrant('root grant resource does not match descriptor');
  if (root.claims.aud !== options.providerKeyId) throw invalidGrant('root grant audience is not this provider');
  if (root.claims.aud !== options.descriptor.claims.provider) {
    throw invalidGrant('root grant audience does not match the descriptor provider');
  }
  for (const action of root.actions) {
    if (!options.descriptor.actions.has(action)) throw invalidGrant(`root grant action ${action} is not declared by the descriptor`);
  }
  checkJwsSignature(parseJws(root.compact, GRANT_TYP), options.descriptor.owner.jwk);

  // Each child must be signed by its parent's subject and narrow every axis.
  for (let index = 1; index < records.length; index += 1) {
    const parent = records[index - 1]!;
    const child = records[index]!;
    if (child.claims.parent !== parent.hash) throw invalidGrant('child grant parent hash does not match the parent');
    if (child.claims.iss !== parent.claims.sub) throw invalidGrant('child grant issuer is not the parent subject');
    checkJwsSignature(parseJws(child.compact, GRANT_TYP), parent.subject.jwk);

    if (child.claims.aud !== parent.claims.aud) throw invalidGrant('delegation changed the audience');
    if (child.claims.rid !== parent.claims.rid) throw invalidGrant('delegation changed the resource');
    for (const action of child.actions) {
      if (!parent.actions.has(action)) throw invalidGrant(`delegation widened actions with ${action}`);
    }
    if (child.claims.nbf < parent.claims.nbf) throw invalidGrant('delegation starts before the parent');
    if (child.claims.exp > parent.claims.exp) throw invalidGrant('delegation ends after the parent');
    for (const member of LIMIT_MEMBERS) {
      if (child.claims.limits[member] > parent.claims.limits[member]) {
        throw invalidGrant(`delegation widened limit ${member}`);
      }
    }
    if (!parent.claims.delegate) throw invalidGrant('parent grant does not permit delegation');
    if (child.claims.depth !== parent.claims.depth - 1) throw invalidGrant('delegation depth did not decrease by one');
  }

  // Leaf: addressed to this provider, on this resource, within the declared
  // action set.
  const leaf = records[records.length - 1]!;
  if (leaf.claims.aud !== options.providerKeyId) throw invalidGrant('leaf audience is not this provider');
  if (leaf.claims.rid !== options.descriptor.claims.rid) throw invalidGrant('leaf resource does not match descriptor');
  for (const action of leaf.actions) {
    if (!options.descriptor.actions.has(action)) throw invalidGrant(`leaf action ${action} is not declared by the descriptor`);
  }

  // Time. No grace: §10.3 forbids it, because a grace window is a window in
  // which a revoked grant still runs.
  const skew = options.skewSeconds ?? 0;
  for (const record of records) {
    if (options.now + skew < record.claims.nbf) throw invalidGrant('grant is not yet valid');
    if (options.now >= record.claims.exp) throw invalidGrant('grant is expired');
  }

  if (options.isRevoked) {
    for (const record of records) {
      if (options.isRevoked(record.claims.jti)) throw new MlpError('revoked', 'grant is revoked', record.claims.jti);
    }
  }

  const limits = effectiveLimits(records);
  return {
    grants: records,
    leaf,
    leafHash: leaf.hash,
    subjects: records.map((record) => record.claims.sub),
    limits,
  };
}

/** The effective ceiling is the minimum of every link (§9.5). */
export function effectiveLimits(records: GrantRecord[]): GrantLimits {
  if (records.length === 0) throw invalidGrant('chain is empty');
  const limits: GrantLimits = { calls: Infinity, bytes: Infinity, max_ms: Infinity };
  for (const record of records) {
    for (const member of LIMIT_MEMBERS) {
      limits[member] = Math.min(limits[member], record.claims.limits[member]);
    }
  }
  return limits;
}

/** Every `jti` an owner would have to revoke to disable a chain, root first. */
export function chainJtis(records: GrantRecord[]): string[] {
  return records.map((record) => record.claims.jti);
}

function requireNonNegativeInteger(payload: JsonObject, member: string): number {
  const value = payload[member];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
    throw invalidGrant(`grant ${member} must be a non-negative integer`);
  }
  return value;
}

function assertGrantTimes(input: { iat: number; nbf: number; exp: number }): void {
  if (!Number.isInteger(input.iat) || !Number.isInteger(input.nbf) || !Number.isInteger(input.exp)) {
    throw new Error('grant times must be integer Unix seconds');
  }
  if (input.nbf < input.iat) throw new Error('nbf must not precede iat');
  if (input.exp <= input.nbf) throw new Error('exp must be after nbf');
  if (input.exp - input.iat > MAX_GRANT_LIFETIME_SECONDS) throw new Error('grant lifetime exceeds 24 hours');
}

/** Hash an arbitrary body exactly as it will be sent (§10.4). */
export function bodyHash(body: Uint8Array): string {
  return sha256b64u(body);
}

/** Convenience: hash a JSON string body. The caller must send these exact bytes. */
export function bodyHashOfJson(text: string): string {
  return sha256b64u(utf8(text));
}

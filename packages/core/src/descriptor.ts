/**
 * Resource descriptors (§7).
 *
 * A descriptor is the owner's signed statement that a resource exists, who
 * serves it, and which actions it supports. It conveys no authority to invoke
 * anything (§7.3), and this module has no function that could be mistaken for
 * granting access.
 *
 * A descriptor carries both public keys it names (`owner_jwk`,
 * `provider_jwk`) so that it is verifiable in isolation — from a file, a QR
 * code, or a clipboard — with no directory lookup. Without `owner_jwk` the
 * discovery paths in §8 could not work at all, because a thumbprint identifies
 * a key but cannot reconstruct it.
 */

import { invalidGrant } from './errors.ts';
import { signJws, parseJws, checkJwsSignature } from './jws.ts';
import { canonicalBytes, isJsonObject, type JsonObject } from './json.ts';
import {
  isKeyId,
  isPublicJwk,
  keyIdFromJwk,
  normalizePublicJwk,
  PublicKeyRef,
  type PublicJwk,
  type SigningKey,
} from './jwk.ts';
import { isResourceId, parseResourceId, resourceBelongsTo } from './ids.ts';

export const DESCRIPTOR_TYP = 'mlp-resource+jwt';

export const RESOURCE_KINDS = ['inference', 'mcp', 'storage', 'sensor', 'compute', 'application'] as const;
export type ResourceKind = (typeof RESOURCE_KINDS)[number];

/** 24 hours. §7.2 makes this a ceiling, not a target. */
export const MAX_DESCRIPTOR_LIFETIME_SECONDS = 86400;

/** `meta` is display data. Refuse to carry a payload inside it. */
export const MAX_META_BYTES = 8192;

export interface DescriptorClaims {
  readonly v: 1;
  readonly rid: string;
  readonly iss: string;
  readonly owner_jwk: PublicJwk;
  readonly provider: string;
  readonly provider_jwk: PublicJwk;
  readonly seq: number;
  readonly iat: number;
  readonly exp: number;
  readonly kind: ResourceKind;
  readonly actions: string[];
  readonly endpoint: string;
  readonly meta?: JsonObject;
}

export interface DescriptorRecord {
  readonly claims: DescriptorClaims;
  readonly compact: string;
  /** The owner key, derived from `owner_jwk` and checked against `iss`. */
  readonly owner: PublicKeyRef;
  /** The provider key, derived from `provider_jwk` and checked against `provider`. */
  readonly provider: PublicKeyRef;
  /** Lowercase HTTPS origin, with no trailing slash. */
  readonly origin: string;
  readonly kind: ResourceKind;
  readonly actions: ReadonlySet<string>;
}

export interface BuildDescriptorInput {
  rid: string;
  seq: number;
  iat: number;
  exp: number;
  kind: ResourceKind;
  actions: string[];
  endpoint: string;
  meta?: JsonObject;
}

/**
 * Build and sign a descriptor.
 *
 * The owner key is the signer; a provider cannot produce a descriptor that
 * names itself, which is what stops a compromised provider from inventing
 * resources it was not given.
 */
export function buildDescriptor(input: BuildDescriptorInput, ownerKey: SigningKey, providerKey: PublicKeyRef): string {
  if (!isResourceId(input.rid)) throw new Error('rid must be an mlp:res identifier');
  if (!resourceBelongsTo(input.rid, ownerKey.keyId)) {
    throw new Error('descriptor issuer does not match the resource owner');
  }
  const payload: JsonObject = {
    v: 1,
    rid: input.rid,
    iss: ownerKey.keyId,
    owner_jwk: { crv: 'Ed25519', kty: 'OKP', x: ownerKey.jwk.x },
    provider: providerKey.keyId,
    provider_jwk: { crv: 'Ed25519', kty: 'OKP', x: providerKey.jwk.x },
    seq: input.seq,
    iat: input.iat,
    exp: input.exp,
    kind: input.kind,
    actions: [...input.actions].sort(),
    endpoint: normalizeEndpoint(input.endpoint),
    ...(input.meta === undefined ? {} : { meta: input.meta }),
  };
  return signJws(payload, ownerKey, DESCRIPTOR_TYP);
}

/**
 * Normalize an endpoint to an HTTPS origin.
 *
 * Rejects a path, query, fragment, credentials, and any scheme other than
 * `https`. A descriptor that pointed at `http://` would silently downgrade the
 * only transport security MLP/1 has.
 */
export function normalizeEndpoint(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('endpoint must be an absolute URL');
  }
  if (url.protocol !== 'https:') throw new Error('endpoint must use https');
  if (url.username || url.password) throw new Error('endpoint must not contain credentials');
  if (url.search || url.hash) throw new Error('endpoint must not contain a query or fragment');
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('endpoint must be an origin, not a path');
  return url.origin;
}

export interface VerifyDescriptorOptions {
  /** Current time in Unix seconds. Required: MLP/1 has no "trust the clock" default. */
  now: number;
  /** Reject unless the owner is the one this consumer has enrolled for the resource. */
  expectedOwnerKeyId?: string;
  /** Reject unless the provider is the one this consumer has approved. */
  expectedProviderKeyId?: string;
  /** Highest `seq` previously accepted for this resource, for rollback defence. */
  highWaterSeq?: number;
  /** Tolerance for a descriptor issued slightly in the future. Default 30s. */
  skewSeconds?: number;
}

/**
 * Verify a descriptor: structure, signature, key bindings, endpoint, actions,
 * and freshness. Returns the parsed record or throws `invalid_grant`.
 */
export function verifyDescriptor(compact: string, options: VerifyDescriptorOptions): DescriptorRecord {
  const parsed = parseJws(compact, DESCRIPTOR_TYP);
  const payload = parsed.payload;

  const iss = payload.iss;
  if (!isKeyId(iss)) throw invalidGrant('descriptor iss must be a key identifier');

  const rid = payload.rid;
  if (!isResourceId(rid)) throw invalidGrant('descriptor rid is not a resource identifier');
  if (!resourceBelongsTo(rid, iss)) throw invalidGrant('descriptor rid owner does not match iss');

  if (!isPublicJwk(payload.owner_jwk)) throw invalidGrant('descriptor owner_jwk is not an Ed25519 public JWK');
  const ownerJwk = normalizePublicJwk(payload.owner_jwk);
  const ownerKeyId = keyIdFromJwk(ownerJwk);
  if (ownerKeyId !== iss) throw invalidGrant('descriptor owner_jwk does not match iss');

  if (!isPublicJwk(payload.provider_jwk)) throw invalidGrant('descriptor provider_jwk is not an Ed25519 public JWK');
  const providerJwk = normalizePublicJwk(payload.provider_jwk);
  const providerKeyId = keyIdFromJwk(providerJwk);
  if (payload.provider !== providerKeyId) throw invalidGrant('descriptor provider does not match provider_jwk');

  checkJwsSignature(parsed, ownerJwk);

  const seq = payload.seq;
  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 0 || !Number.isSafeInteger(seq)) {
    throw invalidGrant('descriptor seq must be a nonnegative safe integer');
  }

  const iat = requireTime(payload, 'iat');
  const exp = requireTime(payload, 'exp');
  if (exp <= iat) throw invalidGrant('descriptor exp must be after iat');
  if (exp - iat > MAX_DESCRIPTOR_LIFETIME_SECONDS) throw invalidGrant('descriptor lifetime exceeds 24 hours');

  const skew = options.skewSeconds ?? 30;
  if (options.now + skew < iat) throw invalidGrant('descriptor is not yet valid');
  if (options.now >= exp) throw invalidGrant('descriptor is expired');

  const kind = payload.kind;
  if (typeof kind !== 'string' || !(RESOURCE_KINDS as readonly string[]).includes(kind)) {
    throw invalidGrant('descriptor kind is not a known resource kind');
  }

  const actionSet = parseActions(payload.actions);

  const endpoint = payload.endpoint;
  if (typeof endpoint !== 'string') throw invalidGrant('descriptor endpoint must be a string');
  let origin: string;
  try {
    origin = normalizeEndpoint(endpoint);
  } catch (error) {
    throw invalidGrant((error as Error).message);
  }

  if (payload.meta !== undefined) {
    if (!isJsonObject(payload.meta)) throw invalidGrant('descriptor meta must be an object');
    if (canonicalBytes(payload.meta).byteLength > MAX_META_BYTES) throw invalidGrant('descriptor meta exceeds limit');
  }

  if (options.expectedOwnerKeyId !== undefined && options.expectedOwnerKeyId !== iss) {
    throw invalidGrant('descriptor owner is not the enrolled owner for this resource');
  }
  if (options.expectedProviderKeyId !== undefined && options.expectedProviderKeyId !== providerKeyId) {
    throw invalidGrant('descriptor provider is not the approved provider');
  }
  if (options.highWaterSeq !== undefined && seq <= options.highWaterSeq) {
    throw invalidGrant('descriptor seq does not advance the high-water mark');
  }

  return {
    claims: payload as unknown as DescriptorClaims,
    compact,
    owner: new PublicKeyRef(ownerJwk),
    provider: new PublicKeyRef(providerJwk),
    origin,
    kind: kind as ResourceKind,
    actions: actionSet,
  };
}

/**
 * Parse and validate an action list.
 *
 * No wildcards, no patterns, no empty strings. A wildcard action is authority
 * invented by string comparison, which is the failure mode MLP/1 exists to
 * avoid.
 */
export function parseActions(value: unknown, label = 'actions'): Set<string> {
  if (!Array.isArray(value) || value.length === 0) throw invalidGrant(`${label} must be a non-empty array`);
  if (value.length > 256) throw invalidGrant(`${label} has too many entries`);
  const set = new Set<string>();
  for (const action of value) {
    if (typeof action !== 'string' || action.length === 0 || action.length > 64) {
      throw invalidGrant(`${label} must contain short non-empty strings`);
    }
    if (/[*?[\]{}()|^$\\]/.test(action)) throw invalidGrant(`${label} must not contain pattern syntax`);
    if (set.has(action)) throw invalidGrant(`${label} must be unique`);
    set.add(action);
  }
  return set;
}

function requireTime(payload: JsonObject, member: string): number {
  const value = payload[member];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
    throw invalidGrant(`descriptor ${member} must be a non-negative integer`);
  }
  return value;
}

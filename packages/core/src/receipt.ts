/**
 * Invocation receipts (§12.4).
 *
 * A receipt is the provider's signed statement that it reports having run an
 * invocation. It is intentionally weak: it says nothing about correctness, and
 * it must not contain the prompt, the arguments, or the result, because a
 * receipt is the one MLP object most likely to end up in a log or a database
 * belonging to someone other than the provider.
 */

import { isUuidV4, sha256b64u } from './bytes.ts';
import { invalidProof } from './errors.ts';
import { checkJwsSignature, parseJws, signJws } from './jws.ts';
import { canonicalBytes, isJsonObject, type JsonObject } from './json.ts';
import { isKeyId, type PublicKeyRef, type SigningKey } from './jwk.ts';
import { isResourceId } from './ids.ts';

export const RECEIPT_TYP = 'mlp-receipt+jwt';

export type ReceiptStatus = 'ok' | 'error';

export interface ReceiptUsage {
  calls: number;
  bytes: number;
  elapsed_ms: number;
}

export interface ReceiptClaims {
  readonly v: 1;
  readonly rid: string;
  readonly iss: string;
  readonly sub: string;
  readonly jti: string;
  readonly request_id: string;
  readonly action: string;
  readonly iat: number;
  readonly status: ReceiptStatus;
  readonly request_hash: string;
  readonly result_hash: string | null;
  readonly usage: ReceiptUsage;
}

const KNOWN_CLAIMS = new Set([
  'v',
  'rid',
  'iss',
  'sub',
  'jti',
  'request_id',
  'action',
  'iat',
  'status',
  'request_hash',
  'result_hash',
  'usage',
]);

export interface BuildReceiptInput {
  rid: string;
  sub: string;
  jti: string;
  requestId: string;
  action: string;
  iat: number;
  /** The input object exactly as received. Canonicalized here for the hash. */
  request: JsonObject;
  /** The result object, or null on failure. */
  result: JsonObject | null;
  usage: ReceiptUsage;
}

export function buildReceipt(input: BuildReceiptInput, providerKey: SigningKey): string {
  const payload: JsonObject = {
    v: 1,
    rid: input.rid,
    iss: providerKey.keyId,
    sub: input.sub,
    jti: input.jti,
    request_id: input.requestId,
    action: input.action,
    iat: input.iat,
    status: input.result === null ? 'error' : 'ok',
    request_hash: sha256b64u(canonicalBytes(input.request)),
    result_hash: input.result === null ? null : sha256b64u(canonicalBytes(input.result)),
    usage: { calls: input.usage.calls, bytes: input.usage.bytes, elapsed_ms: input.usage.elapsed_ms },
  };
  return signJws(payload, providerKey, RECEIPT_TYP);
}

export interface VerifyReceiptInput {
  provider: PublicKeyRef;
  rid: string;
  sub: string;
  jti: string;
  requestId: string;
  action?: string;
  /** When supplied, the request hash is recomputed and compared. */
  request?: JsonObject;
  /** When supplied, the result hash is recomputed and compared. */
  result?: JsonObject;
}

export function verifyReceipt(compact: string, input: VerifyReceiptInput): ReceiptClaims {
  const parsed = parseJws(compact, RECEIPT_TYP);
  const payload = parsed.payload;
  for (const member of Object.keys(payload)) {
    if (!KNOWN_CLAIMS.has(member)) throw invalidProof(`receipt carries unsupported claim ${member}`);
  }
  const claims = payload as unknown as ReceiptClaims;

  checkJwsSignature(parsed, input.provider.jwk);

  if (claims.iss !== input.provider.keyId) throw invalidProof('receipt issuer is not the expected provider');
  if (claims.rid !== input.rid) throw invalidProof('receipt resource does not match');
  if (claims.sub !== input.sub) throw invalidProof('receipt subject does not match');
  if (claims.jti !== input.jti) throw invalidProof('receipt does not reference the leaf grant');
  if (claims.request_id !== input.requestId) throw invalidProof('receipt request_id does not match');
  if (input.action !== undefined && claims.action !== input.action) throw invalidProof('receipt action does not match');
  if (!isResourceId(claims.rid)) throw invalidProof('receipt rid is not a resource identifier');
  if (!isKeyId(claims.iss) || !isKeyId(claims.sub)) throw invalidProof('receipt key identifiers are malformed');
  if (!isUuidV4(claims.jti)) throw invalidProof('receipt jti must be a UUIDv4');
  if (!isUuidV4(claims.request_id)) throw invalidProof('receipt request_id must be a UUIDv4');
  if (claims.status !== 'ok' && claims.status !== 'error') throw invalidProof('receipt status is invalid');
  if (claims.status === 'ok' && typeof claims.result_hash !== 'string') throw invalidProof('receipt result_hash must be present on success');
  if (claims.status === 'error' && claims.result_hash !== null) throw invalidProof('receipt result_hash must be null on failure');
  if (typeof claims.request_hash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(claims.request_hash)) {
    throw invalidProof('receipt request_hash is malformed');
  }
  if (typeof claims.result_hash === 'string' && !/^[A-Za-z0-9_-]{43}$/.test(claims.result_hash)) {
    throw invalidProof('receipt result_hash is malformed');
  }

  if (!isJsonObject(claims.usage)) throw invalidProof('receipt usage must be an object');
  for (const member of ['calls', 'bytes', 'elapsed_ms'] as const) {
    const value = claims.usage[member];
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
      throw invalidProof(`receipt usage.${member} must be a non-negative integer`);
    }
  }

  if (input.request !== undefined) {
    const expected = sha256b64u(canonicalBytes(input.request));
    if (claims.request_hash !== expected) throw invalidProof('receipt request hash does not match the request');
  }
  if (input.result !== undefined) {
    const expected = sha256b64u(canonicalBytes(input.result));
    if (claims.result_hash !== expected) throw invalidProof('receipt result hash does not match the result');
  }

  return claims;
}

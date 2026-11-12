/**
 * Proof of possession (§10.4).
 *
 * A grant is not a bearer credential. Every authenticated request carries a
 * proof that binds the caller's key to this method, this URI, these exact body
 * bytes, this leaf grant, and a nonce the provider issued for this subject.
 * Interception of any other message in the protocol is therefore not enough to
 * invoke anything.
 */

import { isUuidV4, sha256b64u, uuidv4 } from './bytes.ts';
import { invalidProof } from './errors.ts';
import { checkJwsSignature, parseJws, signJws } from './jws.ts';
import { isJsonObject } from './json.ts';
import { isKeyId, verifyBytes, type SigningKey } from './jwk.ts';

export const PROOF_TYP = 'mlp-proof+jwt';

/** §10.4: a proof is accepted only within 30 seconds of the provider clock. */
export const PROOF_SKEW_SECONDS = 30;

export interface ProofClaims {
  readonly v: 1;
  readonly iss: string;
  readonly aud: string;
  readonly jti: string;
  readonly iat: number;
  readonly nonce: string;
  readonly method: string;
  readonly uri: string;
  readonly body_hash: string;
  readonly grant_hash: string;
}

const KNOWN_CLAIMS = new Set(['v', 'iss', 'aud', 'jti', 'iat', 'nonce', 'method', 'uri', 'body_hash', 'grant_hash']);

export interface BuildProofInput {
  key: SigningKey;
  aud: string;
  nonce: string;
  method: string;
  /** Exact origin plus path, no query, no fragment. */
  uri: string;
  /** Exact bytes that will be sent as the request body. */
  body: Uint8Array;
  /** Leaf grant hash, or the empty string for owner-only operations. */
  grantHash: string;
  iat?: number;
  /** Fixed proof id, for deterministic test vectors only. */
  jti?: string;
}

export function buildProof(input: BuildProofInput): string {
  const method = input.method.toUpperCase();
  const payload = {
    v: 1 as const,
    iss: input.key.keyId,
    aud: input.aud,
    jti: input.jti ?? uuidv4(),
    iat: input.iat ?? Math.floor(Date.now() / 1000),
    nonce: input.nonce,
    method,
    uri: input.uri,
    body_hash: sha256b64u(input.body),
    grant_hash: input.grantHash,
  };
  return signJws(payload, input.key, PROOF_TYP);
}

export interface VerifyProofInput {
  /** Expected subject key identifier. */
  subject: string;
  /** Expected audience: this provider. */
  aud: string;
  /** Expected method, compared uppercased. */
  method: string;
  /** Expected URI: exact origin plus path. */
  uri: string;
  /** The exact body bytes received. */
  body: Uint8Array;
  /** Expected leaf grant hash, or empty string for owner-only operations. */
  grantHash: string;
  now: number;
  skewSeconds?: number;
  /** Public key of the subject. Required; a proof never carries its own key. */
  subjectJwk?: { crv: 'Ed25519'; kty: 'OKP'; x: string };
}

/**
 * Verify a proof against the request it arrived with.
 *
 * All bindings are compared as byte strings. The nonce is not consumed here:
 * consumption is the provider's atomic operation, because verification and
 * consumption must not be separable by a caller.
 */
export function verifyProof(compact: string, input: VerifyProofInput): ProofClaims {
  const parsed = parseJws(compact, PROOF_TYP);
  const payload = parsed.payload;

  for (const member of Object.keys(payload)) {
    if (!KNOWN_CLAIMS.has(member)) throw invalidProof(`proof carries unsupported claim ${member}`);
  }

  const claims = payload as unknown as ProofClaims;
  if (!isKeyId(claims.iss)) throw invalidProof('proof iss must be a key identifier');
  if (!isKeyId(claims.aud)) throw invalidProof('proof aud must be a key identifier');
  if (claims.iss !== input.subject) throw invalidProof('proof subject does not match');
  if (claims.aud !== input.aud) throw invalidProof('proof audience does not match');
  if (!isUuidV4(claims.jti)) throw invalidProof('proof jti must be a UUIDv4');
  if (typeof claims.iat !== 'number' || !Number.isInteger(claims.iat)) throw invalidProof('proof iat must be an integer');
  if (typeof claims.nonce !== 'string' || claims.nonce.length < 16 || claims.nonce.length > 128) {
    throw invalidProof('proof nonce is malformed');
  }
  if (typeof claims.method !== 'string' || claims.method !== claims.method.toUpperCase()) {
    throw invalidProof('proof method must be uppercase');
  }
  if (claims.method !== input.method.toUpperCase()) throw invalidProof('proof method does not match the request');
  if (typeof claims.uri !== 'string' || claims.uri !== input.uri) throw invalidProof('proof uri does not match the request');
  if (claims.uri.includes('?') || claims.uri.includes('#')) throw invalidProof('proof uri must not carry a query or fragment');

  const expectedBodyHash = sha256b64u(input.body);
  if (claims.body_hash !== expectedBodyHash) throw invalidProof('proof body hash does not match the body');

  if (claims.grant_hash !== input.grantHash) throw invalidProof('proof grant hash does not match the leaf grant');
  if (input.grantHash === '') {
    // Owner-only operations (revoke) carry an empty grant hash verbatim.
    if (claims.grant_hash !== '') throw invalidProof('proof grant hash must be empty for this operation');
  } else if (!/^[A-Za-z0-9_-]{43}$/.test(claims.grant_hash)) {
    throw invalidProof('proof grant hash is malformed');
  }

  const skew = input.skewSeconds ?? PROOF_SKEW_SECONDS;
  if (Math.abs(input.now - claims.iat) > skew) throw invalidProof('proof timestamp is outside the allowed window');

  if (input.subjectJwk) {
    checkJwsSignature(parsed, input.subjectJwk);
  }
  return claims;
}

/**
 * Check a proof signature against a raw public key. Exposed separately so a
 * provider can verify the signature after it has resolved the subject key from
 * the chain, without rebuilding the whole verification input.
 */
export function verifyProofSignature(compact: string, jwk: { crv: 'Ed25519'; kty: 'OKP'; x: string }): ProofClaims {
  const parsed = parseJws(compact, PROOF_TYP);
  if (!verifyBytes(jwk, parsed.signingInput, parsed.signature)) throw invalidProof('proof signature does not verify');
  return parsed.payload as unknown as ProofClaims;
}

/** True when a body is empty, used for GET proofs where no body is sent. */
export function isEmptyBody(body: Uint8Array | undefined): boolean {
  return body === undefined || body.byteLength === 0;
}

export function isProofShaped(value: unknown): boolean {
  return isJsonObject(value);
}

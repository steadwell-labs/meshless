/**
 * Compact JWS for MLP/1 (§6.3, §10.2).
 *
 * Only one header shape is accepted, only one algorithm, and the payload must
 * arrive already canonicalized. Verification is split into parse and check
 * because MLP/1 learns each key from a different place: a grant's subject key
 * comes from the grant itself, a receipt's key comes from the descriptor, and a
 * proof's key comes from the leaf grant.
 */

import { b64u, b64uDecode, sha256b64u, utf8 } from './bytes.ts';
import { invalidProof } from './errors.ts';
import { assertCanonical, canonicalBytes, isJsonObject, parseJsonStrict, type JsonObject } from './json.ts';
import { isKeyId, verifyBytes, type PublicJwk, type SigningKey } from './jwk.ts';

export type JwsTyp = 'mlp-resource+jwt' | 'mlp-grant+jwt' | 'mlp-proof+jwt' | 'mlp-receipt+jwt';

export interface JwsHeader extends JsonObject {
  alg: 'EdDSA';
  kid: string;
  typ: JwsTyp;
}

export interface ParsedJws {
  readonly compact: string;
  readonly header: JwsHeader;
  readonly payload: JsonObject;
  readonly payloadBytes: Buffer;
  readonly signingInput: Buffer;
  readonly signature: Buffer;
  readonly kid: string;
  readonly typ: JwsTyp;
}

/**
 * Headers that must never appear. `jwk` and friends would let an attacker
 * supply the key that verifies their own object; `crit` would let an object
 * demand an extension the verifier does not implement. §6.3 requires rejection.
 */
const FORBIDDEN_HEADER_MEMBERS = new Set(['jwk', 'jku', 'x5u', 'x5c', 'crit', 'b64', 'cty']);

/** Sign a payload object into compact serialization. */
export function signJws(payload: JsonObject, key: SigningKey, typ: JwsTyp): string {
  const header: JwsHeader = { alg: 'EdDSA', kid: key.keyId, typ };
  const protectedHeader = b64u(utf8(JSON.stringify(header)));
  const body = b64u(canonicalBytes(payload));
  const signingInput = Buffer.from(`${protectedHeader}.${body}`, 'ascii');
  const signature = key.sign(signingInput);
  return `${protectedHeader}.${body}.${b64u(signature)}`;
}

/**
 * Parse and structurally validate a compact JWS.
 *
 * Does not verify the signature; the caller resolves the key. Performs every
 * check that does not need one, so a malformed object is rejected before any
 * key lookup happens.
 */
export function parseJws(compact: string, expectedTyp: JwsTyp): ParsedJws {
  if (typeof compact !== 'string') throw invalidProof('JWS is not a string');
  if (compact.length > 16384) throw invalidProof('JWS exceeds maximum size');
  const parts = compact.split('.');
  if (parts.length !== 3) throw invalidProof('JWS must have three parts');
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  let headerBytes: Buffer;
  let payloadBytes: Buffer;
  let signature: Buffer;
  try {
    headerBytes = b64uDecode(headerPart);
    payloadBytes = b64uDecode(payloadPart);
    signature = b64uDecode(signaturePart);
  } catch {
    throw invalidProof('JWS is not unpadded base64url');
  }
  if (signature.byteLength !== 64) throw invalidProof('Ed25519 signature must be 64 bytes');

  let headerValue: unknown;
  try {
    headerValue = parseJsonStrict(headerBytes);
  } catch {
    throw invalidProof('JWS header is not valid JSON');
  }
  if (!isJsonObject(headerValue)) throw invalidProof('JWS header must be an object');

  for (const member of Object.keys(headerValue)) {
    if (FORBIDDEN_HEADER_MEMBERS.has(member)) throw invalidProof(`JWS header must not contain ${member}`);
  }
  if (headerValue.alg !== 'EdDSA') throw invalidProof('JWS alg must be EdDSA');
  if (headerValue.typ !== expectedTyp) throw invalidProof(`JWS typ must be ${expectedTyp}`);
  const kid = headerValue.kid;
  if (!isKeyId(kid)) throw invalidProof('JWS kid must be an MLP key identifier');
  const unknown = Object.keys(headerValue).filter((name) => name !== 'alg' && name !== 'typ' && name !== 'kid');
  if (unknown.length > 0) throw invalidProof(`JWS header has unknown members: ${unknown.join(',')}`);

  let payloadValue: unknown;
  try {
    // Rejects non-canonical payloads (§10.2).
    payloadValue = assertCanonical(payloadBytes);
  } catch (error) {
    throw invalidProof(`JWS payload rejected: ${(error as Error).message}`);
  }
  if (!isJsonObject(payloadValue)) throw invalidProof('JWS payload must be an object');
  if (payloadValue.iss !== kid) throw invalidProof('JWS kid must equal payload iss');
  if (payloadValue.v !== 1) throw invalidProof('JWS payload v must be 1');

  const header: JwsHeader = { alg: 'EdDSA', kid, typ: expectedTyp };
  const signingInput = Buffer.from(`${headerPart}.${payloadPart}`, 'ascii');
  return { compact, header, payload: payloadValue, payloadBytes, signingInput, signature, kid, typ: expectedTyp };
}

/** Verify a parsed JWS against a known public key. Throws on failure. */
export function checkJwsSignature(parsed: ParsedJws, jwk: PublicJwk): ParsedJws {
  if (!verifyBytes(jwk, parsed.signingInput, parsed.signature)) {
    throw invalidProof('JWS signature does not verify');
  }
  return parsed;
}

/** Parse and verify in one step when the key is already known. */
export function verifyJws(compact: string, expectedTyp: JwsTyp, jwk: PublicJwk): ParsedJws {
  return checkJwsSignature(parseJws(compact, expectedTyp), jwk);
}

/**
 * Hash a compact JWS exactly as it appears on the wire.
 *
 * Used for `parent` (§9.1) and `grant_hash` (§10.4). Both must bind the bytes
 * the counterparty holds, not a re-serialization.
 */
export function compactHash(compact: string): string {
  return sha256b64u(Buffer.from(compact, 'ascii'));
}

/**
 * Ed25519 keys and RFC 7638 thumbprints.
 *
 * MLP/1 has exactly one signature algorithm on the wire: EdDSA over Ed25519
 * (RFC 8037). There is no negotiation, no algorithm registry, and no path by
 * which a caller can select a weaker suite. That is a feature.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { b64u, b64uDecode, sha256 } from './bytes.ts';
import { canonicalBytes, isJsonObject, type JsonObject } from './json.ts';

/** A public Ed25519 JWK with exactly the members MLP/1 permits. */
export interface PublicJwk extends JsonObject {
  crv: 'Ed25519';
  kty: 'OKP';
  x: string;
}

export const KEY_ID_PREFIX = 'mlp:key:';

/**
 * PKCS#8 prefix for an Ed25519 private key: the fixed algorithm identifier
 * followed by an octet string wrapper for the 32-byte seed.
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const keyCache = new Map<string, KeyObject>();

export function isPublicJwk(value: unknown): value is PublicJwk {
  if (!isJsonObject(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.length !== 3 || keys[0] !== 'crv' || keys[1] !== 'kty' || keys[2] !== 'x') return false;
  if (value.crv !== 'Ed25519' || value.kty !== 'OKP') return false;
  const x = value.x;
  if (typeof x !== 'string') return false;
  try {
    return b64uDecode(x).length === 32;
  } catch {
    return false;
  }
}

/**
 * Normalize a JWK to the exact three-member form.
 *
 * Rejects a JWK carrying private key material: a `d` member anywhere in a
 * descriptor or grant is a key leak, not a formatting error.
 */
export function normalizePublicJwk(value: unknown): PublicJwk {
  if (isJsonObject(value) && 'd' in value) {
    throw new Error('JWK contains private key material (d)');
  }
  if (!isPublicJwk(value)) throw new Error('not a valid Ed25519 public JWK');
  return { crv: 'Ed25519', kty: 'OKP', x: value.x };
}

/** RFC 7638 thumbprint: SHA-256 over the canonical three-member JWK. */
export function jwkThumbprint(jwk: PublicJwk): string {
  return b64u(sha256(canonicalBytes(normalizePublicJwk(jwk))));
}

/** `mlp:key:<thumbprint>` per §6.1. */
export function keyIdFromJwk(jwk: PublicJwk): string {
  return `${KEY_ID_PREFIX}${jwkThumbprint(jwk)}`;
}

const KEY_ID_PATTERN = /^mlp:key:[A-Za-z0-9_-]{43}$/;

export function isKeyId(value: unknown): value is string {
  if (typeof value !== 'string' || !KEY_ID_PATTERN.test(value)) return false;
  try {
    return b64uDecode(value.slice(KEY_ID_PREFIX.length)).length === 32;
  } catch {
    return false;
  }
}

/** Extract the thumbprint from a key identifier, validating its shape. */
export function thumbprintOf(keyId: string): string {
  if (!isKeyId(keyId)) throw new Error('not an MLP key identifier');
  return keyId.slice(KEY_ID_PREFIX.length);
}

function keyObjectFromJwk(jwk: PublicJwk): KeyObject {
  const cached = keyCache.get(jwk.x);
  if (cached) return cached;
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  keyCache.set(jwk.x, key);
  return key;
}

/** Verify a detached Ed25519 signature over arbitrary bytes. */
export function verifyBytes(jwk: PublicJwk, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return cryptoVerify(null, message, keyObjectFromJwk(normalizePublicJwk(jwk)), signature);
  } catch {
    return false;
  }
}

/**
 * A private key held by a principal.
 *
 * Construction is deliberately explicit: `generate`, `fromSeed`, or
 * `fromPkcs8`. There is no way to load a key from a path or a URL, because a
 * protocol implementation should never be talked into reading key material it
 * was not given.
 */
export class SigningKey {
  readonly jwk: PublicJwk;
  readonly keyId: string;
  private readonly keyObject: KeyObject;

  private constructor(keyObject: KeyObject) {
    this.keyObject = keyObject;
    const exported = createPublicKey(keyObject).export({ format: 'jwk' }) as JsonObject;
    this.jwk = normalizePublicJwk(exported);
    this.keyId = keyIdFromJwk(this.jwk);
  }

  static generate(): SigningKey {
    return new SigningKey(generateKeyPairSync('ed25519').privateKey);
  }

  /** Deterministic key from a 32-byte seed. Use for fixtures, never for production. */
  static fromSeed(seed: Uint8Array): SigningKey {
    if (seed.byteLength !== 32) throw new Error('Ed25519 seed must be 32 bytes');
    const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
    return new SigningKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }));
  }

  static fromPkcs8Der(der: Uint8Array): SigningKey {
    return new SigningKey(createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' }));
  }

  sign(message: Uint8Array): Buffer {
    return cryptoSign(null, message, this.keyObject);
  }

  /** PKCS#8 DER. Callers are responsible for storing this encrypted at rest. */
  toPkcs8Der(): Buffer {
    return this.keyObject.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  }
}

/**
 * A public-only key reference, used for the provider key a consumer learns from
 * a descriptor and for a subject key learned from a grant.
 */
export class PublicKeyRef {
  readonly jwk: PublicJwk;
  readonly keyId: string;

  constructor(jwk: PublicJwk) {
    this.jwk = normalizePublicJwk(jwk);
    this.keyId = keyIdFromJwk(this.jwk);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return verifyBytes(this.jwk, message, signature);
  }
}

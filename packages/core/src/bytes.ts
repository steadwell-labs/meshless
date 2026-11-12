/**
 * Byte and encoding primitives.
 *
 * Everything here is deliberately boring. MLP/1 defines a small set of
 * encodings and this module is the only place allowed to interpret them.
 */

import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto';

/** Domain separator used when a hash needs a type tag. Not used in MLP/1 wire. */
export const UTF8 = new TextEncoder();

export function utf8(value: string): Buffer {
  return Buffer.from(value, 'utf8');
}

/**
 * Encode bytes as unpadded base64url (RFC 4648 §5).
 * MLP/1 forbids padding anywhere on the wire.
 */
export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * Decode unpadded base64url.
 *
 * Node's decoder tolerates padding and standard-alphabet input, so this
 * function re-encodes the result and requires exact round-trip equality. That
 * rejects `+`, `/`, `=`, and any other non-canonical spelling, which matters
 * because these strings are compared and hashed byte for byte.
 */
export function b64uDecode(text: string): Buffer {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error('not unpadded base64url');
  }
  if (text.length % 4 === 1) throw new Error('invalid base64url length');
  const decoded = Buffer.from(text, 'base64url');
  if (decoded.toString('base64url') !== text) throw new Error('non-canonical base64url');
  return decoded;
}

export function sha256(bytes: Uint8Array): Buffer {
  return createHash('sha256').update(bytes).digest();
}

export function sha256b64u(bytes: Uint8Array): string {
  return b64u(sha256(bytes));
}

export function randomBytes(length: number): Buffer {
  return nodeRandomBytes(length);
}

export function randomToken(length = 32): string {
  return b64u(randomBytes(length));
}

/** Constant-time comparison for equal-length byte strings. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return timingSafeEqual(Buffer.from(a.buffer, a.byteOffset, a.byteLength), Buffer.from(b.buffer, b.byteOffset, b.byteLength));
}

/** Constant-time comparison for UTF-8 strings of any length. */
export function stringsEqual(a: string, b: string): boolean {
  return bytesEqual(utf8(a), utf8(b));
}

/**
 * RFC 9562 UUIDv4 in lowercase 8-4-4-4-12 form.
 *
 * The version and variant nibbles are set from the random source rather than
 * patched afterwards, so a caller cannot accidentally generate a v7-shaped
 * identifier that MLP/1 would reject.
 */
export function uuidv4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** True only for the exact lowercase RFC 9562 UUIDv4 spelling. */
export function isUuidV4(value: unknown): value is string {
  return typeof value === 'string' && UUID_V4.test(value);
}

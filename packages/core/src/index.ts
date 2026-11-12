/**
 * Meshless Protocol (MLP/1) — protocol primitives.
 *
 * Dependency-free by design. Everything a conforming implementation needs to
 * produce and verify MLP/1 objects is here, and nothing here performs I/O, so
 * it can be audited and reused in a gateway, a client, or a test harness.
 */

export * from './bytes.ts';
export * from './errors.ts';
export * from './json.ts';
export * from './jwk.ts';
export * from './jws.ts';
export * from './ids.ts';
export * from './descriptor.ts';
export * from './grant.ts';
export * from './proof.ts';
export * from './receipt.ts';

export const MLP_VERSION = 1;
export const MLP_PROTOCOL = 'MLP/1';
export const MLP_DRAFT = 'Draft 00';

/**
 * Resource identifiers (§7.1).
 *
 * `mlp:res:<owner-thumbprint>:<uuid>` identifies an authorization domain, not a
 * host. Nothing here resolves to an address, and no code in this file may.
 */

import { thumbprintOf, isKeyId } from './jwk.ts';
import { isUuidV4 } from './bytes.ts';

export const RESOURCE_ID_PREFIX = 'mlp:res:';

const RESOURCE_ID_PATTERN = /^mlp:res:([A-Za-z0-9_-]{43}):([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;

export interface ParsedResourceId {
  readonly ownerThumbprint: string;
  readonly ownerKeyId: string;
  readonly uuid: string;
}

export function makeResourceId(ownerKeyId: string, uuid: string): string {
  if (!isKeyId(ownerKeyId)) throw new Error('owner must be an MLP key identifier');
  if (!isUuidV4(uuid)) throw new Error('resource UUID must be a lowercase UUIDv4');
  return `${RESOURCE_ID_PREFIX}${thumbprintOf(ownerKeyId)}:${uuid}`;
}

export function isResourceId(value: unknown): value is string {
  return typeof value === 'string' && RESOURCE_ID_PATTERN.test(value);
}

export function parseResourceId(value: unknown): ParsedResourceId {
  if (typeof value !== 'string') throw new Error('resource ID must be a string');
  const match = RESOURCE_ID_PATTERN.exec(value);
  if (!match) throw new Error('resource ID is not mlp:res:<thumbprint>:<uuidv4>');
  const [, ownerThumbprint, uuid] = match as unknown as [string, string, string];
  return { ownerThumbprint, ownerKeyId: `mlp:key:${ownerThumbprint}`, uuid };
}

/** True when `rid` was issued by the owner identified by `ownerKeyId`. */
export function resourceBelongsTo(rid: string, ownerKeyId: string): boolean {
  try {
    return parseResourceId(rid).ownerThumbprint === thumbprintOf(ownerKeyId);
  } catch {
    return false;
  }
}

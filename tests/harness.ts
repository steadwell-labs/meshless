/**
 * Test harness.
 *
 * Everything the conformance suite needs to stand up a real provider: a TLS
 * certificate generated locally, a free port, a descriptor whose endpoint
 * matches the port, an enrolled ledger, and a client that trusts exactly that
 * certificate. No test mocks the transport, because transport behaviour (TLS
 * version, redirects, body bytes) is part of what is being tested.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SigningKey } from '../packages/core/src/index.ts';
import { makeResourceId } from '../packages/core/src/ids.ts';
import { buildDescriptor, type ResourceKind } from '../packages/core/src/descriptor.ts';
import { PublicKeyRef } from '../packages/core/src/jwk.ts';
import { uuidv4 } from '../packages/core/src/bytes.ts';
import { Ledger } from '../packages/gateway/src/ledger.ts';
import { HandlerRegistry } from '../packages/gateway/src/handlers.ts';
import { Gateway, enrollResource } from '../packages/gateway/src/gateway.ts';
import { serve, type RunningServer } from '../packages/gateway/src/server.ts';
import { MeshlessClient } from '../packages/client/src/client.ts';

export interface Keys {
  owner: SigningKey;
  provider: SigningKey;
  agent: SigningKey;
  delegate: SigningKey;
  other: SigningKey;
}

/** Fixed seeds: reproducible fixtures, never production keys. */
export function fixtureKeys(): Keys {
  return {
    owner: SigningKey.fromSeed(new Uint8Array(32).fill(1)),
    provider: SigningKey.fromSeed(new Uint8Array(32).fill(2)),
    agent: SigningKey.fromSeed(new Uint8Array(32).fill(3)),
    delegate: SigningKey.fromSeed(new Uint8Array(32).fill(4)),
    other: SigningKey.fromSeed(new Uint8Array(32).fill(5)),
  };
}

export interface Certificate {
  key: string;
  cert: string;
  dir: string;
  cleanup(): void;
}

let cachedCertificate: Certificate | undefined;

/**
 * Generate a self-signed certificate for 127.0.0.1/localhost.
 *
 * Skipped loudly if openssl is unavailable; the suite then runs every test
 * except the socket-level ones rather than pretending they passed.
 */
export function testCertificate(): Certificate | undefined {
  if (cachedCertificate) return cachedCertificate;
  const dir = mkdtempSync(join(tmpdir(), 'mlp-cert-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  try {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-sha256',
        '-days',
        '2',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-subj',
        '/CN=meshless-test',
        '-addext',
        'subjectAltName=IP:127.0.0.1,DNS:localhost',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
      ],
      { stdio: 'pipe' },
    );
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return undefined;
  }
  cachedCertificate = {
    key: readFileSync(keyPath, 'utf8'),
    cert: readFileSync(certPath, 'utf8'),
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
  return cachedCertificate;
}

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close();
        reject(new Error('could not allocate a port'));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

export interface Clock {
  now: number;
  read(): number;
  advance(seconds: number): void;
}

export function makeClock(start: number): Clock {
  return {
    now: start,
    read() {
      return this.now;
    },
    advance(seconds: number) {
      this.now += seconds;
    },
  };
}

export interface StackOptions {
  keys?: Keys;
  rid?: string;
  kind?: ResourceKind;
  actions?: string[];
  registry: HandlerRegistry;
  ledgerPath?: string;
  now?: () => number;
  sessionTtlSeconds?: number;
  discovery?: boolean;
  descriptorLifetimeSeconds?: number;
  port?: number;
}

export interface Stack {
  keys: Keys;
  rid: string;
  origin: string;
  descriptor: string;
  /** PEM of the certificate the provider serves, so tests can trust or pin it. */
  certificate: string;
  gateway: Gateway;
  ledger: Ledger;
  server: RunningServer;
  clock: Clock;
  close(): Promise<void>;
  client(key?: SigningKey, overrides?: { ca?: string; pinnedCertSha256?: string }): MeshlessClient;
}

export async function startStack(options: StackOptions): Promise<Stack> {
  const certificate = testCertificate();
  if (!certificate) throw new Error('openssl is required for socket-level conformance tests');

  const keys = options.keys ?? fixtureKeys();
  const clock = makeClock(options.now ? options.now() : 1_762_958_400);
  const now = () => clock.read();
  const rid = options.rid ?? makeResourceId(keys.owner.keyId, uuidv4());

  let port = options.port;
  let descriptor = '';
  let ledger: Ledger | undefined;
  let gateway: Gateway | undefined;
  let server: RunningServer | undefined;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const candidate = port ?? (await freePort());
    const origin = `https://127.0.0.1:${candidate}`;
    descriptor = buildDescriptor(
      {
        rid,
        seq: 1,
        iat: now(),
        exp: now() + (options.descriptorLifetimeSeconds ?? 3600),
        kind: options.kind ?? 'application',
        actions: options.actions ?? ['echo'],
        endpoint: origin,
      },
      keys.owner,
      new PublicKeyRef(keys.provider.jwk),
    );
    ledger = new Ledger(options.ledgerPath === undefined ? {} : { path: options.ledgerPath });
    if (!ledger.enrollment(rid)) enrollResource(ledger, { descriptor, now: now() });
    gateway = new Gateway({
      descriptor,
      providerKey: keys.provider,
      ownerKeyId: keys.owner.keyId,
      ledger,
      registry: options.registry,
      now,
      discovery: options.discovery ?? true,
      ...(options.sessionTtlSeconds === undefined ? {} : { sessionTtlSeconds: options.sessionTtlSeconds }),
    });
    try {
      server = await serve({ gateway, tls: { key: certificate.key, cert: certificate.cert }, port: candidate, host: '127.0.0.1' });
      port = candidate;
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE' || attempt === 4) throw error;
      port = undefined;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }

  if (!server || !gateway || !ledger) throw new Error('could not start the provider');
  const origin = server.origin;

  const stack: Stack = {
    keys,
    rid,
    origin,
    descriptor,
    certificate: certificate.cert,
    gateway,
    ledger,
    server,
    clock,
    async close() {
      await server.close();
    },
    client(key = keys.agent, overrides = {}) {
      return new MeshlessClient({
        origin,
        rid,
        key,
        providerKeyId: keys.provider.keyId,
        providerJwk: keys.provider.jwk,
        ca: overrides.ca ?? certificate.cert,
        now: () => clock.read(),
        ...(overrides.pinnedCertSha256 === undefined ? {} : { pinnedCertSha256: overrides.pinnedCertSha256 }),
      });
    },
  };
  return stack;
}

export function writeTempLedgerPath(): { path: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), 'mlp-ledger-'));
  writeFileSync(join(dir, '.keep'), '');
  return {
    path: join(dir, 'ledger.json'),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

#!/usr/bin/env node
/**
 * `mlp` — reference command line tool.
 *
 * The CLI exists so that the protocol can be exercised without writing code:
 * make keys, publish a descriptor, issue a narrower grant, run a provider, and
 * call it. It is also the generator for the deterministic test vectors, because
 * a vector set that is produced by hand drifts.
 *
 * Draft 00: no command here is stable, and `demo` is the only one that is safe
 * to run against data you care about — and it does not leave your machine.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PublicKeyRef,
  SigningKey,
  buildChildGrant,
  buildDescriptor,
  buildProof,
  buildReceipt,
  buildRootGrant,
  canonicalize,
  compactHash,
  isKeyId,
  isResourceId,
  makeResourceId,
  parseGrant,
  parseJws,
  parseResourceId,
  uuidv4,
  verifyChain,
  verifyDescriptor,
  verifyProof,
  verifyReceipt,
  sha256b64u,
  type JsonObject,
  type ResourceKind,
} from '../../core/src/index.ts';
import { Ledger } from '../../gateway/src/ledger.ts';
import { HandlerRegistry, echoHandler, inferenceHandler, mcpHandler } from '../../gateway/src/handlers.ts';
import { Gateway, enrollResource } from '../../gateway/src/gateway.ts';
import { serve } from '../../gateway/src/server.ts';
import { MeshlessClient } from '../../client/src/client.ts';

const VECTOR_CLOCK = 1_762_958_400;
const VECTOR_RID_UUID = '3f0f8b3c-1a2b-4c3d-8e9f-0123456789ab';

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

interface Args {
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]!;
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const body = token.slice(2);
    const equals = body.indexOf('=');
    if (equals !== -1) {
      flags[body.slice(0, equals)] = body.slice(equals + 1);
      continue;
    }
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[body] = next;
      index += 1;
    } else {
      flags[body] = true;
    }
  }
  return { positional, flags };
}

function str(args: Args, name: string, fallback?: string): string {
  const value = args.flags[name];
  if (typeof value === 'string') return value;
  if (fallback !== undefined) return fallback;
  throw new UsageError(`missing required option --${name}`);
}

function num(args: Args, name: string, fallback: number): number {
  const value = args.flags[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new UsageError(`--${name} must be a number`);
  return parsed;
}

function list(args: Args, name: string, fallback: string[]): string[] {
  const value = args.flags[name];
  if (typeof value !== 'string') return fallback;
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

class UsageError extends Error {}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

interface KeyFile {
  v?: number;
  keyId?: string;
  jwk: JsonObject;
  privateKey?: string;
  note?: string;
}

function loadKeyFile(path: string): KeyFile {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as KeyFile | JsonObject;
  if (typeof parsed !== 'object' || parsed === null) throw new UsageError(`${path} is not a key file`);
  if ('jwk' in parsed) return parsed as KeyFile;
  return { jwk: parsed as JsonObject };
}

function loadPrivateKey(path: string): SigningKey {
  const file = loadKeyFile(path);
  if (typeof file.privateKey !== 'string') throw new UsageError(`${path} does not contain a private key`);
  const key = SigningKey.fromPkcs8Der(Buffer.from(file.privateKey, 'base64'));
  if (file.keyId && file.keyId !== key.keyId) throw new UsageError(`${path} keyId does not match its key material`);
  return key;
}

function loadPublicKey(path: string): PublicKeyRef {
  const file = loadKeyFile(path);
  return new PublicKeyRef(file.jwk as never);
}

function writeKeyFile(path: string, key: SigningKey): void {
  mkdirSync(dirname(path), { recursive: true });
  const file: KeyFile = {
    v: 1,
    keyId: key.keyId,
    jwk: { crv: 'Ed25519', kty: 'OKP', x: key.jwk.x },
    privateKey: key.toPkcs8Der().toString('base64'),
    note: 'MLP/1 reference key file. Private. Never share or commit.',
  };
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
}

function readJwsFile(path: string): string {
  return readFileSync(path, 'utf8').trim();
}

function writeText(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text.endsWith('\n') ? text : `${text}\n`, { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const HELP = `mlp — Meshless Protocol (MLP/1) reference tool, Draft 00

Usage: mlp <command> [options]

  keygen       Create an Ed25519 key file
      --out <path>                  where to write the private key file

  id           Print the key identifier for a key file
      --key <path>

  descriptor   Sign a resource descriptor as the owner
      --owner <key>                 owner private key file
      --provider <key>              provider public key file
      --rid <mlp:res:...>           resource identifier
      --endpoint <https origin>     where the provider serves MLP/1
      --kind <kind>                 inference | mcp | storage | sensor | compute | application
      --actions <a,b>               declared actions
      --seq <n>                     descriptor sequence (default 1)
      --ttl <seconds>               lifetime (default 3600, max 86400)
      --now <unix>                  override the clock (tests)
      --out <path>

  grant        Issue a root grant as the owner
      --owner <key> --provider <key> --subject <key> --rid <mlp:res:...>
      --actions <a,b> [--depth 0..3] [--ttl seconds] [--calls n]
      [--bytes n] [--max-ms n] [--now <unix>] [--out <path>]

  delegate     Narrow an existing grant
      --issuer <key>                the parent grant's subject
      --parent <path>               parent grant compact JWS
      --subject <key> --actions <a,b>
      [--depth n] [--ttl seconds] [--calls n] [--bytes n] [--max-ms n]
      [--now <unix>] [--out <path>]

  serve        Run a provider
      --provider <key> --owner <key id> --descriptor <path>
      --ledger <path> --port <n> --tls-key <path> --tls-cert <path>
      [--kind <kind>] [--discovery] [--host 127.0.0.1]

  call         Open a session and invoke one action
      --key <key> --chain <path> --origin <https origin> --ca <pem path>
      --action <name> [--input <json>] [--rid <mlp:res:...>] [--descriptor <path>]

  inspect      Decode a compact JWS without verifying it
      --jws <path>

  demo         Run a complete exchange in process, no network
  vectors      Write the deterministic conformance vectors
      --output <dir>                default: test-vectors

  examples     Write the expanded wire example (Appendix B)
      --output <dir>                default: specs/examples/mcp-tools

  help         This text

Everything is experimental. No command is stable before MLP/1 Draft 01.`;

function commandKeygen(args: Args): number {
  const out = str(args, 'out', `meshless-key-${Date.now()}.json`);
  const key = SigningKey.generate();
  writeKeyFile(out, key);
  console.log(`wrote ${out}`);
  console.log(`key id: ${key.keyId}`);
  return 0;
}

function commandId(args: Args): number {
  const key = loadKeyFile(str(args, 'key'));
  const publicKey = new PublicKeyRef(key.jwk as never);
  console.log(publicKey.keyId);
  return 0;
}

function commandDescriptor(args: Args): number {
  const owner = loadPrivateKey(str(args, 'owner'));
  const provider = loadPublicKey(str(args, 'provider'));
  const rid = str(args, 'rid');
  if (!isResourceId(rid)) throw new UsageError('--rid must be mlp:res:<thumbprint>:<uuidv4>');
  const now = num(args, 'now', Math.floor(Date.now() / 1000));
  const ttl = Math.min(num(args, 'ttl', 3600), 86400);
  const kind = str(args, 'kind', 'application') as ResourceKind;
  const actions = list(args, 'actions', ['echo']);
  const compact = buildDescriptor(
    { rid, seq: num(args, 'seq', 1), iat: now, exp: now + ttl, kind, actions, endpoint: str(args, 'endpoint') },
    owner,
    provider,
  );
  if (args.flags.out) writeText(str(args, 'out'), compact);
  console.log(compact);
  return 0;
}

function commandGrant(args: Args): number {
  const owner = loadPrivateKey(str(args, 'owner'));
  const provider = loadPublicKey(str(args, 'provider'));
  const subject = loadPublicKey(str(args, 'subject'));
  const rid = str(args, 'rid');
  if (!isResourceId(rid)) throw new UsageError('--rid must be mlp:res:<thumbprint>:<uuidv4>');
  const now = num(args, 'now', Math.floor(Date.now() / 1000));
  const ttl = Math.min(num(args, 'ttl', 600), 86400);
  const compact = buildRootGrant(
    {
      rid,
      aud: provider.keyId,
      subject,
      actions: list(args, 'actions', ['echo']),
      iat: now,
      nbf: now,
      exp: now + ttl,
      depth: Math.min(num(args, 'depth', 0), 3),
      limits: {
        calls: num(args, 'calls', 10),
        bytes: num(args, 'bytes', 1_000_000),
        max_ms: num(args, 'max-ms', 30_000),
      },
    },
    owner,
  );
  if (args.flags.out) writeText(str(args, 'out'), compact);
  console.log(compact);
  return 0;
}

function commandDelegate(args: Args): number {
  const issuer = loadPrivateKey(str(args, 'issuer'));
  const parent = parseGrant(readJwsFile(str(args, 'parent')));
  const subject = loadPublicKey(str(args, 'subject'));
  const now = num(args, 'now', Math.floor(Date.now() / 1000));
  const ttl = num(args, 'ttl', Math.max(1, parent.claims.exp - now));
  const compact = buildChildGrant(
    parent,
    {
      subject,
      actions: list(args, 'actions', [...parent.actions]),
      ...(args.flags['depth'] === undefined ? {} : { depth: num(args, 'depth', parent.claims.depth - 1) }),
      ...(args.flags['ttl'] === undefined ? {} : { exp: Math.min(parent.claims.exp, now + ttl) }),
      limits: {
        ...(args.flags['calls'] === undefined ? {} : { calls: num(args, 'calls', parent.claims.limits.calls) }),
        ...(args.flags['bytes'] === undefined ? {} : { bytes: num(args, 'bytes', parent.claims.limits.bytes) }),
        ...(args.flags['max-ms'] === undefined ? {} : { max_ms: num(args, 'max-ms', parent.claims.limits.max_ms) }),
      },
    },
    issuer,
  );
  if (args.flags.out) writeText(str(args, 'out'), compact);
  console.log(compact);
  return 0;
}

function registryFor(kind: string): HandlerRegistry {
  const registry = new HandlerRegistry();
  switch (kind) {
    case 'inference':
      registry.register(inferenceHandler());
      break;
    case 'mcp':
      for (const action of mcpHandler({
        tools: [
          {
            name: 'system_status',
            description: 'Reference tool: report a fixed status object.',
            handler: async () => ({ status: 'ok', note: 'reference tool, no data leaves this process' }),
          },
        ],
      })) {
        registry.register(action);
      }
      break;
    default:
      registry.register(echoHandler());
  }
  return registry;
}

async function commandServe(args: Args): Promise<number> {
  const providerKey = loadPrivateKey(str(args, 'provider'));
  const descriptor = readJwsFile(str(args, 'descriptor'));
  const ledgerPath = str(args, 'ledger');
  const ledger = new Ledger({ path: ledgerPath });
  const now = Math.floor(Date.now() / 1000);
  const ownerKeyId = str(args, 'owner');
  if (!isKeyId(ownerKeyId)) throw new UsageError('--owner must be an mlp:key: identifier');
  enrollResource(ledger, { descriptor, now });

  const kind = str(args, 'kind', 'application');
  const gateway = new Gateway({
    descriptor,
    providerKey,
    ownerKeyId,
    ledger,
    registry: registryFor(kind),
    discovery: args.flags.discovery === true,
    logger: (event) => {
      if (event.level === 'info' && event.event === 'invoke') return;
      const parts = [event.level.toUpperCase(), event.event];
      if (event.action) parts.push(event.action);
      if (event.requestId) parts.push(event.requestId);
      if (event.detail) parts.push(event.detail);
      console.log(parts.join(' '));
    },
  });

  const port = num(args, 'port', 8443);
  const host = str(args, 'host', '127.0.0.1');
  const running = await serve({
    gateway,
    host,
    port,
    tls: { key: readFileSync(str(args, 'tls-key'), 'utf8'), cert: readFileSync(str(args, 'tls-cert'), 'utf8') },
  });
  console.log(`meshless provider listening on ${running.origin}`);
  console.log(`resource        ${gateway.rid}`);
  console.log(`owner           ${gateway.ownerKeyId}`);
  console.log(`provider key    ${gateway.providerKeyId}`);
  console.log(`descriptor seq  ${gateway.descriptor.claims.seq} exp ${new Date(gateway.descriptor.claims.exp * 1000).toISOString()}`);
  console.log(`discovery       ${args.flags.discovery === true ? 'enabled' : 'disabled'}`);

  await new Promise<void>((resolve) => {
    const stop = () => {
      void running.close().then(resolve);
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  return 0;
}

async function commandCall(args: Args): Promise<number> {
  const key = loadPrivateKey(str(args, 'key'));
  const chainFile = str(args, 'chain');
  const raw = readFileSync(chainFile, 'utf8').trim();
  const chain = raw.startsWith('[') ? (JSON.parse(raw) as string[]) : raw.split(/\r?\n/).filter((line) => line.length > 0);
  const leaf = parseGrant(chain[chain.length - 1]!);
  const rid = str(args, 'rid', leaf.claims.rid);
  const origin = str(args, 'origin');
  const caPath = str(args, 'ca');

  const descriptorPath = typeof args.flags.descriptor === 'string' ? args.flags.descriptor : undefined;
  let providerKeyId = leaf.claims.aud;
  let providerJwk = undefined as JsonObject | undefined;
  if (descriptorPath) {
    const record = verifyDescriptor(readJwsFile(descriptorPath), { now: Math.floor(Date.now() / 1000) });
    providerJwk = { crv: 'Ed25519', kty: 'OKP', x: record.provider.jwk.x };
    providerKeyId = record.provider.keyId;
  }
  if (!providerJwk) throw new UsageError('--descriptor is required so the client can verify receipts');

  const client = new MeshlessClient({
    origin,
    rid,
    key,
    providerKeyId,
    providerJwk: providerJwk as never,
    ca: readFileSync(caPath, 'utf8'),
  });

  const session = await client.openSession(chain);
  const input = JSON.parse(str(args, 'input', '{}')) as JsonObject;
  const invocation = await client.invoke(session, str(args, 'action', 'echo'), input);
  console.log(JSON.stringify({ result: invocation.result, receipt: invocation.receiptClaims }, null, 2));
  await client.close(session);
  return 0;
}

function commandInspect(args: Args): number {
  const compact = readJwsFile(str(args, 'jws'));
  const [header, payload, signature] = compact.split('.') as [string, string, string];
  const decode = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as JsonObject;
  const headerValue = decode(header);
  const payloadValue = decode(payload);
  console.log(JSON.stringify({ header: headerValue, payload: payloadValue, signatureBytes: Buffer.from(signature ?? '', 'base64url').byteLength }, null, 2));
  const canonical = canonicalize(payloadValue);
  const original = Buffer.from(payload, 'base64url').toString('utf8');
  console.log(`canonical payload: ${canonical === original ? 'yes' : 'NO — a verifier must reject this object'}`);
  console.log(`payload sha256:    ${sha256b64u(Buffer.from(original))}`);
  return canonical === original ? 0 : 1;
}

// ---------------------------------------------------------------------------
// demo — the whole protocol in one process
// ---------------------------------------------------------------------------

async function commandDemo(): Promise<number> {
  const line = (label: string, value: string) => console.log(`  ${label.padEnd(18)} ${value}`);
  const step = (n: number, title: string) => console.log(`\n[${n}] ${title}`);

  const now = Math.floor(Date.now() / 1000);
  const owner = SigningKey.generate();
  const provider = SigningKey.generate();
  const agent = SigningKey.generate();
  const rid = makeResourceId(owner.keyId, uuidv4());
  const origin = 'https://127.0.0.1:8443';

  console.log('meshless — in-process demonstration, MLP/1 Draft 00');
  console.log('No socket is opened: this exercises the protocol objects, not TLS.');
  console.log('TLS, quotas, and revocation are covered by `npm test`.');

  step(1, 'keys');
  line('owner', owner.keyId);
  line('provider', provider.keyId);
  line('agent', agent.keyId);
  line('resource', rid);

  step(2, 'owner signs a descriptor');
  const descriptor = buildDescriptor(
    { rid, seq: 1, iat: now, exp: now + 3600, kind: 'inference', actions: ['infer'], endpoint: origin },
    owner,
    new PublicKeyRef(provider.jwk),
  );
  const record = verifyDescriptor(descriptor, { now, expectedOwnerKeyId: owner.keyId, expectedProviderKeyId: provider.keyId });
  line('descriptor', `${descriptor.length} bytes`);
  line('endpoint', record.origin);
  line('actions', [...record.actions].join(', '));

  step(3, 'provider enrolls the owner and starts serving');
  const ledger = new Ledger();
  enrollResource(ledger, { descriptor, now });
  const gateway = new Gateway({
    descriptor,
    providerKey: provider,
    ownerKeyId: owner.keyId,
    ledger,
    registry: new HandlerRegistry().register(inferenceHandler({ maxTokens: 128 })),
    now: () => now,
  });
  line('enrolled', 'yes');
  line('session ttl', '900s maximum');

  step(4, 'owner issues a 5-minute grant with hard limits');
  const root = buildRootGrant(
    {
      rid,
      aud: provider.keyId,
      subject: new PublicKeyRef(agent.jwk),
      actions: ['infer'],
      iat: now,
      nbf: now,
      exp: now + 300,
      depth: 0,
      limits: { calls: 3, bytes: 20_000, max_ms: 2000 },
    },
    owner,
  );
  const rootRecord = parseGrant(root);
  line('grant jti', rootRecord.claims.jti);
  line('calls', String(rootRecord.claims.limits.calls));
  line('byte budget', String(rootRecord.claims.limits.bytes));
  line('delegable', String(rootRecord.claims.delegate));

  const challenge = async (subject: string) => {
    const response = await gateway.handle({
      method: 'POST',
      path: '/mlp/v1/challenge',
      headers: {},
      body: Buffer.from(JSON.stringify({ rid, subject })),
    });
    return (JSON.parse(response.body) as { nonce: string }).nonce;
  };
  const invokeRaw = async (path: string, payload: JsonObject, key: SigningKey, grantHash: string) => {
    const body = Buffer.from(JSON.stringify(payload));
    const nonce = await challenge(key.keyId);
    const proof = buildProof({ key, aud: provider.keyId, nonce, method: 'POST', uri: origin + path, body, grantHash, iat: now });
    const response = await gateway.handle({ method: 'POST', path, headers: { 'meshless-proof': proof }, body });
    return { status: response.status, body: JSON.parse(response.body) as JsonObject };
  };

  step(5, 'agent opens a session with a proof over the exact request bytes');
  const session = await invokeRaw('/mlp/v1/sessions', { chain: [root] }, agent, rootRecord.hash);
  line('http status', String(session.status));
  const sid = session.body.sid as string;
  line('session id', `${sid.slice(0, 12)}…`);

  step(6, 'agent invokes the grant, and the provider signs a receipt');
  const invocation = await invokeRaw(
    '/mlp/v1/invoke',
    { sid, request_id: uuidv4(), rid, action: 'infer', input: { prompt: 'say hello', max_tokens: 32 } },
    agent,
    rootRecord.hash,
  );
  line('http status', String(invocation.status));
  line('result', JSON.stringify(invocation.body.result));
  const receipt = invocation.body.receipt as string;
  const claims = verifyReceipt(receipt, {
    provider: new PublicKeyRef(provider.jwk),
    rid,
    sub: agent.keyId,
    jti: rootRecord.claims.jti,
    requestId: invocation.body.request_id as string,
    action: 'infer',
    request: { prompt: 'say hello', max_tokens: 32 },
    result: invocation.body.result as JsonObject,
  });
  line('receipt status', claims.status);
  line('usage', JSON.stringify(claims.usage));

  step(7, 'the agent asks for an action the grant does not carry');
  const denied = await invokeRaw(
    '/mlp/v1/invoke',
    { sid, request_id: uuidv4(), rid, action: 'admin', input: {} },
    agent,
    rootRecord.hash,
  );
  line('http status', String(denied.status));
  line('error', JSON.stringify(denied.body.error));

  step(8, 'the owner revokes the grant');
  const revoke = await invokeRaw('/mlp/v1/revoke', { rid, jti: rootRecord.claims.jti }, owner, '');
  line('revoked', String(revoke.body.revoked));
  const afterRevocation = await invokeRaw(
    '/mlp/v1/invoke',
    { sid, request_id: uuidv4(), rid, action: 'infer', input: { prompt: 'again', max_tokens: 8 } },
    agent,
    rootRecord.hash,
  );
  line('next invoke', `${afterRevocation.status} ${JSON.stringify(afterRevocation.body.error)}`);

  console.log('\nThat is the whole protocol: a signed statement of existence, a narrowing');
  console.log('grant, a per-request proof, a receipt, and an owner who can always stop it.');
  return 0;
}

// ---------------------------------------------------------------------------
// vectors — deterministic fixtures for other implementations
// ---------------------------------------------------------------------------

function seed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

/** Shape of `test-vectors/mlp1-draft00.json`. Consumers should treat it as data. */
export interface VectorFile {
  spec: string;
  draft: string;
  note: string;
  clock: number;
  resource: string;
  origin: string;
  keys: Array<{ name: string; seed: string; keyId: string; jwk: unknown }>;
  canonicalization: Array<{ input: unknown; canonical: string }>;
  descriptor: { compact: string; claims: unknown };
  grants: {
    root: { compact: string; claims: unknown; hash: string };
    child: { compact: string; claims: unknown; hash: string };
    chain: string[];
  };
  proof: { compact: string; body: string; claims: unknown };
  receipt: { compact: string; claims: unknown };
  negative: Array<Record<string, unknown>>;
}

export function generateVectors(): VectorFile {
  const owner = SigningKey.fromSeed(seed(1));
  const provider = SigningKey.fromSeed(seed(2));
  const agent = SigningKey.fromSeed(seed(3));
  const delegate = SigningKey.fromSeed(seed(4));
  const rid = makeResourceId(owner.keyId, VECTOR_RID_UUID);
  const origin = 'https://127.0.0.1:8443';

  const descriptor = buildDescriptor(
    {
      rid,
      seq: 1,
      iat: VECTOR_CLOCK,
      exp: VECTOR_CLOCK + 3600,
      kind: 'mcp',
      actions: ['tools.call', 'tools.list'],
      endpoint: origin,
    },
    owner,
    new PublicKeyRef(provider.jwk),
  );

  const root = buildRootGrant(
    {
      rid,
      aud: provider.keyId,
      subject: new PublicKeyRef(agent.jwk),
      actions: ['tools.call', 'tools.list'],
      iat: VECTOR_CLOCK,
      nbf: VECTOR_CLOCK,
      exp: VECTOR_CLOCK + 600,
      depth: 1,
      limits: { calls: 4, bytes: 10_000, max_ms: 5_000 },
      jti: '11111111-1111-4111-8111-111111111111',
    },
    owner,
  );

  const child = buildChildGrant(
    parseGrant(root),
    {
      subject: new PublicKeyRef(delegate.jwk),
      actions: ['tools.call'],
      limits: { calls: 2, bytes: 4_000 },
      jti: '22222222-2222-4222-8222-222222222222',
    },
    agent,
  );

  const leaf = parseGrant(child);
  const body = Buffer.from(JSON.stringify({ action: 'tools.call', input: { name: 'system_status', arguments: {} } }), 'utf8');
  const proof = buildProof({
    key: delegate,
    aud: provider.keyId,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    method: 'POST',
    uri: `${origin}/mlp/v1/invoke`,
    body,
    grantHash: leaf.hash,
    iat: VECTOR_CLOCK,
    jti: '33333333-3333-4333-8333-333333333333',
  });

  const receipt = buildReceipt(
    {
      rid,
      sub: delegate.keyId,
      jti: leaf.claims.jti,
      requestId: '44444444-4444-4444-8444-444444444444',
      action: 'tools.call',
      iat: VECTOR_CLOCK + 1,
      request: { name: 'system_status', arguments: {} },
      result: { content: { status: 'ok' } },
      usage: { calls: 1, bytes: 42, elapsed_ms: 7 },
    },
    provider,
  );

  const canonicalCases: Array<{ input: unknown; canonical: string }> = [
    { input: { b: 1, a: 2 }, canonical: canonicalize({ b: 1, a: 2 }) },
    { input: { nested: { z: [1, 2, { y: true, x: null }] } }, canonical: canonicalize({ nested: { z: [1, 2, { y: true, x: null }] } }) },
    { input: -0, canonical: canonicalize(-0) },
    { input: 1e21, canonical: canonicalize(1e21) },
    { input: 1e-7, canonical: canonicalize(1e-7) },
    { input: 'ü', canonical: canonicalize('ü') },
    { input: 'a"b\\c\n', canonical: canonicalize('a"b\\c\n') },
  ];

  return {
    spec: 'MLP/1',
    draft: 'Draft 00',
    note: 'Deterministic fixtures. Fixed seeds and fixed clock; never production keys. Regenerate with `npm run vectors`.',
    clock: VECTOR_CLOCK,
    resource: rid,
    origin,
    keys: [
      { name: 'owner', seed: Buffer.from(seed(1)).toString('hex'), keyId: owner.keyId, jwk: owner.jwk },
      { name: 'provider', seed: Buffer.from(seed(2)).toString('hex'), keyId: provider.keyId, jwk: provider.jwk },
      { name: 'agent', seed: Buffer.from(seed(3)).toString('hex'), keyId: agent.keyId, jwk: agent.jwk },
      { name: 'delegate', seed: Buffer.from(seed(4)).toString('hex'), keyId: delegate.keyId, jwk: delegate.jwk },
    ],
    canonicalization: canonicalCases,
    descriptor: {
      compact: descriptor,
      claims: verifyDescriptor(descriptor, { now: VECTOR_CLOCK }).claims,
    },
    grants: {
      root: { compact: root, claims: parseGrant(root).claims, hash: parseGrant(root).hash },
      child: { compact: child, claims: leaf.claims, hash: leaf.hash },
      chain: [root, child],
    },
    proof: {
      compact: proof,
      body: body.toString('utf8'),
      claims: verifyProof(proof, {
        subject: delegate.keyId,
        aud: provider.keyId,
        method: 'POST',
        uri: `${origin}/mlp/v1/invoke`,
        body,
        grantHash: leaf.hash,
        now: VECTOR_CLOCK,
        subjectJwk: delegate.jwk,
      }),
    },
    receipt: {
      compact: receipt,
      claims: verifyReceipt(receipt, {
        provider: new PublicKeyRef(provider.jwk),
        rid,
        sub: delegate.keyId,
        jti: leaf.claims.jti,
        requestId: '44444444-4444-4444-8444-444444444444',
      }),
    },
    negative: [
      {
        id: 'neg-01-non-canonical-payload',
        description: 'Root grant payload with members reordered. Signature bytes stay valid; a verifier must still reject it.',
        mutation: 'reverse-payload-members',
        target: 'grants.root.compact',
        expected: 'reject',
      },
      {
        id: 'neg-02-delegation-widening',
        description: 'Child grant for an action its parent does not carry.',
        mutation: 'widen-child-actions',
        target: 'grants.grants.chain[1]',
        expected: 'reject',
      },
      {
        id: 'neg-03-wrong-audience',
        description: 'Root grant addressed to a different provider key.',
        mutation: 'replace-aud-with-delegate-key',
        target: 'grants.root.compact',
        expected: 'reject',
      },
      {
        id: 'neg-04-expired-descriptor',
        description: 'Descriptor evaluated at clock + 2 hours.',
        mutation: 'evaluate-at',
        value: VECTOR_CLOCK + 7200,
        target: 'descriptor.compact',
        expected: 'reject',
      },
      {
        id: 'neg-05-proof-body-substitution',
        description: 'Proof verified against a different body.',
        mutation: 'swap-proof-body',
        target: 'proof',
        expected: 'reject',
      },
    ],
  };
}

/**
 * Write the expanded wire examples referenced by Appendix B.
 *
 * Generated rather than hand-written: an example in a specification that no
 * longer verifies is worse than no example, and this repository has already had
 * one draft drift from its fixtures.
 */
function commandExamples(args: Args): number {
  const output = str(args, 'output', 'specs/examples/mcp-tools');
  const vectors = generateVectors();
  mkdirSync(output, { recursive: true });

  writeFileSync(join(output, 'descriptor.jws'), `${vectors.descriptor.compact}\n`);
  writeFileSync(join(output, 'root-grant.jws'), `${vectors.grants.root.compact}\n`);
  writeFileSync(join(output, 'child-grant.jws'), `${vectors.grants.child.compact}\n`);
  writeFileSync(join(output, 'proof.jws'), `${vectors.proof.compact}\n`);
  writeFileSync(join(output, 'receipt.jws'), `${vectors.receipt.compact}\n`);
  writeFileSync(join(output, 'request.json'), `${JSON.stringify(JSON.parse(vectors.proof.body), null, 2)}\n`);
  writeFileSync(
    join(output, 'claims.json'),
    `${JSON.stringify(
      {
        clock: vectors.clock,
        resource: vectors.resource,
        origin: vectors.origin,
        descriptor: vectors.descriptor.claims,
        root: vectors.grants.root.claims,
        child: vectors.grants.child.claims,
        proof: vectors.proof.claims,
        receipt: vectors.receipt.claims,
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(output, 'README.md'),
    `# Wire example: one MCP invocation, two grants deep

Non-normative, but every byte here verifies. Generated from
\`test-vectors/mlp1-draft00.json\` by \`npm run examples\`.

| File | Object |
| --- | --- |
| \`descriptor.jws\` | \`mlp-resource+jwt\`, signed by the owner |
| \`root-grant.jws\` | \`mlp-grant+jwt\`, owner to agent, depth 1 |
| \`child-grant.jws\` | \`mlp-grant+jwt\`, agent to delegate, narrower |
| \`proof.jws\` | \`mlp-proof+jwt\`, over \`request.json\` |
| \`request.json\` | the exact body the proof binds |
| \`receipt.jws\` | \`mlp-receipt+jwt\`, signed by the provider |
| \`claims.json\` | decoded claims for every object |

Verify with the reference implementation:

\`\`\`sh
node packages/cli/src/mlp.ts inspect --jws specs/examples/mcp-tools/descriptor.jws
npm test
\`\`\`

The clock is fixed at \`${vectors.clock}\` (12 November 2026, 12:00 UTC), so the
proof and receipts verify only against that time. That is intentional: an
example whose validity depends on when you read it is not a fixture.
`,
  );
  console.log(`wrote wire example to ${output}`);
  return 0;
}

function commandVectors(args: Args): number {
  const output = str(args, 'output', 'test-vectors');
  mkdirSync(output, { recursive: true });
  const vectors = generateVectors();
  const path = join(output, 'mlp1-draft00.json');
  writeFileSync(path, `${JSON.stringify(vectors, null, 2)}\n`);
  console.log(`wrote ${path}`);
  return 0;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const args = parseArgs(rest);
  switch (command) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      return 0;
    case 'keygen':
      return commandKeygen(args);
    case 'id':
      return commandId(args);
    case 'descriptor':
      return commandDescriptor(args);
    case 'grant':
      return commandGrant(args);
    case 'delegate':
      return commandDelegate(args);
    case 'serve':
      return commandServe(args);
    case 'call':
      return commandCall(args);
    case 'inspect':
      return commandInspect(args);
    case 'demo':
      return commandDemo();
    case 'vectors':
      return commandVectors(args);
    case 'examples':
      return commandExamples(args);
    case 'version':
      console.log('mlp 0.0.1 (MLP/1 Draft 00)');
      return 0;
    default:
      throw new UsageError(`unknown command: ${command}`);
  }
}

const invokedDirectly = process.argv[1] !== undefined && process.argv[1] === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      if (error instanceof UsageError) {
        console.error(`mlp: ${error.message}`);
        console.error('Run `mlp help` for usage.');
        process.exitCode = 2;
        return;
      }
      console.error(`mlp: ${(error as Error).message}`);
      process.exitCode = 1;
    },
  );
}

export { main };

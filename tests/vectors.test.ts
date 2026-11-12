/**
 * Vector conformance.
 *
 * `test-vectors/mlp1-draft00.json` is the normative reference for
 * signature-level interoperability: an independent implementation must be able
 * to reproduce every byte in it from the seeds and the clock, and must reject
 * every negative case. This test proves the reference implementation can, and
 * that the committed vectors have not drifted from the code.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  PublicKeyRef,
  SigningKey,
  canonicalize,
  compactHash,
  isKeyId,
  isResourceId,
  keyIdFromJwk,
  parseGrant,
  parseJsonStrict,
  parseJws,
  signJws,
  verifyChain,
  verifyDescriptor,
  verifyProof,
  verifyReceipt,
  type JsonObject,
} from '../packages/core/src/index.ts';
import { generateVectors } from '../packages/cli/src/mlp.ts';

const VECTORS_PATH = join(process.cwd(), 'test-vectors', 'mlp1-draft00.json');

interface Vectors {
  spec: string;
  draft: string;
  clock: number;
  resource: string;
  origin: string;
  keys: Array<{ name: string; seed: string; keyId: string; jwk: { crv: 'Ed25519'; kty: 'OKP'; x: string } }>;
  canonicalization: Array<{ input: unknown; canonical: string }>;
  descriptor: { compact: string; claims: JsonObject };
  grants: {
    root: { compact: string; claims: JsonObject; hash: string };
    child: { compact: string; claims: JsonObject; hash: string };
    chain: string[];
  };
  proof: { compact: string; body: string; claims: JsonObject };
  receipt: { compact: string; claims: JsonObject };
  negative: Array<{ id: string; description: string; mutation: string; target: string; expected: string; value?: number }>;
}

function load(): Vectors {
  return JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Vectors;
}

const vectors = load();

test('the committed vectors match what the generator produces', () => {
  const regenerated = generateVectors();
  assert.deepEqual(
    JSON.parse(JSON.stringify(regenerated)) as JsonObject,
    vectors as unknown as JsonObject,
    'test-vectors/mlp1-draft00.json is stale; run `npm run vectors`',
  );
});

test('vectors are the right version and shape', () => {
  assert.equal(vectors.spec, 'MLP/1');
  assert.equal(vectors.draft, 'Draft 00');
  assert.equal(typeof vectors.clock, 'number');
  assert.equal(isResourceId(vectors.resource), true);
  assert.equal(vectors.negative.length >= 5, true);
});

test('every key id is derived from the published seed and JWK', () => {
  for (const key of vectors.keys) {
    const derived = SigningKey.fromSeed(Buffer.from(key.seed, 'hex'));
    assert.equal(derived.keyId, key.keyId, `${key.name} key id`);
    assert.equal(derived.jwk.x, key.jwk.x, `${key.name} public key`);
    assert.equal(keyIdFromJwk(key.jwk), key.keyId, `${key.name} thumbprint`);
    assert.equal(isKeyId(key.keyId), true);
  }
});

test('keys are distinct and are not the all-zero seed', () => {
  const ids = new Set(vectors.keys.map((key) => key.keyId));
  assert.equal(ids.size, vectors.keys.length);
  for (const key of vectors.keys) {
    assert.notEqual(key.seed, '0'.repeat(64), 'a fixture key is the zero seed');
  }
});

test('canonicalization fixtures reproduce byte for byte', () => {
  for (const fixture of vectors.canonicalization) {
    assert.equal(canonicalize(fixture.input as never), fixture.canonical, JSON.stringify(fixture.input));
  }
});

test('descriptor verifies, and its claims are the fixture claims', () => {
  const record = verifyDescriptor(vectors.descriptor.compact, { now: vectors.clock });
  assert.deepEqual(JSON.parse(JSON.stringify(record.claims)) as JsonObject, vectors.descriptor.claims);
  assert.equal(record.origin, vectors.origin);
  assert.equal(record.claims.rid, vectors.resource);
});

test('grant chain verifies from root to leaf', () => {
  const owner = new PublicKeyRef(vectors.keys.find((key) => key.name === 'owner')!.jwk);
  const chain = verifyChain(vectors.grants.chain, {
    now: vectors.clock,
    descriptor: verifyDescriptor(vectors.descriptor.compact, { now: vectors.clock }),
    providerKeyId: vectors.grants.root.claims.aud as string,
    ownerKeyId: owner.keyId,
  });

  assert.equal(chain.grants.length, 2);
  assert.equal(chain.leafHash, vectors.grants.child.hash);
  assert.equal(chain.leaf.claims.exp, vectors.clock + 600);
  assert.equal(chain.leaf.claims.jti, '22222222-2222-4222-8222-222222222222');
  assert.equal(compactHash(vectors.grants.root.compact), vectors.grants.root.hash);

  // Delegation narrowed: fewer actions, fewer calls, less bytes, shorter depth.
  const root = parseGrant(vectors.grants.root.compact);
  const child = parseGrant(vectors.grants.child.compact);
  assert.equal(child.claims.depth, root.claims.depth - 1);
  assert.equal(child.claims.actions.length < root.claims.actions.length, true);
  assert.equal(child.claims.limits.calls < root.claims.limits.calls, true);
  assert.equal(child.claims.limits.bytes < root.claims.limits.bytes, true);
});

test('proof verifies against the exact body in the fixture', () => {
  const delegate = vectors.keys.find((key) => key.name === 'delegate')!;
  const body = Buffer.from(vectors.proof.body, 'utf8');
  const claims = verifyProof(vectors.proof.compact, {
    subject: delegate.keyId,
    aud: vectors.grants.root.claims.aud as string,
    method: 'POST',
    uri: `${vectors.origin}/mlp/v1/invoke`,
    body,
    grantHash: vectors.grants.child.hash,
    now: vectors.clock,
    subjectJwk: delegate.jwk,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(claims)) as JsonObject, vectors.proof.claims);
});

test('receipt verifies and is bound to the leaf grant and request', () => {
  const provider = new PublicKeyRef(vectors.keys.find((key) => key.name === 'provider')!.jwk);
  const claims = verifyReceipt(vectors.receipt.compact, {
    provider,
    rid: vectors.resource,
    sub: vectors.keys.find((key) => key.name === 'delegate')!.keyId,
    jti: '22222222-2222-4222-8222-222222222222',
    requestId: '44444444-4444-4444-8444-444444444444',
    action: 'tools.call',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(claims)) as JsonObject, vectors.receipt.claims);
  assert.equal(claims.status, 'ok');
});

// ---------------------------------------------------------------------------
// Negative vectors: the failure each mutation must produce.
// ---------------------------------------------------------------------------

function descriptorRecord() {
  return verifyDescriptor(vectors.descriptor.compact, { now: vectors.clock });
}

test('neg-01 non-canonical payload is rejected', () => {
  const [header, payload, signature] = vectors.grants.root.compact.split('.') as [string, string, string];
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as JsonObject;
  const reordered = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(claims).reverse()))).toString('base64url');
  assert.notEqual(reordered, payload);
  assert.throws(() => parseJws(`${header}.${reordered}.${signature}`, 'mlp-grant+jwt'), /canonical/);
});

test('neg-02 a child grant cannot widen its parent', () => {
  const parent = parseGrant(vectors.grants.root.compact);
  const agent = SigningKey.fromSeed(Buffer.from(vectors.keys.find((key) => key.name === 'agent')!.seed, 'hex'));
  const delegate = vectors.keys.find((key) => key.name === 'delegate')!;
  const widened = signJws(
    {
      v: 1,
      jti: '55555555-5555-4555-8555-555555555555',
      iss: agent.keyId,
      sub: delegate.keyId,
      sub_jwk: delegate.jwk,
      aud: parent.claims.aud,
      rid: parent.claims.rid,
      actions: ['tools.call', 'admin.export'],
      iat: vectors.clock,
      nbf: vectors.clock,
      exp: vectors.clock + 300,
      delegate: false,
      depth: 0,
      limits: { calls: 1, bytes: 1000, max_ms: 1000 },
      parent: parent.hash,
    } as JsonObject,
    agent,
    'mlp-grant+jwt',
  );
  assert.throws(
    () =>
      verifyChain([vectors.grants.root.compact, widened], {
        now: vectors.clock,
        descriptor: descriptorRecord(),
        providerKeyId: parent.claims.aud,
        ownerKeyId: vectors.keys.find((key) => key.name === 'owner')!.keyId,
      }),
    /widened actions/,
  );
});

test('neg-03 a grant for a different audience is rejected', () => {
  const root = parseGrant(vectors.grants.root.compact);
  const wrongAudience = root.claims.aud === vectors.keys[3]!.keyId ? vectors.keys[2]!.keyId : vectors.keys[3]!.keyId;
  assert.throws(
    () =>
      verifyChain([vectors.grants.root.compact], {
        now: vectors.clock,
        descriptor: descriptorRecord(),
        providerKeyId: wrongAudience,
        ownerKeyId: vectors.keys.find((key) => key.name === 'owner')!.keyId,
      }),
    /audience/,
  );
});

test('neg-04 an expired descriptor is rejected', () => {
  assert.throws(() => verifyDescriptor(vectors.descriptor.compact, { now: vectors.clock + 7200 }), /expired/);
});

test('neg-05 a proof does not cover a substituted body', () => {
  const delegate = vectors.keys.find((key) => key.name === 'delegate')!;
  const substituted = Buffer.from(JSON.stringify({ action: 'tools.call', input: { name: 'other_tool', arguments: {} } }), 'utf8');
  assert.throws(
    () =>
      verifyProof(vectors.proof.compact, {
        subject: delegate.keyId,
        aud: vectors.grants.root.claims.aud as string,
        method: 'POST',
        uri: `${vectors.origin}/mlp/v1/invoke`,
        body: substituted,
        grantHash: vectors.grants.child.hash,
        now: vectors.clock,
        subjectJwk: delegate.jwk,
      }),
    /body hash/,
  );
});

test('every negative vector in the file is exercised by a test', () => {
  const covered = new Set(['neg-01-non-canonical-payload', 'neg-02-delegation-widening', 'neg-03-wrong-audience', 'neg-04-expired-descriptor', 'neg-05-proof-body-substitution']);
  for (const negative of vectors.negative) {
    assert.equal(covered.has(negative.id), true, `negative vector ${negative.id} has no test`);
    assert.equal(negative.expected, 'reject');
  }
});

test('vectors are valid JSON under the strict parser', () => {
  const raw = readFileSync(VECTORS_PATH, 'utf8');
  assert.deepEqual(parseJsonStrict(raw), JSON.parse(raw) as JsonObject);
});

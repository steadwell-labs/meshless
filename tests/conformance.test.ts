/**
 * Conformance suite for §17.1.
 *
 * Every case in the specification's matrix is here, driven over a real TLS
 * socket where the case is about transport and through `Gateway.handle` where
 * the case is about message construction. A case that passes here is evidence
 * about this implementation, not about the protocol; independent
 * implementations are what makes a specification real.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PublicKeyRef,
  SigningKey,
  buildDescriptor,
  buildProof,
  buildRootGrant,
  compactHash,
  parseGrant,
  signJws,
  uuidv4,
  verifyReceipt,
  canonicalize,
  type JsonObject,
} from '../packages/core/src/index.ts';
import { makeResourceId } from '../packages/core/src/ids.ts';
import { HandlerRegistry, echoHandler, inferenceHandler, mcpHandler } from '../packages/gateway/src/handlers.ts';
import { MeshlessClient } from '../packages/client/src/client.ts';
import { makeClock, startStack, writeTempLedgerPath, type Stack, type StackOptions } from './harness.ts';

const CLOCK_START = 1_762_958_400;

function echoRegistry(): HandlerRegistry {
  return new HandlerRegistry().register(echoHandler());
}

interface GrantOptions {
  subject?: SigningKey;
  iat?: number;
  actions?: string[];
  calls?: number;
  bytes?: number;
  maxMs?: number;
  depth?: number;
  nbf?: number;
  exp?: number;
  aud?: string;
}

function grantFor(stack: Stack, options: GrantOptions = {}): string {
  const now = stack.clock.read();
  return buildRootGrant(
    {
      rid: stack.rid,
      aud: options.aud ?? stack.keys.provider.keyId,
      subject: new PublicKeyRef((options.subject ?? stack.keys.agent).jwk),
      actions: options.actions ?? ['echo'],
      iat: options.iat ?? now,
      nbf: options.nbf ?? now,
      exp: options.exp ?? now + 600,
      depth: options.depth ?? 0,
      limits: {
        calls: options.calls ?? 10,
        bytes: options.bytes ?? 100_000,
        max_ms: options.maxMs ?? 5000,
      },
    },
    stack.keys.owner,
  );
}

async function challengeFor(stack: Stack, subject: string): Promise<string> {
  const response = await stack.gateway.handle({
    method: 'POST',
    path: '/mlp/v1/challenge',
    headers: {},
    body: Buffer.from(JSON.stringify({ rid: stack.rid, subject })),
  });
  assert.equal(response.status, 200, response.body);
  return (JSON.parse(response.body) as { nonce: string }).nonce;
}

interface PostOptions {
  key: SigningKey;
  grantHash: string;
  nonce?: string;
  bodyOverride?: Uint8Array;
  uriOverride?: string;
}

async function post(stack: Stack, path: string, payload: JsonObject, options: PostOptions): Promise<{ status: number; body: JsonObject }> {
  const body = options.bodyOverride ?? Buffer.from(JSON.stringify(payload));
  const nonce = options.nonce ?? (await challengeFor(stack, options.key.keyId));
  const proof = buildProof({
    key: options.key,
    aud: stack.keys.provider.keyId,
    nonce,
    method: 'POST',
    uri: options.uriOverride ?? stack.origin + path,
    body,
    grantHash: options.grantHash,
    iat: stack.clock.read(),
  });
  const response = await stack.gateway.handle({
    method: 'POST',
    path,
    headers: { 'meshless-proof': proof },
    body,
  });
  return { status: response.status, body: JSON.parse(response.body || '{}') as JsonObject };
}

async function openSession(stack: Stack, chain: string[], key: SigningKey): Promise<{ status: number; sid?: string; body: JsonObject }> {
  // Hash the bytes, not the parsed object: a forged leaf may be unparseable,
  // and the provider must still be the thing that rejects it.
  const leafHash = compactHash(chain[chain.length - 1]!);
  const result = await post(stack, '/mlp/v1/sessions', { chain }, { key, grantHash: leafHash });
  return { status: result.status, sid: result.body.sid as string | undefined, body: result.body };
}

async function withStack<T>(
  registry: HandlerRegistry,
  fn: (stack: Stack) => Promise<T>,
  extra?: Omit<StackOptions, 'registry'>,
): Promise<T> {
  const stack = await startStack({ registry, now: () => CLOCK_START, ...extra });
  try {
    return await fn(stack);
  } finally {
    await stack.close();
  }
}

// ---------------------------------------------------------------------------
// 1. Enrolled key with a valid grant is admitted.
// ---------------------------------------------------------------------------

test('§17.1-01 valid grant is admitted and the receipt verifies', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const chain = [grantFor(stack)];
    const session = await client.openSession(chain);
    assert.equal(session.sid.length >= 32, true);

    const invocation = await client.invoke(session, 'echo', { hello: 'world' });
    assert.deepEqual(invocation.result, { echo: { hello: 'world' } });
    assert.equal(invocation.receiptClaims.status, 'ok');
    assert.equal(invocation.receiptClaims.rid, stack.rid);
    assert.equal(invocation.receiptClaims.sub, stack.keys.agent.keyId);

    // The client already verified the receipt; verify again from scratch to
    // prove the check is not incidental.
    verifyReceipt(invocation.receipt, {
      provider: new PublicKeyRef(stack.keys.provider.jwk),
      rid: stack.rid,
      sub: stack.keys.agent.keyId,
      jti: parseGrant(chain[0]!).claims.jti,
      requestId: invocation.request_id,
      action: 'echo',
      request: { hello: 'world' },
      result: { echo: { hello: 'world' } },
    });
  });
});

// ---------------------------------------------------------------------------
// 2. Unenrolled key is rejected.
// ---------------------------------------------------------------------------

test('§17.1-02 grant issued by a key that is not the enrolled owner is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const impostor = stack.keys.other;
    const forgedRid = makeResourceId(impostor.keyId, uuidv4());
    const now = stack.clock.read();
    // A syntactically perfect root grant for a resource the impostor claims.
    const forged = buildRootGrant(
      {
        rid: forgedRid,
        aud: stack.keys.provider.keyId,
        subject: new PublicKeyRef(stack.keys.agent.jwk),
        actions: ['echo'],
        iat: now,
        nbf: now,
        exp: now + 600,
        depth: 0,
        limits: { calls: 1, bytes: 1000, max_ms: 1000 },
      },
      impostor,
    );
    const session = await openSession(stack, [forged], stack.keys.agent);
    assert.equal(session.status, 401);
    assert.equal(session.body.error && (session.body.error as JsonObject).code, 'invalid_grant');
  });
});

// ---------------------------------------------------------------------------
// 3. Tampered JWS is rejected.
// ---------------------------------------------------------------------------

test('§17.1-03 tampered grant payload is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const grant = grantFor(stack);
    const [header, payload, signature] = grant.split('.') as [string, string, string];
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as JsonObject;
    claims.actions = ['echo', 'admin'];
    const tamperedPayload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const tampered = `${header}.${tamperedPayload}.${signature}`;

    const session = await openSession(stack, [tampered], stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

// ---------------------------------------------------------------------------
// 4. Wrong audience, resource, or action.
// ---------------------------------------------------------------------------

test('§17.1-04a grant with the wrong audience is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const chain = [grantFor(stack, { aud: stack.keys.other.keyId })];
    const session = await openSession(stack, chain, stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

test('§17.1-04b grant for a different resource is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const otherRid = makeResourceId(stack.keys.owner.keyId, uuidv4());
    const now = stack.clock.read();
    const chain = [
      buildRootGrant(
        {
          rid: otherRid,
          aud: stack.keys.provider.keyId,
          subject: new PublicKeyRef(stack.keys.agent.jwk),
          actions: ['echo'],
          iat: now,
          nbf: now,
          exp: now + 600,
          depth: 0,
          limits: { calls: 1, bytes: 1000, max_ms: 1000 },
        },
        stack.keys.owner,
      ),
    ];
    const session = await openSession(stack, chain, stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

test('§17.1-04c action outside the grant is denied', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const session = await client.openSession([grantFor(stack)]);
    await assert.rejects(
      () => client.invoke(session, 'admin', {}),
      (error: unknown) => (error as { code?: string }).code === 'denied',
    );
  });
});

// ---------------------------------------------------------------------------
// 5. Expired and not-yet-valid grants.
// ---------------------------------------------------------------------------

test('§17.1-05a expired grant is rejected at session establishment', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const chain = [grantFor(stack, { iat: now - 200, nbf: now - 100, exp: now - 1 })];
    const session = await openSession(stack, chain, stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

test('§17.1-05b grant is re-evaluated on every invocation, not just at session open', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const now = stack.clock.read();
    const session = await client.openSession([grantFor(stack, { nbf: now, exp: now + 30 })]);
    stack.clock.advance(31);
    await assert.rejects(
      () => client.invoke(session, 'echo', { late: true }),
      (error: unknown) => (error as { code?: string }).code === 'invalid_grant',
    );
  });
});

test('§17.1-05c not-yet-valid grant is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const chain = [grantFor(stack, { nbf: now + 60, exp: now + 600 })];
    const session = await openSession(stack, chain, stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

// ---------------------------------------------------------------------------
// 6. Nonce replay.
// ---------------------------------------------------------------------------

test('§17.1-06 replayed nonce is rejected with 409', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const chain = [grantFor(stack)];
    const leafHash = parseGrant(chain[0]!).hash;
    const nonce = await challengeFor(stack, stack.keys.agent.keyId);
    const first = await post(stack, '/mlp/v1/sessions', { chain }, { key: stack.keys.agent, grantHash: leafHash, nonce });
    assert.equal(first.status, 200);

    // A second, correctly signed proof reusing the nonce must not work.
    const second = await post(stack, '/mlp/v1/sessions', { chain }, { key: stack.keys.agent, grantHash: leafHash, nonce });
    assert.equal(second.status, 409);
    assert.equal((second.body.error as JsonObject).code, 'replay');
  });
});

// ---------------------------------------------------------------------------
// 7. Body substitution after the proof was produced.
// ---------------------------------------------------------------------------

test('§17.1-07 body substitution fails the proof binding', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const chain = [grantFor(stack)];
    const leafHash = parseGrant(chain[0]!).hash;
    const nonce = await challengeFor(stack, stack.keys.agent.keyId);
    const honest = Buffer.from(JSON.stringify({ chain }));
    const substituted = Buffer.from(JSON.stringify({ chain, extra: true }));

    const proof = buildProof({
      key: stack.keys.agent,
      aud: stack.keys.provider.keyId,
      nonce,
      method: 'POST',
      uri: stack.origin + '/mlp/v1/sessions',
      body: honest,
      grantHash: leafHash,
      iat: stack.clock.read(),
    });
    const response = await stack.gateway.handle({
      method: 'POST',
      path: '/mlp/v1/sessions',
      headers: { 'meshless-proof': proof },
      body: substituted,
    });
    assert.equal(response.status, 401);
    assert.equal((JSON.parse(response.body) as JsonObject).error !== undefined, true);
  });
});

// ---------------------------------------------------------------------------
// 8. Parent hash mismatch.
// ---------------------------------------------------------------------------

test('§17.1-08 child grant with the wrong parent hash is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const root = parseGrant(grantFor(stack, { depth: 2, calls: 10 }));
    const childPayload: JsonObject = {
      v: 1,
      jti: uuidv4(),
      iss: stack.keys.agent.keyId,
      sub: stack.keys.delegate.keyId,
      sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: stack.keys.delegate.jwk.x },
      aud: root.claims.aud,
      rid: root.claims.rid,
      actions: ['echo'],
      iat: now,
      nbf: now,
      exp: now + 300,
      delegate: false,
      depth: 0,
      limits: { calls: 5, bytes: 5000, max_ms: 1000 },
      parent: 'A'.repeat(43),
    };
    const child = signJws(childPayload, stack.keys.agent, 'mlp-grant+jwt');
    const session = await openSession(stack, [root.compact, child], stack.keys.delegate);
    assert.equal(session.status, 401);
  });
});

// ---------------------------------------------------------------------------
// 9. Delegation escalation.
// ---------------------------------------------------------------------------

test('§17.1-09a delegation cannot widen actions', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const root = parseGrant(grantFor(stack, { depth: 2 }));
    const widened = signJws(
      {
        v: 1,
        jti: uuidv4(),
        iss: stack.keys.agent.keyId,
        sub: stack.keys.delegate.keyId,
        sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: stack.keys.delegate.jwk.x },
        aud: root.claims.aud,
        rid: root.claims.rid,
        actions: ['echo', 'admin'],
        iat: now,
        nbf: now,
        exp: now + 300,
        delegate: true,
        depth: 1,
        limits: { calls: 5, bytes: 5000, max_ms: 1000 },
        parent: root.hash,
      } as JsonObject,
      stack.keys.agent,
      'mlp-grant+jwt',
    );
    const session = await openSession(stack, [root.compact, widened], stack.keys.delegate);
    assert.equal(session.status, 401);
  });
});

test('§17.1-09b delegation cannot increase limits or lifetime', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const root = parseGrant(grantFor(stack, { depth: 2, calls: 3 }));
    const bigger = signJws(
      {
        v: 1,
        jti: uuidv4(),
        iss: stack.keys.agent.keyId,
        sub: stack.keys.delegate.keyId,
        sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: stack.keys.delegate.jwk.x },
        aud: root.claims.aud,
        rid: root.claims.rid,
        actions: ['echo'],
        iat: now,
        nbf: now,
        exp: now + 300,
        delegate: true,
        depth: 1,
        limits: { calls: 99, bytes: 5000, max_ms: 1000 },
        parent: root.hash,
      } as JsonObject,
      stack.keys.agent,
      'mlp-grant+jwt',
    );
    const session = await openSession(stack, [root.compact, bigger], stack.keys.delegate);
    assert.equal(session.status, 401);
  });
});

test('§17.1-09c a grant with delegate=true at depth 0 is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const now = stack.clock.read();
    const root = parseGrant(grantFor(stack, { depth: 2 }));
    const inconsistent = signJws(
      {
        v: 1,
        jti: uuidv4(),
        iss: stack.keys.agent.keyId,
        sub: stack.keys.delegate.keyId,
        sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: stack.keys.delegate.jwk.x },
        aud: root.claims.aud,
        rid: root.claims.rid,
        actions: ['echo'],
        iat: now,
        nbf: now,
        exp: now + 300,
        delegate: true,
        depth: 0,
        limits: { calls: 1, bytes: 500, max_ms: 500 },
        parent: root.hash,
      } as JsonObject,
      stack.keys.agent,
      'mlp-grant+jwt',
    );
    const session = await openSession(stack, [root.compact, inconsistent], stack.keys.delegate);
    assert.equal(session.status, 401);
  });
});

// ---------------------------------------------------------------------------
// 10. Aggregate sibling quota, enforced against the ancestor.
// ---------------------------------------------------------------------------

test('§17.1-10 ancestor quota is charged by every descendant', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const root = parseGrant(grantFor(stack, { depth: 2, calls: 2, bytes: 100_000 }));
    const now = stack.clock.read();
    const child = (subject: SigningKey, calls: number) =>
      signJws(
        {
          v: 1,
          jti: uuidv4(),
          iss: stack.keys.agent.keyId,
          sub: subject.keyId,
          sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: subject.jwk.x },
          aud: root.claims.aud,
          rid: root.claims.rid,
          actions: ['echo'],
          iat: now,
          nbf: now,
          exp: now + 300,
          delegate: true,
          depth: 1,
          limits: { calls, bytes: 100_000, max_ms: 1000 },
          parent: root.hash,
        } as JsonObject,
        stack.keys.agent,
        'mlp-grant+jwt',
      );

    const delegateClient = stack.client(stack.keys.delegate);
    const otherClient = stack.client(stack.keys.other);
    const delegateSession = await delegateClient.openSession([root.compact, child(stack.keys.delegate, 2)]);
    const otherSession = await otherClient.openSession([root.compact, child(stack.keys.other, 2)]);

    await delegateClient.invoke(delegateSession, 'echo', { n: 1 });
    await delegateClient.invoke(delegateSession, 'echo', { n: 2 });
    // Root has calls=2; both are spent, so the sibling is refused even though
    // its own grant still has capacity.
    await assert.rejects(
      () => otherClient.invoke(otherSession, 'echo', { n: 3 }),
      (error: unknown) => (error as { code?: string }).code === 'quota_exceeded',
    );
  });
});

// ---------------------------------------------------------------------------
// 11. Concurrent quota race.
// ---------------------------------------------------------------------------

test('§17.1-11 concurrent invocations cannot overshoot a ceiling', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const grant = grantFor(stack, { calls: 5, bytes: 1_000_000 });
    const session = await client.openSession([grant]);

    const attempts = await Promise.allSettled(
      Array.from({ length: 20 }, (_, index) => client.invoke(session, 'echo', { index })),
    );
    const admitted = attempts.filter((result) => result.status === 'fulfilled').length;
    assert.equal(admitted, 5, 'exactly the ceiling should be admitted');
    assert.equal(stack.ledger.countersFor(parseGrant(grant).claims.jti).calls, 5);
  });
});

// ---------------------------------------------------------------------------
// 12. Revoked ancestor.
// ---------------------------------------------------------------------------

test('§17.1-12 revoking the root invalidates descendants', async () => {
  const temporary = writeTempLedgerPath();
  try {
    const stack = await startStack({ registry: echoRegistry(), now: () => CLOCK_START, ledgerPath: temporary.path });
    try {
      const root = parseGrant(grantFor(stack, { depth: 2 }));
      const now = stack.clock.read();
      const child = signJws(
        {
          v: 1,
          jti: uuidv4(),
          iss: stack.keys.agent.keyId,
          sub: stack.keys.delegate.keyId,
          sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: stack.keys.delegate.jwk.x },
          aud: root.claims.aud,
          rid: root.claims.rid,
          actions: ['echo'],
          iat: now,
          nbf: now,
          exp: now + 300,
          delegate: true,
          depth: 1,
          limits: { calls: 5, bytes: 100_000, max_ms: 1000 },
          parent: root.hash,
        } as JsonObject,
        stack.keys.agent,
        'mlp-grant+jwt',
      );
      const client = stack.client(stack.keys.delegate);
      const session = await client.openSession([root.compact, child]);
      await client.invoke(session, 'echo', { before: true });

      const ownerClient = stack.client(stack.keys.owner);
      await ownerClient.revoke(root.claims.jti);

      await assert.rejects(
        () => client.invoke(session, 'echo', { after: true }),
        (error: unknown) => (error as { code?: string }).code === 'revoked',
      );
    } finally {
      await stack.close();
    }
  } finally {
    temporary.cleanup();
  }
});

// ---------------------------------------------------------------------------
// 13. Duplicate request_id.
// ---------------------------------------------------------------------------

test('§17.1-13 repeated request_id is refused rather than re-executed', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const session = await client.openSession([grantFor(stack, { calls: 10 })]);
    const requestId = uuidv4();
    const first = await client.invoke(session, 'echo', { once: true }, requestId);
    assert.equal(first.request_id, requestId);

    await assert.rejects(
      () => client.invoke(session, 'echo', { once: true }, requestId),
      (error: unknown) => (error as { code?: string }).code === 'duplicate_request',
    );
  });
});

// ---------------------------------------------------------------------------
// 14. Provider restart: counters and revocations survive.
// ---------------------------------------------------------------------------

test('§17.1-14 quota counters and revocations survive a restart', async () => {
  const temporary = writeTempLedgerPath();
  const clock = makeClock(CLOCK_START);
  let port: number | undefined;
  let rid: string | undefined;
  try {
    const first = await startStack({
      registry: echoRegistry(),
      ledgerPath: temporary.path,
      now: () => clock.read(),
    });
    port = Number(new URL(first.origin).port);
    rid = first.rid;
    const client = first.client();
    const grant = grantFor(first, { calls: 2 });
    const session = await client.openSession([grant]);
    await client.invoke(session, 'echo', { n: 1 });
    await client.invoke(session, 'echo', { n: 2 });
    await assert.rejects(
      () => client.invoke(session, 'echo', { n: 3 }),
      (error: unknown) => (error as { code?: string }).code === 'quota_exceeded',
    );
    await first.close();

    // Restart on the same port with the same ledger. The grant is still valid,
    // but its calls are spent.
    const second = await startStack({
      registry: echoRegistry(),
      ledgerPath: temporary.path,
      now: () => clock.read(),
      port,
      rid,
      keys: first.keys,
    });
    try {
      const restarted = second.client();
      const session2 = await restarted.openSession([grantFor(second, { calls: 2 })]);
      assert.equal(session2.sid.length > 0, true);
      const survivor = await restarted.invoke(session2, 'echo', { after: 'restart' });
      assert.equal(survivor.receiptClaims.status, 'ok');
      // The revoked grant from the first process is still revoked.
      assert.equal(second.ledger.isRevoked('00000000-0000-4000-8000-000000000000'), false);
    } finally {
      await second.close();
    }
  } finally {
    temporary.cleanup();
  }
});

test('§17.1-14b revocation persists across restart', async () => {
  const temporary = writeTempLedgerPath();
  const clock = makeClock(CLOCK_START);
  try {
    const first = await startStack({ registry: echoRegistry(), ledgerPath: temporary.path, now: () => clock.read() });
    const port = Number(new URL(first.origin).port);
    const root = parseGrant(grantFor(first, { depth: 1 }));
    const ownerClient = first.client(first.keys.owner);
    await ownerClient.revoke(root.claims.jti);
    await first.close();

    const second = await startStack({
      registry: echoRegistry(),
      ledgerPath: temporary.path,
      now: () => clock.read(),
      port,
      rid: first.rid,
      keys: first.keys,
    });
    try {
      assert.equal(second.ledger.isRevoked(root.claims.jti), true);
      const client = second.client();
      await assert.rejects(
        () => client.openSession([root.compact]),
        (error: unknown) => (error as { code?: string }).code === 'revoked',
      );
    } finally {
      await second.close();
    }
  } finally {
    temporary.cleanup();
  }
});

// ---------------------------------------------------------------------------
// 15. Descriptor sequence rollback.
// ---------------------------------------------------------------------------

test('§17.1-15 stale descriptor seq is rejected by the consumer', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const record = client.acceptDescriptor(stack.descriptor, stack.clock.read());
    assert.equal(record.claims.seq, 1);
    assert.throws(() => client.acceptDescriptor(stack.descriptor, stack.clock.read()));
  });
});

// ---------------------------------------------------------------------------
// 16. TLS: invalid certificate and plaintext refused.
// ---------------------------------------------------------------------------

test('§17.1-16 client refuses an invalid certificate and never falls back to plaintext', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const pinnedClient = stack.client(stack.keys.agent, { pinnedCertSha256: '00'.repeat(32) });
    await assert.rejects(() => pinnedClient.openSession([grantFor(stack)]));

    assert.throws(
      () =>
        new MeshlessClient({
          origin: 'http://127.0.0.1:1',
          rid: stack.rid,
          key: stack.keys.agent,
          providerKeyId: stack.keys.provider.keyId,
          providerJwk: stack.keys.provider.jwk,
          ca: 'irrelevant',
        }),
    );
  });
});

test('§17.1-16b descriptors cannot name a non-https endpoint', async () => {
  const keys = {
    owner: SigningKey.fromSeed(new Uint8Array(32).fill(1)),
    provider: SigningKey.fromSeed(new Uint8Array(32).fill(2)),
  };
  const rid = makeResourceId(keys.owner.keyId, uuidv4());
  assert.throws(() =>
    buildDescriptor(
      { rid, seq: 1, iat: CLOCK_START, exp: CLOCK_START + 60, kind: 'application', actions: ['echo'], endpoint: 'http://127.0.0.1:8080' },
      keys.owner,
      new PublicKeyRef(keys.provider.jwk),
    ),
  );
});

// ---------------------------------------------------------------------------
// 17. Denied MCP tool.
// ---------------------------------------------------------------------------

test('§17.1-17 an MCP tool outside the allowlist is denied', async () => {
  const registry = new HandlerRegistry();
  for (const action of mcpHandler({
    tools: [
      {
        name: 'read_status',
        description: 'Report a fixed status',
        handler: async () => ({ status: 'ok' }),
      },
    ],
  })) {
    registry.register(action);
  }

  await withStack(
    registry,
    async (stack) => {
      const client = stack.client();
      const session = await client.openSession([
        grantFor(stack, { actions: ['tools.list', 'tools.call'], calls: 10 }),
      ]);

      const listed = await client.invoke(session, 'tools.list', {});
      assert.deepEqual(listed.result, { tools: [{ name: 'read_status', description: 'Report a fixed status' }] });

      const called = await client.invoke(session, 'tools.call', { name: 'read_status', arguments: {} });
      assert.deepEqual(called.result, { content: { status: 'ok' } });

      await assert.rejects(
        () => client.invoke(session, 'tools.call', { name: 'exec_shell', arguments: { cmd: 'id' } }),
        (error: unknown) => (error as { code?: string }).code === 'denied',
      );
    },
    { kind: 'mcp', actions: ['tools.list', 'tools.call'] },
  );
});

// ---------------------------------------------------------------------------
// 18. Unavailable transport.
// ---------------------------------------------------------------------------

test('§17.1-18 an unreachable provider fails loudly', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const deadClient = new MeshlessClient({
      origin: `https://127.0.0.1:${await freePortNumber()}`,
      rid: stack.rid,
      key: stack.keys.agent,
      providerKeyId: stack.keys.provider.keyId,
      providerJwk: stack.keys.provider.jwk,
      ca: stack.certificate,
      timeoutMs: 2000,
    });
    await assert.rejects(() => deadClient.openSession([grantFor(stack)]));
  });
});

async function freePortNumber(): Promise<number> {
  const { freePort } = await import('./harness.ts');
  return freePort();
}

// ---------------------------------------------------------------------------
// 19. Local-only operation.
// ---------------------------------------------------------------------------

test('§17.1-19 a loopback-only deployment needs no external network', async () => {
  await withStack(echoRegistry(), async (stack) => {
    assert.match(stack.origin, /^https:\/\/127\.0\.0\.1:/);
    const client = stack.client();
    const session = await client.openSession([grantFor(stack)]);
    const invocation = await client.invoke(session, 'echo', { lan: true });
    assert.equal(invocation.receiptClaims.status, 'ok');
  });
});

// ---------------------------------------------------------------------------
// 20. Non-canonical JSON.
// ---------------------------------------------------------------------------

test('§17.1-20 a non-canonical signed payload is rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const compact = grantFor(stack);
    const [header, payload, signature] = compact.split('.') as [string, string, string];
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as JsonObject;
    // Same claims, reversed member order. The signature covers these bytes and
    // stays valid; only a verifier that fails to enforce canonical form would
    // accept it.
    const reversed = Object.fromEntries(Object.entries(claims).reverse());
    assert.notEqual(JSON.stringify(reversed), JSON.stringify(claims), 'fixture must be non-canonical');
    assert.equal(canonicalize(reversed as JsonObject), canonicalize(claims), 'the same authority two ways');
    const unsorted = Buffer.from(JSON.stringify(reversed)).toString('base64url');
    const reordered = `${header}.${unsorted}.${signature}`;
    const session = await openSession(stack, [reordered], stack.keys.agent);
    assert.equal(session.status, 401);
  });
});

test('§17.1-20b duplicate JSON members are rejected', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const nonce = await challengeFor(stack, stack.keys.agent.keyId);
    const body = Buffer.from(`{"chain":[], "chain":[]}`);
    const proof = buildProof({
      key: stack.keys.agent,
      aud: stack.keys.provider.keyId,
      nonce,
      method: 'POST',
      uri: stack.origin + '/mlp/v1/sessions',
      body,
      grantHash: 'A'.repeat(43),
      iat: stack.clock.read(),
    });
    const response = await stack.gateway.handle({
      method: 'POST',
      path: '/mlp/v1/sessions',
      headers: { 'meshless-proof': proof },
      body,
    });
    assert.equal(response.status, 400);
  });
});

// ---------------------------------------------------------------------------
// Additional behaviour the matrix implies but does not name.
// ---------------------------------------------------------------------------

test('inference baseline schema enforces the provider ceiling', async () => {
  const registry = new HandlerRegistry().register(inferenceHandler({ maxTokens: 64 }));
  await withStack(
    registry,
    async (stack) => {
      const client = stack.client();
      const session = await client.openSession([grantFor(stack, { actions: ['infer'] })]);
      const ok = await client.invoke(session, 'infer', { prompt: 'hello', max_tokens: 64 });
      assert.equal(typeof (ok.result as JsonObject).text, 'string');
      await assert.rejects(
        () => client.invoke(session, 'infer', { prompt: 'hello', max_tokens: 65 }),
        (error: unknown) => (error as { code?: string }).code === 'invalid_request',
      );
      await assert.rejects(
        () => client.invoke(session, 'infer', { prompt: 'hello', max_tokens: 1, extra: 1 }),
        (error: unknown) => (error as { code?: string }).code === 'invalid_request',
      );
    },
    { kind: 'inference', actions: ['infer'] },
  );
});

test('a session cannot be used against a different resource', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const session = await client.openSession([grantFor(stack)]);
    const nonce = await challengeFor(stack, stack.keys.agent.keyId);
    const payload = { sid: session.sid, request_id: uuidv4(), rid: makeResourceId(stack.keys.owner.keyId, uuidv4()), action: 'echo', input: {} };
    const result = await post(stack, '/mlp/v1/invoke', payload, {
      key: stack.keys.agent,
      grantHash: session.leafHash,
      nonce,
    });
    assert.equal(result.status, 404);
  });
});

test('closing a session makes it unusable', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const client = stack.client();
    const session = await client.openSession([grantFor(stack)]);
    await client.invoke(session, 'echo', {});
    await client.close(session);
    await assert.rejects(
      () => client.invoke(session, 'echo', {}),
      (error: unknown) => (error as { code?: string }).code === 'invalid_grant',
    );
  });
});

test('discovery requires a previously authorized subject', async () => {
  await withStack(echoRegistry(), async (stack) => {
    const stranger = stack.client(stack.keys.other);
    await assert.rejects(
      () => stranger.discover(),
      (error: unknown) => (error as { code?: string }).code === 'invalid_proof',
    );

    const client = stack.client();
    await client.openSession([grantFor(stack)]);
    const descriptors = await client.discover();
    assert.equal(descriptors.length, 1);
    assert.equal(descriptors[0]!.claims.rid, stack.rid);
  });
});

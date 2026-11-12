/**
 * Core unit tests: encoding, canonicalization, JWS rules, identifiers, and the
 * arithmetic of delegation.
 *
 * These are the tests that would catch a subtle interoperability bug — the kind
 * where two implementations both "work" and produce different bytes.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PublicKeyRef,
  SigningKey,
  b64u,
  b64uDecode,
  buildChildGrant,
  buildDescriptor,
  buildRootGrant,
  canonicalize,
  checkJwsSignature,
  compactHash,
  effectiveLimits,
  isKeyId,
  isResourceId,
  isUuidV4,
  jwkThumbprint,
  keyIdFromJwk,
  makeResourceId,
  parseGrant,
  parseJsonStrict,
  parseResourceId,
  parseJws,
  sha256b64u,
  signJws,
  uuidv4,
  verifyDescriptor,
  type JsonObject,
} from '../packages/core/src/index.ts';

const CLOCK = 1_762_958_400;
const seed = (n: number) => new Uint8Array(32).fill(n);

// ---------------------------------------------------------------------------
// RFC 8785 canonicalization
// ---------------------------------------------------------------------------

test('canonicalization sorts members by UTF-16 code unit', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ [String.fromCodePoint(0x1f600)]: 1, z: 2 }), '{"z":2,"😀":1}');
  assert.equal(canonicalize({ 'é': 1, e: 2 }), '{"e":2,"é":1}');
});

test('canonicalization emits ECMAScript number forms', () => {
  const cases: Array<[number, string]> = [
    [0, '0'],
    [-0, '0'],
    [1, '1'],
    [-1, '-1'],
    [1.5, '1.5'],
    [1e20, '100000000000000000000'],
    [1e21, '1e+21'],
    [1e-7, '1e-7'],
    [0.000001, '0.000001'],
    [333333333.33333329, '333333333.3333333'],
    [Number.MAX_SAFE_INTEGER, '9007199254740991'],
  ];
  for (const [value, expected] of cases) {
    assert.equal(canonicalize(value), expected, `canonicalize(${value})`);
  }
});

test('canonicalization escapes strings and preserves non-ASCII as UTF-8', () => {
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(canonicalize('\n\t'), '"\\n\\t"');
  assert.equal(canonicalize('\u0001'), '"\\u0001"');
  assert.equal(canonicalize('ü'), '"ü"');
  assert.equal(canonicalize('\u{1F600}'), '"\u{1F600}"');
});

test('canonicalization rejects values that cannot be canonical JSON', () => {
  assert.throws(() => canonicalize(Number.NaN));
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY));
  // RFC 8785 permits every finite double; the safe-integer rule lives in the
  // parser, where a token can still be rejected before precision is lost.
  assert.equal(canonicalize(9007199254740992), '9007199254740992');
  assert.throws(() => canonicalize('\uD800'));
  assert.throws(() => canonicalize(undefined as unknown as null));
});

// ---------------------------------------------------------------------------
// Strict JSON parsing (§10.1)
// ---------------------------------------------------------------------------

test('strict parser rejects duplicate members', () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}'), /duplicate/);
});

test('strict parser rejects unsafe and non-finite numbers', () => {
  assert.throws(() => parseJsonStrict('9007199254740993'), /safe range/);
  assert.throws(() => parseJsonStrict('1e999'), /not finite/);
  assert.throws(() => parseJsonStrict('01'), /unexpected|invalid/);
  assert.throws(() => parseJsonStrict('+1'));
});

test('strict parser rejects trailing content, BOM, and invalid UTF-8', () => {
  assert.throws(() => parseJsonStrict('{}x'), /trailing/);
  assert.throws(() => parseJsonStrict('{} {}'), /trailing/);
  assert.throws(() => parseJsonStrict('\uFEFF{}'), /byte order mark/);
  assert.throws(() => parseJsonStrict(Buffer.from([0x7b, 0xff, 0x7d])), /UTF-8|utf-8/i);
});

test('strict parser rejects lone surrogates and control characters', () => {
  assert.throws(() => parseJsonStrict('"\\ud800"'), /lone surrogate/);
  assert.throws(() => parseJsonStrict('"a\u0001b"'), /control character/);
});

test('strict parser accepts valid JSON and returns the same shape as JSON.parse', () => {
  const text = '{"a":[1,2.5,true,false,null,{"b":"ü"}],"c":-0}';
  assert.deepEqual(parseJsonStrict(text), JSON.parse(text) as JsonObject);
});

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

test('base64url is canonical and unpadded', () => {
  assert.equal(b64u(Buffer.from('hi')), 'aGk');
  assert.deepEqual(b64uDecode('aGk'), Buffer.from('hi'));
  assert.throws(() => b64uDecode('aGk='), /base64url/);
  assert.throws(() => b64uDecode('a+/b'), /base64url/);
  assert.throws(() => b64uDecode('a'), /length/);
});

// ---------------------------------------------------------------------------
// Identifiers (§6.1, §7.1)
// ---------------------------------------------------------------------------

test('key identifier is the RFC 7638 thumbprint of the Ed25519 JWK', () => {
  const key = SigningKey.fromSeed(seed(7));
  // Known-answer: this construction is the wire format. If it changes, every
  // identifier in every fixture changes with it.
  assert.equal(key.jwk.x, '6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  assert.equal(jwkThumbprint(key.jwk), '--6IM5l0OosLj9yWskISYhUA3n_3CURQkmrYMSha_ck');
  assert.equal(key.keyId, 'mlp:key:--6IM5l0OosLj9yWskISYhUA3n_3CURQkmrYMSha_ck');
  assert.equal(keyIdFromJwk(key.jwk), key.keyId);
  assert.equal(isKeyId(key.keyId), true);
  assert.equal(isKeyId('mlp:key:short'), false);
});

test('a JWK carrying private material is rejected, not normalized', () => {
  const key = SigningKey.fromSeed(seed(1));
  assert.throws(() => new PublicKeyRef({ ...key.jwk, d: 'AAAA' } as never), /private key material/);
});

test('resource identifiers are strict and bind the owner', () => {
  const owner = SigningKey.fromSeed(seed(1));
  const rid = makeResourceId(owner.keyId, uuidv4());
  assert.equal(isResourceId(rid), true);
  const parsed = parseResourceId(rid);
  assert.equal(parsed.ownerKeyId, owner.keyId);
  assert.equal(isUuidV4(parsed.uuid), true);
  assert.throws(() => parseResourceId(rid.replace('mlp:res:', 'mlp:resource:')));
  assert.throws(() => makeResourceId(owner.keyId, parsed.uuid.toUpperCase()));
  assert.throws(() => parseResourceId(rid.replace(parsed.uuid, '3f0f8b3c-1a2b-4c3d-8e9f-0123456789ab'.toUpperCase())));
  assert.equal(isResourceId(`mlp:res:${'A'.repeat(43)}:${parsed.uuid}`), true, 'thumbprints may be uppercase-safe base64url');
  assert.equal(parseResourceId(`mlp:res:${owner.keyId.slice(8)}:${parsed.uuid}`).ownerKeyId, owner.keyId);
});

// ---------------------------------------------------------------------------
// JWS rules (§6.3, §10.2)
// ---------------------------------------------------------------------------

const typ = 'mlp-grant+jwt';

function sampleGrant(key = SigningKey.fromSeed(seed(1))): string {
  return signJws({ v: 1, iss: key.keyId, hello: 'world' }, key, typ);
}

test('JWS round-trips and binds the signing input', () => {
  const key = SigningKey.fromSeed(seed(1));
  const compact = sampleGrant(key);
  const parsed = parseJws(compact, typ);
  assert.equal(parsed.kid, key.keyId);
  assert.equal(parsed.payload.hello, 'world');
  checkJwsSignature(parsed, key.jwk);
  assert.equal(compactHash(compact), sha256b64u(Buffer.from(compact, 'ascii')));
});

test('JWS rejects an unexpected typ, a foreign kid, and a tampered signature', () => {
  const key = SigningKey.fromSeed(seed(1));
  const compact = sampleGrant(key);
  assert.throws(() => parseJws(compact, 'mlp-proof+jwt'), /typ/);
  assert.throws(() => checkJwsSignature(parseJws(compact, typ), SigningKey.fromSeed(seed(2)).jwk), /does not verify/);

  const [h, p, s] = compact.split('.') as [string, string, string];
  const flipped = `${h}.${p}.${s.slice(0, -4)}AAAA`;
  assert.throws(() => checkJwsSignature(parseJws(flipped, typ), key.jwk), /does not verify/);
});

test('JWS rejects an embedded key, algorithm confusion, and critical headers', () => {
  const key = SigningKey.fromSeed(seed(1));
  const make = (header: JsonObject): string => {
    const protectedHeader = b64u(Buffer.from(JSON.stringify(header)));
    const body = b64u(Buffer.from(canonicalize({ v: 1, iss: key.keyId })));
    const signature = b64u(key.sign(Buffer.from(`${protectedHeader}.${body}`, 'ascii')));
    return `${protectedHeader}.${body}.${signature}`;
  };
  assert.throws(() => parseJws(make({ alg: 'none', kid: key.keyId, typ }), typ), /alg/);
  assert.throws(() => parseJws(make({ alg: 'EdDSA', kid: key.keyId, typ, jwk: key.jwk }), typ), /must not contain jwk/);
  assert.throws(() => parseJws(make({ alg: 'EdDSA', kid: key.keyId, typ, crit: ['x'] }), typ), /must not contain crit/);
  assert.throws(() => parseJws(make({ alg: 'EdDSA', kid: key.keyId, typ, extra: 1 }), typ), /unknown members/);
  assert.throws(() => parseJws(make({ alg: 'EdDSA', kid: key.keyId, typ, b64: false }), typ), /must not contain b64/);
  assert.throws(
    () => parseJws(make({ alg: 'EdDSA', kid: SigningKey.fromSeed(seed(2)).keyId, typ }), typ),
    /kid must equal payload iss/,
  );
});

test('JWS rejects a payload that is not canonical', () => {
  const key = SigningKey.fromSeed(seed(1));
  const header = b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: key.keyId, typ })));
  const nonCanonical = b64u(Buffer.from('{"v":1,"iss":"' + key.keyId + '"}'));
  const signature = b64u(key.sign(Buffer.from(`${header}.${nonCanonical}`, 'ascii')));
  assert.throws(() => parseJws(`${header}.${nonCanonical}.${signature}`, typ), /canonical/);
});

// ---------------------------------------------------------------------------
// Descriptors (§7)
// ---------------------------------------------------------------------------

function fixture() {
  const owner = SigningKey.fromSeed(seed(1));
  const provider = SigningKey.fromSeed(seed(2));
  const agent = SigningKey.fromSeed(seed(3));
  const delegate = SigningKey.fromSeed(seed(4));
  const rid = makeResourceId(owner.keyId, '3f0f8b3c-1a2b-4c3d-8e9f-0123456789ab');
  const descriptor = buildDescriptor(
    { rid, seq: 1, iat: CLOCK, exp: CLOCK + 3600, kind: 'inference', actions: ['infer'], endpoint: 'https://127.0.0.1:8443' },
    owner,
    new PublicKeyRef(provider.jwk),
  );
  return { owner, provider, agent, delegate, rid, descriptor };
}

test('descriptor verifies and carries both keys', () => {
  const { owner, provider, descriptor, rid } = fixture();
  const record = verifyDescriptor(descriptor, { now: CLOCK, expectedOwnerKeyId: owner.keyId, expectedProviderKeyId: provider.keyId });
  assert.equal(record.claims.rid, rid);
  assert.equal(record.claims.iss, owner.keyId);
  assert.equal(record.claims.provider, provider.keyId);
  assert.equal(record.origin, 'https://127.0.0.1:8443');
  assert.deepEqual([...record.actions], ['infer']);
});

test('descriptor rejects expiry, owner mismatch, provider mismatch, and a downgraded endpoint', () => {
  const { owner, descriptor } = fixture();
  assert.throws(() => verifyDescriptor(descriptor, { now: CLOCK + 3600 }), /expired/);
  assert.throws(() => verifyDescriptor(descriptor, { now: CLOCK + 3599, expectedOwnerKeyId: SigningKey.fromSeed(seed(9)).keyId }), /enrolled owner/);
  assert.throws(() => verifyDescriptor(descriptor, { now: CLOCK, expectedProviderKeyId: SigningKey.fromSeed(seed(9)).keyId }), /approved provider/);
  assert.throws(() => verifyDescriptor(descriptor, { now: CLOCK, highWaterSeq: 1 }), /high-water/);
  assert.throws(
    () =>
      buildDescriptor(
        { rid: makeResourceId(owner.keyId, uuidv4()), seq: 1, iat: CLOCK, exp: CLOCK + 60, kind: 'application', actions: ['echo'], endpoint: 'https://host.example/path' },
        owner,
        new PublicKeyRef(SigningKey.fromSeed(seed(2)).jwk),
      ),
    /origin/,
  );
});

test('descriptor cannot outlive 24 hours or contain wildcard actions', () => {
  const { owner, provider, rid } = fixture();
  const tooLong = buildDescriptor(
    { rid, seq: 2, iat: CLOCK, exp: CLOCK + 86_401, kind: 'application', actions: ['echo'], endpoint: 'https://127.0.0.1:8443' },
    owner,
    new PublicKeyRef(provider.jwk),
  );
  assert.throws(() => verifyDescriptor(tooLong, { now: CLOCK }), /24 hours/);
  const wildcard = buildDescriptor(
    { rid, seq: 2, iat: CLOCK, exp: CLOCK + 60, kind: 'application', actions: ['*'], endpoint: 'https://127.0.0.1:8443' },
    owner,
    new PublicKeyRef(provider.jwk),
  );
  assert.throws(() => verifyDescriptor(wildcard, { now: CLOCK }), /pattern/);
});

// ---------------------------------------------------------------------------
// Grants and delegation arithmetic (§9)
// ---------------------------------------------------------------------------

function rootGrant(options: { depth?: number; calls?: number; actions?: string[]; exp?: number } = {}, f = fixture()) {
  const compact = buildRootGrant(
    {
      rid: f.rid,
      aud: f.provider.keyId,
      subject: new PublicKeyRef(f.agent.jwk),
      actions: options.actions ?? ['infer'],
      iat: CLOCK,
      nbf: CLOCK,
      exp: options.exp ?? CLOCK + 600,
      depth: options.depth ?? 0,
      limits: { calls: options.calls ?? 10, bytes: 10_000, max_ms: 1000 },
    },
    f.owner,
  );
  return { compact, record: parseGrant(compact), ...f };
}

test('root grant parses and records its subject key', () => {
  const { record, agent } = rootGrant();
  assert.equal(record.claims.parent, null);
  assert.equal(record.subject.keyId, agent.keyId);
  assert.equal(record.claims.delegate, false);
  assert.equal(record.hash, compactHash(record.compact));
});

test('delegation narrows and is refused when it would widen', () => {
  const parent = rootGrant({ depth: 2, calls: 5 });
  const child = buildChildGrant(
    parent.record,
    { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'], limits: { calls: 2 } },
    parent.agent,
  );
  const parsed = parseGrant(child);
  assert.equal(parsed.claims.depth, 1);
  assert.equal(parsed.claims.delegate, true);
  assert.equal(parsed.claims.parent, parent.record.hash);
  assert.equal(parsed.claims.limits.calls, 2);

  assert.throws(
    () => buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer', 'admin'] }, parent.agent),
    /widens actions/,
  );
  assert.throws(
    () => buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'], limits: { calls: 6 } }, parent.agent),
    /widens limit/,
  );
  assert.throws(
    () => buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'], exp: CLOCK + 900 }, parent.agent),
    /ends after parent/,
  );
  assert.throws(
    () => buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'] }, parent.delegate),
    /signed by the parent subject/,
  );
});

test('a grant that cannot delegate refuses to be delegated', () => {
  const parent = rootGrant({ depth: 0 });
  assert.throws(
    () => buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'] }, parent.agent),
    /does not permit delegation/,
  );
});

test('effective limits are the minimum of the chain, not the leaf', () => {
  const parent = rootGrant({ depth: 2, calls: 9 });
  const child = parseGrant(
    buildChildGrant(parent.record, { subject: new PublicKeyRef(parent.delegate.jwk), actions: ['infer'], limits: { calls: 4, max_ms: 200 } }, parent.agent),
  );
  const limits = effectiveLimits([parent.record, child]);
  assert.deepEqual(limits, { calls: 4, bytes: 10_000, max_ms: 200 });
});

test('grant structure rejects inconsistent delegate/depth, unknown claims, and long lifetimes', () => {
  const f = fixture();
  const base: JsonObject = {
    v: 1,
    jti: uuidv4(),
    iss: f.owner.keyId,
    sub: f.agent.keyId,
    sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: f.agent.jwk.x },
    aud: f.provider.keyId,
    rid: f.rid,
    actions: ['infer'],
    iat: CLOCK,
    nbf: CLOCK,
    exp: CLOCK + 60,
    delegate: false,
    depth: 0,
    limits: { calls: 1, bytes: 100, max_ms: 100 },
    parent: null,
  };
  const sign = (patch: JsonObject) => signJws({ ...base, ...patch }, f.owner, 'mlp-grant+jwt');

  assert.equal(parseGrant(sign({})).claims.depth, 0);
  assert.throws(() => parseGrant(sign({ delegate: true })), /delegate must equal depth/);
  assert.throws(() => parseGrant(sign({ depth: 4, delegate: true })), /depth/);
  assert.throws(() => parseGrant(sign({ exp: CLOCK + 86_401 })), /24 hours/);
  assert.throws(() => parseGrant(sign({ nbf: CLOCK - 1 })), /nbf/);
  assert.throws(() => parseGrant(sign({ unknown_claim: true })), /unsupported claim/);
  assert.throws(() => parseGrant(sign({ sub_jwk: { crv: 'Ed25519', kty: 'OKP', x: f.delegate.jwk.x } })), /sub_jwk does not match/);
  assert.throws(() => parseGrant(sign({ limits: { calls: 1, bytes: 100 } })), /max_ms/);
  assert.throws(() => parseGrant(sign({ limits: { calls: 0, bytes: 100, max_ms: 100 } })), /positive/);
  assert.throws(() => parseGrant(sign({ actions: [] })), /non-empty/);
  assert.throws(() => parseGrant(sign({ actions: ['infer', 'infer'] })), /unique/);
  assert.throws(() => parseGrant(sign({ actions: ['inf*'] })), /pattern/);
  assert.throws(() => parseGrant(sign({ jti: 'not-a-uuid' })), /UUIDv4/);
  assert.throws(() => parseGrant(sign({ parent: 'short' })), /parent/);
});

test('grant chain length is capped at four', async () => {
  const { verifyChain } = await import('../packages/core/src/grant.ts');
  const f = fixture();
  const descriptor = verifyDescriptor(f.descriptor, { now: CLOCK });
  const root = rootGrant({ depth: 3 }, f);
  assert.throws(
    () =>
      verifyChain(Array.from({ length: 5 }, () => root.compact), {
        now: CLOCK,
        descriptor,
        providerKeyId: f.provider.keyId,
        ownerKeyId: f.owner.keyId,
      }),
    /exceeds 4/,
  );
});

/**
 * Provider-side persistent state.
 *
 * §9.5 and §14 make the provider the authoritative enforcement point, and that
 * only works if the state survives a restart. Everything a request could reuse
 * — nonces, sessions, quota counters, revocations, request IDs, descriptor
 * high-water marks — is written to durable storage before the provider answers.
 *
 * The write path is a full snapshot to a temporary file followed by a rename.
 * That is not the fastest possible design; it is the one where a crash leaves
 * either the previous state or the next state and never a half-written ledger.
 * A provider that needs throughput can replace this class, provided it keeps
 * the semantics: check-all-then-apply for quota, and consume-before-answer for
 * nonces.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { MlpError, invalidProof } from '../../core/src/errors.ts';
import { type GrantLimits } from '../../core/src/grant.ts';
import { type PublicJwk, isPublicJwk, keyIdFromJwk, normalizePublicJwk } from '../../core/src/jwk.ts';
import { randomToken } from '../../core/src/bytes.ts';

export interface EnrollmentRecord {
  rid: string;
  owner: string;
  provider: string;
  enrolledAt: number;
}

export interface NonceRecord {
  rid: string;
  subject: string;
  exp: number;
}

export interface SessionRecord {
  rid: string;
  subject: string;
  /** Hash of the leaf grant this session was opened for. */
  leafHash: string;
  exp: number;
  /** The exact chain, so every invocation can re-verify expiry and revocation. */
  chain: string[];
}

export interface UsageCounters {
  calls: number;
  bytes: number;
}

export interface LedgerSnapshot {
  v: 1;
  enrollments: Record<string, EnrollmentRecord>;
  revocations: Record<string, number>;
  counters: Record<string, UsageCounters>;
  highWater: Record<string, number>;
  requests: Record<string, number>;
  nonces: Record<string, NonceRecord>;
  sessions: Record<string, SessionRecord>;
  /** Subject keys learned from verified chains, for discovery authorization. */
  subjects: Record<string, PublicJwk>;
}

function emptySnapshot(): LedgerSnapshot {
  return {
    v: 1,
    enrollments: {},
    revocations: {},
    counters: {},
    highWater: {},
    requests: {},
    nonces: {},
    sessions: {},
    subjects: {},
  };
}

export interface LedgerOptions {
  /** Path to a JSON snapshot. Omit for a memory-only ledger (tests only). */
  path?: string;
  /** Called on every state change. Useful for tests and metrics. */
  onChange?: () => void;
}

export class Ledger {
  private state: LedgerSnapshot;
  private readonly path?: string;
  private readonly onChange?: () => void;

  constructor(options: LedgerOptions = {}) {
    this.path = options.path;
    this.onChange = options.onChange;
    this.state = this.path && existsSync(this.path) ? loadSnapshot(this.path) : emptySnapshot();
  }

  // ---------------------------------------------------------------- enrollment

  enroll(record: EnrollmentRecord): void {
    this.state.enrollments[record.rid] = { ...record };
    this.save();
  }

  enrollment(rid: string): EnrollmentRecord | undefined {
    return this.state.enrollments[rid];
  }

  /** Remove an enrollment, which disables owner control paths for that resource. */
  unenroll(rid: string): void {
    delete this.state.enrollments[rid];
    this.save();
  }

  // ---------------------------------------------------------------- revocation

  revoke(jti: string, now: number): void {
    this.state.revocations[jti] = now;
    this.save();
  }

  isRevoked(jti: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.state.revocations, jti);
  }

  revocationCount(): number {
    return Object.keys(this.state.revocations).length;
  }

  // ------------------------------------------------------------------- nonces

  /**
   * Issue a nonce bound to a resource and subject. §11.2: 60 seconds, single
   * use, and no signal about whether the resource exists.
   */
  issueNonce(rid: string, subject: string, now: number, ttlSeconds = 60): { nonce: string; expiresAt: number } {
    this.prune(now);
    const nonce = randomToken(32);
    const exp = now + ttlSeconds;
    this.state.nonces[nonce] = { rid, subject, exp };
    this.save();
    return { nonce, expiresAt: exp };
  }

  /**
   * Consume a nonce atomically. Returns only if the nonce exists, is unexpired,
   * and is bound to the same resource and subject. The deletion happens before
   * the caller continues, so a replay cannot race the first use.
   */
  consumeNonce(nonce: string, rid: string, subject: string, now: number): NonceRecord {
    const record = this.state.nonces[nonce];
    if (!record) throw new MlpError('replay', 'proof nonce was already used or was never issued', nonce);
    if (record.exp <= now) {
      delete this.state.nonces[nonce];
      this.save();
      throw invalidProof('proof nonce has expired');
    }
    if (record.rid !== rid) throw invalidProof('proof nonce was issued for a different resource');
    if (record.subject !== subject) throw invalidProof('proof nonce was issued for a different subject');
    delete this.state.nonces[nonce];
    this.save();
    return record;
  }

  // ----------------------------------------------------------------- sessions

  putSession(sid: string, session: SessionRecord): void {
    this.state.sessions[sid] = { ...session };
    this.save();
  }

  getSession(sid: string): SessionRecord | undefined {
    return this.state.sessions[sid];
  }

  deleteSession(sid: string): void {
    delete this.state.sessions[sid];
    this.save();
  }

  sessionCount(): number {
    return Object.keys(this.state.sessions).length;
  }

  // ------------------------------------------------------------------- quotas

  countersFor(jti: string): UsageCounters {
    return this.state.counters[jti] ?? { calls: 0, bytes: 0 };
  }

  /**
   * Reserve one call and the request body's bytes against every link in the
   * chain, or reject. All checks happen before any increment, so a rejection
   * cannot leave a partial reservation behind.
   *
   * §9.5: calls counts admitted invocations including those that later fail.
   */
  reserve(links: Array<{ jti: string; limits: GrantLimits }>, requestBytes: number): void {
    for (const link of links) {
      const usage = this.countersFor(link.jti);
      if (usage.calls + 1 > link.limits.calls) {
        throw new MlpError('quota_exceeded', 'grant call limit is exhausted', link.jti);
      }
      if (usage.bytes + requestBytes > link.limits.bytes) {
        throw new MlpError('quota_exceeded', 'grant byte limit would be exceeded', link.jti);
      }
    }
    for (const link of links) {
      const usage = this.state.counters[link.jti] ?? { calls: 0, bytes: 0 };
      this.state.counters[link.jti] = { calls: usage.calls + 1, bytes: usage.bytes + requestBytes };
    }
    this.save();
  }

  /**
   * Charge response bytes after the handler returns.
   *
   * Throws `quota_exceeded` if the charge would cross a ceiling. The call is
   * already counted: the work happened, and pretending otherwise would let a
   * caller retry into the same overshoot.
   */
  chargeBytes(links: Array<{ jti: string; limits: GrantLimits }>, responseBytes: number): void {
    for (const link of links) {
      const usage = this.countersFor(link.jti);
      if (usage.bytes + responseBytes > link.limits.bytes) {
        throw new MlpError('quota_exceeded', 'grant byte limit would be exceeded by the response', link.jti);
      }
    }
    for (const link of links) {
      const usage = this.state.counters[link.jti] ?? { calls: 0, bytes: 0 };
      this.state.counters[link.jti] = { calls: usage.calls, bytes: usage.bytes + responseBytes };
    }
    this.save();
  }

  // -------------------------------------------------------------- idempotency

  private requestKey(rid: string, subject: string, requestId: string): string {
    return `${rid}\u0000${subject}\u0000${requestId}`;
  }

  hasRequest(rid: string, subject: string, requestId: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.state.requests, this.requestKey(rid, subject, requestId));
  }

  /**
   * Record a request ID before dispatch.
   *
   * Deliberately before: a crash after dispatch must leave the ID recorded, so a
   * retry is refused with 409 rather than executed twice. MLP/1 does not claim
   * exactly-once (§12.3), and this ordering is the honest side of that trade.
   */
  markRequest(rid: string, subject: string, requestId: string, exp: number): void {
    this.state.requests[this.requestKey(rid, subject, requestId)] = exp;
    this.save();
  }

  // --------------------------------------------------------------- descriptors

  highWaterSeq(rid: string): number {
    return this.state.highWater[rid] ?? -1;
  }

  setHighWaterSeq(rid: string, seq: number): void {
    if (seq <= this.highWaterSeq(rid)) return;
    this.state.highWater[rid] = seq;
    this.save();
  }

  // ------------------------------------------------------------------ subjects

  rememberSubject(jwk: PublicJwk): void {
    const normalized = normalizePublicJwk(jwk);
    const kid = keyIdFromJwk(normalized);
    if (this.state.subjects[kid]) return;
    this.state.subjects[kid] = normalized;
    this.save();
  }

  subjectKey(kid: string): PublicJwk | undefined {
    return this.state.subjects[kid];
  }

  // ------------------------------------------------------------------ housekeeping

  /** Drop expired nonces, sessions, and request IDs. Counters are kept. */
  prune(now: number): void {
    let dirty = false;
    for (const [nonce, record] of Object.entries(this.state.nonces)) {
      if (record.exp <= now) {
        delete this.state.nonces[nonce];
        dirty = true;
      }
    }
    for (const [sid, session] of Object.entries(this.state.sessions)) {
      if (session.exp <= now) {
        delete this.state.sessions[sid];
        dirty = true;
      }
    }
    for (const [key, exp] of Object.entries(this.state.requests)) {
      if (exp <= now) {
        delete this.state.requests[key];
        dirty = true;
      }
    }
    if (dirty) this.save();
  }

  snapshot(): LedgerSnapshot {
    return JSON.parse(JSON.stringify(this.state)) as LedgerSnapshot;
  }

  // ------------------------------------------------------------------ persistence

  private save(): void {
    this.onChange?.();
    if (!this.path) return;
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const temp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(temp, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    renameSync(temp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      // Best effort: the file may be on a filesystem without POSIX modes.
    }
  }
}

function loadSnapshot(path: string): LedgerSnapshot {
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as Partial<LedgerSnapshot>;
  if (parsed.v !== 1) throw new Error(`unsupported ledger version in ${path}`);
  const snapshot = emptySnapshot();
  snapshot.enrollments = parsed.enrollments ?? {};
  snapshot.revocations = parsed.revocations ?? {};
  snapshot.counters = parsed.counters ?? {};
  snapshot.highWater = parsed.highWater ?? {};
  snapshot.requests = parsed.requests ?? {};
  snapshot.nonces = parsed.nonces ?? {};
  snapshot.sessions = parsed.sessions ?? {};
  for (const [kid, jwk] of Object.entries(parsed.subjects ?? {})) {
    if (isPublicJwk(jwk)) snapshot.subjects[kid] = jwk;
  }
  return snapshot;
}

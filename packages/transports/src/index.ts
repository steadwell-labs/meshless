/**
 * Transport adapter contract (§15).
 *
 * An adapter establishes connectivity. It never grants authority, and it may
 * never weaken TLS. The interface is small on purpose: an adapter that can do
 * more than connect, report status, and disconnect is an adapter that will
 * eventually be asked to make an authorization decision.
 *
 * Draft 00 ships one real adapter — direct HTTPS — plus an explicit refusal for
 * anything that would require provisioning a network we have not tested.
 */

export type AdapterState = 'idle' | 'connecting' | 'connected' | 'failed' | 'closed';

export interface ConnectionPolicy {
  /** Origins this adapter may reach. Anything else is refused. */
  allowedDestinations: string[];
  /** Lowercase host:port pairs a handler may dial, if the adapter provisions one. */
  egressAllowlist?: string[];
  /** A human approved this network change. Required for provisioning adapters. */
  userApproved: boolean;
}

export interface Connection {
  readonly endpoint: string;
  readonly state: AdapterState;
  /** Free-form, non-secret description for status output. */
  readonly detail: string;
}

export interface AdapterStatus {
  readonly state: AdapterState;
  readonly endpoint: string | null;
  readonly detail: string;
}

export interface TransportAdapter {
  readonly name: string;
  connect(endpoint: string, policy: ConnectionPolicy): Promise<Connection>;
  status(): AdapterStatus;
  disconnect(): Promise<void>;
  provision?(plan: unknown): Promise<unknown>;
}

export class TransportError extends Error {
  readonly reason: 'denied' | 'unavailable' | 'unverified' | 'policy';
  constructor(reason: 'denied' | 'unavailable' | 'unverified' | 'policy', message: string) {
    super(message);
    this.name = 'TransportError';
    this.reason = reason;
  }
}

/**
 * Direct HTTPS on a LAN or an existing private network.
 *
 * This adapter adds policy, not connectivity: it refuses an origin outside the
 * allowlist and refuses a non-HTTPS origin. It deliberately does not touch TLS
 * material, because the client owns the trust anchor and an adapter must not be
 * able to replace it.
 */
export class DirectHttpsAdapter implements TransportAdapter {
  readonly name = 'direct-https';
  private current: AdapterStatus = { state: 'idle', endpoint: null, detail: 'not connected' };

  async connect(endpoint: string, policy: ConnectionPolicy): Promise<Connection> {
    this.current = { state: 'connecting', endpoint, detail: 'validating policy' };

    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      this.fail(endpoint, 'endpoint is not an absolute URL');
      throw new TransportError('policy', 'endpoint is not an absolute URL');
    }
    if (url.protocol !== 'https:') {
      this.fail(endpoint, 'endpoint is not https');
      throw new TransportError('policy', 'MLP/1 requires https; there is no plaintext fallback');
    }
    if (url.pathname !== '/' && url.pathname !== '') {
      this.fail(endpoint, 'endpoint is not an origin');
      throw new TransportError('policy', 'descriptor endpoint must be an origin');
    }

    const allowed = new Set(policy.allowedDestinations.map((value) => normalizeOrigin(value)));
    if (!allowed.has(url.origin)) {
      this.fail(endpoint, 'destination is not on the local allowlist');
      throw new TransportError('denied', 'destination is not approved by local policy');
    }

    this.current = { state: 'connected', endpoint: url.origin, detail: 'direct https' };
    return { endpoint: url.origin, state: 'connected', detail: 'direct https' };
  }

  status(): AdapterStatus {
    return this.current;
  }

  async disconnect(): Promise<void> {
    this.current = { state: 'closed', endpoint: this.current.endpoint, detail: 'disconnected' };
  }

  private fail(endpoint: string, detail: string): void {
    this.current = { state: 'failed', endpoint, detail };
  }
}

/**
 * A placeholder for a provisioning adapter such as doxx.net.
 *
 * It refuses everything, on purpose. §15 and §17 require that a claim of
 * compatibility be backed by recorded tests; until those exist, an adapter that
 * pretends to work would be worse than no adapter, because it would move
 * traffic over a path nobody has measured.
 */
export class UnverifiedProvisioningAdapter implements TransportAdapter {
  readonly name: string;
  private current: AdapterStatus = { state: 'idle', endpoint: null, detail: 'no adapter is configured' };

  constructor(name: string) {
    this.name = name;
  }

  async connect(endpoint: string, _policy: ConnectionPolicy): Promise<Connection> {
    this.current = { state: 'failed', endpoint, detail: 'unverified adapter' };
    throw new TransportError(
      'unverified',
      `${this.name} integration is proposed but not implemented or tested; see docs/doxx-pilot.md`,
    );
  }

  status(): AdapterStatus {
    return this.current;
  }

  async disconnect(): Promise<void> {
    this.current = { state: 'closed', endpoint: this.current.endpoint, detail: 'disconnected' };
  }

  async provision(): Promise<never> {
    throw new TransportError('unverified', 'provisioning is not implemented');
  }
}

export function normalizeOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:') throw new TransportError('policy', 'allowlist entries must be https origins');
  return url.origin;
}

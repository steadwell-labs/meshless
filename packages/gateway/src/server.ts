/**
 * HTTP binding (§5.1, §11.1).
 *
 * The adapter is deliberately dumb: it reads bytes, hands them to `Gateway`,
 * and writes back what it is told. Every policy decision lives above it. It
 * refuses redirects by never producing them, caps the request body, and will
 * not start without TLS 1.3 material.
 */

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type ServerOptions as HttpsOptions } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { Gateway, RawRequest } from './gateway.ts';

export interface ServerTls {
  key: string;
  cert: string;
  /** Additional trust anchors, for a private CA. */
  ca?: string | string[];
}

export interface ServerOptions {
  gateway: Gateway;
  host?: string;
  port?: number;
  tls: ServerTls;
  maxBodyBytes?: number;
}

export interface RunningServer {
  readonly server: import('node:http').Server;
  readonly origin: string;
  close(): Promise<void>;
}

const DEFAULT_MAX_BODY = 1024 * 1024;

export function createServer(options: ServerOptions): RunningServer {
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const tlsOptions: HttpsOptions = {
    key: options.tls.key,
    cert: options.tls.cert,
    ...(options.tls.ca === undefined ? {} : { ca: options.tls.ca }),
    // §5.1: TLS 1.3 only. There is no configuration knob to lower this.
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  };

  const handler = (request: IncomingMessage, response: ServerResponse): void => {
    void handleRequest(options.gateway, request, response, maxBody);
  };

  const server = createHttpsServer(tlsOptions, handler);
  server.requestTimeout = 60_000;
  server.headersTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  return {
    server,
    origin: `https://${options.host ?? '127.0.0.1'}:${options.port ?? 0}`,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

/** Bind and return the origin with the real port, which matters for port 0. */
export async function listen(running: RunningServer, host = '127.0.0.1', port = 0): Promise<RunningServer> {
  await new Promise<void>((resolve, reject) => {
    running.server.once('error', reject);
    running.server.listen(port, host, () => {
      running.server.off('error', reject);
      resolve();
    });
  });
  const address = running.server.address() as AddressInfo;
  return {
    server: running.server,
    origin: `https://${host}:${address.port}`,
    close: running.close,
  };
}

export function serve(options: ServerOptions & { host?: string; port?: number }): Promise<RunningServer> {
  const running = createServer(options);
  return listen(running, options.host ?? '127.0.0.1', options.port ?? 8443);
}

async function handleRequest(gateway: Gateway, request: IncomingMessage, response: ServerResponse, maxBody: number): Promise<void> {
  const chunks: Buffer[] = [];
  let size = 0;
  let aborted = false;

  try {
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      size += buffer.byteLength;
      if (size > maxBody) {
        aborted = true;
        break;
      }
      chunks.push(buffer);
    }

    if (aborted) {
      request.destroy();
      writeResponse(response, {
        status: 413,
        body: JSON.stringify({ error: { code: 'too_large', message: 'request body exceeds the provider limit' } }),
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
      return;
    }

    const headers: Record<string, string | undefined> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value[0] : value;
    }

    const url = request.url ?? '/';
    const path = url.split('?')[0] ?? '/';
    if (path !== url) {
      // §11.1: no query strings on baseline endpoints. Reject rather than
      // silently ignore, because a query would not be covered by the proof.
      writeResponse(response, {
        status: 400,
        body: JSON.stringify({ error: { code: 'invalid_request', message: 'query strings are not permitted' } }),
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
      return;
    }

    const raw: RawRequest = {
      method: request.method ?? 'GET',
      path,
      headers,
      body: Buffer.concat(chunks),
      remoteAddress: request.socket.remoteAddress ?? undefined,
    };

    const result = await gateway.handle(raw);
    writeResponse(response, result);
  } catch {
    if (!response.headersSent) {
      writeResponse(response, {
        status: 503,
        body: JSON.stringify({ error: { code: 'unavailable', message: 'provider could not complete the request' } }),
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
  }
}

function writeResponse(response: ServerResponse, result: { status: number; body: string; headers: Record<string, string> }): void {
  response.writeHead(result.status, { ...result.headers, 'content-length': Buffer.byteLength(result.body, 'utf8') });
  response.end(result.body);
}

/** Present for symmetry with `createServer`; the baseline profile is HTTPS only. */
export function createInsecureServerForLoopbackOnly(): never {
  throw new Error('MLP/1 requires TLS 1.3; there is no plaintext server mode');
}

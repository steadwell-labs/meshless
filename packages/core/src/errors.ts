/**
 * Errors.
 *
 * MLP/1 §13 fixes both the wire codes and the HTTP status for each. Keeping the
 * mapping in one table means a provider cannot invent a new code by accident,
 * and the conformance suite can assert on it.
 */

export type ErrorCode =
  | 'invalid_request'
  | 'invalid_proof'
  | 'invalid_grant'
  | 'denied'
  | 'revoked'
  | 'unknown_resource'
  | 'replay'
  | 'duplicate_request'
  | 'too_large'
  | 'quota_exceeded'
  | 'unavailable'
  | 'deadline_exceeded';

export const ERROR_STATUS: Readonly<Record<ErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  invalid_proof: 401,
  invalid_grant: 401,
  denied: 403,
  revoked: 403,
  unknown_resource: 404,
  replay: 409,
  duplicate_request: 409,
  too_large: 413,
  quota_exceeded: 429,
  unavailable: 503,
  deadline_exceeded: 504,
});

export class MlpError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  /** Safe to send to the caller. Never contains credentials or addresses. */
  readonly publicMessage: string;
  /** Internal detail for logs. Never sent over the wire. */
  readonly detail?: string;

  constructor(code: ErrorCode, publicMessage: string, detail?: string) {
    super(detail === undefined ? `${code}: ${publicMessage}` : `${code}: ${publicMessage} (${detail})`);
    this.name = 'MlpError';
    this.code = code;
    this.status = ERROR_STATUS[code];
    this.publicMessage = publicMessage;
    this.detail = detail;
  }

  toWire(requestId?: string): { error: { code: ErrorCode; message: string; request_id?: string } } {
    return {
      error: {
        code: this.code,
        message: this.publicMessage,
        ...(requestId === undefined ? {} : { request_id: requestId }),
      },
    };
  }
}

export function isMlpError(value: unknown): value is MlpError {
  return value instanceof MlpError;
}

/** Coerce anything thrown into an error that is safe to expose. */
export function asMlpError(value: unknown): MlpError {
  if (isMlpError(value)) return value;
  return new MlpError('invalid_request', 'request rejected', value instanceof Error ? value.message : String(value));
}

export function invalidRequest(detail: string): MlpError {
  return new MlpError('invalid_request', 'request is malformed or violates schema', detail);
}

export function invalidProof(detail: string): MlpError {
  return new MlpError('invalid_proof', 'proof could not be verified', detail);
}

export function invalidGrant(detail: string): MlpError {
  return new MlpError('invalid_grant', 'grant chain could not be verified', detail);
}

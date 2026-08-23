export class KeymeshError extends Error {
  readonly code: string;

  constructor(message: string, code: string, cause?: Error) {
    super(message);
    this.name = 'KeymeshError';
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

export class ValidationError extends KeymeshError {
  readonly field?: string;

  constructor(message: string, field?: string, cause?: Error) {
    super(message, 'VALIDATION_ERROR', cause);
    this.name = 'ValidationError';
    if (field !== undefined) {
      this.field = field;
    }
  }
}

export class CryptographyError extends KeymeshError {
  readonly operation: string;

  constructor(message: string, operation: string, cause?: Error) {
    super(message, 'CRYPTOGRAPHY_ERROR', cause);
    this.name = 'CryptographyError';
    this.operation = operation;
  }
}

export class NetworkError extends KeymeshError {
  readonly endpoint?: string;

  constructor(message: string, endpoint?: string, cause?: Error) {
    super(message, 'NETWORK_ERROR', cause);
    this.name = 'NetworkError';
    if (endpoint !== undefined) {
      this.endpoint = endpoint;
    }
  }
}

export class ProtocolError extends KeymeshError {
  readonly protocolState?: string;

  constructor(message: string, protocolState?: string, cause?: Error) {
    super(message, 'PROTOCOL_ERROR', cause);
    this.name = 'ProtocolError';
    if (protocolState !== undefined) {
      this.protocolState = protocolState;
    }
  }
}

export class NotFoundError extends KeymeshError {
  constructor(resource: string, identifier: string, cause?: Error) {
    super(`${resource} not found: ${identifier}`, 'NOT_FOUND', cause);
    this.name = 'NotFoundError';
  }
}

export class UnauthorizedError extends KeymeshError {
  constructor(message = 'Unauthorized', cause?: Error) {
    super(message, 'UNAUTHORIZED', cause);
    this.name = 'UnauthorizedError';
  }
}

export class TimeoutError extends KeymeshError {
  constructor(operation: string, timeoutMs: number, cause?: Error) {
    super(`${operation} timed out after ${timeoutMs}ms`, 'TIMEOUT', cause);
    this.name = 'TimeoutError';
  }
}

export function isKeymeshError(error: unknown): error is KeymeshError {
  return error instanceof KeymeshError;
}

export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}

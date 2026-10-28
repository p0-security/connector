export interface PublicError {
  publicMessage: string;
}

export class BaseError extends Error {
  override readonly cause: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
    this.name = "BaseError";
  }

  public toJSON(): Record<string, unknown> {
    const jsonData: Record<string, unknown> = {
      name: this.name,
      message: this.message,
      stack: this.stack,
    };

    if (this.cause) {
      jsonData.cause = this.serializeCause();
    }

    if ("type" in this) {
      jsonData.type = (this as { type: string }).type;
    }

    if ("publicMessage" in this) {
      jsonData.publicMessage = (
        this as { publicMessage: string }
      ).publicMessage;
    }

    return jsonData;
  }

  private serializeCause(): Record<string, unknown> {
    if (this.cause instanceof BaseError) {
      return this.cause.toJSON();
    } else if (this.cause instanceof Error) {
      return {
        message: this.cause.message,
        stack: this.cause.stack,
      };
    } else {
      return { message: String(this.cause) };
    }
  }
}

export class AuthError extends BaseError implements PublicError {
  readonly type = "auth";

  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "AuthError";
  }

  get publicMessage() {
    return "P0 could not properly identify you.";
  }
}

export class ProxyError extends BaseError implements PublicError {
  readonly type = "proxy";
  readonly service: string;

  constructor(service: string, message: string, cause: Error) {
    super(message, cause);
    this.service = service;
    this.name = "ProxyError";
  }

  public override toJSON(): Record<string, unknown> {
    const jsonData = super.toJSON();
    jsonData.service = this.service;
    return jsonData;
  }

  get publicMessage() {
    return `Error in service ${this.service}: ${this.message}`;
  }
}

export class ValidationError extends BaseError implements PublicError {
  readonly type = "validate";

  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "ValidationError";
  }

  get publicMessage() {
    return this.message;
  }
}

export type UpstreamError = ProxyError;

export const isPublicError = (error: unknown): error is PublicError =>
  error instanceof Error &&
  "publicMessage" in error &&
  typeof error.publicMessage === "string";

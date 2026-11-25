import type { RequestHandler } from "express";

import { asyncRequestHandler } from "../async.ts";
import { AuthError } from "../types/error.ts";

/**
 * Checks a request's bearer token. Resolves `true` to admit it; resolves
 * `false` or throws to refuse it.
 */
export type TokenVerifier = (token: string) => Promise<boolean>;

/**
 * Thrown by a `TokenVerifier` to refuse a token, with a fixed message that
 * names the failed check and never contains the token or any of its claims.
 * `bearerAuthzMiddleware` keeps this message as the cause of its `AuthError`.
 * Any other error a verifier throws becomes "Token verification failed", since
 * a library's message may quote the token.
 */
export class TokenRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenRefusal";
  }
}

/**
 * Names the check a verifier library's error reports: the name paired with the
 * first prefix its message starts with, or `undefined` if none does. Only the
 * name is returned, never any of the message, which may quote the token.
 */
export const failedCheck = (
  err: unknown,
  checks: readonly (readonly [prefix: string, check: string])[]
): string | undefined =>
  err instanceof Error
    ? checks.find(([prefix]) => err.message.startsWith(prefix))?.[1]
    : undefined;

/**
 * Admits a request whose `header` (lower case) is exactly `Bearer <token>`,
 * with a token that `handler` admits. Anything else throws an `AuthError`,
 * answered with a 403. Its cause, which the error handler logs, is the failed
 * header check or the verifier's `TokenRefusal`; for any other error the
 * verifier throws it says only "Token verification failed", and for a verifier
 * that resolves `false`, "Token refused". It never contains the token.
 */
export const bearerAuthzMiddleware = (
  handler: TokenVerifier,
  header = "authorization"
): RequestHandler =>
  asyncRequestHandler(async (req, _res, next) => {
    const value = req.headers[header];
    if (typeof value !== "string" || !value) {
      throw new AuthError("Unauthorized", new Error(`No ${header} header`));
    }
    const parts = value.split(" ");
    const [authenticationType, token] = parts;
    if (
      parts.length !== 2 ||
      !authenticationType ||
      !token ||
      authenticationType.toLowerCase() !== "bearer"
    ) {
      throw new AuthError(
        "Unauthorized",
        new Error(`The ${header} header is not a bearer token`)
      );
    }

    let admitted: boolean;
    try {
      admitted = await handler(token);
    } catch (err) {
      throw new AuthError(
        "Unauthorized",
        err instanceof TokenRefusal
          ? err
          : new Error("Token verification failed")
      );
    }
    if (!admitted) {
      throw new AuthError("Unauthorized", new Error("Token refused"));
    }
    next();
  });

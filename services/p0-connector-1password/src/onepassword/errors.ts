import { ConnectorError } from "@p0security/connector";

import { describeFailure, failureFacts } from "./failure.ts";

/** The SDK failures the connector words in its own copy. */
type SdkFailure = "auth_expired" | "rate_limited";

// The SDK's own error classes, by name. The SDK is loaded on first use, so
// its classes can't be imported for `instanceof`, and its errors don't set
// `name`, so `failureFacts` reads them as bare errors.
const SDK_FAILURES = new Map<string, SdkFailure>([
  ["AuthExpiredError", "auth_expired"],
  ["RateLimitExceededError", "rate_limited"],
]);

/** Which of the SDK's typed failures `error` is, if it is one. */
export const sdkFailureOf = (error: unknown): SdkFailure | undefined =>
  error instanceof Error ? SDK_FAILURES.get(error.constructor.name) : undefined;

/**
 * A failed SDK call as P0 shows it. The message is the connector's own: the
 * SDK's is a string from its Rust core, which nothing promises is free of
 * what the call carried. The payload holds `payload` and the failure's
 * {@link failureFacts}.
 */
export const toConnectorError = (
  error: unknown,
  payload: Record<string, string> = {}
): ConnectorError => {
  if (error instanceof ConnectorError) return error;
  const facts = { ...payload, ...failureFacts(error) };
  switch (sdkFailureOf(error)) {
    case "rate_limited":
      return new ConnectorError({
        type: "rate_limited",
        message:
          "1Password is rate limiting the account's service account. Try again in a few minutes.",
        payload: facts,
      });
    case "auth_expired":
      return new ConnectorError({
        type: "insufficient_privileges",
        message:
          "1Password no longer accepts the account's service account token. Store a current service account token in the token secret.",
        payload: facts,
      });
    default: {
      const described = describeFailure(error);
      return new ConnectorError({
        type: "unknown",
        message: `1Password failed the connector's call${described ? ` (${described})` : ""}.`,
        payload: facts,
      });
    }
  }
};

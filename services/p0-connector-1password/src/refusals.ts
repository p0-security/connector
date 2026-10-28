import { ConnectorError, type ConnectorErrorData } from "@p0security/connector";
import { z } from "zod";

/**
 * Why the connector refused a call, for the refusals P0 words in its own
 * copy. A refusal of that kind carries a `payload.reason` from this closed
 * set, so a new one is a change to the contract. Any other
 * `validation_error` carries no reason, and P0 passes it through with its
 * own message.
 *
 * - `domain_not_allowed`: the email's domain isn't one
 *   `DOMAIN_ALLOW_PATTERN` allows.
 * - `sharing_policy`: 1Password's item sharing policy doesn't allow the
 *   share: not with a person by email, or not for that long.
 */
export const ONEPASSWORD_REFUSAL_REASONS = [
  "domain_not_allowed",
  "sharing_policy",
] as const;

/** One of {@link ONEPASSWORD_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const onePasswordRefusalReason = z.enum(ONEPASSWORD_REFUSAL_REASONS);

export type OnePasswordRefusalReason = z.infer<typeof onePasswordRefusalReason>;

/**
 * A refusal P0 words in its own copy: a `validation_error` whose payload
 * carries `reason`. Every refusal with a reason is made here, so none can
 * carry one outside the set.
 */
export const refusal = ({
  reason,
  message,
  payload = {},
}: {
  reason: OnePasswordRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { ...payload, reason },
  });

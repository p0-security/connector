import { ConnectorError, type ConnectorErrorData } from "@p0security/connector";
import { z } from "zod";

/**
 * Why the connector refused a call, for the refusals P0 shows in its own
 * words. A refusal of that kind carries a `payload.reason` from this closed
 * set, so a new one is a change to the contract. Any other
 * `validation_error` carries no reason, and P0 passes it through with its
 * own message. Being rate limited is an error type, `rate_limited`, not a
 * reason.
 *
 * - `domain_not_allowed`: the email's domain isn't one
 *   `DOMAIN_ALLOW_PATTERN` allows.
 * - `domain_pattern_unusable`: the pattern is unset, blank or doesn't
 *   compile, so every email is refused.
 * - `own_member`: the member is the access token's own member, which the
 *   connector never changes.
 * - `member_changed`: the access token now belongs to another account, or,
 *   at a grant, the member's email or invite state is no longer what P0
 *   resolved.
 * - `base_role_ignored`: the member has custom roles, so LaunchDarkly
 *   ignores their base role, and a `base-role` grant would do nothing.
 */
export const LAUNCHDARKLY_REFUSAL_REASONS = [
  "base_role_ignored",
  "domain_not_allowed",
  "domain_pattern_unusable",
  "member_changed",
  "own_member",
] as const;

/** One of {@link LAUNCHDARKLY_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const launchDarklyRefusalReason = z.enum(LAUNCHDARKLY_REFUSAL_REASONS);

export type LaunchDarklyRefusalReason = z.infer<
  typeof launchDarklyRefusalReason
>;

/**
 * A refusal P0 shows in its own words: a `validation_error` whose payload
 * carries `reason`. Every refusal with a reason is made here, so none can
 * carry one outside the set.
 */
export const refusal = ({
  reason,
  message,
  payload = {},
}: {
  reason: LaunchDarklyRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    message,
    payload: { ...payload, reason },
    type: "validation_error",
  });

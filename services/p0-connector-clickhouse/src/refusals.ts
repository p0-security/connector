import { ConnectorError, type ConnectorErrorData } from "@p0security/connector";
import { z } from "zod";

/**
 * Why the connector refused a call, for the refusals P0 words in its own
 * copy. A refusal of that kind carries a `payload.reason` from this closed
 * set, so a new one is a change to the contract. Any other
 * `validation_error` carries no reason, and P0 passes it through with its
 * own message.
 *
 * - `ambiguous_member`: more than one member of the organization has the
 *   requestor's email, ignoring case.
 * - `domain_not_allowed`: the email's domain isn't one
 *   `DOMAIN_ALLOW_PATTERN` allows.
 * - `not_member`: no member of the organization has the requestor's email.
 * - `not_p0_role`: a call asked to change or delete a role whose name doesn't
 *   start with `p0_`. The framework refuses such a name before any primitive
 *   runs, so this is the primitives' own guard.
 */
export const CLICKHOUSE_REFUSAL_REASONS = [
  "ambiguous_member",
  "domain_not_allowed",
  "not_member",
  "not_p0_role",
] as const;

/** One of {@link CLICKHOUSE_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const clickhouseRefusalReason = z.enum(CLICKHOUSE_REFUSAL_REASONS);

export type ClickHouseRefusalReason = z.infer<typeof clickhouseRefusalReason>;

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
  reason: ClickHouseRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { ...payload, reason },
  });

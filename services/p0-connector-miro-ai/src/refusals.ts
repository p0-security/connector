import {
  ConnectorError,
  type ConnectorErrorData,
} from "@p0security/connector-core";
import { z } from "zod";

/**
 * Why the connector refused a call, for the refusals P0 shows in its own
 * words. A refusal of that kind carries a `payload.reason` from this closed
 * set, so a new one is a change to the contract. Any other
 * `validation_error` carries no reason, and P0 passes it through with its
 * own message. Being rate limited is an error type, `rate_limited`, not a
 * reason.
 *
 * The board access's grants and revokes raise these (spec section 4):
 *
 * - `not_in_team`: no member of the team has the requester's email. P0
 *   never invites, so it never spends a seat.
 * - `pending_invite`: the requester was invited to the team but hasn't
 *   created a Miro account yet.
 * - `member_changed`: the access token now belongs to another team, or the
 *   member P0 recorded no longer has the requester's email.
 * - `board_not_shareable`: the connector user isn't the board's owner or
 *   co-owner, so it can't share the board.
 */
export const MIRO_REFUSAL_REASONS = [
  "board_not_shareable",
  "member_changed",
  "not_in_team",
  "pending_invite",
] as const;

/** One of {@link MIRO_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const miroRefusalReason = z.enum(MIRO_REFUSAL_REASONS);

export type MiroRefusalReason = z.infer<typeof miroRefusalReason>;

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
  reason: MiroRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    message,
    payload: { ...payload, reason },
    type: "validation_error",
  });

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
 *   `ALLOWED_EMAIL_DOMAIN_PATTERN` allows.
 * - `domain_pattern_unusable`: the pattern is unset, blank or doesn't
 *   compile, so every email is refused.
 * - `duplicate_email`: more than one Harbor user has the email, ignoring
 *   ASCII case.
 * - `no_user`: at a grant, the email no longer belongs to the Harbor user P0
 *   resolved: no Harbor user has it, or it resolves to a different user id.
 *   Only a grant refuses with it: the `member` lister answers `[]` for no
 *   user, and P0 words that.
 * - `project_gone`: the project a call named doesn't exist on the instance,
 *   or no longer does. A revoke treats it as done.
 * - `admin_signin_expired`: the identity provider refused the Harbor admin
 *   credential's refresh token (`invalid_grant`): someone has to sign the
 *   admin account in again and store a new one.
 * - `admin_token_rejected`: Harbor answered 401 to the admin account's ID
 *   token: the token's audience isn't Harbor's OIDC client, no Harbor user
 *   has its subject and issuer, or Harbor doesn't sign users in with OIDC.
 * - `admin_not_harbor_admin`: Harbor answered 403 to the admin account: it
 *   isn't a Harbor system administrator.
 */
export const HARBOR_REFUSAL_REASONS = [
  "admin_not_harbor_admin",
  "admin_signin_expired",
  "admin_token_rejected",
  "domain_not_allowed",
  "domain_pattern_unusable",
  "duplicate_email",
  "no_user",
  "project_gone",
] as const;

/** One of {@link HARBOR_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const harborRefusalReason = z.enum(HARBOR_REFUSAL_REASONS);

export type HarborRefusalReason = z.infer<typeof harborRefusalReason>;

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
  reason: HarborRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { ...payload, reason },
  });

/**
 * The refusal for an email more than one Harbor user has, ignoring ASCII
 * case, in INT-231's words. `userIds` lists them, comma-joined since a
 * payload holds scalars, for the admin who removes one.
 */
export const duplicateEmail = ({
  host,
  email,
  users,
}: {
  host: string;
  email: string;
  users: readonly { userId: number }[];
}) =>
  refusal({
    reason: "duplicate_email",
    message: `More than one Harbor user on ${host} has the email ${email}. Ask a Harbor admin to remove the duplicate.`,
    payload: { host, userIds: users.map(({ userId }) => userId).join(",") },
  });

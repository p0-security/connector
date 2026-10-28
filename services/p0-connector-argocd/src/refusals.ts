// copy of services/p0-connector-harbor/src/refusals.ts, with Argo CD's
// reasons
import { ConnectorError, type ConnectorErrorData } from "@p0security/connector";
import { z } from "zod";

/**
 * Why the connector refused a call, for the refusals P0 words in its own
 * copy. A refusal of that kind carries a `payload.reason` from this closed
 * set, so a new one is a change to the contract. Any other
 * `validation_error` carries no reason, and P0 passes it through with its
 * own message.
 *
 * - `connector_role`: the role is the connector's own, `role:p0-connector`.
 *   The connector never changes its own privileges.
 * - `default_role`: the role is `policy.default`'s, which every user holds.
 * - `not_an_email`: the user isn't an email the connector writes a line for.
 * - `domain_not_allowed`: the email's domain isn't one
 *   `ALLOWED_EMAIL_DOMAIN_PATTERN` allows.
 * - `domain_pattern_unusable`: the pattern is unset, blank or doesn't
 *   compile, so every email is refused.
 * - `role_not_found`: no policy line names the role, and it isn't built in;
 *   or, for a project role, the project doesn't define it.
 * - `project_not_found`: the account can't see an AppProject by that name.
 * - `self_check_failed`: the `p0-connector` account may do something it
 *   never should, such as sync any Application, so the connector grants
 *   nothing until its privileges are cut back.
 * - `already_held`: the user holds the role already, through a line P0
 *   didn't write, a group, `policy.default` or a role that inherits it.
 * - `policy_not_loaded`: `argocd-rbac-cm` has a line Argo CD refuses, so
 *   Argo CD keeps enforcing the policy it had and a new line wouldn't take
 *   effect.
 *
 * Only a grant is refused with these, but for `domain_not_allowed` and
 * `domain_pattern_unusable`, which a lookup that names an email is refused
 * with too. A revoke is never refused with a reason.
 */
export const ARGOCD_REFUSAL_REASONS = [
  "connector_role",
  "default_role",
  "not_an_email",
  "domain_not_allowed",
  "domain_pattern_unusable",
  "role_not_found",
  "project_not_found",
  "self_check_failed",
  "already_held",
  "policy_not_loaded",
] as const;

/** One of {@link ARGOCD_REFUSAL_REASONS}, for P0 to parse a payload with. */
export const argoCdRefusalReason = z.enum(ARGOCD_REFUSAL_REASONS);

export type ArgoCdRefusalReason = z.infer<typeof argoCdRefusalReason>;

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
  reason: ArgoCdRefusalReason;
  message: string;
  payload?: ConnectorErrorData["payload"];
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { ...payload, reason },
  });

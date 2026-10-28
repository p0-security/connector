import { ConnectorError, type Logger } from "@p0security/connector";

import type { ConnectArgoCd } from "../../argocd/client.ts";
import type { Grant } from "../../argocd/policy.ts";
import { refusal } from "../../refusals.ts";
import { hostOf } from "../common.ts";
import { type InstancePolicy, grantLine, revokeLine } from "../lines.ts";
import type { ResourceSchema } from "./handler.ts";

/**
 * Refuses a global role the instance doesn't have: `policy.default`'s, which
 * every user holds, or one no line of the customer's names and that isn't
 * built in.
 */
const refuseMissing =
  (host: string, grant: Extract<Grant, { kind: "global" }>) =>
  ({ roles, defaultRole }: InstancePolicy) => {
    if (grant.role === defaultRole) {
      throw refusal({
        reason: "default_role",
        message: `${grant.role} is the default role on Argo CD at ${host}: every user holds it already.`,
        payload: { host, role: grant.role },
      });
    }
    if (!roles.global.includes(grant.role)) {
      throw refusal({
        reason: "role_not_found",
        message: `Argo CD at ${host} has no role ${grant.role}.`,
        payload: { host, role: grant.role },
      });
    }
  };

/**
 * `setPoliciesForUser`: P0 sends exactly one policy. Its role is a grant of
 * that role, which must be the request context's; `null` is a revoke of the
 * request context's role.
 */
export const setPolicies = async ({
  connect,
  logger,
  context,
  userId,
  policies,
}: {
  connect: ConnectArgoCd;
  logger: Logger;
  context: ResourceSchema["RequestContext"];
  userId: ResourceSchema["UserId"];
  policies: ResourceSchema["Policy"][];
}): Promise<void> => {
  const { requestId } = context;
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    // `unknown`, not `validation_error`: P0 sends exactly one policy, so
    // anything else is a P0 bug the requester can't correct.
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for an Argo CD global role, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  if (policy.role !== null && policy.role !== context.role) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to grant a role other than the request's.",
      payload: { requestId },
    });
  }
  const host = hostOf(context);
  const grant = { kind: "global", role: context.role } as const;
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({ requestId, host, role: context.role });
  const request = {
    connect,
    log,
    instance: context,
    email: userId,
    grant,
  };
  if (policy.role === null) {
    await revokeLine(request);
    return;
  }
  await grantLine(request, refuseMissing(host, grant));
};

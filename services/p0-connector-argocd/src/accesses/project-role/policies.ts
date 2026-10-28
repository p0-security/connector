import { ConnectorError, type Logger } from "@p0security/connector";

import type { ConnectArgoCd } from "../../argocd/client.ts";
import type { Grant } from "../../argocd/policy.ts";
import { refusal } from "../../refusals.ts";
import { hostOf } from "../common.ts";
import { type InstancePolicy, grantLine, revokeLine } from "../lines.ts";
import type { ResourceSchema } from "./handler.ts";

/**
 * Refuses a project role the instance doesn't have: a project the account
 * can't see, or a role the project doesn't define. P0 never creates either.
 */
const refuseMissing =
  (host: string, { project, role }: Extract<Grant, { kind: "project" }>) =>
  ({ roles }: InstancePolicy) => {
    const found = roles.projects.find(({ name }) => name === project);
    if (found === undefined) {
      throw refusal({
        reason: "project_not_found",
        message: `Argo CD at ${host} has no project ${project}.`,
        payload: { host, project },
      });
    }
    if (!found.roles.includes(role)) {
      throw refusal({
        reason: "role_not_found",
        message: `Project ${project} on Argo CD at ${host} has no role ${role}.`,
        payload: { host, project, role },
      });
    }
  };

/**
 * `setPoliciesForUser`: P0 sends exactly one policy, for the request
 * context's project. Its role is a grant of that role, which must be the
 * request context's; `null` is a revoke of the request context's role.
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
  const { requestId, project, role } = context;
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    // `unknown`, not `validation_error`: P0 sends exactly one policy, so
    // anything else is a P0 bug the requester can't correct.
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for an Argo CD project role, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  if (
    policy.project !== project ||
    (policy.role !== null && policy.role !== role)
  ) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to set a project role other than the request's.",
      payload: { requestId },
    });
  }
  const host = hostOf(context);
  const grant = { kind: "project", project, role } as const;
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({ requestId, host, project, role });
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

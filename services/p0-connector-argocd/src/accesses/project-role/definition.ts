import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { isProjectName, isProjectRole } from "../../argocd/policy.ts";
import { instance } from "../../instance.ts";
import { email, listerResponse, userBody, userId } from "../common.ts";

/**
 * An AppProject's name, a Kubernetes object name: dot-separated parts of
 * lowercase letters, digits and inner hyphens, at most 253.
 */
export const projectName = z
  .string()
  .max(253, { error: "must be an Argo CD project name", abort: true })
  .refine(isProjectName, "must be an Argo CD project name");

/**
 * A role an AppProject defines, by its own name (`deployer`, not
 * `proj:payments:deployer`): letters, digits, `-` and `_`, starting and
 * ending with a letter or a digit, at most 253.
 */
export const projectRole = z
  .string()
  .max(253, { error: "must be an Argo CD project role name", abort: true })
  .refine(isProjectRole, "must be an Argo CD project role name");

// The role to leave the user with on the project. `null` means P0's grant of
// the request's role is over, which is a revoke: the connector removes the
// line for the role the request context names.
const policy = z.object({ project: projectName, role: projectRole.nullable() });

// `list` gets no request context, so every query carries the instance, as
// its `context`. `project` lists the AppProjects the account can see, or
// with a `project`, answers `[]` or that one project. `role` lists the roles
// one project defines, or with a `role`, `[]` or that one role. `held`
// answers whether the user with `email` holds the project's role already,
// `[]` or one row, through any policy line, the role's groups,
// `policy.default` or inheritance: P0's check for an existing grant.
const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("project"),
    context: instance,
    project: projectName.optional(),
  }),
  z.object({
    type: z.literal("role"),
    context: instance,
    project: projectName,
    role: projectRole.optional(),
  }),
  z.object({
    type: z.literal("held"),
    context: instance,
    email,
    project: projectName,
    role: projectRole,
  }),
]);

// What every user and policy call needs besides the user and the policies:
// the instance, and the project role this request is for. A revoke's policy
// role is `null`, so the request context is what names the line it
// removes. A grant names the project and the role in both, and they must
// agree.
const requestContext = instance.extend({
  requestId: z.string(),
  project: projectName,
  role: projectRole,
});

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

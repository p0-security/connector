import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

const userBody = z.string().min(1);
const userId = z.string().min(1);

/** GitLab access levels of the roles that a grant can give. Owner is left out
 * on purpose. */
export const GitlabRoleAccessLevels = {
  guest: 10,
  reporter: 20,
  developer: 30,
  maintainer: 40,
} as const;

const role = z.enum(
  Object.keys(GitlabRoleAccessLevels) as [
    keyof typeof GitlabRoleAccessLevels,
    ...(keyof typeof GitlabRoleAccessLevels)[],
  ]
);

// The control plane merges every open request into this one policy, with one
// role per project. It sends no memberships when it revokes the last request.
const policy = z.object({
  memberships: z.array(
    z.object({
      /** Full path, e.g. "my-group/my-project" */
      project: z.string().min(1),
      role,
    })
  ),
});

/** Where the admin token is stored. The secret value is the token. */
const adminToken = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    adminTokenSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    adminTokenSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const group = {
  /** Id or full path of the top-level group that owns the service accounts */
  groupId: z.string().min(1),
  secrets: adminToken,
};

// "policy" lists "<project>:<role>" for every project of the group.
const listerQuery = z.object({
  type: z.literal("policy"),
  context: z.object(group),
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

const requestContext = z.object({
  requestId: z.string(),
  ...group,
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

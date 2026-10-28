import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { atlasProjectRoleNames } from "../../atlas/roles.ts";

const userBody = z.string().min(1);
const userId = z.string().min(1);

// The control plane merges every open request's roles into this one policy.
// It sends no roles when it revokes the last request.
const policy = z.object({
  roles: z.array(z.enum(atlasProjectRoleNames)),
});

/** Where the admin service account's client secret is stored. The secret value
 * is the client secret itself. */
const clientSecret = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    clientSecretSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    clientSecretSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const project = {
  // Atlas project IDs are 24 hexadecimal digits.
  atlasProjectId: z.string().regex(/^[0-9a-f]{24}$/),
  clientId: z.string().min(1),
  secrets: clientSecret,
};

const listerQuery = z.object({
  type: z.literal("role"),
  context: z.object(project),
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
  ...project,
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

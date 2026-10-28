import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { AGENT_KEY_PATTERN } from "../../servicenow/client.ts";

const userBody = z.string().regex(AGENT_KEY_PATTERN);
// A ServiceNow sys_id
const userId = z.string().regex(/^[0-9a-f]{32}$/);

// The name of one ServiceNow role
const policy = z.string().min(1);

/** Where the install secret is. Its value is the JSON in `InstallSecret`. */
const installSecret = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    installSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    installSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const instance = {
  // The connector sends client secrets to this host only.
  domain: z.string().regex(/^[a-z0-9-]+\.service-now\.com$/i),
  provisionerClientId: z.string().min(1),
  jwtClientId: z.string().min(1),
  keyId: z.string().min(1),
  secrets: installSecret,
};

const listerQuery = z.object({
  type: z.literal("role"),
  context: z.object(instance),
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
  // The secret that holds the session's ServiceNow token
  tokenSecretName: z.string().min(1),
  ...instance,
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

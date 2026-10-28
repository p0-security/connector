import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { AGENT_KEY_PATTERN } from "../../salesforce/facade.ts";

const userBody = z.string().regex(AGENT_KEY_PATTERN);
// A Salesforce user ID
const userId = z.string().regex(/^005[A-Za-z0-9]{12}([A-Za-z0-9]{3})?$/);

// The name of one grantable permission set
const policy = z.string().min(1);

/** Where the provisioner app's consumer secret is stored. The secret value is
 * the consumer secret itself. */
const consumerSecret = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    consumerSecretSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    consumerSecretSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const org = {
  // The connector sends the consumer secret to this host only.
  domain: z.string().regex(/^[a-z0-9.-]+\.my\.salesforce\.com$/i),
  consumerKey: z.string().min(1),
  secrets: consumerSecret,
};

const listerQuery = z.object({
  type: z.literal("permission-set"),
  context: z.object(org),
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
  ...org,
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

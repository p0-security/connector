import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { pagerdutyRegions } from "../../pagerduty/regions.ts";

const userBody = z.string().min(1);
const userId = z.string().min(1);

// The control plane merges every open request's scopes into this one policy.
// It sends no scopes when it revokes the last request.
const policy = z.object({
  scopes: z.array(z.string().min(1)),
});

// The subdomain goes into a space-separated scope list.
const subdomain = z.string().regex(/^[a-z0-9-]+$/);

/** Where the Scoped OAuth app's client secret is stored. The secret value is
 * the client secret itself. */
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

const account = {
  region: z.enum(pagerdutyRegions),
  subdomain,
  clientId: z.string().min(1),
  secrets: clientSecret,
};

const listerQuery = z.object({
  type: z.literal("scope"),
  context: z.object(account),
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
  ...account,
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

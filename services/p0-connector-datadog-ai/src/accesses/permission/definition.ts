import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

const userBody = z.string().min(1);
const userId = z.string().min(1);

// The control plane merges every open request's scopes into this one policy.
// It sends no scopes when it revokes the last request.
const policy = z.object({
  scopes: z.array(z.string().min(1)),
});

// Datadog serves each site from its own API host, `api.<site>`. The list is
// closed so that a request context cannot send the admin keys to another host.
const site = z.enum([
  "datadoghq.com",
  "us3.datadoghq.com",
  "us5.datadoghq.com",
  "datadoghq.eu",
  "ap1.datadoghq.com",
  "ap2.datadoghq.com",
  "ddog-gov.com",
]);

/** Where the admin API key and application key are stored. The secret value is
 * JSON: `{ "apiKey": "...", "appKey": "..." }`. */
const adminKeys = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    adminKeysSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    adminKeysSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const organization = {
  site,
  serviceAccountId: z.string().min(1),
  secrets: adminKeys,
};

const listerQuery = z.object({
  type: z.literal("scope"),
  context: z.object(organization),
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
  ...organization,
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

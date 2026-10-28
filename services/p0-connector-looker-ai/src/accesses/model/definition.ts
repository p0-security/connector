import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// The grant's secret name, as both the user body and the user id. The grant's
// Looker service account is named after the secret, and every call finds the
// account again by that name.
//
// The shape is a Google Secret Manager secret id, so that the value can only
// name a secret in the request's own project.
const secretName = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,255}$/, "must be a Google Secret Manager secret id");

const userBody = secretName;
const userId = secretName;

export const Levels = ["read", "edit"] as const;

export type Level = (typeof Levels)[number];

// One model at one level, which becomes the account's only role. `null` is no
// role: the control plane sends it when it revokes the grant.
const policy = z
  .object({
    model: z.string().min(1),
    level: z.enum(Levels),
  })
  .nullable();

// Looker (Google Cloud core) serves each instance from its own `looker.app`
// host. The pattern is closed so that a request context cannot send the Admin
// key to another host.
const baseUrl = z
  .string()
  .regex(
    /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*\.looker\.app$/,
    "must be https://<instance>.looker.app"
  );

/** Where the Looker Admin API key is stored. The secret value is JSON:
 * `{ "client_id": "...", "client_secret": "..." }`. The connector writes each
 * grant's secret to the same project. */
const adminKey = z.object({
  manager: z.literal("gcp"),
  adminKeySecretId: z.string().min(1),
  projectId: z.string().min(1),
});

/** What the connector needs to reach one Looker instance: its URL, and where
 * its Admin key is. */
export const instanceContext = z.object({
  baseUrl,
  secrets: adminKey,
});

export type InstanceContext = z.infer<typeof instanceContext>;

// The folder the customer picked at install for content that agents save, if
// any. An edit grant gets edit access on it. The id goes into a URL path, so
// it may not hold a `.` or a `/`.
export const contentFolderId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,64}$/, "must be a Looker folder id");

const listerQuery = z.object({
  type: z.literal("model"),
  context: instanceContext,
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

const requestContext = instanceContext.extend({
  requestId: z.string(),
  contentFolderId: contentFolderId.optional(),
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

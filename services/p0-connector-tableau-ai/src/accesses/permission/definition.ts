import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

const userBody = z.string().min(1);
const userId = z.string().min(1);

/** An access level on one project, written `<level>:<project id>`, e.g.
 * `read:1f2f3e4e-5d6d-7c8c-9b0b-1a2a3f4f5e6e`. */
export const PROJECT_GRANT_PATTERN = /^(read|write):([^:]+)$/;

// The control plane merges every open request's project grants into this one
// policy. It sends no grants when it revokes the last request.
const policy = z.object({
  grants: z.array(z.string().regex(PROJECT_GRANT_PATTERN)),
});

// Only Tableau Cloud pod hosts, so that a request context cannot send a JWT
// signed with the admin secret to another host.
const server = z.string().regex(/^https:\/\/[a-z0-9-]+\.online\.tableau\.com$/);

/** Where the admin connected app's secret is stored. The secret value is JSON:
 * `{ "clientId": "...", "secretId": "...", "secret": "..." }`. */
const adminApp = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    adminAppSecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    adminAppSecretId: z.string(),
    projectId: z.string(),
  }),
]);

const site = {
  server,
  /** The site's content URL, as in `/#/site/<contentUrl>/` */
  contentUrl: z.string().min(1),
  /** Site administrator that the admin connected app signs in as */
  adminUser: z.email(),
  /** Mailbox that agent user names extend with `+<suffix>` */
  agentMailbox: z.email(),
  secrets: adminApp,
};

const listerQuery = z.object({
  type: z.literal("project"),
  context: z.object(site),
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
  ...site,
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

import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// The org becomes a URL path segment, so nothing that could change the URL
// gets in: no `/`, and no dot segment.
const org = z
  .string()
  .regex(
    /^[a-z0-9][a-z0-9_-]{1,254}$/,
    "must be a Docker Hub organization name"
  );

const email = z.email();

/** The org roles P0 sets, lowest first. Docker Hub takes them lower-case. */
export const coreRole = z.enum(["member", "editor", "owner"]);

export type CoreRole = z.infer<typeof coreRole>;

// Where the organization access token is, in the customer's own secret
// manager. A pointer, never the token: the connector reads it itself.
const tokenSecret = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    secretId: z.string().min(1),
    region: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    secretId: z.string().min(1),
    projectId: z.string().min(1),
  }),
]);

export type TokenSecret = z.infer<typeof tokenSecret>;

/** What the connector needs to act on one Docker Hub organization. */
export const orgCredentials = z.object({ org, tokenSecret });

export type OrgCredentials = z.infer<typeof orgCredentials>;

// Someone who was already in the org when they asked, as P0 recorded them
// after approval. The uuid tells whether the username still names the same
// account. P0 refuses custom-role holders, so the prior role is a core role.
const standingMember = z.object({
  username: z.string().min(1),
  uuid: z.string().min(1),
  priorRole: coreRole,
});

export type StandingMember = z.infer<typeof standingMember>;

// The requestor's P0 email is the only identity the connector takes.
const userBody = email;
const userId = email;

// The role to leave the user with. `null` takes back what P0 gave. Both this
// and `priorRole` are closed, so the connector only ever sets a core role.
const policy = z.object({ role: coreRole.nullable() });

const requestContext = orgCredentials.extend({
  requestId: z.string(),
  // `null` for someone P0 invites.
  standingMember: standingMember.nullable(),
  // P0 finished granting this request. Only then may a revoke remove a member.
  grantCompleted: z.boolean(),
});

// `list` gets no request context, so each query carries the credentials. Each
// answers for one email: `member` with `{ key: <username>, value: <uuid>,
// group: <role> }`, and `invite` with `{ key: <invite id>, value: <role> }`.
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("member"), context: orgCredentials, email }),
  z.object({ type: z.literal("invite"), context: orgCredentials, email }),
]);

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

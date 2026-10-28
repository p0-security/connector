import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

/**
 * Harbor's five project roles, under Harbor's own names. The list is closed,
 * so a role outside it fails to parse instead of reaching Harbor.
 */
export const harborRole = z.enum([
  "projectAdmin",
  "maintainer",
  "developer",
  "guest",
  "limitedGuest",
]);

export type HarborRole = z.infer<typeof harborRole>;

/**
 * A pointer to the instance's Harbor admin credential (admin-credential.ts)
 * in the customer's own secret manager, under whatever name they chose. P0
 * never holds the credential: the connector reads it itself.
 *
 * On GCP, `secretId` is the secret's bare name. A full resource name
 * (`projects/<project>/secrets/<name>`) would be read as it stands, whatever
 * `projectId` says, so it is refused. On AWS, `secretId` may be a partial
 * ARN, which is how a secret in another account is named.
 *
 * `projectId` and `region` are held to their own shapes, because each becomes
 * part of the address the read is sent to: the project is a segment of the
 * request's path, and the region is a label of the endpoint's host. A project
 * id is 6 to 30 lowercase letters, digits and hyphens, starting with a letter
 * and not ending in a hyphen. A legacy id with a domain in it
 * (`example.com:project`) is refused.
 */
export const secretPointer = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("gcp"),
    projectId: z
      .string()
      .regex(
        /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/,
        "must be a Google Cloud project id"
      ),
    secretId: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,255}$/, "must be a Secret Manager secret name"),
  }),
  z.object({
    manager: z.literal("aws"),
    region: z.string().regex(/^[a-z0-9-]+$/, "must be an AWS region"),
    secretId: z.string().min(1),
  }),
]);

export type SecretPointer = z.infer<typeof secretPointer>;

const URL_ERROR = "must be https://<host>[:<port>]";

// The instance's origin: `https://<host>`, with a port when it has one. Every
// call sends the admin user's ID token to it, so anything but https is refused
// here, before a call is made. Harbor isn't served under a path, so a path, a
// query or a fragment is refused, not dropped. So is a username or password:
// `fetch` rejects such a URL, with an error that quotes it, password
// included.
//
// What parses comes back as the URL's origin, so every caller gets the one
// spelling, with no trailing slash, whatever P0 sent. `z.url()` goes first
// because `new URL` throws on a value it can't parse, and that error carries
// the value.
const url = z.url({ error: URL_ERROR }).transform((value, ctx) => {
  const { protocol, username, password, pathname, search, hash, origin } =
    new URL(value);
  const isBareOrigin =
    protocol === "https:" &&
    username === "" &&
    password === "" &&
    pathname === "/" &&
    search === "" &&
    hash === "";
  if (!isBareOrigin) {
    ctx.addIssue({ code: "custom", message: URL_ERROR });
    return z.NEVER;
  }
  return origin;
});

/**
 * Where a Harbor instance is, and where its admin credential lives. Every
 * list query carries one as its `context`, both accesses' request contexts
 * extend it, and it is what install validation takes.
 */
export const instance = z.object({ url, secret: secretPointer });

export type Instance = z.infer<typeof instance>;

/**
 * The instance's host, which stands for it in messages: the connector knows
 * an instance only by its URL, not by P0's id for it.
 */
export const hostOf = ({ url }: Pick<Instance, "url">) => new URL(url).host;

// Harbor's own rule for a project name (`validProjectName` in its
// src/pkg/project/manager.go, the same at v2.12.0 and v2.14.0): lowercase
// letters and digits, with single `.`, `_` or `-` characters between them, at
// most 255 characters. A name becomes a URL path segment, and the rule leaves
// no room for a `/`, or for a `.` or `..` that would be resolved away.
//
// The length check stops the parse, so the pattern never runs over an
// over-long name: on one of a few megabytes it overflows the stack.
const project = z
  .string()
  .max(255, { error: "must be a Harbor project name", abort: true })
  .regex(/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/, "must be a Harbor project name");

// Harbor's `user_id`, the numeric id behind a username, as a decimal string:
// the framework's user id is a string.
//
// Harbor's JSON carries the id as a number, so the string has to be one that
// `Number` reads exactly and `String` writes back unchanged: a safe integer
// with no leading zeros.
export const userId = z
  .string()
  .regex(/^[1-9][0-9]{0,15}$/, {
    error: "must be a Harbor user id",
    abort: true,
  })
  .refine((id) => Number.isSafeInteger(Number(id)), "must be a Harbor user id");

// The principal's email, as P0 holds it. Not `z.email()` on purpose: the
// connector decides which emails it accepts, against its own domain
// allowlist, and refuses the rest with a message the requestor reads. Parsing
// the shape here would turn that refusal into a bad request.
export const email = z.string().min(1);

// The Harbor user to act on. `instanceId` is the id of the instance's install
// item in P0, and it is there for P0 alone: P0 groups a user's open requests
// by this body, and locks on it, and the same user id can exist on two
// instances. The connector ignores it.
export const userBody = z.object({
  instanceId: z.string().min(1),
  userId,
});

// The direct role to leave the user with on one project. `null` means no P0
// grant is open on the project any more, which is a revoke, and a revoke only
// ever lowers access. The connector restores the request context's
// `priorRole` only when it ranks below the role the member holds now, and
// leaves the member alone otherwise. When `priorRole` is `null` it removes
// the member.
const policy = z.object({
  project,
  role: harborRole.nullable(),
});

// `list` gets no request context, so every query carries the instance, as its
// `context`. A lookup's own fields sit beside it. `member` and `direct-role`
// aren't listings, and return `[]` or one item, which is how P0 reads without
// a read verb in the framework. `project` lists the instance's projects by
// name. `member` reads the Harbor user behind an email,
// `{ key: <user id>, value: <username> }`. `direct-role` reads the role one
// user holds directly on one project, `{ key: <role>, value: <role> }`, for
// the prior role and the check for an existing grant. With a `project`, the
// `project` query asks about that one project only, and answers `[]` or its
// one row (A18): P0's check that a requested project exists needn't page
// every project.
const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("project"),
    context: instance,
    project: project.optional(),
  }),
  z.object({ type: z.literal("member"), context: instance, email }),
  z.object({
    type: z.literal("direct-role"),
    context: instance,
    project,
    userId,
  }),
]);

export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

// What every user and policy call needs besides the user and the policies.
// `email` is the principal's email: `setPoliciesForUser` gets a user id and
// a user body that names the user by id, so the email travels here.
//
// `priorRole` is the direct role the user held on the project before P0
// granted, or `null` when they held none. It is required: a context that lost
// it must fail to parse, not read as "held none" and remove the member.
//
// A revoke skips the checks a grant runs on the email, so what it restores is
// bounded: without a bound, a tampered P0 could use one to raise any member
// to any role. On a `null` policy role the connector restores `priorRole`
// only when it ranks below the role the member holds now, and leaves the
// member alone otherwise. With a `null` `priorRole` it removes the member. A
// grant only raises a role, so a true prior role is always lower.
const requestContext = instance.extend({
  requestId: z.string(),
  email,
  priorRole: harborRole.nullable(),
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

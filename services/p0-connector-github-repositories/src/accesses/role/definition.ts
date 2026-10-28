import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// A pointer to the customer app's private key in the customer's own AWS
// Secrets Manager, under whatever name they chose. P0 never holds the key: the connector reads
// it itself on every call.
const privateKey = z.object({
  manager: z.literal("aws"),
  secretId: z.string().min(1),
  region: z.string().min(1),
});

export type PrivateKeyPointer = z.infer<typeof privateKey>;

// GitHub's naming rules, checked up front so a value can't change which URL a
// call reaches: each one becomes a path segment, and `.` or `..` would be
// resolved away, so a stray `/` or dot segment fails here instead.

// An organization name: letters, digits and hyphens, not starting with a
// hyphen, at most 39 characters.
const org = z
  .string()
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/,
    "must be a GitHub organization name"
  );

// A user login follows the same rule, plus the underscore that Enterprise
// Managed Users carry before their enterprise's short code (`octocat_acme`).
const login = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$/, "must be a GitHub login");

// A repository's bare name, without its owner: letters, digits, `.`, `_` and
// `-`, at most 100 characters, and never `.` or `..`.
const repo = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,100}$/, "must be a GitHub repository name")
  .refine(
    (name) => name !== "." && name !== "..",
    "must be a GitHub repository name"
  );

// The GitHub user id: the numeric id behind a login, as a string. Unlike the
// login it never changes, so a renamed account is still the one P0 granted to.
//
// GitHub's JSON ids are parsed as JavaScript numbers, and the connector matches
// one against this string, so it has to be a safe integer, written the way
// `String` writes it back: no leading zeros.
const githubUserId = z
  .string()
  .regex(/^[1-9][0-9]{0,15}$/, "must be a GitHub user id")
  .refine((id) => Number.isSafeInteger(Number(id)), "must be a GitHub user id");

/** What the connector needs to act as the customer app on one org. There is
 * no installation id: the connector looks it up from the org on every call. */
export const appCredentials = z.object({
  org,
  appId: z.string().min(1),
  privateKey,
});

export type AppCredentials = z.infer<typeof appCredentials>;

// The org member's GitHub login, as both the user body and the user id. A
// login can't carry a P0 marker, so `validation` has nothing to check it
// against.
const userBody = login;
const userId = login;

// The direct collaborator role to leave the user with on one repository. The
// role is in the form PUT accepts: `pull`, `triage`, `triage_plus`, `push`,
// `maintain`, `admin`, or a custom role's name. `null` is no direct role at
// all. A grant sends the requested role, and a revoke the role the user held
// before the grant, so `null` when they had none.
const policy = z.object({
  repo,
  role: z.string().min(1).nullable(),
});

// `list` gets no request context, so every query carries the credentials, as
// its `context`. A lookup's own fields sit beside it. `direct-role` and
// `account` aren't listings, and return `[]` or one item, which is how P0
// reads without a read verb in the framework. `direct-role` reads one user's
// direct role on one repo, for the prior role and the check for an existing
// grant. `account` reads the GitHub user id behind a login,
// `{ key: <id>, value: <login> }`, for the request context's `githubUserId`.
// `repository-id` reads the id behind a repository's name,
// `{ key: <id>, value: <name> }`, so P0 can tell two requests are for one
// repository after it's renamed.
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("repository"), context: appCredentials }),
  z.object({ type: z.literal("role"), context: appCredentials }),
  z.object({
    type: z.literal("direct-role"),
    context: appCredentials,
    repo,
    login,
  }),
  z.object({
    type: z.literal("member"),
    context: appCredentials,
    email: z.string().min(1),
  }),
  z.object({ type: z.literal("account"), context: appCredentials, login }),
  z.object({
    type: z.literal("repository-id"),
    context: appCredentials,
    repo,
  }),
]);

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

// What every user and policy call needs besides the user id and the policy:
// the app's credentials, and the GitHub user id behind the login. The user id
// is a login, which its owner can change, and the role moves with the account,
// so the connector looks the account up by its GitHub user id and acts on the
// login it has now.
const requestContext = appCredentials.extend({
  requestId: z.string(),
  githubUserId,
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

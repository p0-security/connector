import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// A Google Secret Manager secret, by its ID or by its resource name,
// `projects/<project>/secrets/<id>`. There's no `/versions/` suffix: the
// connector always reads the latest version.
const GCP_SECRET_REF =
  /^(?:projects\/([^/]+)\/secrets\/)?[A-Za-z0-9_-]{1,255}$/;

// A pointer to the customer app's private key in the customer's own vault,
// under whatever name they chose. P0 never holds the key: the connector reads
// it itself on every call.
//
// Google's client reads a resource name as it is, whatever `projectId` says,
// so a resource name has to be in the pointer's own project.
const privateKey = z
  .discriminatedUnion("manager", [
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
  ])
  .refine(
    (pointer) => {
      if (pointer.manager !== "gcp") return true;
      const match = GCP_SECRET_REF.exec(pointer.secretId);
      return (
        match !== null && (match[1] ?? pointer.projectId) === pointer.projectId
      );
    },
    {
      message:
        "must be a Google Secret Manager secret's ID, or its resource name in projectId's project",
      path: ["secretId"],
    }
  );

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
export const login = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$/, "must be a GitHub login");

// A repository's bare name, without its owner: letters, digits, `.`, `_` and
// `-`, at most 100 characters, and never `.` or `..`.
export const repo = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,100}$/, "must be a GitHub repository name")
  .refine(
    (name) => name !== "." && name !== "..",
    "must be a GitHub repository name"
  );

// One of GitHub's numeric ids, as a string. Unlike a name it never changes,
// so a renamed account or team is still the one P0 granted to.
//
// GitHub's JSON ids are parsed as JavaScript numbers, and the connector matches
// one against this string, so it has to be a safe integer, written the way
// `String` writes it back: no leading zeros.
export const newGitHubId = (message: string) =>
  z
    .string()
    .regex(/^[1-9][0-9]{0,15}$/, message)
    .refine((id) => Number.isSafeInteger(Number(id)), message);

// The GitHub user id: the id behind a login.
const githubUserId = newGitHubId("must be a GitHub user id");

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
export const userBody = login;
export const userId = login;

export const listerResponse = z
  .object({ key: z.string(), value: z.string(), group: z.string().optional() })
  .array();

// What every user and policy call needs besides the user id and the policy:
// the app's credentials, and the GitHub user id behind the login. The user id
// is a login, which its owner can change, and access moves with the account,
// so the connector looks the account up by its GitHub user id and acts on the
// login it has now.
export const requestContext = appCredentials.extend({
  requestId: z.string(),
  githubUserId,
});

export type RequestContext = z.infer<typeof requestContext>;

// The lookups every access's lister answers, since each finds the requestor
// the same way. `list` gets no request context, so a query carries the
// credentials, as its `context`, with its own fields beside it. Neither is a
// listing: each returns `[]` or one item, which is how P0 reads without a read
// verb in the framework. `member` reads the login of the org member with a
// verified-domain email. `account` reads the GitHub user id behind a login,
// `{ key: <id>, value: <login> }`, for the request context's `githubUserId`.
export const userQueries = [
  z.object({
    type: z.literal("member"),
    context: appCredentials,
    email: z.string().min(1),
  }),
  z.object({ type: z.literal("account"), context: appCredentials, login }),
] as const;

export type UserQuery = z.infer<(typeof userQueries)[number]>;

type AccessSchemas = Parameters<typeof newZodResourceRootParsers>[0];

/**
 * Builds the parsers for an access. Every access shares the same users and
 * request context, so an access supplies only its own policy and the queries
 * its lister answers, which should include {@link userQueries}.
 */
export const newAccessSpec = <
  PolicySchema extends AccessSchemas["policy"],
  ListerQuerySchema extends AccessSchemas["listerQuery"],
>(
  policy: PolicySchema,
  listerQuery: ListerQuerySchema
) =>
  newZodResourceRootParsers({
    userBody,
    userId,
    policy,
    listerQuery,
    listerResponse,
    requestContext,
  });

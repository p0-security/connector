import { z } from "zod";

// copy of `secretPointer` in services/p0-connector-harbor/src/accesses/project-role/definition.ts
/**
 * A pointer to the connector's Argo CD API token in the customer's own secret
 * manager, under whatever name they chose. P0 never holds the token: the
 * connector reads it itself.
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
const secretPointer = z.discriminatedUnion("manager", [
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

// copy of `url` in services/p0-connector-harbor/src/accesses/project-role/definition.ts
//
// The instance's origin: `https://<host>`, with a port when it has one. Every
// call sends the API token to it, so anything but https is refused here,
// before a call is made. A path, a query or a fragment is refused, not
// dropped, so an instance served under a path (Argo CD's `server.rootpath`)
// isn't supported. So is a username or password: `fetch` rejects such a URL,
// with an error that quotes it, password included.
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

// Kubernetes' rule for most resource names (a DNS-1123 subdomain), which
// Argo CD holds Applications and AppProjects to: lowercase letters, digits,
// `-` and `.`, starting and ending with a letter or a digit, with no two dots
// in a row, at most 253 characters. It leaves no room for a `/`, a `?` or a
// `..`, so a name is safe in an API path or query.
const SUBDOMAIN =
  /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$/;
const SUBDOMAIN_MAX = 253;

const MANAGING_APP_ERROR = "must be <project>/<application>";

/**
 * The Application that manages `argocd-rbac-cm`, as `<project>/<app>`. The
 * connector writes its policy key through this Application's resource-patch
 * endpoint.
 *
 * The length check stops the parse, so the pattern never runs over an
 * over-long value.
 */
const managingApp = z
  .string()
  .max(SUBDOMAIN_MAX * 2 + 1, { error: MANAGING_APP_ERROR, abort: true })
  .refine((value) => {
    const parts = value.split("/");
    return (
      parts.length === 2 &&
      parts.every(
        (part) => part.length <= SUBDOMAIN_MAX && SUBDOMAIN.test(part)
      )
    );
  }, MANAGING_APP_ERROR);

/**
 * The namespace `argocd-rbac-cm` lives in: a Kubernetes namespace, which is a
 * DNS-1123 label (no dots, at most 63 characters). Argo CD installs into
 * `argocd` unless someone chose otherwise, so that is the default.
 */
const namespace = z
  .string()
  .max(63, { error: "must be a Kubernetes namespace", abort: true })
  .regex(/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/, "must be a Kubernetes namespace")
  .default("argocd");

/**
 * Where an Argo CD instance is, which Application manages its
 * `argocd-rbac-cm`, the namespace that ConfigMap is in, and where the
 * connector's API token lives.
 *
 * No value in a refusal is repeated: each issue's message is fixed text.
 */
export const instance = z.object({
  url,
  managingApp,
  namespace,
  secret: secretPointer,
});

export type Instance = z.infer<typeof instance>;

import { z } from "zod";

/**
 * The LaunchDarkly instance an account lives on. Each has its own fixed host,
 * and the connector calls no other: P0 names the instance, never a URL.
 */
export const instance = z.enum(["commercial", "eu", "federal"]);

export type Instance = z.infer<typeof instance>;

/**
 * Each instance's API host, from LaunchDarkly's API reference ("Federal and EU
 * environments"). The client builds every URL from this map.
 */
export const LAUNCHDARKLY_HOSTS = {
  commercial: "app.launchdarkly.com",
  eu: "app.eu.launchdarkly.com",
  federal: "app.launchdarkly.us",
} as const satisfies Record<Instance, string>;

/**
 * A pointer to the account's access token in the customer's own secret
 * manager, under whatever name they chose. P0 never holds the token: the
 * connector reads it itself. A copy of the Harbor connector's pointer.
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

/**
 * LaunchDarkly's id for the account, as `GET /caller-identity` reports it.
 * Install validation finds it, and P0 sends it back on every later call so
 * a grant can check the token still belongs to the same account.
 */
export const accountId = z.string().min(1);

/**
 * One LaunchDarkly account: where it is, which account it is, and where its
 * access token lives. Every list query carries one as its `context`, and
 * every access's request context extends it.
 */
export const account = z.object({ accountId, instance, secret: secretPointer });

export type Account = z.infer<typeof account>;

/**
 * What install validation takes: the account without its id, which
 * validation finds.
 */
export const installInput = account.omit({ accountId: true });

export type InstallInput = z.infer<typeof installInput>;

/** The instance's host, which stands for the account in messages. */
export const hostOf = ({ instance }: Pick<Account, "instance">) =>
  LAUNCHDARKLY_HOSTS[instance];

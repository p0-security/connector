import { z } from "zod";

/**
 * A pointer to the bind account's password in the customer's own secret
 * manager. P0 never holds the password: the connector reads it itself.
 *
 * On GCP, `secretId` is the secret's bare name. On AWS, it may be a partial
 * ARN.
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
 * One PingFederate SP connection that signs users in to AWS, and the LDAP
 * user store it reads the user's AWS roles from. Every call carries one.
 */
export const app = z.object({
  /** PingFederate's runtime base URL, such as `https://sso.example.com:9031`. */
  pingFederateUrl: z
    .url({ protocol: /^https$/, error: "must be an https URL" })
    .transform((url) => url.replace(/\/+$/, "")),
  /** Only LDAPS: the bind sends the password. */
  directoryUrl: z
    .string()
    .regex(
      /^ldaps:\/\/[^/\s?#]+$/,
      "must be an ldaps:// URL with a host and an optional port"
    ),
  bindDn: z.string().min(1),
  bindPassword: secretPointer,
  /** The entry under which the connector finds users. */
  baseDn: z.string().min(1),
  /** The multi-valued attribute that holds the user's AWS roles. */
  roleAttribute: z
    .string()
    .regex(/^[A-Za-z][A-Za-z0-9-]{0,99}$/, "must be an LDAP attribute name"),
  /**
   * PEM certificates that the connector trusts for the user store and for
   * PingFederate, in addition to the public CAs.
   */
  caCertificate: z
    .string()
    .includes("-----BEGIN CERTIFICATE-----", {
      error: "must be one or more PEM certificates",
    })
    .optional(),
});

export type App = z.infer<typeof app>;

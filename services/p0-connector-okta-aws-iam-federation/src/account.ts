import { z } from "zod";

/**
 * A pointer to the service app's private key in the customer's own secret
 * manager. P0 never holds the key: the connector reads it itself.
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
 * The org's Okta domain. It becomes the host of every URL the connector
 * calls, so a custom domain, a port and a path are refused.
 */
export const domain = z
  .string()
  .regex(
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:okta|oktapreview|okta-emea|okta-gov)\.com$/,
    "must be the org's Okta domain, such as acme.okta.com"
  );

const oktaId = z
  .string()
  .regex(/^[A-Za-z0-9]{20}$/, "must be an Okta application id");

/**
 * One Okta AWS Account Federation app, and how the connector signs in to
 * Okta: the client ID of an Okta API service app, and where its private key
 * is. Every call carries one.
 */
export const app = z.object({
  domain,
  appId: oktaId,
  clientId: oktaId,
  privateKey: secretPointer,
});

export type App = z.infer<typeof app>;

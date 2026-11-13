import { z } from "zod";

/**
 * A pointer to the worker app's client secret in the customer's own secret
 * manager. P0 never holds the secret: the connector reads it itself.
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

export const region = z.enum(["AP", "AU", "CA", "EU", "NA"]);

export type Region = z.infer<typeof region>;

/** The top-level domain of each PingOne region's hosts. */
export const REGION_TLDS: Record<Region, string> = {
  AP: "asia",
  AU: "com.au",
  CA: "ca",
  EU: "eu",
  NA: "com",
};

const pingOneId = z.guid("must be a PingOne id");

/**
 * One PingOne SAML app that signs users in to AWS, and how the connector
 * signs in to PingOne: the client ID of a worker app, and where its client
 * secret is. Every call carries one.
 */
export const app = z.object({
  region,
  environmentId: pingOneId,
  appId: pingOneId,
  /** The name of the multi-valued user attribute that holds the user's AWS roles. */
  roleAttribute: z
    .string()
    .regex(/^[A-Za-z][A-Za-z0-9_]{0,99}$/, "must be a PingOne attribute name"),
  clientId: pingOneId,
  clientSecret: secretPointer,
});

export type App = z.infer<typeof app>;

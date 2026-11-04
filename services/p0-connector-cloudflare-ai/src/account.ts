import { z } from "zod";

/**
 * A pointer to the install token in the customer's own secret manager, under
 * whatever name they chose. P0 never holds the token: the connector reads it
 * itself. A copy of the Miro (AI) connector's pointer.
 *
 * On GCP, `secretId` is the secret's bare name. A full resource name
 * (`projects/<project>/secrets/<name>`) would be read as it stands, whatever
 * `projectId` says, so it is refused. On AWS, `secretId` may be a partial
 * ARN.
 *
 * `projectId` and `region` are held to their own shapes, because each becomes
 * part of the address the read is sent to.
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

/** Cloudflare's id for an account: 32 lowercase hex characters. */
export const accountId = z
  .string()
  .regex(/^[0-9a-f]{32}$/, "must be a Cloudflare account id");

/**
 * One Cloudflare account, and where its install token lives. Every call
 * carries one.
 */
export const account = z.object({ accountId, secret: secretPointer });

export type Account = z.infer<typeof account>;

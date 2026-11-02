import { z } from "zod";

/**
 * A pointer to the team's access token in the customer's own secret manager,
 * under whatever name they chose. P0 never holds the token: the connector
 * reads it itself. A copy of the LaunchDarkly connector's pointer.
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
 * Miro's id for a team, as `GET /v1/oauth-token` reports it: a decimal
 * number too large for a JavaScript number, so always a string. Install
 * validation finds it, and P0 sends it back on every later call, so a grant
 * can check the token still belongs to the same team.
 */
export const teamId = z
  .string()
  .regex(/^[0-9]{1,20}$/, "must be a Miro team id");

/**
 * One Miro team: which team it is, and where the connector user's access
 * token lives. Every later call carries one.
 */
export const team = z.object({ teamId, secret: secretPointer });

export type Team = z.infer<typeof team>;

/**
 * What install validation takes: the team without its id, which validation
 * finds.
 */
export const installInput = team.omit({ teamId: true });

export type InstallInput = z.infer<typeof installInput>;

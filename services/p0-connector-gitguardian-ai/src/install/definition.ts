import { z } from "zod";

// Closed list, so that a request cannot send the admin token to another host.
const region = z.enum(["us", "eu"]);

/** Where the admin token is stored. The secret value is the token as plain
 * text. */
const secrets = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    adminTokenSecretId: z.string().min(1),
    region: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    adminTokenSecretId: z.string().min(1),
    projectId: z.string().min(1),
  }),
]);

/**
 * What an install verifier sends to `get`. Strict, so a caller sending a field
 * this schema doesn't know fails instead of validating less and reporting
 * success.
 */
export const installValidationInput = z.strictObject({
  region,
  /** The install item's ID, which is the GitGuardian workspace ID. */
  workspaceId: z.string().regex(/^\d+$/),
  secrets,
});

export type InstallValidationInput = z.input<typeof installValidationInput>;

/** What `get` returns: the admin token it checked. */
export type InstallValidation = {
  tokenId: string;
  workspaceId: string;
  memberId: number | null;
  type: string;
  scopes: string[];
  /** `null` for a token that never expires. */
  expireAt: string | null;
};

import { z } from "zod";

/** Where the admin token is stored. The secret value is the token as plain
 * text. */
export const adminTokenSecret = z.discriminatedUnion("manager", [
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

export type AdminTokenSecret = z.infer<typeof adminTokenSecret>;

// Closed list, so that a request cannot send the admin token to another host.
export const region = z.enum(["us", "eu"]);

/** A GitGuardian workspace ID, which is also the install item's ID. */
export const workspaceId = z.string().regex(/^\d+$/);

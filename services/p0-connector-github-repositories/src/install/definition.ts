import { z } from "zod";

export const installValidation = z.object({
  /** GitHub accepted a JWT signed with the key, so the app id and key belong together. */
  keyAccepted: z.boolean(),
  /** The app is installed on the org. */
  installed: z.boolean(),
  /** An org owner suspended the installation, so nothing works until it's unsuspended. Always `false` when not installed. */
  suspended: z.boolean(),
  /** Required permissions the installation lacks, as `name=level`. Empty when it has all four. */
  missingPermissions: z.array(z.string()),
  /** Whether the installation sees all of the org's repositories or only selected ones. */
  repositorySelection: z.enum(["all", "selected"]).nullable(),
});
export type InstallValidation = z.infer<typeof installValidation>;

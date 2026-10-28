import { z } from "zod";

export const installValidation = z.object({
  /** Docker Hub exchanged the organization access token for a JWT. */
  tokenAccepted: z.boolean(),
  /** The token could read the org's member list. */
  canReadMembers: z.boolean(),
  /** Docker Hub accepted a dry-run invite, which sends nothing and uses no seat. */
  canInvite: z.boolean(),
  /** The connector's `DOMAIN_ALLOW_PATTERN` as deployed, for the install to display. */
  allowedDomains: z.string(),
});
export type InstallValidation = z.infer<typeof installValidation>;

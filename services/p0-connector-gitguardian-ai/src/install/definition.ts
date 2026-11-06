import { z } from "zod";

import { adminTokenSecret, region, workspaceId } from "../secret-location.ts";

/**
 * What an install verifier sends to `get`. Strict, so a caller sending a field
 * this schema doesn't know fails instead of validating less and reporting
 * success.
 */
export const installValidationInput = z.strictObject({
  region,
  /** The install item's ID, which is the GitGuardian workspace ID. */
  workspaceId,
  secrets: adminTokenSecret,
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

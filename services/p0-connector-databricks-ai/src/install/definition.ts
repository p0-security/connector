import { z } from "zod";

import { agentName } from "../agent/name.ts";
import type { OwnServicePrincipal } from "../databricks/client.ts";
import { accountContext, workspaceId } from "../databricks/context.ts";

/**
 * What an install verifier sends to `get`: the account to authenticate to,
 * and which account checks to run. Signing in always runs. Each other check
 * runs only when asked for, so a caller can run and report each on its own.
 * None of them writes anything.
 *
 * Strict, so a caller sending a field this schema doesn't know (a
 * misspelled field, say) fails instead of validating less and reporting
 * success.
 */
export const installValidationInput = z.strictObject({
  ...accountContext.shape,
  /** Fail unless the principal holds account admin. Read through account SCIM. */
  requireAccountAdmin: z.boolean().optional(),
  /**
   * Fail unless the principal owns every metastore in the account, itself or
   * through a group it is a direct member of.
   */
  requireMetastoreAdmin: z.boolean().optional(),
  /**
   * Fail unless this names exactly one principal in account SCIM: a group by
   * its display name, a user by their `userName`, or a service principal by
   * its application ID.
   */
  ownerPrincipal: z.string().min(1).optional(),
});

/** A metastore P0's principal owns, and how. */
export type MetastoreAdmin = {
  metastoreId: string;
  name: string;
  /** The metastore's `owner`: P0's application ID, or the name of a group P0 is in. */
  owner: string;
};

/** The one account SCIM principal an owner principal names. */
export type OwnerPrincipal = {
  type: "group" | "servicePrincipal" | "user";
  /** Its account SCIM ID. */
  id: string;
  /** How Unity Catalog names it: a group's display name, a user's `userName`, or a service principal's application ID. */
  name: string;
};

/** What `get` returns. Each field is `null` when its check didn't run. */
export type InstallValidation = {
  /** The principal in account SCIM, with account admin. Read when `requireAccountAdmin` is set. */
  servicePrincipal: OwnServicePrincipal | null;
  /** Every metastore in the account. Read when `requireMetastoreAdmin` is set. */
  metastores: MetastoreAdmin[] | null;
  /** The principal `ownerPrincipal` names. Read when `ownerPrincipal` is set. */
  ownerPrincipal: OwnerPrincipal | null;
};

export type InstallValidationInput = z.input<typeof installValidationInput>;

/**
 * What `probe` takes: the account to authenticate to, and the workspace to
 * look for the Unity Gateway beta in. Strict, as
 * {@link installValidationInput} is.
 */
export const probeInput = z.strictObject({
  ...accountContext.shape,
  workspaceId,
});

export type ProbeInput = z.input<typeof probeInput>;

/** What `probe` returns. */
export type Probe = {
  workspaceId: string;
  workspaceName: string;
  /** The workspace origin P0 built from the account workspaces API. */
  workspaceHost: string;
  /** Whether the workspace serves the Databricks SQL MCP server through Unity Gateway, which the Unity Gateway beta turns on. */
  unityGatewayBeta: boolean;
};

/**
 * What `principal.stage` takes: the account to act in, and the display name
 * of the agent principal to get or create. Strict, as
 * {@link installValidationInput} is.
 */
export const stageInput = z.strictObject({
  ...accountContext.shape,
  principalName: agentName,
});

export type StageInput = z.input<typeof stageInput>;

/** What `principal.stage` returns. */
export const stageOutput = z.object({
  /** The agent principal's application ID, which the gateway and every later call name it by. */
  applicationId: z.guid(),
});

export type Stage = z.infer<typeof stageOutput>;

import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  withRouteLogging,
} from "@p0security/connector-core";
import type { SecretRef } from "@p0security/connector-secret-manager-client";

import {
  type ApiToken,
  type GitguardianRegion,
  getCurrentToken,
} from "../gitguardian/gitguardian-api.ts";
import { createSecretManager, getAdminToken } from "../secrets.ts";
import {
  type InstallValidation,
  type InstallValidationInput,
  installValidationInput,
} from "./definition.ts";

const refusal = (message: string, payload: Record<string, string> = {}) =>
  new ConnectorError({ type: "validation_error", message, payload });

/** The admin token's own record. GitGuardian answers 401 for a revoked or
 * expired key, and for a key sent to the other region's host. */
const readAdminToken = async (
  region: GitguardianRegion,
  token: string
): Promise<ApiToken> => {
  try {
    return await getCurrentToken({ region, token });
  } catch (error) {
    if (error instanceof ConnectorError && error.data.payload?.status === 401) {
      throw refusal(
        `GitGuardian rejected the admin token in the ${region} region. Check that it isn't revoked or expired, and that the workspace is in that region.`,
        { region }
      );
    }
    throw error;
  }
};

/**
 * Checks the admin token, read-only: it is valid in the region, active,
 * belongs to the installed workspace, and can find and revoke tokens. A missing
 * requestable scope and token-cap headroom are not checked here, because a
 * grant that hits either fails with its own message.
 */
const validate = async (
  input: InstallValidationInput
): Promise<InstallValidation> => {
  const { region, workspaceId, secrets } = input;
  const secretManager = await createSecretManager(secrets);
  const token = await getAdminToken(
    secretManager,
    secrets.adminTokenSecretId as SecretRef
  );
  const self = await readAdminToken(region, token);

  if (self.status !== "active") {
    throw refusal(`The admin token is ${self.status}. Create a new one.`, {
      status: self.status,
    });
  }
  if (String(self.workspace_id) !== workspaceId) {
    throw refusal(
      `The admin token belongs to workspace ${self.workspace_id}, but this install is for workspace ${workspaceId}.`,
      { workspaceId, tokenWorkspaceId: String(self.workspace_id) }
    );
  }
  if (!self.scopes.includes("api_tokens:write")) {
    throw refusal(
      "P0 can't revoke tokens without api_tokens:write. Create a new admin token with every scope and store it in the secret."
    );
  }
  if (!self.scopes.includes("api_tokens:read")) {
    throw refusal(
      "P0 can't find grant tokens without api_tokens:read. Create a new admin token with every scope and store it in the secret."
    );
  }

  return {
    tokenId: self.id,
    workspaceId,
    memberId: self.member_id,
    type: self.type,
    scopes: self.scopes,
    expireAt: self.expire_at,
  };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(installValidationInput.parse)
      .query(async ({ input }) => await validate(input)),
  });
};

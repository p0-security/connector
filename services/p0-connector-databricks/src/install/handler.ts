import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  withRouteLogging,
} from "@p0security/connector-core";

import { failedRequest, parse } from "../databricks/api.ts";
import {
  type DatabricksClient,
  type OwnIdentity,
  type OwnServicePrincipal,
  asAccountAdmin,
  hasAccountAdmin,
  isWorkspaceAdmin,
  newDatabricksClient,
  notAccountAdmin,
  scimRoles,
} from "../databricks/client.ts";
import { databricksAccessToken } from "../databricks/federation.ts";
import { type WorkspaceRef, bindWorkspace } from "../databricks/workspaces.ts";
import { assertDomainPatternIsValid } from "../domain.ts";
import {
  type InstallValidation,
  installValidationInput,
} from "./definition.ts";

/**
 * Finds the principal in account SCIM and refuses it unless its `roles`
 * include `account_admin`. Account SCIM refuses any other principal with a
 * 403, which gets the same refusal.
 */
const assertAccountAdmin = async (
  client: DatabricksClient
): Promise<OwnServicePrincipal> => {
  const { context } = client;
  const servicePrincipal = await client.ownServicePrincipal();
  // Read fresh, not from the cached principal: a customer re-running
  // validation after granting the role must see it.
  const principal = parse({
    schema: scimRoles,
    data: await asAccountAdmin(context, async () =>
      client.account({
        method: "GET",
        path: `/scim/v2/ServicePrincipals/${encodeURIComponent(servicePrincipal.id)}`,
      })
    ),
    what: "account SCIM ServicePrincipals",
    requestId: context.requestId,
  });
  if (!hasAccountAdmin(principal)) throw notAccountAdmin(context);
  return servicePrincipal;
};

/**
 * Checks the principal can act in the workspace: `SCIM /Me` succeeds only
 * for a principal assigned to it, and binding confirms the URL answers for
 * the workspace ID. With `requireAdmin`, `/Me` must also list the
 * workspace's admins group.
 */
const checkWorkspace = async (
  client: DatabricksClient,
  workspace: WorkspaceRef,
  requireAdmin: boolean
): Promise<NonNullable<InstallValidation["workspace"]>> => {
  const { requestId, applicationId } = client.context;
  const { workspaceId, workspaceUrl } = workspace;
  let identity: OwnIdentity;
  try {
    identity = await client.inWorkspace(workspaceUrl).ownIdentity();
  } catch (error) {
    const status = failedRequest(error)?.status;
    if (status === 401 || status === 403) {
      throw new ConnectorError({
        type: "insufficient_privileges",
        message: `Service principal ${applicationId} can't call Databricks workspace ${workspaceId} at ${workspaceUrl}. Check the URL, and that the service principal is assigned to the workspace.`,
        payload: { requestId, applicationId, workspaceId, workspaceUrl },
        cause: error,
      });
    }
    throw error;
  }

  const { metastoreId } = await bindWorkspace(client, workspace);

  const isAdmin = isWorkspaceAdmin(identity);
  if (requireAdmin && !isAdmin) {
    throw new ConnectorError({
      type: "insufficient_privileges",
      message: `Service principal ${applicationId} is not an admin of Databricks workspace ${workspaceId}`,
      payload: { requestId, applicationId, workspaceId },
    });
  }
  return { identity, metastoreId, isAdmin };
};

/**
 * Lets the installer's verifiers confirm the connector can act in an account,
 * and in one of its workspaces.
 *
 * It checks that domain verification is configured, then exchanges a token
 * for the given service principal, which proves its federation policy
 * trusts the connector's role and needs no role in Databricks. Only with
 * `requireAccountAdmin` does it call an account API: it finds the principal
 * in account SCIM and confirms its `roles` include `account_admin`. Given a
 * workspace, it calls the workspace's `SCIM /Me`, which proves the principal
 * is assigned there, binds the URL to the workspace ID, and with
 * `requireWorkspaceAdmin` confirms `/Me` lists the admins group.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(installValidationInput.parse)
      .query(async ({ input, ctx }): Promise<InstallValidation> => {
        const {
          requestId,
          accountId,
          applicationId,
          workspaceId,
          workspaceUrl,
          requireAccountAdmin = false,
          requireWorkspaceAdmin = false,
        } = input;
        const logger = ctx.logger.child({
          requestId,
          accountId,
          applicationId,
          workspaceId,
          workspaceUrl,
          requireAccountAdmin,
          requireWorkspaceAdmin,
        });
        assertDomainPatternIsValid(requestId);

        await databricksAccessToken(input);
        const client = newDatabricksClient(input);

        const servicePrincipal = requireAccountAdmin
          ? await assertAccountAdmin(client)
          : null;
        // The parser refuses one without the other.
        const workspace =
          workspaceId !== undefined && workspaceUrl !== undefined
            ? await checkWorkspace(
                client,
                { workspaceId, workspaceUrl },
                requireWorkspaceAdmin
              )
            : null;

        logger.info(
          {
            servicePrincipalId: servicePrincipal?.id,
            metastoreId: workspace?.metastoreId,
            isWorkspaceAdmin: workspace?.isAdmin,
          },
          "validated Databricks federation"
        );
        return { servicePrincipal, workspace };
      }),
  });
};

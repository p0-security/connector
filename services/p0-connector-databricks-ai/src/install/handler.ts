import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  withRouteLogging,
} from "@p0security/connector";
import { z } from "zod";

import { parse } from "../databricks/api.ts";
import {
  type DatabricksClient,
  type OwnServicePrincipal,
  asAccountAdmin,
  hasAccountAdmin,
  newDatabricksClient,
  notAccountAdmin,
  scimRoles,
} from "../databricks/client.ts";
import { databricksAccessToken } from "../databricks/federation.ts";
import { type AccountScim, newAccountScim } from "../databricks/scim.ts";
import { ensureWorkspaceAdmin } from "../databricks/workspace-admin.ts";
import { lookupWorkspace } from "../databricks/workspaces.ts";
import {
  type InstallValidation,
  type MetastoreAdmin,
  type OwnerPrincipal,
  type Probe,
  installValidationInput,
  probeInput,
} from "./definition.ts";
import { probeUnityGateway } from "./probe.ts";

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

const metastoreList = z.object({
  metastores: z
    .array(
      z.object({
        metastore_id: z.string().min(1),
        name: z.string(),
        owner: z.string().optional(),
      })
    )
    .optional(),
});

/**
 * How a metastore's `owner` relates to P0's principal: it is the principal,
 * a group that lists the principal as a direct member, a group that doesn't,
 * or something else. Nested groups aren't followed.
 *
 * `owner` names a principal the way Unity Catalog does everywhere: a user by
 * user name, a service principal by application ID, a group by display name.
 * The INT-810 live check saw a metastore owned by a user name, and a table
 * owned by a service principal's application ID.
 */
const metastoreOwnership = async (
  scim: AccountScim,
  own: OwnServicePrincipal,
  owner: string
): Promise<"group member" | "not a member" | "other" | "principal"> => {
  if (owner.toLowerCase() === own.applicationId.toLowerCase()) {
    return "principal";
  }
  const group = await scim.groupByDisplayName(owner);
  if (!group) return "other";
  const members = (await scim.groupById(group.id))?.members ?? [];
  return members.some(({ value }) => value === own.id)
    ? "group member"
    : "not a member";
};

/**
 * Refuses the principal unless it owns every metastore in the account, which
 * makes it the metastore admin: itself, or through a group it is a direct
 * member of. Each refusal names the metastore.
 */
const assertMetastoreAdmin = async (
  client: DatabricksClient
): Promise<MetastoreAdmin[]> => {
  const { context } = client;
  const { requestId, accountId, applicationId } = context;
  const own = await client.ownServicePrincipal();
  const scim = newAccountScim(client);
  const { metastores = [] } = parse({
    schema: metastoreList,
    data: await asAccountAdmin(context, async () =>
      client.account({ method: "GET", path: "/metastores" })
    ),
    what: "account metastores",
    requestId,
  });

  const remedy = `Make service principal ${applicationId}, or a group it is a direct member of, the metastore's owner.`;
  const refuse = (metastoreId: string, problem: string, fix = remedy) =>
    new ConnectorError({
      type: "insufficient_privileges",
      message: `${problem} ${fix}`,
      payload: { requestId, accountId, applicationId, metastoreId },
    });

  const admins: MetastoreAdmin[] = [];
  for (const { metastore_id: metastoreId, name, owner } of metastores) {
    const metastore = `Databricks metastore ${name} (${metastoreId})`;
    if (!owner) throw refuse(metastoreId, `${metastore} has no owner.`);
    const ownership = await metastoreOwnership(scim, own, owner);
    if (ownership === "not a member") {
      throw refuse(
        metastoreId,
        `${metastore} is owned by group ${owner}, which service principal ${applicationId} is not a direct member of.`,
        `Add group ${owner} to the account Terraform's metastore admin groups, then apply it.`
      );
    }
    if (ownership === "other") {
      throw refuse(
        metastoreId,
        `${metastore} is owned by ${owner}, which is neither service principal ${applicationId} nor a group.`
      );
    }
    admins.push({ metastoreId, name, owner });
  }
  return admins;
};

/**
 * Finds the one principal in account SCIM that `ownerPrincipal` names: a
 * group by display name, a user by `userName` or a service principal by
 * application ID. Revoke hands what an agent created to it, so none, or more
 * than one, fails.
 */
const requireOwnerPrincipal = async (
  client: DatabricksClient,
  ownerPrincipal: string
): Promise<OwnerPrincipal> => {
  const { requestId, accountId } = client.context;
  const scim = newAccountScim(client);
  const group = await scim.groupByDisplayName(ownerPrincipal);
  const user = await scim.userByUserName(ownerPrincipal);
  const servicePrincipal =
    await scim.servicePrincipalByApplicationId(ownerPrincipal);
  const matches: OwnerPrincipal[] = [
    ...(group
      ? [{ type: "group" as const, id: group.id, name: group.displayName }]
      : []),
    ...(user
      ? [{ type: "user" as const, id: user.id, name: user.userName }]
      : []),
    ...(servicePrincipal
      ? [
          {
            type: "servicePrincipal" as const,
            id: servicePrincipal.id,
            name: servicePrincipal.applicationId,
          },
        ]
      : []),
  ];
  const payload = { requestId, accountId, ownerPrincipal };
  const [match, ...others] = matches;
  if (!match) {
    throw new ConnectorError({
      type: "object_not_found",
      message: `No group, user or service principal in Databricks account ${accountId} is named ${ownerPrincipal}. Set the owner principal to a group's display name, a user's userName, or a service principal's application ID.`,
      payload,
    });
  }
  if (others.length > 0) {
    const named = matches.map(({ type, id }) => `${type} ${id}`).join(", ");
    throw new ConnectorError({
      type: "validation_error",
      message: `The owner principal ${ownerPrincipal} names more than one principal in Databricks account ${accountId}: ${named}. Set it to one that names a single group, user or service principal.`,
      payload,
    });
  }
  return match;
};

/**
 * Lets the installer confirm the connector can act in an account.
 *
 * `get` is what install validation runs, every hour, so it never writes. It
 * exchanges a token for the given service principal, which proves its
 * federation policy trusts the connector's role. Then it runs the account
 * checks the input asks for: account admin, metastore admin on every
 * metastore, and that the owner principal names exactly one principal.
 *
 * `probe` writes. It makes P0's principal an admin of the given workspace,
 * then asks that workspace's Databricks SQL MCP server for its tools, to
 * learn whether the Unity Gateway beta is on.
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
          requireAccountAdmin = false,
          requireMetastoreAdmin = false,
          ownerPrincipal,
        } = input;
        const logger = ctx.logger.child({
          requestId,
          accountId,
          applicationId,
          requireAccountAdmin,
          requireMetastoreAdmin,
          ownerPrincipal,
        });

        await databricksAccessToken(input);
        const client = newDatabricksClient(input);

        const servicePrincipal = requireAccountAdmin
          ? await assertAccountAdmin(client)
          : null;
        const metastores = requireMetastoreAdmin
          ? await assertMetastoreAdmin(client)
          : null;
        const owner =
          ownerPrincipal !== undefined
            ? await requireOwnerPrincipal(client, ownerPrincipal)
            : null;

        logger.info(
          {
            servicePrincipalId: servicePrincipal?.id,
            metastoreIds: metastores?.map(({ metastoreId }) => metastoreId),
            ownerPrincipalType: owner?.type,
          },
          "validated the Databricks account"
        );
        return { servicePrincipal, metastores, ownerPrincipal: owner };
      }),

    probe: procedure
      .input(probeInput.parse)
      .mutation(async ({ input, ctx }): Promise<Probe> => {
        const { requestId, accountId, applicationId, workspaceId } = input;
        const logger = ctx.logger.child({
          requestId,
          accountId,
          applicationId,
          workspaceId,
        });

        await databricksAccessToken(input);
        const client = newDatabricksClient(input);
        const workspace = await lookupWorkspace(client, workspaceId);
        const assigned = await ensureWorkspaceAdmin(client, workspaceId);
        const unityGatewayBeta = await probeUnityGateway(
          client.inWorkspace(workspace.host),
          { workspaceId, assigned }
        );

        logger.info(
          { workspaceHost: workspace.host, assigned, unityGatewayBeta },
          "probed for the Databricks Unity Gateway beta"
        );
        return {
          workspaceId,
          workspaceName: workspace.name,
          workspaceHost: workspace.host,
          unityGatewayBeta,
        };
      }),
  });
};

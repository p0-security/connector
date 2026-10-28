import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";

import { createUser, deleteUser, getUser } from "../../agent/agent.ts";
import { AGENT_NAME_PATTERN } from "../../agent/name.ts";
import { failedRequest, parse } from "../../databricks/api.ts";
import {
  type DatabricksClient,
  type DatabricksWorkspaceClient,
  asAccountAdmin,
  newDatabricksClient,
} from "../../databricks/client.ts";
import { ensureWorkspaceAdmin } from "../../databricks/workspace-admin.ts";
import {
  accountWorkspace,
  lookupWorkspace,
  workspaceHost,
} from "../../databricks/workspaces.ts";
import { type ListerQuery, spec } from "./definition.ts";
import { grantData, revokeAgent } from "./grants.ts";
import { type UcItem, newUnityCatalog } from "./unity-catalog.ts";

type DataSchema = ResourceRootSchemaOf<typeof spec>;

/** The `workspace_status` of a workspace that is ready to use. */
const RUNNING = "RUNNING";

/** The warehouse type that serves pro and serverless SQL warehouses. */
const PRO = "PRO";

/**
 * Catalogs the listings hide, so no agent is offered access to them: the
 * metastore's system tables, such as audit logs and billing, and
 * Databricks' own.
 */
const HIDDEN_CATALOGS = new Set(["system", "__databricks_internal"]);

/**
 * The waits, in milliseconds, between tries of a listing the workspace
 * refuses just after P0 became workspace admin there. They add up to 30 s,
 * well inside the connector's 270 s Lambda timeout.
 */
const ADMIN_RETRY_DELAYS = [2_000, 4_000, 8_000, 16_000];

const toItems = (items: UcItem[]) =>
  items.map(({ name }) => ({ key: name, value: name }));

const isWithHost = <T extends { host: string | undefined }>(
  value: T
): value is T & { host: string } => value.host !== undefined;

/**
 * Every running workspace in the account, keyed by workspace ID and valued
 * `<name> (<host>)`. A workspace whose host P0 can't build as a Databricks
 * workspace origin is skipped with a warning.
 */
const listWorkspaces = async (client: DatabricksClient, logger: Logger) => {
  const { context } = client;
  const workspaces = parse({
    schema: z.array(accountWorkspace),
    data: await asAccountAdmin(context, async () =>
      client.account({ method: "GET", path: "/workspaces" })
    ),
    what: "account workspaces",
    requestId: context.requestId,
  });
  const running = workspaces
    .filter(({ workspace_status }) => workspace_status === RUNNING)
    .map((workspace) => ({
      workspace,
      host: workspaceHost(context.accountsUrl, workspace.deployment_name),
    }));
  running
    .filter(({ host }) => host === undefined)
    .forEach(({ workspace }) =>
      logger.warn(
        { workspaceId: workspace.workspace_id },
        "skipped a workspace whose host isn't a Databricks workspace origin"
      )
    );
  return running.filter(isWithHost).map(({ workspace, host }) => ({
    key: String(workspace.workspace_id),
    value: `${workspace.workspace_name} (${host})`,
  }));
};

const warehouseList = z.object({
  warehouses: z
    .array(
      z.object({
        id: z.string().min(1),
        name: z.string(),
        warehouse_type: z.string().optional(),
      })
    )
    .optional(),
});

/**
 * Runs a workspace call. When P0 became workspace admin there just now, a
 * 401 or 403 is most likely the workspace not having seen that assignment
 * yet, so the call is tried again after each of
 * {@link ADMIN_RETRY_DELAYS}. Then it fails as retryable.
 */
const whileAdminSettles = async <T>(
  assigned: boolean,
  workspace: DatabricksWorkspaceClient,
  workspaceId: string,
  call: () => Promise<T>
): Promise<T> => {
  const attempt = async (delays: readonly number[]): Promise<T> => {
    try {
      return await call();
    } catch (error) {
      const status = failedRequest(error)?.status;
      if (!assigned || (status !== 401 && status !== 403)) throw error;
      const [delay, ...later] = delays;
      if (delay === undefined) {
        throw new ConnectorError({
          type: "upstream_unavailable",
          message: `Databricks hasn't seen P0's new workspace admin assignment in workspace ${workspaceId} yet. Try again in a few minutes.`,
          payload: { requestId: workspace.requestId, workspaceId, status },
          cause: error,
        });
      }
      await sleep(delay);
      return await attempt(later);
    }
  };
  return await attempt(ADMIN_RETRY_DELAYS);
};

/** One listing in `workspace`, for {@link listInWorkspace}. */
const listWith = async (
  workspace: DatabricksWorkspaceClient,
  query: Exclude<ListerQuery, { type: "workspace" | "workspaces" }>
) => {
  const uc = newUnityCatalog(workspace);

  switch (query.type) {
    case "warehouses": {
      const { warehouses = [] } = parse({
        schema: warehouseList,
        data: await workspace.call({
          method: "GET",
          path: "/api/2.0/sql/warehouses",
        }),
        what: "SQL warehouses list",
        requestId: workspace.requestId,
      });
      return warehouses
        .filter(({ warehouse_type }) => warehouse_type === PRO)
        .map(({ id, name }) => ({ key: id, value: name }));
    }
    // P0's metastore admin sees every catalog on the metastore, except
    // unbound ISOLATED ones while `include_unbound` stays off.
    case "catalogs":
      return toItems(
        (await uc.list("catalogs")).filter(
          ({ name }) => !HIDDEN_CATALOGS.has(name.toLowerCase())
        )
      );
    case "schemas":
      return toItems(await uc.list("schemas", { catalog_name: query.catalog }));
    case "tables":
    case "volumes":
      return toItems(
        await uc.list(query.type, {
          catalog_name: query.catalog,
          schema_name: query.schema,
        })
      );
    default:
      throw throwAssertNever(query);
  }
};

/**
 * Lists one workspace's warehouses or Unity Catalog objects. P0 becomes
 * workspace admin first, since listings run before any grant has in that
 * workspace.
 */
const listInWorkspace = async (
  client: DatabricksClient,
  query: Exclude<ListerQuery, { type: "workspace" | "workspaces" }>
) => {
  const { host } = await lookupWorkspace(client, query.workspaceId);
  const assigned = await ensureWorkspaceAdmin(client, query.workspaceId);
  const workspace = client.inWorkspace(host);
  return await whileAdminSettles(
    assigned,
    workspace,
    query.workspaceId,
    async () => await listWith(workspace, query)
  );
};

/**
 * Unity Catalog data, granted to a service principal P0 creates for the
 * request alone (resource root). The "user" is that principal, named
 * `p0-agent-<request id>`, which `principal.stage` created.
 *
 * - `getUser`, `createUser` and `deleteUser` are the principal's lifecycle
 *   (`src/agent/agent.ts`). `deleteUser` runs the revoke first, because the
 *   control plane deletes the user even after a failed revoke, and a deleted
 *   principal's revoke could never be retried.
 * - `setPoliciesForUser` with policies grants them ({@link grantData}). With
 *   none it revokes ({@link revokeAgent}).
 * - `list` serves the workspaces, one workspace's host, its pro and
 *   serverless warehouses, and its catalogs, schemas, tables and volumes.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<DataSchema>(t, spec, (ctx: ConnectorContext) => {
    const loggerFor = (requestId: string, user: string) =>
      ctx.logger.child({ requestId, user });

    return {
      validation: () => ({
        user: {
          userIsNamespacedByBody: async (name) => AGENT_NAME_PATTERN.test(name),
          userIsNamespacedById: async (name) => AGENT_NAME_PATTERN.test(name),
        },
      }),

      getUser: async (context, name) =>
        await getUser(
          newDatabricksClient(context),
          loggerFor(context.requestId, name),
          context,
          name
        ),

      createUser: async (context, name) =>
        await createUser(
          newDatabricksClient(context),
          loggerFor(context.requestId, name),
          context,
          name
        ),

      deleteUser: async (context, name) => {
        const client = newDatabricksClient(context);
        const logger = loggerFor(context.requestId, name);
        await revokeAgent(client, logger, context, name);
        await deleteUser(client, logger, context, name);
      },

      setPoliciesForUser: async (context, name, _user, policies) => {
        const client = newDatabricksClient(context);
        const logger = loggerFor(context.requestId, name);
        if (policies.length === 0) {
          await revokeAgent(client, logger, context, name);
          return;
        }
        await grantData(client, logger, context, policies);
      },

      list: async (query) => {
        const client = newDatabricksClient(query.context);
        switch (query.type) {
          case "workspaces":
            return await listWorkspaces(
              client,
              ctx.logger.child({ requestId: query.context.requestId })
            );
          case "workspace": {
            // One item, so the control plane can read the host P0 built.
            const { workspaceId, host } = await lookupWorkspace(
              client,
              query.workspaceId
            );
            return [{ key: workspaceId, value: host }];
          }
          default:
            return await listInWorkspace(client, query);
        }
      },
    };
  });

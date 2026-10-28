import { ConnectorError } from "@p0security/connector-core";
import { z } from "zod";

import { isNotFound, memoizeByKey, parse } from "./api.ts";
import { type DatabricksClient, asAccountAdmin } from "./client.ts";
import { DATABRICKS_HOSTS, cacheKey, workspaceUrl } from "./context.ts";

/**
 * A workspace as the account workspaces API reports it, in a list or alone.
 * `z.int()` only accepts safe integers, so an ID that JSON parsing rounded
 * (above 2^53), which would name a different workspace, fails the parse.
 */
export const accountWorkspace = z.object({
  workspace_id: z.int(),
  workspace_name: z.string(),
  deployment_name: z.string().optional(),
  workspace_status: z.string().optional(),
});

export type AccountWorkspace = z.infer<typeof accountWorkspace>;

/** The `workspace_status` of a workspace that is ready to use. */
const RUNNING = "RUNNING";

/** A workspace P0 can call: its ID, its name, and the origin that serves it. */
export type Workspace = {
  workspaceId: string;
  name: string;
  /** The workspace origin, already checked by the `workspaceUrl` parser. */
  host: string;
};

/**
 * The origin that serves a workspace, built from its `deployment_name` and
 * the workspace domain of the account console the connector calls, the way
 * the Databricks SDKs build it. `undefined` when the result isn't a
 * Databricks workspace origin, so a token never goes to it. The INT-810 live
 * check saw this origin match the workspace's own URL and serve it.
 */
export const workspaceHost = (
  accountsUrl: string,
  deploymentName: string | undefined
): string | undefined => {
  const domain = Object.entries(DATABRICKS_HOSTS).find(
    ([host]) => accountsUrl === `https://${host}`
  )?.[1];
  if (!domain || !deploymentName) return undefined;
  const parsed = workspaceUrl.safeParse(`https://${deploymentName}.${domain}`);
  return parsed.success ? parsed.data : undefined;
};

/**
 * Workspaces, keyed by principal and workspace ID. A workspace's
 * deployment name never changes, so each is read once for the life of the
 * Lambda instance. A failed or refused read is not cached.
 */
const workspaces = new Map<string, Promise<Workspace>>();

/** Clears every cached workspace. For tests. */
export const resetWorkspaceCache = () => workspaces.clear();

/** How {@link lookupWorkspace} treats a workspace that isn't ready to use. */
export type WorkspaceLookup = {
  /**
   * Returns the workspace whatever its status, as long as P0 can build its
   * origin. Revoke sets it: the grants it removes are on the metastore, so
   * they must come off even when the workspace isn't `RUNNING`.
   */
  anyStatus?: boolean;
  /** The message for a workspace the account doesn't have, in place of the default. */
  missingMessage?: string;
};

const readWorkspace = async (
  client: DatabricksClient,
  workspaceId: string,
  { anyStatus = false, missingMessage }: WorkspaceLookup
): Promise<Workspace> => {
  const { context } = client;
  const { requestId, accountId, accountsUrl } = context;
  const payload = { requestId, accountId, workspaceId };
  const data = await asAccountAdmin(context, async () =>
    client.account({
      method: "GET",
      path: `/workspaces/${encodeURIComponent(workspaceId)}`,
    })
  ).catch((error: unknown) => {
    if (!isNotFound(error)) throw error;
    throw new ConnectorError({
      type: "object_not_found",
      message:
        missingMessage ??
        `Databricks account ${accountId} has no workspace ${workspaceId}. Check the workspace ID.`,
      payload,
      cause: error,
    });
  });
  const workspace = parse({
    schema: accountWorkspace,
    data,
    what: "account workspaces",
    requestId,
  });

  if (!anyStatus && workspace.workspace_status !== RUNNING) {
    throw new ConnectorError({
      type: "validation_error",
      message: `Databricks workspace ${workspaceId} is ${workspace.workspace_status ?? "in an unknown state"}, not ${RUNNING}. Wait until it is running, then try again.`,
      payload,
    });
  }
  const host = workspaceHost(accountsUrl, workspace.deployment_name);
  if (!host) {
    throw new ConnectorError({
      type: "validation_error",
      message: `P0 can't build a Databricks workspace URL for workspace ${workspaceId} from its deployment name.`,
      payload,
    });
  }
  return { workspaceId, name: workspace.workspace_name, host };
};

/**
 * Looks one workspace up in the account workspaces API, which needs account
 * admin, and returns its name and the origin that serves it. Only a
 * `RUNNING` workspace, or one in any status with `anyStatus`, whose origin is
 * on the account console's workspace domain is returned. Anything else is
 * refused, so a token never goes to a host P0 didn't build.
 */
export const lookupWorkspace = async (
  client: DatabricksClient,
  workspaceId: string,
  lookup: WorkspaceLookup = {}
): Promise<Workspace> =>
  await memoizeByKey(
    workspaces,
    `${cacheKey(client.context)}|${workspaceId}|${lookup.anyStatus ? "any" : RUNNING}`,
    async () => await readWorkspace(client, workspaceId, lookup)
  );

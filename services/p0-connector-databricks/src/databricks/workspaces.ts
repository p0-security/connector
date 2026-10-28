import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import { isNotFoundWith, memoizeByKey, parse } from "./api.ts";
import type { DatabricksClient } from "./client.ts";
import {
  accountContext,
  cacheKey,
  databricksId,
  workspaceUrl,
} from "./context.ts";

/** A Databricks workspace ID. */
export const workspaceId = databricksId;

/**
 * The workspace a call acts in: its ID, and the URL the customer entered at
 * install. Every call binds the URL to the ID first (see
 * {@link bindWorkspace}), so a URL can't stand in for another workspace.
 */
export const workspaceContext = accountContext.extend({
  workspaceId,
  workspaceUrl,
});

export type DatabricksWorkspaceContext = z.infer<typeof workspaceContext>;

/** Whether optional `workspaceId` and `workspaceUrl` are both set or both absent. */
export const hasWorkspacePair = (value: {
  workspaceId?: string;
  workspaceUrl?: string;
}) => (value.workspaceId === undefined) === (value.workspaceUrl === undefined);

/** The refusal for a schema that gets one of `workspaceId` and `workspaceUrl`. */
export const WORKSPACE_PAIR_ERROR =
  "workspaceId and workspaceUrl must be sent together";

/** A workspace as P0 names it: its ID, and the URL P0 says serves it. */
export type WorkspaceRef = Pick<
  DatabricksWorkspaceContext,
  "workspaceId" | "workspaceUrl"
>;

/** A workspace whose URL answers for its ID, and the metastore it's on. */
export type WorkspaceBinding = { workspaceId: string; metastoreId: string };

const METASTORE_ASSIGNMENT_PATH =
  "/api/2.1/unity-catalog/current-metastore-assignment";

/**
 * Error codes for a workspace that has no metastore assignment. The API
 * documents only that the assignment "will not be found and a 404 returned",
 * so this is Unity Catalog's code for a missing metastore, accepted but
 * unverified (build ticket 22). Any other 404 is not read as "unassigned"
 * and fails as itself.
 */
const NO_METASTORE_ASSIGNMENT_CODES = new Set(["METASTORE_DOES_NOT_EXIST"]);

/**
 * The workspace's metastore assignment. `z.int()` only accepts safe
 * integers, so an ID that JSON parsing rounded (above 2^53), which would
 * name a different workspace, fails the parse instead of binding.
 */
const metastoreAssignment = z.object({
  workspace_id: z.int(),
  metastore_id: z.string().min(1),
});

type MetastoreAssignment = z.infer<typeof metastoreAssignment>;

/**
 * Metastore assignments, keyed by principal and workspace URL. A URL always
 * serves the same workspace, so each is read once for the life of the Lambda
 * instance. A failed read is not cached.
 */
const workspaceBindings = new Map<string, Promise<MetastoreAssignment>>();

/** Clears every cached workspace binding. For tests. */
export const resetWorkspaceBindingCache = () => workspaceBindings.clear();

const readMetastoreAssignment = async (
  client: DatabricksClient,
  url: string
): Promise<MetastoreAssignment> =>
  parse({
    schema: metastoreAssignment,
    // Through `inWorkspace`, so the URL passes the Databricks host check
    // before the token is sent.
    data: await client.inWorkspace(url).call({
      method: "GET",
      path: METASTORE_ASSIGNMENT_PATH,
    }),
    what: "Unity Catalog current metastore assignment",
    requestId: client.context.requestId,
  });

/**
 * Confirms that `workspaceUrl` serves workspace `workspaceId`, by asking the
 * workspace itself for its Unity Catalog metastore assignment, and returns
 * the metastore ID. P0 sends the URL the customer entered at install, so
 * this is what stops a wrong or stale URL from acting in another workspace.
 *
 * The assignment is cached per principal and URL, but the requested ID is
 * compared on every call, so a cached binding still refuses a different ID.
 * A workspace without a metastore can't be bound.
 */
export const bindWorkspace = async (
  client: DatabricksClient,
  { workspaceId, workspaceUrl }: WorkspaceRef
): Promise<WorkspaceBinding> => {
  const { requestId } = client.context;
  let assignment: MetastoreAssignment;
  try {
    assignment = await memoizeByKey(
      workspaceBindings,
      `${cacheKey(client.context)}|${workspaceUrl}`,
      async () => await readMetastoreAssignment(client, workspaceUrl)
    );
  } catch (error) {
    if (isNotFoundWith(error, NO_METASTORE_ASSIGNMENT_CODES)) {
      throw new ConnectorError({
        type: "validation_error",
        message: `Databricks workspace ${workspaceId} has no Unity Catalog metastore. P0 needs one to confirm the workspace's URL. Assign the workspace a metastore, then try again.`,
        payload: { requestId, workspaceId, workspaceUrl },
        cause: error,
      });
    }
    throw error;
  }

  const actualId = String(assignment.workspace_id);
  if (BigInt(actualId) !== BigInt(workspaceId)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `Databricks workspace URL ${workspaceUrl} belongs to workspace ${actualId}, not ${workspaceId}. Check the URL saved for workspace ${workspaceId} in P0.`,
      payload: { requestId, workspaceId, workspaceUrl, actualId },
    });
  }
  return { workspaceId, metastoreId: assignment.metastore_id };
};

/**
 * The client bound to one workspace, once {@link bindWorkspace} confirms its
 * URL answers for its ID. `client.inWorkspace` re-checks the host on every
 * call.
 */
export const inBoundWorkspace = async (
  client: DatabricksClient,
  ref: WorkspaceRef
) => {
  await bindWorkspace(client, ref);
  return client.inWorkspace(ref.workspaceUrl);
};

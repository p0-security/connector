import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
} from "@p0security/connector-core";

import { CONNECTOR_VERSION } from "../databricks/api.ts";
import type { DatabricksWorkspaceClient } from "../databricks/client.ts";

/**
 * The Databricks SQL MCP server's path on Unity Gateway, which only the
 * Unity Gateway beta serves. Genie One is generally available, so only this
 * one is probed.
 */
export const DBSQL_MCP_PATH = "/ai-gateway/mcp-services/system.ai.dbsql";

/**
 * MCP's streamable HTTP transport requires a client to accept both. A server
 * may refuse a request that accepts only JSON with a 406, which would read as
 * the beta being off.
 */
export const MCP_ACCEPT = "application/json, text/event-stream";

/** The MCP protocol version P0 offers. A server answers with the one it speaks. */
const MCP_PROTOCOL_VERSION = "2025-06-18";

/** The header a stateful MCP server names its session in, which every later call must carry. */
const MCP_SESSION_HEADER = "Mcp-Session-Id";

type ProbeContext = {
  requestId: string;
  workspaceId: string;
  /** Whether P0 made its principal the workspace's admin just now. */
  assigned: boolean;
};

/**
 * Whether one MCP call's status says the beta is on (`true`) or off
 * (`false`). Only a 404 says off, since the gateway has no such server then.
 * Any other status that isn't a 2xx fails the probe, so neither a Databricks
 * outage nor a refusal reads as the beta being off.
 *
 * A 401 or 403 means the gateway refused P0's principal. The INT-810 live
 * check got a 403 "Not authorized to invoke MCP service" with the beta on.
 * Right after P0 made itself workspace admin, the workspace may not have seen
 * the new assignment yet. Otherwise the message points at the default
 * `EXECUTE` on `system.ai`, which lets callers invoke the MCP services.
 *
 * TODO(INT-810): that a disabled beta answers 404. It isn't documented, and
 * the live check had no account with the beta off.
 */
const betaAnswer = (status: number, step: string, context: ProbeContext) => {
  const { requestId, workspaceId, assigned } = context;
  if (status >= 200 && status < 300) return true;
  if (assigned && (status === 401 || status === 403)) {
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Databricks hasn't seen P0's new workspace admin assignment in workspace ${workspaceId} yet. Try again in a few minutes.`,
      payload: { requestId, workspaceId, status },
    });
  }
  if (status === 401 || status === 403) {
    throw new ConnectorError({
      type: connectorErrorTypeForHttpStatus(status),
      message: `Databricks Unity Gateway refused P0's service principal on the Databricks SQL MCP server in workspace ${workspaceId} (MCP ${step} answered ${status}). Callers invoke the system.ai MCP servers through the EXECUTE privilege that account users hold on the system.ai schema by default. Make sure account users still hold it, then try again.`,
      payload: { requestId, workspaceId, status },
    });
  }
  if (status === 404) return false;
  throw new ConnectorError({
    type: connectorErrorTypeForHttpStatus(status),
    message: `Databricks Unity Gateway answered MCP ${step} with ${status}, so P0 can't tell whether the Unity Gateway beta is on. Try again in a few minutes.`,
    payload: { requestId, status },
  });
};

/**
 * Asks the workspace's Databricks SQL MCP server for its tools, the way an
 * MCP client starts a session: `initialize`, the `initialized` notification,
 * then `tools/list`, carrying the session ID the server names, if any. It
 * reads only each answer's status, since a body may be an event stream.
 *
 * Returns whether the Unity Gateway beta is on. A call that answers 404 says
 * it's off and stops the probe there. Pass `assigned` from `ensureWorkspaceAdmin`, so a
 * refusal right after the assignment fails rather than reads as off.
 */
export const probeUnityGateway = async (
  workspace: DatabricksWorkspaceClient,
  { workspaceId, assigned }: { workspaceId: string; assigned: boolean }
): Promise<boolean> => {
  const context = { requestId: workspace.requestId, workspaceId, assigned };
  const post = async (body: unknown, sessionId?: string) =>
    await workspace.status({
      method: "POST",
      path: DBSQL_MCP_PATH,
      accept: MCP_ACCEPT,
      headers: sessionId ? { [MCP_SESSION_HEADER]: sessionId } : undefined,
      body,
    });

  const initialize = await post({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: "p0-connector-databricks-ai",
        version: CONNECTOR_VERSION,
      },
    },
  });
  if (!betaAnswer(initialize.status, "initialize", context)) return false;
  const sessionId = initialize.headers.get(MCP_SESSION_HEADER) ?? undefined;

  const initialized = await post(
    { jsonrpc: "2.0", method: "notifications/initialized" },
    sessionId
  );
  if (!betaAnswer(initialized.status, "notifications/initialized", context)) {
    return false;
  }

  const toolsList = await post(
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    sessionId
  );
  return betaAnswer(toolsList.status, "tools/list", context);
};

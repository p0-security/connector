import { ConnectorError, type Logger } from "@p0security/connector";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";

import { failedRequest, isNotFound, parse } from "../databricks/api.ts";
import {
  type DatabricksClient,
  type DatabricksWorkspaceClient,
  asAccountAdmin,
  assertNotOwnPrincipal,
} from "../databricks/client.ts";
import {
  type ScimServicePrincipal,
  newAccountScim,
  scimServicePrincipal,
} from "../databricks/scim.ts";
import {
  ensureWorkspaceAdmin,
  workspaceAssignment,
} from "../databricks/workspace-admin.ts";
import { lookupWorkspace } from "../databricks/workspaces.ts";
import type { AgentContext } from "./context.ts";

/**
 * The ID of the one federation policy P0 puts on an agent principal. The API
 * takes 2 to 63 lowercase letters, digits, hyphens and slashes. A fixed ID
 * makes "the policy is there" an exact check.
 */
export const FEDERATION_POLICY_ID = "p0-databricks";

/** The workspace entitlements an agent principal gets, in the order they are added. */
export const AGENT_ENTITLEMENTS = [
  "workspace-consume",
  "databricks-sql-access",
] as const;

/** The workspace permission an agent principal is assigned. */
const USER = "USER";

const SCIM_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/** Account SCIM service principals, relative to the account API. */
const ACCOUNT_PRINCIPALS = "/scim/v2/ServicePrincipals";

/** Workspace SCIM service principals, as a full workspace API path. */
const WORKSPACE_PRINCIPALS = "/api/2.0/preview/scim/v2/ServicePrincipals";

/** Guards against a server that keeps returning a next page. */
// A principal has one federation policy, so 100 pages is far past any real
// list and still ends a looping server quickly.
const MAX_PAGES = 100;

/**
 * The waits, in milliseconds, between lookups of an agent principal the
 * workspace doesn't list yet. They add up to 60 s, so the whole grant still
 * finishes well inside the connector's 270 s Lambda timeout.
 */
const LISTED_RETRY_DELAYS = [2_000, 4_000, 8_000, 16_000, 30_000];

const accountPrincipalPath = (id: string) =>
  `${ACCOUNT_PRINCIPALS}/${encodeURIComponent(id)}`;

const policiesPath = (principalId: string) =>
  `/servicePrincipals/${encodeURIComponent(principalId)}/federationPolicies`;

const assignmentPath = (workspaceId: string, principalId: string) =>
  `/workspaces/${encodeURIComponent(workspaceId)}/permissionassignments/principals/${encodeURIComponent(principalId)}`;

/** Runs `call` and counts a Databricks 404 as done. */
const unlessGone = async (call: () => Promise<unknown>) => {
  try {
    await call();
  } catch (error) {
    if (!isNotFound(error)) throw error;
  }
};

/**
 * The federation policy body for the agent principal. Databricks then trades
 * a token P0's auth server signed for this session's subject, with the
 * account as its audience, for the principal's own Databricks token.
 */
export const federationPolicyBody = (context: AgentContext) => {
  const { accountId, federation } = context;
  return {
    oidc_policy: {
      issuer: federation.issuer,
      audiences: [accountId],
      subject: federation.subject,
    },
  };
};

/**
 * The service principal whose display name is exactly `name`, or `null`.
 * Account SCIM's `eq` may ignore case, so a principal whose name differs
 * only in case is not P0's. Two matches fail, and so does P0's own principal.
 * It doesn't check the principal's application ID: `principal.stage` uses it
 * before there is one to check.
 */
export const principalByName = async (
  client: DatabricksClient,
  name: string
): Promise<ScimServicePrincipal | null> => {
  const found =
    await newAccountScim(client).servicePrincipalByDisplayName(name);
  if (!found || found.displayName !== name) return null;
  assertNotOwnPrincipal(
    await client.ownServicePrincipal(),
    found,
    client.context.requestId
  );
  return found;
};

/**
 * The refusal for a grant whose principal isn't the one stage created. A
 * principal created now would get a new application ID, which neither the
 * gateway nor any later call knows, so only `principal.stage` creates one.
 */
// A `validation_error`, the framework's type for a request refused before
// acting, since retrying the same request can't succeed.
const notStaged = (context: AgentContext, name: string, problem: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `${problem} P0 grants only to the service principal it created when the request was staged. Make the request again.`,
    payload: {
      requestId: context.requestId,
      principalName: name,
      agentApplicationId: context.agentApplicationId,
    },
  });

/**
 * The agent principal named `name`, by {@link principalByName}, or `null`.
 * One whose application ID isn't the one stage recorded is refused.
 */
export const findPrincipal = async (
  client: DatabricksClient,
  context: AgentContext,
  name: string
): Promise<ScimServicePrincipal | null> => {
  const found = await principalByName(client, name);
  if (
    found &&
    found.applicationId.toLowerCase() !==
      context.agentApplicationId.toLowerCase()
  ) {
    throw notStaged(
      context,
      name,
      `Databricks service principal ${name} has application ID ${found.applicationId}, not ${context.agentApplicationId}.`
    );
  }
  return found;
};

const policyList = z.object({
  policies: z
    .array(
      z.object({
        policy_id: z.string().optional(),
        /** `accounts/<account>/servicePrincipals/<id>/federationPolicies/<policy id>`. */
        name: z.string().optional(),
      })
    )
    .optional(),
  next_page_token: z.string().optional(),
});

/** The IDs of every federation policy on a service principal. */
const policyIds = async (
  client: DatabricksClient,
  principalId: string
): Promise<string[]> => {
  const { context } = client;
  const ids: string[] = [];
  let pageToken: string | undefined;
  for (let count = 0; count < MAX_PAGES; count++) {
    const page = parse({
      schema: policyList,
      data: await asAccountAdmin(context, async () =>
        client.account({
          method: "GET",
          path: policiesPath(principalId),
          query: pageToken ? { page_token: pageToken } : undefined,
        })
      ),
      what: "service principal federation policies",
      requestId: context.requestId,
    });
    for (const { policy_id, name } of page.policies ?? []) {
      const id = policy_id ?? name?.split("/").at(-1);
      if (id) ids.push(id);
    }
    pageToken = page.next_page_token || undefined;
    if (!pageToken) return ids;
  }
  throw new ConnectorError({
    type: "unknown",
    message: `Databricks federation policies list returned more than ${MAX_PAGES} pages`,
    payload: { requestId: context.requestId },
  });
};

const deletePolicy = async (
  client: DatabricksClient,
  principalId: string,
  policyId: string
) =>
  await unlessGone(async () =>
    asAccountAdmin(client.context, async () =>
      client.account({
        method: "DELETE",
        path: `${policiesPath(principalId)}/${encodeURIComponent(policyId)}`,
      })
    )
  );

/** Deletes every federation policy on the principal. */
const deletePolicies = async (
  client: DatabricksClient,
  principalId: string
) => {
  for (const policyId of await policyIds(client, principalId)) {
    await deletePolicy(client, principalId, policyId);
  }
};

const unassign = async (
  client: DatabricksClient,
  workspaceId: string,
  principalId: string
) =>
  await unlessGone(async () =>
    asAccountAdmin(client.context, async () =>
      client.account({
        method: "DELETE",
        path: assignmentPath(workspaceId, principalId),
      })
    )
  );

/**
 * Runs a workspace call made just after P0's principal was assigned there.
 * A workspace can take a while to see a new assignment and refuse P0 with a
 * 401 or 403 meanwhile, so that refusal says to try again, as a retryable
 * failure, not as a missing role.
 */
const whileAssignmentSettles = async <T>(
  workspace: DatabricksWorkspaceClient,
  workspaceId: string,
  call: () => Promise<T>
): Promise<T> => {
  try {
    return await call();
  } catch (error) {
    const status = failedRequest(error)?.status;
    if (status !== 401 && status !== 403) throw error;
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Databricks workspace ${workspaceId} refused P0's service principal (${status}). A new workspace assignment can take a few minutes to reach a workspace. Try again shortly.`,
      payload: { requestId: workspace.requestId, workspaceId, status },
      cause: error,
    });
  }
};

const workspacePrincipal = z.object({
  id: z.string().min(1),
  applicationId: z.string(),
  entitlements: z.array(z.object({ value: z.string() })).optional(),
});

/**
 * The agent principal's ID in the workspace's own SCIM, or `undefined` when
 * the workspace doesn't list it. The entitlements API takes that ID, which
 * the docs don't promise equals the account SCIM ID, so it is looked up by
 * application ID.
 */
const listedPrincipalId = async (
  workspace: DatabricksWorkspaceClient,
  context: AgentContext
): Promise<string | undefined> => {
  const { agentApplicationId, requestId } = context;
  const { Resources = [] } = parse({
    schema: z.object({ Resources: z.array(workspacePrincipal).optional() }),
    data: await workspace.call({
      method: "GET",
      path: WORKSPACE_PRINCIPALS,
      query: { filter: `applicationId eq "${agentApplicationId}"` },
    }),
    what: "workspace SCIM ServicePrincipals",
    requestId,
  });
  return Resources.find(
    (principal) =>
      principal.applicationId.toLowerCase() === agentApplicationId.toLowerCase()
  )?.id;
};

/**
 * The agent principal's workspace SCIM ID, by {@link listedPrincipalId}.
 * The assignment just made can take a while to reach the workspace, so a
 * principal it doesn't list is looked up again after each of
 * {@link LISTED_RETRY_DELAYS} before the grant fails.
 */
const workspacePrincipalId = async (
  workspace: DatabricksWorkspaceClient,
  context: AgentContext
): Promise<string> => {
  const { agentApplicationId, requestId, workspaceId } = context;
  for (const delay of [0, ...LISTED_RETRY_DELAYS]) {
    if (delay > 0) await sleep(delay);
    const id = await listedPrincipalId(workspace, context);
    if (id !== undefined) return id;
  }
  throw new ConnectorError({
    type: "upstream_unavailable",
    message: `Databricks workspace ${workspaceId} doesn't list service principal ${agentApplicationId} yet. Try again shortly.`,
    payload: { requestId, workspaceId, agentApplicationId },
  });
};

const patchEntitlement = async (
  workspace: DatabricksWorkspaceClient,
  id: string,
  op: "add" | "remove",
  entitlement: string
) =>
  await workspace.call({
    method: "PATCH",
    path: `${WORKSPACE_PRINCIPALS}/${encodeURIComponent(id)}`,
    body: {
      schemas: [SCIM_PATCH_OP],
      Operations: [
        { op, path: "entitlements", value: [{ value: entitlement }] },
      ],
    },
  });

/**
 * Fails unless the principal holds every one of {@link AGENT_ENTITLEMENTS}
 * directly. Groups the principal is in may grant more, which isn't checked.
 *
 * terraform-provider-databricks issue 6039 reports `workspace-consume`
 * dropping `databricks-sql-access`. The INT-810 live check saw a principal
 * keep both. If one is ever dropped, this fails the grant, as it should.
 */
const assertEntitlements = async (
  workspace: DatabricksWorkspaceClient,
  context: AgentContext,
  id: string
) => {
  const { entitlements = [] } = parse({
    schema: workspacePrincipal,
    data: await workspace.call({
      method: "GET",
      path: `${WORKSPACE_PRINCIPALS}/${encodeURIComponent(id)}`,
    }),
    what: "workspace SCIM ServicePrincipals",
    requestId: context.requestId,
  });
  const held = new Set(entitlements.map(({ value }) => value));
  const missing = AGENT_ENTITLEMENTS.filter((value) => !held.has(value));
  if (missing.length > 0) {
    throw new ConnectorError({
      type: "unknown",
      message: `Databricks workspace ${context.workspaceId} didn't keep entitlements ${missing.join(", ")} for service principal ${context.agentApplicationId}`,
      payload: { requestId: context.requestId, missing: missing.join(", ") },
    });
  }
};

/**
 * The agent principal's name if its grant setup finished, which its
 * federation policy, created last, shows. An active principal without it is
 * reported missing, so a grant sets it up and a revoke sees it as already
 * gone. One that holds another policy or a workspace assignment was left by
 * a create that never finished, and those are removed here. One that holds
 * neither is the bare principal `principal.stage` created, and nothing is
 * changed.
 *
 * An inactive principal is returned whatever it holds. Revoke deactivates it
 * first, so a revoke that failed after removing the policy must still find
 * it, for the retry to finish.
 */
export const getUser = async (
  client: DatabricksClient,
  logger: Logger,
  context: AgentContext,
  name: string
): Promise<string | null> => {
  const principal = await findPrincipal(client, context, name);
  if (!principal) return null;
  if (principal.active === false) return name;
  const policies = await policyIds(client, principal.id);
  if (policies.includes(FEDERATION_POLICY_ID)) return name;
  const assigned =
    (await workspaceAssignment(client, context.workspaceId, principal)) !==
    undefined;
  // A bare principal is what `principal.stage` leaves, so it isn't a leftover.
  if (policies.length === 0 && !assigned) return null;
  logger.warn(
    { principalId: principal.id },
    "found an agent principal without its federation policy, removing its policies and workspace assignment"
  );
  for (const policyId of policies) {
    await deletePolicy(client, principal.id, policyId);
  }
  if (assigned) await unassign(client, context.workspaceId, principal.id);
  return null;
};

type Undo = { label: string; run: () => Promise<unknown> };

/**
 * Sets up the principal `principal.stage` created for the grant: P0's
 * principal becomes workspace admin (never undone), the agent principal is
 * assigned to the workspace as a user with {@link AGENT_ENTITLEMENTS}, read
 * back, and its federation policy is created last. The requested data is
 * granted later, by `setPoliciesForUser`.
 *
 * A missing principal, or one with another application ID, is refused (see
 * {@link notStaged}).
 *
 * Each write registers its undo before it runs, since a write that timed out
 * may still have landed. When a step fails, the undos run in reverse, each
 * failure is logged, and the step's error is thrown. That leaves the bare
 * principal, which can't get a token without its policy.
 */
export const createUser = async (
  client: DatabricksClient,
  logger: Logger,
  context: AgentContext,
  name: string
): Promise<string> => {
  const { workspaceId } = context;
  const principal = await findPrincipal(client, context, name);
  if (!principal) {
    throw notStaged(
      context,
      name,
      `No Databricks service principal is named ${name}.`
    );
  }
  const workspace = await lookupWorkspace(client, workspaceId);
  await ensureWorkspaceAdmin(client, workspaceId);
  const inWorkspace = client.inWorkspace(workspace.host);

  const undos: Undo[] = [];
  try {
    undos.push({
      label: "unassign from workspace",
      run: () => unassign(client, workspaceId, principal.id),
    });
    await asAccountAdmin(context, async () =>
      client.account({
        method: "PUT",
        path: assignmentPath(workspaceId, principal.id),
        body: { permissions: [USER] },
      })
    );

    const id = await whileAssignmentSettles(inWorkspace, workspaceId, () =>
      workspacePrincipalId(inWorkspace, context)
    );
    for (const entitlement of AGENT_ENTITLEMENTS) {
      undos.push({
        label: `remove entitlement ${entitlement}`,
        run: () => patchEntitlement(inWorkspace, id, "remove", entitlement),
      });
      await whileAssignmentSettles(inWorkspace, workspaceId, () =>
        patchEntitlement(inWorkspace, id, "add", entitlement)
      );
    }
    await assertEntitlements(inWorkspace, context, id);

    undos.push({
      label: "delete federation policy",
      run: () => deletePolicy(client, principal.id, FEDERATION_POLICY_ID),
    });
    await asAccountAdmin(context, async () =>
      client.account({
        method: "POST",
        path: policiesPath(principal.id),
        query: { policy_id: FEDERATION_POLICY_ID },
        body: federationPolicyBody(context),
      })
    );
    logger.info(
      { principalId: principal.id },
      "set up agent principal in the workspace"
    );
    return name;
  } catch (error) {
    for (const undo of [...undos].reverse()) {
      await undo
        .run()
        .catch((undoError: unknown) =>
          logger.error(
            { undo: undo.label, error: undoError },
            "failed to undo a step of a failed grant"
          )
        );
    }
    throw error;
  }
};

/**
 * Deletes the agent principal's federation policies, then the principal,
 * which also ends its workspace assignment. Each step counts a 404 as done,
 * and no principal is done. The principal goes last because it is what
 * {@link getUser} looks for, so a delete that fails partway is found and
 * finished by the retry.
 */
export const deleteUser = async (
  client: DatabricksClient,
  logger: Logger,
  context: AgentContext,
  name: string
): Promise<void> => {
  const principal = await findPrincipal(client, context, name);
  if (!principal) return;
  await deletePolicies(client, principal.id);
  await unlessGone(async () =>
    asAccountAdmin(context, async () =>
      client.account({
        method: "DELETE",
        path: accountPrincipalPath(principal.id),
      })
    )
  );
  logger.info({ principalId: principal.id }, "deleted agent principal");
};

/**
 * Deactivates the principal in account SCIM, so Databricks issues it no new
 * token. Repeating it is safe.
 *
 * The body follows the API reference's example, which sends `active` as
 * `[{"value":"false"}]`, not a plain `false`. The INT-810 live check on
 * 2026-10-21 measured it: new token exchanges were refused about 78 seconds
 * later, but the token the principal already held still worked 300 seconds
 * later. That token lives until it expires, up to about 15 minutes, and
 * Databricks documents no way to revoke it.
 */
export const deactivatePrincipal = async (
  client: DatabricksClient,
  principalId: string
) =>
  await asAccountAdmin(client.context, async () =>
    client.account({
      method: "PATCH",
      path: accountPrincipalPath(principalId),
      body: {
        schemas: [SCIM_PATCH_OP],
        Operations: [
          { op: "replace", path: "active", value: [{ value: "false" }] },
        ],
      },
    })
  );

/**
 * Creates the bare principal named `name` in account SCIM, active and with
 * nothing else, and returns it.
 */
export const createPrincipal = async (
  client: DatabricksClient,
  name: string
): Promise<ScimServicePrincipal> => {
  const { context } = client;
  return parse({
    schema: scimServicePrincipal,
    data: await asAccountAdmin(context, async () =>
      client.account({
        method: "POST",
        path: ACCOUNT_PRINCIPALS,
        body: { displayName: name, active: true },
      })
    ),
    what: "account SCIM ServicePrincipals",
    requestId: context.requestId,
  });
};

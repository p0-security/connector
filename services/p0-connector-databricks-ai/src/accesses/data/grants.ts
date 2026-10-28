import {
  ConnectorError,
  type Logger,
  throwAssertNever,
} from "@p0security/connector";
import { z } from "zod";

import { deactivatePrincipal, findPrincipal } from "../../agent/agent.ts";
import { parse } from "../../databricks/api.ts";
import type {
  DatabricksClient,
  DatabricksWorkspaceClient,
} from "../../databricks/client.ts";
import { lookupWorkspace } from "../../databricks/workspaces.ts";
import {
  NAME_PARTS,
  type Policy,
  type RequestContext,
  type RequestGrant,
} from "./definition.ts";
import {
  type OwnableKind,
  type PermissionsSecurable,
  type UcItem,
  type UnityCatalog,
  isSecurableNotFound,
  isUnknownPrincipal,
  newUnityCatalog,
  securableKey,
} from "./unity-catalog.ts";

const CAN_USE = "CAN_USE";

type SecurableChange = {
  securable: PermissionsSecurable;
  privileges: string[];
};

const securableOf = ({ securableType, fullName }: RequestGrant) => ({
  type: securableType,
  fullName,
});

/** Identifies a grant's securable. UC names are case-insensitive, so the name is lowercased. */
const securableKeyOf = (grant: RequestGrant) =>
  securableKey(securableOf(grant));

/** Identifies one grant. */
const grantKeyOf = (grant: RequestGrant) =>
  `${grant.privilege}@${securableKeyOf(grant)}`;

/**
 * Groups grants by securable, so each securable takes one `PATCH`, ordered
 * catalog first. Revokes walk the result in reverse, leaves first.
 */
const bySecurable = (grants: RequestGrant[]): SecurableChange[] => {
  const sorted = [...grants].sort(
    (a, b) => NAME_PARTS[a.securableType] - NAME_PARTS[b.securableType]
  );
  const firstPerSecurable = sorted.filter(
    (grant, index) =>
      sorted.findIndex(
        (other) => securableKeyOf(other) === securableKeyOf(grant)
      ) === index
  );
  return firstPerSecurable.map((first) => ({
    securable: securableOf(first),
    privileges: [
      ...new Set(
        sorted
          .filter((grant) => securableKeyOf(grant) === securableKeyOf(first))
          .map(({ privilege }) => privilege)
      ),
    ],
  }));
};

const warehousePermissionsPath = (warehouseId: string) =>
  `/api/2.0/permissions/warehouses/${encodeURIComponent(warehouseId)}`;

const warehouseAcl = z.object({
  access_control_list: z
    .array(
      z.object({
        service_principal_name: z.string().optional(),
        all_permissions: z
          .array(z.object({ permission_level: z.string() }))
          .optional(),
      })
    )
    .optional(),
});

/** Whether the agent principal holds `CAN_USE` on the warehouse. */
const canUseWarehouse = async (
  workspace: DatabricksWorkspaceClient,
  { warehouseId, agentApplicationId, requestId }: RequestContext
) => {
  const { access_control_list = [] } = parse({
    schema: warehouseAcl,
    data: await workspace.call({
      method: "GET",
      path: warehousePermissionsPath(warehouseId),
    }),
    what: "SQL warehouse permissions",
    requestId,
  });
  return access_control_list.some(
    ({ service_principal_name, all_permissions = [] }) =>
      service_principal_name?.toLowerCase() ===
        agentApplicationId.toLowerCase() &&
      all_permissions.some(
        ({ permission_level }) => permission_level === CAN_USE
      )
  );
};

/** The client bound to the workspace the grant is in, and its Unity Catalog. */
const inGrantWorkspace = async (
  client: DatabricksClient,
  context: RequestContext
) => {
  const workspace = client.inWorkspace(
    (await lookupWorkspace(client, context.workspaceId)).host
  );
  return { workspace, uc: newUnityCatalog(workspace) };
};

/**
 * The Unity Catalog of the workspace the grant was made in, for a revoke.
 * The grants are on the metastore, so the workspace may be in any status. A
 * deleted one leaves no way in, and the message says how to finish the
 * revoke by hand, in the order the Databricks docs give.
 */
const revokeCatalog = async (
  client: DatabricksClient,
  context: RequestContext,
  name: string
) => {
  const { accountId, workspaceId, agentApplicationId, ownerPrincipal } =
    context;
  // The account workspaces API answers 404 for a missing workspace, as the
  // INT-810 live check saw, which is what gives this message.
  const { host } = await lookupWorkspace(client, workspaceId, {
    anyStatus: true,
    missingMessage: `Databricks account ${accountId} has no workspace ${workspaceId}, so P0 can't revoke service principal ${name} (${agentApplicationId}) through it. Its grants are on the workspace's metastore and stay there. To remove them, have a metastore admin work from another workspace on the same metastore. First hand anything that principal owns to ${ownerPrincipal}, then revoke every privilege it holds. Last, delete service principal ${name} in the account console.`,
  });
  return newUnityCatalog(client.inWorkspace(host));
};

/**
 * Grants the agent principal its data: `CAN_USE` on the warehouse, then the
 * policies, catalog first. It then reads all of it back and fails on any
 * mismatch. Every write only adds, so repeating it is safe.
 *
 * Nothing is granted on the MCP services. Databricks doesn't expose the
 * `system.ai` ones as grantable securables, and `account users` hold
 * `EXECUTE` on the `system.ai` schema by default, which lets the agent call
 * them. The warehouse and Unity Catalog grants decide what it can reach.
 *
 * Every policy must be one of the request's `addedGrants`, since revoke
 * removes only those. P0's own principal is refused, as `createUser` refuses
 * it. Databricks not knowing the principal yet is left as its own failure,
 * so the grant's retries cover a principal that has only just been created.
 */
export const grantData = async (
  client: DatabricksClient,
  logger: Logger,
  context: RequestContext,
  policies: Policy[]
) => {
  const { requestId, agentApplicationId, applicationId, warehouseId } = context;
  if (agentApplicationId.toLowerCase() === applicationId.toLowerCase()) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "P0 cannot grant access to its own Databricks service principal.",
      payload: { requestId },
    });
  }
  const added = new Set(context.addedGrants.map(grantKeyOf));
  const unrecorded = policies.filter(
    (policy) => !added.has(grantKeyOf(policy))
  );
  if (unrecorded.length > 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: `A grant's policies must all be in its added grants, but these aren't: ${unrecorded
        .map(grantKeyOf)
        .join(", ")}.`,
      payload: { requestId },
    });
  }

  const { workspace, uc } = await inGrantWorkspace(client, context);
  await workspace.call({
    method: "PATCH",
    path: warehousePermissionsPath(warehouseId),
    body: {
      access_control_list: [
        {
          service_principal_name: agentApplicationId,
          permission_level: CAN_USE,
        },
      ],
    },
  });
  const changes = bySecurable(policies);
  for (const { securable, privileges } of changes) {
    await uc.updatePrivileges(securable, agentApplicationId, {
      add: privileges,
    });
  }

  const mismatches: string[] = [];
  if (!(await canUseWarehouse(workspace, context))) {
    mismatches.push(`warehouse ${warehouseId} is missing ${CAN_USE}`);
  }
  for (const { securable, privileges } of changes) {
    const held = await uc.directPrivileges(securable, agentApplicationId);
    const missing = privileges.filter((privilege) => !held.has(privilege));
    if (missing.length > 0) {
      mismatches.push(
        `${securable.type} ${securable.fullName} is missing ${missing.join(", ")}`
      );
    }
  }
  if (mismatches.length > 0) {
    // Databricks took every write, so the mismatch is on its side, as Argo
    // CD's and Harbor's read-backs treat theirs.
    throw new ConnectorError({
      type: "dependency_violation",
      message: `Databricks permissions for ${agentApplicationId} don't match after the grant: ${mismatches.join(", and ")}`,
      payload: { requestId, agentApplicationId },
    });
  }
  logger.info(
    { nPolicies: policies.length },
    "granted data to the agent principal"
  );
};

/** One object the agent may own, by the API that serves it. */
type Ownable = { kind: OwnableKind; fullName: string; owner?: string };

/** Runs a Unity Catalog read, and returns `fallback` when its securable is gone. */
const unlessDropped = async <T>(read: () => Promise<T>, fallback: T) => {
  try {
    return await read();
  } catch (error) {
    if (isSecurableNotFound(error)) return fallback;
    throw error;
  }
};

const ownablesIn = async (
  uc: UnityCatalog,
  catalog: string,
  schema: string
): Promise<Ownable[]> => {
  const ownables: Ownable[] = [];
  for (const kind of ["tables", "volumes", "functions"] as const) {
    const items = await unlessDropped<UcItem[]>(
      () => uc.list(kind, { catalog_name: catalog, schema_name: schema }),
      []
    );
    for (const { name, full_name, owner } of items) {
      ownables.push({
        kind,
        fullName: full_name ?? `${catalog}.${schema}.${name}`,
        owner,
      });
    }
  }
  return ownables;
};

/**
 * Every table, volume and function under the securable: a catalog's schemas
 * each, a schema's, or the one table or volume. The tables list holds views,
 * materialized views, streaming tables and metric views too. An agent can't
 * own a schema, since no level grants `CREATE_SCHEMA`. A dropped securable
 * holds nothing.
 */
const ownablesUnder = async (
  uc: UnityCatalog,
  { securable }: RequestContext
): Promise<Ownable[]> => {
  const [catalog = "", schema = ""] = securable.fullName.split(".");
  switch (securable.type) {
    case "catalog": {
      const schemas = await unlessDropped<UcItem[]>(
        () => uc.list("schemas", { catalog_name: catalog }),
        []
      );
      const ownables: Ownable[] = [];
      for (const { name } of schemas) {
        ownables.push(...(await ownablesIn(uc, catalog, name)));
      }
      return ownables;
    }
    case "schema":
      return await ownablesIn(uc, catalog, schema);
    case "table":
    case "volume": {
      const kind = securable.type === "table" ? "tables" : "volumes";
      const item = await unlessDropped(
        () => uc.get(kind, securable.fullName),
        undefined
      );
      return item
        ? [{ kind, fullName: securable.fullName, owner: item.owner }]
        : [];
    }
    default:
      throw throwAssertNever(securable.type);
  }
};

/**
 * Hands everything the agent owns under the securable to the owner
 * principal. Unity Catalog names a service principal owner by its
 * application ID. A failure throws, and the retry finds what is left.
 */
const transferOwnership = async (
  uc: UnityCatalog,
  logger: Logger,
  context: RequestContext
) => {
  const agent = context.agentApplicationId.toLowerCase();
  const owned = (await ownablesUnder(uc, context)).filter(
    ({ owner }) => owner?.toLowerCase() === agent
  );
  for (const { kind, fullName } of owned) {
    await uc.setOwner(kind, fullName, context.ownerPrincipal);
  }
  if (owned.length > 0) {
    logger.info(
      { transferred: owned.map(({ fullName }) => fullName) },
      "transferred what the agent owned to the owner principal"
    );
  }
};

/**
 * Revokes the agent principal: it is deactivated, so it gets no new token,
 * then its grants are removed, leaves first. The token it already holds
 * keeps working until it expires, up to about 15 minutes, with its grants
 * already gone. Then, if the request added a `CREATE_*` privilege, whatever
 * it owns under the securable goes to the owner principal. Revoking first
 * means a failed transfer can't leave a grant in place.
 *
 * `CAN_USE` on the warehouse stays until the principal is deleted, because
 * removing one entry means rewriting the warehouse's whole access list.
 *
 * Every call is attempted, the principal's lookup and deactivation
 * included, and the first failure is thrown once all have run. A dropped
 * securable, or a principal the metastore no longer knows, counts as done.
 * Every step repeats safely, so a failed revoke is retried from the start,
 * and `deleteUser` runs this before it deletes anything.
 */
export const revokeAgent = async (
  client: DatabricksClient,
  logger: Logger,
  context: RequestContext,
  name: string
) => {
  const { agentApplicationId } = context;
  const failures: unknown[] = [];
  try {
    const principal = await findPrincipal(client, context, name);
    if (principal && principal.active !== false) {
      await deactivatePrincipal(client, principal.id);
    }
  } catch (error) {
    logger.warn(
      { error },
      "deactivating the agent principal failed on revoke, attempting the rest"
    );
    failures.push(error);
  }

  const uc = await revokeCatalog(client, context, name);
  const removals = bySecurable(context.addedGrants).reverse();
  for (const { securable, privileges } of removals) {
    try {
      await uc.updatePrivileges(securable, agentApplicationId, {
        remove: privileges,
      });
    } catch (error) {
      if (isSecurableNotFound(error) || isUnknownPrincipal(error)) {
        logger.warn(
          { securable },
          "securable or principal not found on revoke, treating as revoked"
        );
        continue;
      }
      logger.warn(
        { securable, error },
        "privilege change failed on revoke, attempting the rest"
      );
      failures.push(error);
    }
  }

  // Only a CREATE_* privilege lets the agent create, and so own, anything.
  const couldCreate = context.addedGrants.some(({ privilege }) =>
    privilege.toUpperCase().startsWith("CREATE_")
  );
  if (couldCreate) {
    try {
      await transferOwnership(uc, logger, context);
    } catch (error) {
      logger.warn(
        { error },
        "ownership transfer failed on revoke, the retry finishes it"
      );
      failures.push(error);
    }
  }
  if (failures.length > 0) throw failures[0];
  logger.info("revoked the agent principal");
};

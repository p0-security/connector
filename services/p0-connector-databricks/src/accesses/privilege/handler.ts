import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";

import {
  type DatabricksClient,
  newDatabricksClient,
} from "../../databricks/client.ts";
import {
  type WorkspaceRef,
  bindWorkspace,
  inBoundWorkspace,
} from "../../databricks/workspaces.ts";
import { verifyEmailDomain } from "../../domain.ts";
import {
  isUnknownDatabricksUser,
  neverDeleteUser,
  userMustAlreadyExist,
} from "../common/handler.ts";
import {
  NAME_PARTS,
  type RequestGrant,
  type Securable,
  isUcPrivilege,
  spec,
} from "./definition.ts";
import {
  type UnityCatalog,
  grantKey,
  isSecurableNotFound,
  newUnityCatalog,
  securableKey,
} from "./unity-catalog.ts";

type PrivilegeSchema = ResourceRootSchemaOf<typeof spec>;
type Operation = PrivilegeSchema["RequestContext"]["operation"];

type SecurableChange = { securable: Securable; privileges: string[] };

/** What a revoke logs when Databricks knows no principal by the user's email. */
const USER_GONE_WARNING = "user not found on revoke; treating as revoked";

/**
 * Groups grants by securable, so each securable takes one `PATCH`, ordered
 * catalog first. Revokes walk the result in reverse, leaves first.
 */
const bySecurable = (grants: RequestGrant[]): Map<string, SecurableChange> => {
  const changes = new Map<string, SecurableChange>();
  const sorted = [...grants].sort(
    (a, b) => NAME_PARTS[a.securableType] - NAME_PARTS[b.securableType]
  );
  for (const { securableType, fullName, privilege } of sorted) {
    const securable = { type: securableType, fullName };
    const key = securableKey(securable);
    const change = changes.get(key) ?? { securable, privileges: [] };
    if (!change.privileges.includes(privilege)) {
      change.privileges.push(privilege);
    }
    changes.set(key, change);
  }
  return changes;
};

const policyKey = (grant: RequestGrant) =>
  `${grant.privilege}@${securableKey({
    type: grant.securableType,
    fullName: grant.fullName,
  })}`;

/** The grants' keys (see {@link grantKey}), for a message. */
const grantKeys = (grants: RequestGrant[]) =>
  grants
    .map(({ securableType, fullName, privilege }) =>
      grantKey(privilege, { type: securableType, fullName })
    )
    .join(", ");

/**
 * The client bound to the workspace P0 recorded at stage, by its ID and URL.
 * A revoke can't go through a workspace it can't bind, such as one deleted
 * since, but the grants it removes live on the metastore, so they outlive
 * the workspace. So when a call that removes grants can't bind, the error
 * names those grants, for whoever removes them by hand, and keeps the
 * binding error's type. A call that removes nothing fails with the binding's
 * own error.
 */
const inRecordedWorkspace = async ({
  client,
  workspace,
  principal,
  removed,
  requestId,
}: {
  client: DatabricksClient;
  workspace: WorkspaceRef;
  principal: string;
  /** The grants the call removes. */
  removed: RequestGrant[];
  requestId: string;
}) => {
  try {
    return await inBoundWorkspace(client, workspace);
  } catch (error) {
    if (removed.length === 0) throw error;
    const { workspaceId, workspaceUrl } = workspace;
    const grants = grantKeys(removed);
    throw new ConnectorError({
      type: error instanceof ConnectorError ? error.data.type : "unknown",
      message: `P0 can't reach Databricks workspace ${workspaceId} at ${workspaceUrl} to revoke. If the workspace was deleted, Unity Catalog grants outlive it, so remove these from ${principal} by hand in another workspace on the same metastore: ${grants}`,
      payload: { requestId, workspaceId, workspaceUrl, principal, grants },
      cause: error,
    });
  }
};

/**
 * Unity Catalog privileges, granted straight to a user's existing Databricks
 * account (resource root).
 *
 * The grantee is the requestor's email, which is their Databricks username,
 * and the connector never looks the user up: it calls only the token
 * endpoint and the workspace. The user ID parser refuses anything that isn't
 * an email, which rules out service principals and bare group names. The
 * connector can't name itself either, because a service principal's Unity
 * Catalog principal is its application ID, which isn't an email. A grant to
 * an email Databricks doesn't know fails, and a revoke counts it as done. The
 * connector never creates or deletes users.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<PrivilegeSchema>(t, spec, (ctx: ConnectorContext) => ({
    // Never null: a null `user` skips the framework's check entirely.
    validation: ({ requestId, operation }) => ({
      user: {
        // Domain verification gates a user resolved from an email, and throws
        // a refusal that says why. A body carrying the `userName` P0 recorded
        // at stage names a user P0 already verified, so that lookup checks
        // nothing and logs nothing: a lookup never changes access, and
        // `setPoliciesForUser` makes the decision. The framework also runs
        // this before `deleteUser` and `setPoliciesForUser`, and a revoke is
        // never refused: it only warns, as `setPoliciesForUser` does. This
        // runs before the policies are seen, so it takes the call for a
        // revoke by its `operation` alone.
        userIsNamespacedByBody: async ({ email, userName }) => {
          if (!userName) {
            verifyEmailDomain({
              email,
              requestId,
              alreadyGranted: operation === "revoke",
            });
          }
          return true;
        },
        // Domain verification for an ID runs once, in `setPoliciesForUser`.
        userIsNamespacedById: async () => true,
      },
    }),

    /**
     * The `userName` P0 recorded at stage, when there is one, and otherwise
     * the requestor's email, which is the Databricks username P0 grants to.
     * It calls nothing: `validation` already ran domain verification on an
     * email without a recorded `userName`. So it never returns `null`, and
     * `createUser` is never reached. A Databricks user that doesn't exist
     * fails the grant instead.
     *
     * This doesn't read `operation`, and `validation` reads it only to warn
     * rather than refuse on a revoke. A lookup that rolls back a failed
     * grant says `"grant"`, but it carries the recorded `userName` like a
     * revoke's, so domain verification never refuses it.
     */
    getUser: async (_context, { email, userName }) => userName ?? email,

    createUser: userMustAlreadyExist,

    deleteUser: neverDeleteUser,

    /**
     * Removes this request's grants that no remaining request needs
     * (`requestGrants − policies`), leaves first, then adds the ones still
     * wanted (`policies ∩ requestGrants`) that aren't already held, then
     * reads the permissions it changed back and fails if they don't match.
     *
     * A call is a revoke when the context's `operation` says so, or when it
     * removes anything. The policies alone can't say: a revoke whose grants
     * an open sibling request still holds removes nothing, just like a grant.
     * Nor can `operation` alone: the control plane sets it from the request's
     * status, so the calls that roll back a grant that failed partway say
     * `"grant"`, and they remove its grants. Every other call is a grant.
     * Only a rollback should say `"grant"` and remove anything, so taking a
     * call for a revoke against its label logs a warning.
     *
     * Only a revoke removes anything, and its adds only repair a grant it
     * shares with an open sibling. It removes first, so a failed repair
     * can't keep this request's own grants in place, and it attempts every
     * call even when one fails, then throws the first failure: a failed
     * grant's rollback runs only once and is never retried. A grant stops at
     * its first failure.
     *
     * A grant whose policies name a privilege outside `UC_PRIVILEGES` is
     * refused. A revoke's policies may name one, since its siblings' stored
     * grants can, but it is never added. In a revoke, a securable that no
     * longer exists counts as done for every grant on it, and an email that
     * names no Databricks principal counts as done for the whole call. In a
     * grant either fails, the second with an error that says to add the
     * Databricks user. A revoke that can't bind its workspace, such as one
     * deleted since stage, fails naming the grants left to remove by hand
     * (see `inRecordedWorkspace`).
     *
     * `policies` is the union of every open request's grants in the catalog,
     * so a privilege another request still needs, such as a shared
     * `USE_SCHEMA`, is never revoked. Nothing outside `requestGrants` is ever
     * written: a sibling request's securable that has since been dropped
     * can't block this request, and the audit log never shows this request
     * granting a sibling's privileges.
     */
    setPoliciesForUser: async (context, userId, _user, policies) => {
      const { requestId, workspaceId, workspaceUrl, requestGrants, operation } =
        context;

      const wanted = new Set(policies.map(policyKey));
      const requested = new Set(requestGrants.map(policyKey));
      const removed = requestGrants.filter(
        (grant) => !wanted.has(policyKey(grant))
      );
      const effectiveOperation: Operation =
        operation === "revoke" || removed.length > 0 ? "revoke" : "grant";
      const isRevoke = effectiveOperation === "revoke";
      const revokes = bySecurable(removed);
      const logger = ctx.logger.child({
        requestId,
        workspaceId,
        workspaceUrl,
        userId,
        operation,
        effectiveOperation,
      });
      if (effectiveOperation !== operation) {
        // A control-plane bug that left a grant's own grants out of its
        // policies would look just like this, so it is never silent.
        logger.warn(
          { removed: grantKeys(removed) },
          "call says grant but removes grants; treating it as the rollback of a failed grant"
        );
      }

      // The parser takes any privilege name in `policies`, because a
      // revoke's can name one P0 has since stopped granting. A grant's can't.
      const notGranted = policies.filter(
        (policy) => !isUcPrivilege(policy.privilege)
      );
      if (!isRevoke && notGranted.length > 0) {
        throw new ConnectorError({
          type: "validation_error",
          message: `A grant's policies may only name privileges P0 grants, but this one's include ${grantKeys(notGranted)}`,
          payload: { requestId, query: userId },
        });
      }

      // Domain verification on the user ID, which is the email every call
      // names as the principal. A grant to a user who fails is refused
      // before anything is called, even when there's nothing left to add:
      // otherwise a user outside the pattern could keep access by requesting
      // it again. A revoke is never refused. It warns, and then adds nothing
      // for the user, not even a shared grant a sibling request still needs.
      const mayAdd = verifyEmailDomain({
        email: userId,
        requestId,
        alreadyGranted: isRevoke,
      });
      // Only a privilege P0 grants is ever added. A revoke's shared grant
      // can name one P0 has since stopped granting: it stays in place for
      // the sibling that holds it, but is never added back.
      const grants = mayAdd
        ? bySecurable(
            policies.filter(
              (policy) =>
                requested.has(policyKey(policy)) &&
                isUcPrivilege(policy.privilege)
            )
          )
        : new Map<string, SecurableChange>();

      // Nothing looks the user up. Every call names the email, and the first
      // one Databricks can't match to a principal reports it.
      const principal = userId;
      const client = newDatabricksClient(context);
      const uc = newUnityCatalog(
        await inRecordedWorkspace({
          client,
          workspace: context,
          principal,
          removed,
          requestId,
        })
      );

      /** Securables found dropped during a revoke: nothing is left on them. */
      const dropped = new Set<string>();
      /** Securables the pre-read already showed in their final state. */
      const unchanged = new Set<string>();
      const added: SecurableChange[] = [];
      /** A revoke's failed calls, other than on a dropped securable. */
      const failures: unknown[] = [];
      /**
       * Whether a revoke found that the email names no Databricks principal.
       * Then it holds no grants anywhere on the metastore, and nothing is
       * left to revoke.
       */
      let userGone = false;

      /**
       * A grant stops at its first failure. A revoke keeps going and throws
       * its first failure once every call has run, and in a revoke a
       * securable that no longer exists counts as done for every grant on
       * it, including a shared parent another request still needs. A revoke
       * that finds the principal unknown stops there.
       */
      const onFailure = (key: string, securable: Securable, error: unknown) => {
        if (!isRevoke) throw error;
        if (isUnknownDatabricksUser(error)) {
          userGone = true;
          return;
        }
        if (isSecurableNotFound(error)) {
          logger.warn(
            { securable },
            "securable not found on revoke; treating as revoked"
          );
          dropped.add(key);
          return;
        }
        logger.warn(
          { securable, error },
          "privilege change failed on revoke; attempting the rest"
        );
        failures.push(error);
      };

      // Removals first, leaves first. They never touch a grant a sibling
      // still needs, so they don't depend on the repairs below.
      for (const [key, { securable, privileges }] of [
        ...revokes.entries(),
      ].reverse()) {
        if (userGone) break;
        try {
          await uc.updatePrivileges(securable, principal, {
            remove: privileges,
          });
        } catch (error) {
          onFailure(key, securable, error);
        }
      }

      // Adds only what isn't already held, so a revoke never writes an add
      // for a grant that's still in place.
      for (const [key, { securable, privileges }] of grants) {
        if (userGone) break;
        if (dropped.has(key)) continue;
        let held: Set<string>;
        try {
          held = await uc.directPrivileges(securable, principal);
        } catch (error) {
          onFailure(key, securable, error);
          continue;
        }
        const missing = privileges.filter((privilege) => !held.has(privilege));
        if (!missing.length) {
          if (!revokes.has(key)) unchanged.add(key);
          continue;
        }
        try {
          await uc.updatePrivileges(securable, principal, { add: missing });
          added.push({ securable, privileges: missing });
        } catch (error) {
          onFailure(key, securable, error);
        }
      }

      if (userGone) {
        logger.warn(USER_GONE_WARNING);
        return;
      }
      if (failures.length > 0) throw failures[0];
      await verify({
        uc,
        principal,
        grants,
        revokes,
        skip: new Set([...dropped, ...unchanged]),
        isRevoke,
        requestId,
        logger,
      });
      logger.info(
        {
          added,
          revoked: [...revokes.values()],
          dropped: [...dropped],
        },
        "set Unity Catalog privileges"
      );
    },

    list: async (query) => {
      const client = newDatabricksClient(query.context);
      if (query.type === "metastore") {
        // Never empty: a workspace without a metastore fails to bind.
        const { metastoreId } = await bindWorkspace(client, query.context);
        return [{ key: metastoreId, value: metastoreId }];
      }

      const uc = newUnityCatalog(await inBoundWorkspace(client, query.context));
      const toItems = (items: { name: string }[]) =>
        items.map(({ name }) => ({ key: name, value: name }));

      switch (query.type) {
        case "catalogs":
          return toItems(await uc.list("catalogs"));
        case "schemas":
          return toItems(
            await uc.list("schemas", { catalog_name: query.catalog })
          );
        case "tables":
        case "volumes":
        case "functions":
          return toItems(
            await uc.list(query.type, {
              catalog_name: query.catalog,
              schema_name: query.schema,
            })
          );
        case "directGrants": {
          const grants = [];
          for (const securable of query.securables) {
            const held = await uc.directPrivileges(securable, query.userName);
            const group = `${securable.type}:${securable.fullName}`;
            for (const privilege of [...held].sort()) {
              grants.push({
                key: grantKey(privilege, securable),
                value: privilege,
                group,
              });
            }
          }
          return grants;
        }
        default:
          throw throwAssertNever(query);
      }
    },
  }));

/**
 * Reads back every securable the change touched, and fails unless each
 * granted privilege is present and each revoked one is gone.
 */
const verify = async ({
  uc,
  principal,
  grants,
  revokes,
  skip,
  isRevoke,
  requestId,
  logger,
}: {
  uc: UnityCatalog;
  principal: string;
  /** The privileges that must be held, by securable key. */
  grants: Map<string, SecurableChange>;
  /** The privileges revoked, by securable key. */
  revokes: Map<string, SecurableChange>;
  /** Keys of securables already known to be in their final state, or dropped. */
  skip: Set<string>;
  /** Whether the call is a revoke, where a dropped securable counts as done. */
  isRevoke: boolean;
  requestId: string;
  logger: ConnectorContext["logger"];
}) => {
  const mismatches: string[] = [];
  /** Whether a revoke's read-back found the principal unknown. */
  let userGone = false;
  const touched = new Map([...revokes, ...grants]);
  for (const [key, { securable }] of touched) {
    if (skip.has(key)) continue;
    const granted = grants.get(key);
    const revoked = revokes.get(key);

    let held: Set<string>;
    try {
      held = await uc.directPrivileges(securable, principal);
    } catch (error) {
      // A principal Databricks doesn't know holds nothing, so in a revoke
      // the securable is done, as a dropped one is. A mismatch found before
      // still fails the call.
      if (isRevoke && isUnknownDatabricksUser(error)) {
        userGone = true;
        continue;
      }
      // Dropped since it was changed. In a revoke that is done; in a grant
      // the privilege is missing.
      if (isRevoke && isSecurableNotFound(error)) {
        logger.warn(
          { securable },
          "securable not found on revoke; treating as revoked"
        );
        continue;
      }
      throw error;
    }

    const missing = granted?.privileges.filter((p) => !held.has(p)) ?? [];
    const lingering = revoked?.privileges.filter((p) => held.has(p)) ?? [];
    const name = `${securable.type} ${securable.fullName}`;
    if (missing.length) {
      mismatches.push(`${name} is missing ${missing.join(", ")}`);
    }
    if (lingering.length) {
      mismatches.push(`${name} still has ${lingering.join(", ")}`);
    }
  }

  if (userGone) logger.warn(USER_GONE_WARNING);
  if (mismatches.length) {
    throw new ConnectorError({
      type: "unknown",
      message: `Databricks permissions for ${principal} don't match after the change: ${mismatches.join("; ")}`,
      payload: { requestId, principal },
    });
  }
};

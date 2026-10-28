import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";

import { setFolderAccess } from "../../folder.ts";
import { type InstanceClients, withInstance } from "../../instance.ts";
import {
  createApiKey,
  createServiceAccount,
  deleteServiceAccount,
  listDirectRoleIds,
  listModels,
  listServiceAccountIds,
  listServiceAccounts,
  setUserName,
  setUserRoles,
} from "../../looker/looker-api.ts";
import { setModelRole } from "../../roles.ts";
import { deleteGrantSecret, setGrantSecret } from "../../secrets.ts";
import { type Level, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

// P0 names each Looker grant's secret `p0/access-token/looker/<instance>/...`,
// which is `p0_access-token_looker_...` as a Google Secret Manager secret id.
const GRANT_SECRET_PREFIX = "p0_access-token_looker_";

// Set last, once the account's key is stored, so it marks a finished account.
const ACCOUNT_FIRST_NAME = "P0";

// The access each level gets on the agent content folder.
const FOLDER_ACCESS = {
  read: undefined,
  edit: "edit",
} as const satisfies Record<Level, "edit" | undefined>;

const isLookerGrantSecret = async (name: string) =>
  name.startsWith(GRANT_SECRET_PREFIX);

/**
 * Creates the grant's Looker service account, and stores the account's new
 * Looker API key in the grant's secret.
 */
const createGrantAccount = async (
  log: Logger,
  { secretManager, looker }: InstanceClients,
  name: ResourceSchema["UserBody"]
) => {
  const accountId = await createServiceAccount(looker, name);
  try {
    const key = await createApiKey(looker, accountId);
    await setGrantSecret(secretManager, name, key);
    // The MCP Toolbox may fail to start as an account that lacks either name
    // (W5). The names also label the account wherever Looker shows a person.
    // They're set last: an account without them is one whose key may not be
    // stored, and the next call deletes it.
    await setUserName(looker, accountId, {
      firstName: ACCOUNT_FIRST_NAME,
      lastName: name,
    });
  } catch (error) {
    // Delete the account that this call made, so it doesn't outlive the
    // failure. If this delete fails too, the account has no first name, and
    // the next call for the grant deletes it.
    await deleteServiceAccount(looker, accountId).catch(
      (deleteError: unknown) =>
        log.warn(
          { accountId, error: deleteError },
          "failed to delete the Looker service account of a failed grant, so it stays until someone deletes it"
        )
    );
    // The secret may already hold the account's key. Delete it too, so that a
    // live key doesn't stay behind if the account couldn't be deleted.
    // Known gap: if P0 retries a timed-out grant while this call still runs,
    // this delete can remove the retry's secret. That fails closed, since the
    // agent can't sign in. Disabling only this call's secret version would
    // need secretmanager.versions.disable, which gcpConnectorTf doesn't grant.
    await deleteGrantSecret(secretManager, name).catch((deleteError: unknown) =>
      log.warn(
        { error: deleteError },
        "failed to delete the secret of a failed grant, so it stays until the grant is retried or revoked"
      )
    );
    throw error;
  }
  log.info(
    { accountId },
    "created Looker service account and stored its API key in the secret"
  );
};

/**
 * Looker service account lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds the Looker API key of one Looker service account, which is named after
 * the secret and exists for that grant alone. Its policy is the one model and
 * level that the account may use.
 *
 * Looker shows an API key's secret once, so one call creates the account,
 * creates its key, writes the secret and names the account. It deletes the
 * account if any of that fails.
 *
 * The P0 control plane must serialize calls for the same secret.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    // The Admin key can change or delete any Looker service account. Every
    // call names its account by the user, so this limits the calls to accounts
    // that are named like a P0 Looker grant secret.
    validation: () => ({
      user: {
        userIsNamespacedById: isLookerGrantSecret,
        userIsNamespacedByBody: isLookerGrantSecret,
      },
    }),

    getUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      return await withInstance(logger, context, async (clients) => {
        const { looker, secretManager } = clients;
        const accounts = await listServiceAccounts(looker, username);
        // An account without P0's first name is one that a failed grant left
        // behind: its key may never have been stored, and its rollback failed,
        // or the response that named it was lost. Delete it, so that the
        // framework provisions the grant again rather than take it as done.
        const unfinished = accounts.filter(
          ({ firstName }) => firstName !== ACCOUNT_FIRST_NAME
        );
        for (const { id: accountId } of unfinished) {
          await deleteServiceAccount(looker, accountId);
          logger.warn(
            { accountId },
            "deleted a Looker service account that a failed grant left behind"
          );
        }
        // With no finished account left, the grant's secret holds a dead key
        // or none: an unfinished grant's, or one that a revoke deleted the
        // account of and then failed to delete. The framework skips deleteUser
        // for a user it can't find, so a revoke would otherwise leave the
        // secret behind. A grant writes it again.
        if (accounts.length === unfinished.length) {
          await deleteGrantSecret(secretManager, username);
          logger.debug(
            "no Looker service account found, so the user will be provisioned"
          );
          return null;
        }
        // Return the name, as createUser does: the account is found by it, so
        // both must give the same user id.
        return username;
      });
    },

    createUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      await withInstance(logger, context, (clients) =>
        createGrantAccount(logger, clients, username)
      );
      return username;
    },

    deleteUser: async (context, userId) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await withInstance(logger, context, async (clients) => {
        const { secretManager, looker } = clients;
        const accountIds = await listServiceAccountIds(looker, userId);
        // Delete the account before the secret, so that a failure in between
        // leaves a secret that holds a dead key, and not a live account. The
        // control plane then finds no account and does not call this again,
        // but getUser deletes that secret when the revoke is retried.
        for (const accountId of accountIds) {
          await deleteServiceAccount(looker, accountId);
          logger.info({ accountId }, "deleted Looker service account");
        }
        await deleteGrantSecret(secretManager, userId);
        logger.info("deleted secret");
      });
    },

    // The account ends with exactly the access the policy names: one role, and
    // edit access on the agent content folder for an edit grant.
    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      if (policies.length !== 1) {
        logger.error(
          { nPolicies: policies.length },
          "expected exactly 1 policy for a Looker service account"
        );
        // "unknown" rather than "validation_error": this is a control-plane
        // bug, not a problem with the user's request.
        throw new ConnectorError({
          type: "unknown",
          message:
            "Invalid parameters for a Looker service account, expected exactly 1 policy",
          payload: { requestId: context.requestId, nPolicies: policies.length },
        });
      }

      const [policy] = policies;
      const { contentFolderId } = context;
      await withInstance(logger, context, async ({ looker }) => {
        const accountIds = await listServiceAccountIds(looker, userId);

        if (policy === null) {
          for (const accountId of accountIds) {
            await setUserRoles(looker, accountId, []);
            if (contentFolderId !== undefined) {
              await setFolderAccess(looker, {
                folderId: contentFolderId,
                userId: accountId,
                access: undefined,
              });
            }
            logger.info({ accountId }, "cleared Looker service account access");
          }
          return;
        }

        // The grant's key belongs to one account. Giving a role to another
        // with the same name would give it to a key P0 doesn't hold.
        const [accountId] = accountIds;
        if (accountId === undefined || accountIds.length !== 1) {
          throw new ConnectorError({
            type: accountId === undefined ? "object_not_found" : "unknown",
            message: `Expected 1 Looker service account named ${userId}, found ${accountIds.length}`,
            payload: {
              requestId: context.requestId,
              nAccounts: accountIds.length,
            },
          });
        }

        // The folder comes first, so that a grant to a folder that is gone
        // fails before the account gets its role. Edit access there gives
        // nothing without the role's permissions, apart from roles the
        // account inherits from groups every new user joins (W2, W6). A
        // failed grant's rollback clears it either way.
        if (contentFolderId !== undefined) {
          await setFolderAccess(looker, {
            folderId: contentFolderId,
            userId: accountId,
            access: FOLDER_ACCESS[policy.level],
          });
        }

        const roleId = await setModelRole(looker, policy);
        await setUserRoles(looker, accountId, [roleId]);
        // `set_user_roles` answers with the roles, but read them back as
        // their own call: what the account holds is what matters (W2).
        const held = await listDirectRoleIds(looker, accountId);
        if (held.length !== 1 || held[0] !== roleId) {
          await setUserRoles(looker, accountId, []).catch((error: unknown) =>
            logger.warn(
              { accountId, error },
              "failed to clear the roles of a Looker service account whose roles were not the ones set"
            )
          );
          throw new ConnectorError({
            type: "unknown",
            message: `Looker gave the Looker service account ${userId} other roles than the one P0 set, so P0 removed them`,
            payload: { requestId: context.requestId, nRoles: held.length },
          });
        }

        logger.info(
          { accountId, roleId, model: policy.model, level: policy.level },
          "gave Looker service account its role"
        );
      });
    },

    list: async ({ type, context }) => {
      switch (type) {
        case "model":
          return await withInstance(ctx.logger, context, async ({ looker }) =>
            (await listModels(looker)).map(({ name, label }) => ({
              key: name,
              value: label,
            }))
          );
        default:
          throw throwAssertNever(type);
      }
    },
  }));

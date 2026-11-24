import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceRootConnectorPrimitives,
  newResourceRootRouter,
} from "@p0security/connector-core";
import { randomBytes as cryptoRandomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

import {
  GRANT_LOGIN_PATTERN,
  type RequestContext,
  isGrantSecretOfLogin,
} from "../../context.ts";
import type { Dependencies } from "../../dependencies.ts";
import {
  activateGrantLogin,
  endGrantLoginSessions,
  prepareGrantLogin,
  readCleanup,
  readGrantLoginState,
  releaseOwned,
  retireGrantLogin,
  takeGrantLoginPrivileges,
} from "../../grant-login.ts";
import { newGrantSecretStore } from "../../grant-secret.ts";
import {
  type InDatabase,
  isGrantSecretOfManagerTarget,
  managerSecretFor,
  withManager,
} from "../../manager.ts";
import {
  listConnectableDatabases,
  listDatabases,
  listGrantableRoles,
} from "../../postgres/catalog.ts";
import type { PgSession } from "../../postgres/client.ts";
import { SALT_BYTES, scramVerifier } from "../../postgres/scram.ts";
import { execute } from "../../postgres/statement.ts";
import { type RoleSchema, spec } from "./definition.ts";

/** What `list` returns for each type of its query, by name. */
const LISTERS = { role: listGrantableRoles, database: listDatabases };

/** A grant login's password is this many random bytes, as base64url. */
const PASSWORD_BYTES = 32;

/**
 * The grant login lifecycle, as resource-root primitives. The resource-root
 * "user" is a grant login: a login role named `p0v_<grant key>`, created for
 * exactly one grant. P0 chooses the name; the connector refuses any other,
 * and refuses a grant secret that is another login's.
 *
 * What each primitive does is in the README, under Lifecycle: `getUser`,
 * `createUser` and `setPoliciesForUser` with policies are the grant path,
 * and `setPoliciesForUser` with no policies and `deleteUser` the revoke
 * path.
 *
 * Nothing here logs a password, its verifier or a statement's text.
 */
export const newRolePrimitives = (
  ctx: ConnectorContext,
  dependencies: Dependencies = {}
): ResourceRootConnectorPrimitives<RoleSchema> => {
  /**
   * The call's logger, its grant secrets, and a way to run as the target's
   * manager. It refuses a grant secret that belongs to another target than
   * the request's, before the call reaches Secrets Manager or PostgreSQL.
   */
  const forGrant = (context: RequestContext, login: string) => {
    const { requestId, target, secrets, secretName } = context;
    const { host, port, database } = target;
    const secret = managerSecretFor(host, dependencies.env);
    if (!isGrantSecretOfManagerTarget(secretName, secret)) {
      throw new ConnectorError({
        type: "validation_error",
        message:
          "The grant secret's name is for another target than the request's. Its target id must be the one the connector's manager mapping holds for the target's host.",
        payload: { host },
      });
    }
    const logger = ctx.logger.child({ requestId, host, port, database, login });
    return {
      logger,
      grantSecrets: newGrantSecretStore(secrets.region, dependencies),
      asManager: <T>(
        run: (session: PgSession, inDatabase: InDatabase) => Promise<T>
      ) => withManager(target, secret, dependencies, logger, run),
    };
  };

  return {
    validation: ({ secretName }) => {
      const isGrantLoginOfSecret = async (login: string) =>
        GRANT_LOGIN_PATTERN.test(login) &&
        isGrantSecretOfLogin(secretName, login);

      return {
        user: {
          userIsNamespacedByBody: isGrantLoginOfSecret,
          userIsNamespacedById: isGrantLoginOfSecret,
        },
      };
    },

    getUser: async (context, login) => {
      const { logger, grantSecrets, asManager } = forGrant(context, login);
      const state = await asManager(({ query }) =>
        readGrantLoginState(query, login)
      );
      // A login that was ever activated is found whatever became of its
      // secret: a revoke that found no grant would skip the cutoff of a login
      // that can still log in. Only a prepared login depends on its secret,
      // so that `createUser` finishes one whose password was never stored.
      const isStored =
        state === "prepared" &&
        (await grantSecrets.describe(context.secretName))?.hasValue === true;
      const found =
        state === "active" || state === "retired" || isStored ? login : null;
      logger.info({ state, found: found !== null }, "looked up the grant");
      return found;
    },

    createUser: async (context, login) => {
      const { logger, grantSecrets, asManager } = forGrant(context, login);
      const { deadline, comment, secretName } = context;
      const { randomBytes = cryptoRandomBytes } = dependencies;
      // First, so that a refusal by Secrets Manager leaves the database as
      // it was.
      await grantSecrets.findOrCreate(secretName);
      const password = randomBytes(PASSWORD_BYTES).toString("base64url");
      const verifier = scramVerifier(password, randomBytes(SALT_BYTES));
      const from = await asManager(({ committed }) =>
        committed(async (query) => {
          const state = await prepareGrantLogin(query, {
            login,
            verifier,
            deadline,
            comment,
          });
          // A new login is committed only once its password is stored. The
          // secret may hold a value from an earlier try, which `getUser`
          // would take for this login's password if the write came after
          // the commit and failed.
          if (state === "absent") {
            await grantSecrets.write(secretName, password);
          }
          return state;
        })
      );
      // A prepared login had no stored password, or `getUser` would have
      // found it. Its password is stored after the commit: when the write
      // fails the secret still has no value, so the next `createUser` gives
      // the login a new password.
      if (from !== "absent") await grantSecrets.write(secretName, password);
      logger.info(
        { from, to: "prepared" },
        "prepared the grant login and stored its password"
      );
      return login;
    },

    deleteUser: async (context, login) => {
      const { logger, grantSecrets, asManager } = forGrant(context, login);
      const { secretName, objectOwner: owner } = context;
      const { wait = (ms) => sleep(ms) } = dependencies;
      const { from, databases } = await asManager(
        async ({ query }, inDatabase) => {
          const cleanup = await readCleanup(query, { login, owner });
          // Before the login is touched: `getUser` finds a retired login
          // without its secret, so a cleanup that stops after this is found
          // and finished by the next call.
          await grantSecrets.remove(secretName);
          if (!cleanup.drop) return { from: cleanup.from, databases: [] };
          // Each of these statements is its own transaction. The grant is
          // committed here because every database below needs it.
          await takeGrantLoginPrivileges(query, login);
          // With no owner to hand objects to, `DROP OWNED` below drops
          // whatever the login owns. It checks that the login owns nothing,
          // so no session of the login may still be able to create something.
          if (!cleanup.ownerIsGrantable) {
            await endGrantLoginSessions(query, login, wait);
          }
          const connectable = await listConnectableDatabases(query);
          for (const database of connectable) {
            await inDatabase(database, (there) =>
              there.committed((inTransaction) =>
                releaseOwned(inTransaction, {
                  login,
                  owner,
                  ownerIsGrantable: cleanup.ownerIsGrantable,
                })
              )
            );
          }
          // PostgreSQL drops a role whose session is still open, and the
          // session lives on under no name, where no later call finds it.
          // A session the cutoff missed has had time to show by now.
          await endGrantLoginSessions(query, login, wait);
          await execute(query, cleanup.drop);
          return { from: cleanup.from, databases: connectable };
        }
      );
      logger.info(
        { from, to: "absent", owner, databases },
        "cleaned up the grant: its secret is deleted and its login is gone"
      );
    },

    setPoliciesForUser: async (context, login, _userBody, policies) => {
      const { logger, asManager } = forGrant(context, login);
      if (policies.length === 0) {
        const { wait = (ms) => sleep(ms) } = dependencies;
        const { from, revoked, sessionsEnded } = await asManager((session) =>
          retireGrantLogin(session, login, wait)
        );
        logger.info(
          { from, revoked, sessionsEnded },
          "cut off the grant login and confirmed that none of its sessions is left"
        );
        return;
      }
      const roles = [...new Set(policies.map(({ rolename }) => rolename))];
      const { from, granted, revoked } = await asManager(({ committed }) =>
        committed((query) =>
          activateGrantLogin(query, {
            login,
            roles,
            deadline: context.deadline,
          })
        )
      );
      logger.info(
        { from, to: "active", roles, granted, revoked },
        "granted the approved roles and activated the grant login"
      );
    },

    list: async ({ type, context: target }) => {
      const { host, port, database } = target;
      const logger = ctx.logger.child({ host, port, database, type });
      const names = await withManager(
        target,
        managerSecretFor(host, dependencies.env),
        dependencies,
        logger,
        ({ query }) => LISTERS[type](query)
      );
      logger.info({ count: names.length }, "listed from the PostgreSQL target");
      return names.map((name) => ({ key: name, value: name }));
    },
  };
};

export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: Dependencies = {}
) =>
  newResourceRootRouter(t, spec, (ctx) => newRolePrimitives(ctx, dependencies));

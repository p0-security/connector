import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type ResourceRootConnectorPrimitives,
  newResourceRootRouter,
} from "@p0security/connector-core";
import { randomBytes as cryptoRandomBytes } from "node:crypto";

import {
  GRANT_LOGIN_PATTERN,
  type RequestContext,
  isGrantSecretOfLogin,
} from "../../context.ts";
import type { Dependencies } from "../../dependencies.ts";
import {
  activateGrantLogin,
  prepareGrantLogin,
  readGrantLoginState,
} from "../../grant-login.ts";
import { newGrantSecretStore } from "../../grant-secret.ts";
import { managerSecretFor, withManager } from "../../manager.ts";
import { newNotImplementedError } from "../../not-implemented.ts";
import { listDatabases, listGrantableRoles } from "../../postgres/catalog.ts";
import type { PgSession } from "../../postgres/client.ts";
import { SALT_BYTES, scramVerifier } from "../../postgres/scram.ts";
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
 * What each primitive does is in the README, under Lifecycle. The grant path
 * is implemented: `getUser`, `createUser` and `setPoliciesForUser` with
 * policies. The revoke path is not: `setPoliciesForUser` with no policies
 * and `deleteUser` throw {@link newNotImplementedError}.
 *
 * Nothing here logs a password, its verifier or a statement's text.
 */
export const newRolePrimitives = (
  ctx: ConnectorContext,
  dependencies: Dependencies = {}
): ResourceRootConnectorPrimitives<RoleSchema> => {
  /** The call's logger, its grant secrets, and a way to run as the target's
   * manager. */
  const forGrant = (context: RequestContext, login: string) => {
    const { requestId, target, secrets } = context;
    const { host, port, database } = target;
    const logger = ctx.logger.child({ requestId, host, port, database, login });
    return {
      logger,
      grantSecrets: newGrantSecretStore(secrets.region, dependencies),
      asManager: <T>(run: (session: PgSession) => Promise<T>) =>
        withManager(
          target,
          managerSecretFor(host, dependencies.env),
          dependencies,
          logger,
          run
        ),
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

    deleteUser: async () => {
      throw newNotImplementedError("deleteUser");
    },

    setPoliciesForUser: async (context, login, _userBody, policies) => {
      if (policies.length === 0) {
        throw newNotImplementedError("setPoliciesForUser");
      }
      const { logger, asManager } = forGrant(context, login);
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

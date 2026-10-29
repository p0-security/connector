import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  SecretNotFoundError,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";

import type { RequestContext } from "./context.ts";
import { secretRef } from "./secrets.ts";
import type { SnowflakeSession } from "./snowflake/client.ts";
import {
  objectNameParts,
  quoteIdentifier,
  quoteLiteral,
  quoteObjectName,
} from "./sql.ts";

// The Snowflake statements below ran against a live account on 2026-10-22:
// minting, the token's `token_secret` column, the authentication policy, the
// MCP call with the token, and the revoke, which left the agent's objects
// with its owner role. INT-617 runs them again end to end.

/** Snowflake's default PAT policy caps a token's life at 365 days. The user
 * gets the same cap, since it is of no use once its token has expired. */
export const MAX_DAYS_TO_EXPIRY = 365;

/** The name of the grant's token. Each minted user holds only this one. */
export const TOKEN_NAME = "P0_GRANT";

/** A minted user's comment until its token is stored. A user that still has
 * it was left by a mint that never finished. */
export const PENDING_COMMENT = "P0: storing this user's token";

export const daysToExpiryFor = (
  context: Pick<RequestContext, "daysToExpiry">
) => Math.min(context.daysToExpiry, MAX_DAYS_TO_EXPIRY);

/** The statements that mint the wrapper role and the user, in order, without
 * the token: `createRole`, the role's base grants, then the user. */
export const mintStatements = (context: RequestContext, name: string) => {
  const role = quoteIdentifier(name);
  const days = daysToExpiryFor(context);
  const comment = quoteLiteral(context.comment);
  const [mcpDatabase, mcpSchema] = objectNameParts(context.mcpServer);
  return {
    // This runs only when no complete agent has this name. A role with it is
    // then left by an earlier mint whose undo failed, holding only the grants
    // below, so it is reused rather than failing every retry.
    createRole: `CREATE ROLE IF NOT EXISTS ${role} COMMENT = ${comment}`,
    roleGrants: [
      `GRANT USAGE ON WAREHOUSE ${quoteIdentifier(context.warehouse)} TO ROLE ${role}`,
      // An object in a schema is reachable only with USAGE on its database
      // and its schema.
      `GRANT USAGE ON DATABASE ${quoteIdentifier(mcpDatabase)} TO ROLE ${role}`,
      `GRANT USAGE ON SCHEMA ${quoteObjectName(`${mcpDatabase}.${mcpSchema}`)} TO ROLE ${role}`,
      `GRANT USAGE ON MCP SERVER ${quoteObjectName(context.mcpServer)} TO ROLE ${role}`,
    ],
    createUser: [
      `CREATE USER ${role}`,
      "TYPE = SERVICE_AGENT",
      `DEFAULT_WAREHOUSE = ${quoteIdentifier(context.warehouse)}`,
      `DEFAULT_ROLE = ${role}`,
      "DEFAULT_SECONDARY_ROLES = ()",
      `DAYS_TO_EXPIRY = ${days}`,
      `COMMENT = ${quoteLiteral(PENDING_COMMENT)}`,
    ].join(" "),
    // Token sign-in only, and a token that works without a network policy,
    // which Snowflake otherwise requires before it accepts one.
    setAuthPolicy: `ALTER USER ${role} SET AUTHENTICATION POLICY ${quoteObjectName(context.agentAuthPolicy)}`,
    grantRoleToUser: `GRANT ROLE ${role} TO USER ${role}`,
    addToken: [
      `ALTER USER ${role} ADD PROGRAMMATIC ACCESS TOKEN ${quoteIdentifier(TOKEN_NAME)}`,
      `ROLE_RESTRICTION = ${quoteLiteral(name)}`,
      `DAYS_TO_EXPIRY = ${days}`,
      `COMMENT = ${comment}`,
    ].join(" "),
    // Last, once the token is stored: the user is then complete.
    markReady: `ALTER USER ${role} SET COMMENT = ${comment}`,
  };
};

export const dropUserStatement = (name: string) =>
  `DROP USER IF EXISTS ${quoteIdentifier(name)}`;

/** The empty role that takes over an agent's wrapper role when it is
 * dropped, and with it whatever the agent created. One per agent, so one
 * agent's leftovers never reach another's. */
export const ownerRoleFor = (name: string) => `${name}_OWNER`;

/**
 * The statements that drop an agent's wrapper role as its own empty owner
 * role (see {@link ownerRoleFor}). Snowflake gives a dropped role's objects
 * to the role that drops it, so whatever the agent created goes to a role
 * that can do nothing, never to the connector's admin role. The owner role
 * is lent to the connector's role so the connector can act as it, takes
 * ownership of the wrapper role (only its owner can drop it as that role),
 * and is taken back afterwards. It stays: dropping it would hand the
 * leftovers to whoever drops it.
 */
export const dropRoleStatements = (context: RequestContext, name: string) => {
  const role = quoteIdentifier(name);
  const owner = quoteIdentifier(ownerRoleFor(name));
  const connector = quoteIdentifier(context.connector.role);
  return {
    createOwner: `CREATE ROLE IF NOT EXISTS ${owner} COMMENT = ${quoteLiteral(`Owns what P0 agent ${name} created`)}`,
    lendOwner: `GRANT ROLE ${owner} TO ROLE ${connector}`,
    transfer: `GRANT OWNERSHIP ON ROLE ${role} TO ROLE ${owner} COPY CURRENT GRANTS`,
    useOwner: `USE ROLE ${owner}`,
    drop: `DROP ROLE IF EXISTS ${role}`,
    useConnector: `USE ROLE ${connector}`,
    reclaimOwner: `REVOKE ROLE ${owner} FROM ROLE ${connector}`,
  };
};

/** Whether the role exists, matched on its exact name (see {@link findUser}
 * on `LIKE`). */
const roleExists = async (session: SnowflakeSession, name: string) => {
  const rows = await session.query<{ name?: string }>(
    `SHOW ROLES LIKE ${quoteLiteral(name)}`
  );
  return rows.some((row) => row.name === name);
};

/** Drops the agent's wrapper role (see {@link dropRoleStatements}). A no-op
 * when the role is already gone. */
export const dropAgentRole = async (
  session: SnowflakeSession,
  context: RequestContext,
  name: string
) => {
  if (!(await roleExists(session, name))) return;
  const statements = dropRoleStatements(context, name);
  await session.execute(statements.createOwner);
  await session.execute(statements.lendOwner);
  await session.execute(statements.transfer);
  await session.execute(statements.useOwner);
  try {
    await session.execute(statements.drop);
  } finally {
    await session.execute(statements.useConnector);
  }
  await session.execute(statements.reclaimOwner);
};

/** `ALTER USER … SET DISABLED` aborts the user's running queries and blocks
 * new ones. */
export const disableUserStatement = (name: string) =>
  `ALTER USER IF EXISTS ${quoteIdentifier(name)} SET DISABLED = TRUE`;

/**
 * The user's row, if it exists. `LIKE` matches a pattern (`_` is a
 * wildcard), so it can only return extra rows, never miss this one; the rows
 * are filtered to the exact name. The pattern is not escaped, because
 * Snowflake documents no escape character for `SHOW … LIKE`.
 */
export const findUser = async (session: SnowflakeSession, name: string) => {
  const rows = await session.query<{ name?: string; comment?: string }>(
    `SHOW USERS LIKE ${quoteLiteral(name)}`
  );
  return rows.find((row) => row.name === name);
};

const secretExists = async (
  secrets: SecretManagerClient,
  secretName: string
) => {
  try {
    await secrets.getSecret({ ref: secretRef(secretName) });
    return true;
  } catch (error) {
    if (error instanceof SecretNotFoundError) return false;
    throw secretManagerError(error, "read");
  }
};

/**
 * The agent's name if its mint finished: the user exists, its token is
 * stored (it no longer has {@link PENDING_COMMENT}), and so does its token's
 * secret. Anything less is left by a mint that never finished (the process
 * died, or its undo failed) or a revoke that never finished. Either way it
 * holds no usable grant, so it is removed here and reported missing: a grant
 * then mints it afresh, and a revoke sees it as already gone.
 */
export const findAgent = async (
  session: SnowflakeSession,
  secrets: SecretManagerClient,
  logger: Logger,
  context: RequestContext,
  name: string
) => {
  const user = await findUser(session, name);
  if (!user) return null;
  if (
    user.comment !== PENDING_COMMENT &&
    (await secretExists(secrets, context.secretName))
  )
    return name;
  logger.warn("found an unfinished agent user; removing it");
  await removeAgent(session, secrets, context, name);
  return null;
};

/**
 * A secret manager failure, without its cause. The client's errors can carry
 * the request they failed on, and a token write's request body holds the
 * token, so the cause is never passed on or logged.
 */
const secretManagerError = (error: unknown, action: string) =>
  error instanceof ConnectorError
    ? error
    : new ConnectorError({
        type:
          error instanceof UnauthorizedError
            ? "insufficient_privileges"
            : "upstream_unavailable",
        message: `Failed to ${action} the grant's token secret`,
        payload: { action },
      });

type Undo = { label: string; run: () => Promise<unknown> };

/**
 * Mints the grant's identity: the wrapper role with USAGE on the warehouse and
 * the MCP server, the `SERVICE_AGENT` user, and its token, which is written to
 * the secret P0 names. The requested access is granted later, by
 * `setPoliciesForUser`; until then the user can reach nothing.
 *
 * Each step registers an undo. When a step fails, the undos run in reverse,
 * so a failed grant leaves no role, no user, no token and no secret. Dropping
 * the user also removes its token.
 */
export const mintAgent = async (
  session: SnowflakeSession,
  secrets: SecretManagerClient,
  logger: Logger,
  context: RequestContext,
  name: string
) => {
  const statements = mintStatements(context, name);
  const undos: Undo[] = [];
  try {
    await session.execute(statements.createRole);
    undos.push({
      label: "drop role",
      run: () => dropAgentRole(session, context, name),
    });
    for (const grant of statements.roleGrants) await session.execute(grant);

    await session.execute(statements.createUser);
    undos.push({
      label: "drop user",
      run: () => session.execute(dropUserStatement(name)),
    });
    await session.execute(statements.setAuthPolicy);
    await session.execute(statements.grantRoleToUser);

    const [row] = await session.query<{ token_secret?: string }>(
      statements.addToken
    );
    const token = row?.token_secret;
    if (!token) {
      throw new ConnectorError({
        type: "unknown",
        message: "Snowflake returned no programmatic access token",
        payload: { requestId: context.requestId },
      });
    }

    const ref = secretRef(context.secretName);
    try {
      await secrets.createSecret({ name: context.secretName });
    } catch (error) {
      // Left by an earlier attempt whose undo failed. P0 names the secret for
      // this grant only, so it is reused.
      if (!(error instanceof SecretAlreadyExistsError))
        throw secretManagerError(error, "create");
    }
    undos.push({
      label: "delete secret",
      run: () => deleteSecretIfExists(secrets, context.secretName),
    });
    try {
      await secrets.createSecretVersion({
        ref,
        type: "value",
        value: Buffer.from(token),
      });
    } catch (error) {
      throw secretManagerError(error, "write");
    }
    await session.execute(statements.markReady);
    logger.info("minted agent user and stored its token");
    return name;
  } catch (error) {
    for (const undo of undos.reverse()) {
      await undo
        .run()
        .catch((undoError: unknown) =>
          logger.error(
            { undo: undo.label, error: undoError },
            "failed to undo a step of a failed grant; it expires with its day TTL"
          )
        );
    }
    throw error;
  }
};

const deleteSecretIfExists = async (
  secrets: SecretManagerClient,
  secretName: string
) => {
  try {
    await secrets.deleteSecret({ ref: secretRef(secretName) });
  } catch (error) {
    if (!(error instanceof SecretNotFoundError))
      throw secretManagerError(error, "delete");
  }
};

/**
 * Removes the grant's identity: the secret, the wrapper role, then the user
 * (and with it the token). Each step is a no-op when its object is already
 * gone. The user goes last because it is what {@link findAgent} looks for: a
 * revoke that fails partway leaves the user, so the retry finds it and
 * finishes. By then the user is disabled, so it can do nothing meanwhile.
 */
export const removeAgent = async (
  session: SnowflakeSession,
  secrets: SecretManagerClient,
  context: RequestContext,
  name: string
) => {
  await deleteSecretIfExists(secrets, context.secretName);
  await dropAgentRole(session, context, name);
  await session.execute(dropUserStatement(name));
};

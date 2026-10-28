import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";

import { type InstallContext, installContext } from "../context.ts";
import { createSecretManager, signInFor } from "../secrets.ts";
import {
  type SnowflakeSession,
  toConnectorError,
  withSnowflake,
} from "../snowflake/client.ts";
import { objectNameParts, quoteLiteral, quoteObjectName } from "../sql.ts";
import type {
  InstallValidation,
  SnowflakeAiInstallStep,
} from "./definition.ts";

/**
 * Runs `run` as `step`: its failure is thrown as a `ConnectorError` that
 * carries the step and the account. A failure that already names a step
 * keeps it.
 */
const at = async <T>(
  step: SnowflakeAiInstallStep,
  account: string,
  run: () => Promise<T>
): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    const { data } = toConnectorError(error);
    if ("step" in data.payload) throw error;
    throw new ConnectorError({
      ...data,
      payload: { ...data.payload, step, account },
    });
  }
};

const failed = (
  step: SnowflakeAiInstallStep,
  account: string,
  type: ConnectorErrorOptions["type"],
  message: string
) => new ConnectorError({ type, message, payload: { step, account } });

/** The checks inside the session, in order. */
export const checkAccount = async (
  session: SnowflakeSession,
  install: InstallContext
): Promise<InstallValidation> => {
  const { account } = install;
  const [identity] = await at("sign_in", account, () =>
    session.query<{ USER_NAME: string; ROLE_NAME: string }>(
      "SELECT CURRENT_USER() AS USER_NAME, CURRENT_ROLE() AS ROLE_NAME"
    )
  );
  if (!identity) {
    throw failed(
      "sign_in",
      account,
      "unknown",
      "Snowflake returned no session"
    );
  }

  const [roles] = await at("admin_roles", account, () =>
    session.query<{ USERADMIN: boolean; SECURITYADMIN: boolean }>(
      "SELECT IS_ROLE_IN_SESSION('USERADMIN') AS USERADMIN, IS_ROLE_IN_SESSION('SECURITYADMIN') AS SECURITYADMIN"
    )
  );
  if (!roles?.USERADMIN || !roles?.SECURITYADMIN) {
    throw failed(
      "admin_roles",
      account,
      "insufficient_privileges",
      `The connector's role ${install.connector.role} must be granted USERADMIN and SECURITYADMIN`
    );
  }

  await at("account_usage", account, () =>
    session.query("SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES LIMIT 1")
  );

  const [database, schema, name] = objectNameParts(install.mcpServer);
  const servers = await at("mcp_server", account, () =>
    session.query<{ name?: string }>(
      `SHOW MCP SERVERS LIKE ${quoteLiteral(name)} IN SCHEMA ${quoteObjectName(`${database}.${schema}`)}`
    )
  );
  if (!servers.some((server) => server.name === name)) {
    throw failed(
      "mcp_server",
      account,
      "object_not_found",
      `The MCP server ${install.mcpServer} does not exist`
    );
  }

  const [policyDatabase, policySchema, policyName] = objectNameParts(
    install.agentAuthPolicy
  );
  const policies = await at("agent_auth_policy", account, () =>
    session.query<{ name?: string }>(
      `SHOW AUTHENTICATION POLICIES LIKE ${quoteLiteral(policyName)} IN SCHEMA ${quoteObjectName(`${policyDatabase}.${policySchema}`)}`
    )
  );
  if (!policies.some((policy) => policy.name === policyName)) {
    throw failed(
      "agent_auth_policy",
      account,
      "object_not_found",
      `The authentication policy ${install.agentAuthPolicy} does not exist`
    );
  }

  return { user: identity.USER_NAME, role: identity.ROLE_NAME };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure.input(installContext.parse).query(async ({ input, ctx }) => {
      const logger = ctx.logger.child({ account: input.account });
      const signIn = await at("private_key", input.account, async () =>
        signInFor(input, await createSecretManager(input))
      );
      const validation = await at("sign_in", input.account, () =>
        withSnowflake(signIn, logger, (session) => checkAccount(session, input))
      );
      logger.info(validation, "validated Snowflake install");
      return validation;
    }),
  });
};

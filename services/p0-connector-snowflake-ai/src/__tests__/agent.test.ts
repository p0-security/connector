import { ConnectorError } from "@p0security/connector-core";
import * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { describe, expect, it } from "vitest";

import {
  MAX_DAYS_TO_EXPIRY,
  PENDING_COMMENT,
  dropRoleStatements,
  findAgent,
  mintAgent,
  mintStatements,
  removeAgent,
} from "../agent.ts";
import {
  NAME,
  TOKEN,
  capturingLogger,
  context,
  fakeSecrets,
  fakeSession,
} from "./fakes.ts";

/** What dropping the agent's role runs, when the role exists. */
const dropRoleSteps = [
  `SHOW ROLES LIKE '${NAME}'`,
  ...Object.values(dropRoleStatements(context, NAME)),
];

/** A session in which the agent's role exists. */
const sessionWithRole = () => {
  const snowflake = fakeSession();
  snowflake.on("SHOW ROLES", () => [{ name: NAME }]);
  return snowflake;
};

const setup = () => {
  const snowflake = sessionWithRole();
  snowflake.on("ALTER USER", () => [
    { token_name: "P0_GRANT", token_secret: TOKEN },
  ]);
  const secrets = fakeSecrets(SecretManagerClientModule);
  const { logger, lines } = capturingLogger();
  const mint = () =>
    mintAgent(snowflake.session, secrets.client, logger, context, NAME);
  return { snowflake, secrets, lines, mint };
};

describe("mintStatements", () => {
  it("quotes every name and escapes the comment", () => {
    const statements = mintStatements(
      { ...context, comment: "it's \\ odd" },
      NAME
    );

    expect(statements.createRole).toBe(
      `CREATE ROLE IF NOT EXISTS "P0_AGENT_R123" COMMENT = 'it''s \\\\ odd'`
    );
    expect(statements.roleGrants).toEqual([
      `GRANT USAGE ON WAREHOUSE "ANALYTICS_WH" TO ROLE "P0_AGENT_R123"`,
      `GRANT USAGE ON DATABASE "P0_AI" TO ROLE "P0_AGENT_R123"`,
      `GRANT USAGE ON SCHEMA "P0_AI"."MCP" TO ROLE "P0_AGENT_R123"`,
      `GRANT USAGE ON MCP SERVER "P0_AI"."MCP"."P0_SQL_V1" TO ROLE "P0_AGENT_R123"`,
    ]);
    expect(statements.createUser).toBe(
      `CREATE USER "P0_AGENT_R123" TYPE = SERVICE_AGENT DEFAULT_WAREHOUSE = "ANALYTICS_WH" DEFAULT_ROLE = "P0_AGENT_R123" DEFAULT_SECONDARY_ROLES = () DAYS_TO_EXPIRY = 2 COMMENT = 'P0: storing this user''s token'`
    );
    expect(statements.setAuthPolicy).toBe(
      `ALTER USER "P0_AGENT_R123" SET AUTHENTICATION POLICY "P0_AI"."MCP"."P0_AGENT_AUTH"`
    );
    expect(statements.markReady).toBe(
      `ALTER USER "P0_AGENT_R123" SET COMMENT = 'it''s \\\\ odd'`
    );
    expect(statements.addToken).toBe(
      `ALTER USER "P0_AGENT_R123" ADD PROGRAMMATIC ACCESS TOKEN "P0_GRANT" ROLE_RESTRICTION = 'P0_AGENT_R123' DAYS_TO_EXPIRY = 2 COMMENT = 'it''s \\\\ odd'`
    );
  });

  it("caps the user's and the token's expiry at 365 days", () => {
    const statements = mintStatements({ ...context, daysToExpiry: 400 }, NAME);

    expect(MAX_DAYS_TO_EXPIRY).toBe(365);
    expect(statements.createUser).toContain("DAYS_TO_EXPIRY = 365 ");
    expect(statements.addToken).toContain("DAYS_TO_EXPIRY = 365 ");
  });

  it("refuses a warehouse that is not a plain identifier", () => {
    expect(() =>
      mintStatements({ ...context, warehouse: 'WH" TO ROLE PUBLIC; --' }, NAME)
    ).toThrow(ConnectorError);
  });
});

describe("mintAgent", () => {
  it("runs the steps in order and stores only the token", async () => {
    const { snowflake, secrets, mint } = setup();

    await expect(mint()).resolves.toBe(NAME);

    const statements = mintStatements(context, NAME);
    expect(snowflake.statements).toEqual([
      statements.createRole,
      ...statements.roleGrants,
      statements.createUser,
      statements.setAuthPolicy,
      statements.grantRoleToUser,
      statements.addToken,
      statements.markReady,
    ]);
    expect(secrets.values.get(context.secretName)).toBe(TOKEN);
  });

  // Each failure point, with the undos that must follow it, newest first.
  const statements = mintStatements(context, NAME);
  const dropUser = `DROP USER IF EXISTS "${NAME}"`;
  const dropRole = dropRoleSteps;
  it.each([
    { step: statements.createRole, undos: [] },
    { step: statements.roleGrants[0], undos: dropRole },
    { step: statements.roleGrants[3], undos: dropRole },
    { step: statements.createUser, undos: dropRole },
    { step: statements.setAuthPolicy, undos: [dropUser, ...dropRole] },
    { step: statements.grantRoleToUser, undos: [dropUser, ...dropRole] },
    { step: statements.addToken, undos: [dropUser, ...dropRole] },
  ])("undoes what ran when $step fails", async ({ step, undos }) => {
    const { snowflake, secrets, mint } = setup();
    snowflake.failOn(step, new Error("boom"));

    await expect(mint()).rejects.toThrow("boom");

    const failedAt = snowflake.statements.indexOf(step);
    expect(snowflake.statements.slice(failedAt + 1)).toEqual(undos);
    expect(secrets.existing.size).toBe(0);
  });

  it("removes the secret, user and role when the user can't be marked ready", async () => {
    const { snowflake, secrets, mint } = setup();
    snowflake.failOn(statements.markReady, new Error("boom"));

    await expect(mint()).rejects.toThrow("boom");

    expect(secrets.existing.size).toBe(0);
    expect(snowflake.statements.slice(-9)).toEqual([dropUser, ...dropRole]);
  });

  it("drops the user, and with it the token, when the secret can't be created", async () => {
    const { snowflake, secrets, mint } = setup();
    secrets.failures.createSecret = true;

    await expect(mint()).rejects.toThrow("Failed to create");

    expect(snowflake.statements.slice(-9)).toEqual([dropUser, ...dropRole]);
  });

  it("deletes the secret, then drops the user and role, when the token can't be written", async () => {
    const { snowflake, secrets, mint } = setup();
    secrets.failures.createSecretVersion = true;

    await expect(mint()).rejects.toThrow("Failed to write");

    expect(secrets.existing.has(context.secretName)).toBe(false);
    expect(snowflake.statements.slice(-9)).toEqual([dropUser, ...dropRole]);
  });

  it("keeps unwinding when an undo fails, and throws the step's error", async () => {
    const { snowflake, mint } = setup();
    snowflake.failOn(statements.addToken, new Error("boom"));
    snowflake.failOn(dropUser, new Error("drop failed"));

    await expect(mint()).rejects.toThrow("boom");

    expect(snowflake.statements.slice(-9)).toEqual([dropUser, ...dropRole]);
  });

  it("fails, and unwinds, when Snowflake returns no token", async () => {
    const { snowflake, mint } = setup();
    snowflake.on("ALTER USER", () => []);

    await expect(mint()).rejects.toThrow("no programmatic access token");

    expect(snowflake.statements.slice(-9)).toEqual([dropUser, ...dropRole]);
  });

  it("reuses a secret an earlier failed attempt left behind", async () => {
    const { secrets, mint } = setup();
    secrets.existing.add(context.secretName);

    await mint();

    expect(secrets.values.get(context.secretName)).toBe(TOKEN);
  });

  it("never logs the token", async () => {
    const { lines, mint } = setup();

    await mint();

    expect(lines.length).toBeGreaterThan(0);
    expect(lines.join("\n")).not.toContain(TOKEN);
  });

  it("drops the request that held the token when its write fails", async () => {
    const { secrets, lines, mint } = setup();
    // Like googleapis' GaxiosError: the failed request, body and all, rides on
    // the error.
    const encoded = Buffer.from(TOKEN).toString("base64");
    secrets.failures.createSecretVersion = Object.assign(
      new Error("Too Many Requests"),
      { config: { data: { payload: { data: encoded } }, body: encoded } }
    );

    const error = await mint().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).cause).toBeUndefined();
    const everything = JSON.stringify(error) + String(error) + lines.join("\n");
    expect(everything).not.toContain(TOKEN);
    expect(everything).not.toContain(encoded);
  });
});

describe("findAgent", () => {
  const find = (
    snowflake: ReturnType<typeof fakeSession>,
    secrets: ReturnType<typeof fakeSecrets>
  ) =>
    findAgent(
      snowflake.session,
      secrets.client,
      capturingLogger().logger,
      context,
      NAME
    );

  it("matches only the exact name, since LIKE's `_` is a wildcard", async () => {
    const snowflake = fakeSession();
    snowflake.on("SHOW USERS", () => [{ name: "P0_AGENTXR123" }]);
    const secrets = fakeSecrets(SecretManagerClientModule);
    secrets.existing.add(context.secretName);

    await expect(find(snowflake, secrets)).resolves.toBeNull();
    expect(snowflake.statements).toEqual([`SHOW USERS LIKE 'P0_AGENT_R123'`]);
  });

  it("returns the name when the user and its secret exist", async () => {
    const snowflake = fakeSession();
    snowflake.on("SHOW USERS", () => [{ name: NAME }]);
    const secrets = fakeSecrets(SecretManagerClientModule);
    secrets.existing.add(context.secretName);

    await expect(find(snowflake, secrets)).resolves.toBe(NAME);
    expect(snowflake.statements).toHaveLength(1);
  });

  it("removes a user whose mint never finished, and reports it missing", async () => {
    const snowflake = sessionWithRole();
    snowflake.on("SHOW USERS", () => [{ name: NAME }]);
    const secrets = fakeSecrets(SecretManagerClientModule);

    await expect(find(snowflake, secrets)).resolves.toBeNull();
    expect(snowflake.statements.slice(1)).toEqual([
      ...dropRoleSteps,
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
  });

  // The process died after the secret was created but before the token was
  // stored in it: the secret exists, but holds nothing.
  it("removes a user still pending its token, even with its secret", async () => {
    const snowflake = fakeSession();
    snowflake.on("SHOW USERS", () => [
      { name: NAME, comment: PENDING_COMMENT },
    ]);
    const secrets = fakeSecrets(SecretManagerClientModule);
    secrets.existing.add(context.secretName);

    await expect(find(snowflake, secrets)).resolves.toBeNull();
    expect(secrets.existing.size).toBe(0);
    expect(snowflake.statements.slice(-1)).toEqual([
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
  });
});

describe("removeAgent", () => {
  it("deletes the secret, then drops the role, then the user", async () => {
    const snowflake = sessionWithRole();
    const secrets = fakeSecrets(SecretManagerClientModule);
    secrets.existing.add(context.secretName);

    await removeAgent(snowflake.session, secrets.client, context, NAME);

    expect(secrets.existing.size).toBe(0);
    expect(snowflake.statements).toEqual([
      ...dropRoleSteps,
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
  });

  // Snowflake gives a dropped role's objects to the role that drops it, so
  // the drop runs as the agent's own empty owner role, never the connector's.
  it("drops the role as the agent's own owner role, then takes it back", () => {
    expect(dropRoleStatements(context, NAME)).toEqual({
      createOwner: `CREATE ROLE IF NOT EXISTS "${NAME}_OWNER" COMMENT = 'Owns what P0 agent ${NAME} created'`,
      lendOwner: `GRANT ROLE "${NAME}_OWNER" TO ROLE "P0_AI_CONNECTOR"`,
      transfer: `GRANT OWNERSHIP ON ROLE "${NAME}" TO ROLE "${NAME}_OWNER" COPY CURRENT GRANTS`,
      useOwner: `USE ROLE "${NAME}_OWNER"`,
      drop: `DROP ROLE IF EXISTS "${NAME}"`,
      useConnector: `USE ROLE "P0_AI_CONNECTOR"`,
      reclaimOwner: `REVOKE ROLE "${NAME}_OWNER" FROM ROLE "P0_AI_CONNECTOR"`,
    });
  });

  it("makes no owner role when the agent's role is already gone", async () => {
    const snowflake = fakeSession();
    const secrets = fakeSecrets(SecretManagerClientModule);

    await removeAgent(snowflake.session, secrets.client, context, NAME);

    expect(snowflake.statements).toEqual([
      `SHOW ROLES LIKE '${NAME}'`,
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
  });

  it("switches back to the connector's role when the drop fails", async () => {
    const snowflake = sessionWithRole();
    snowflake.failOn("DROP ROLE", new Error("boom"));
    const secrets = fakeSecrets(SecretManagerClientModule);

    await expect(
      removeAgent(snowflake.session, secrets.client, context, NAME)
    ).rejects.toThrow("boom");
    expect(snowflake.statements.slice(-1)).toEqual([
      `USE ROLE "P0_AI_CONNECTOR"`,
    ]);
  });

  it("succeeds when everything is already gone", async () => {
    const snowflake = fakeSession();
    const secrets = fakeSecrets(SecretManagerClientModule);

    await expect(
      removeAgent(snowflake.session, secrets.client, context, NAME)
    ).resolves.toBeUndefined();
  });

  it("leaves the user when the role drop fails, so a retry finds it and finishes", async () => {
    const snowflake = sessionWithRole();
    snowflake.failOn("DROP ROLE", new Error("boom"));
    const secrets = fakeSecrets(SecretManagerClientModule);
    secrets.existing.add(context.secretName);

    await expect(
      removeAgent(snowflake.session, secrets.client, context, NAME)
    ).rejects.toThrow("boom");
    expect(snowflake.statements.join("\n")).not.toContain("DROP USER");

    // The retry: the user is still there, without its secret.
    const retry = fakeSession();
    retry.on("SHOW USERS", () => [{ name: NAME }]);
    await expect(
      findAgent(
        retry.session,
        secrets.client,
        capturingLogger().logger,
        context,
        NAME
      )
    ).resolves.toBeNull();
    expect(retry.statements.slice(-1)).toEqual([
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
  });
});

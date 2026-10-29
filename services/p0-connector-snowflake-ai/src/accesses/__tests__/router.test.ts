import { ConnectorError, createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  NAME,
  PRIVATE_KEY,
  PRIVATE_KEY_SECRET,
  TOKEN,
  context,
  fakeSecrets,
  fakeSession,
} from "../../__tests__/fakes.ts";
import { dropRoleStatements } from "../../agent.ts";
import type { RequestContext } from "../../context.ts";
import { t } from "../../router.ts";
import type * as ClientModule from "../../snowflake/client.ts";
import type { SnowflakeSignIn } from "../../snowflake/client.ts";
import { router as objectsRouter } from "../objects/handler.ts";
import { router as roleRouter } from "../role/handler.ts";

let snowflake = fakeSession();
let secrets: ReturnType<typeof fakeSecrets>;
const signIns: SnowflakeSignIn[] = [];

vi.mock("../../snowflake/client.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof ClientModule>();
  return {
    ...actual,
    withSnowflake: async (
      signIn: SnowflakeSignIn,
      _logger: unknown,
      use: (session: typeof snowflake.session) => Promise<unknown>
    ) => {
      signIns.push(signIn);
      return await use(snowflake.session);
    },
  };
});

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SecretManagerClientModule>();
    return {
      ...actual,
      createSecretManagerClient: async (config: unknown) => {
        secretManagerConfigs.push(config);
        return secrets.client;
      },
    };
  }
);

/** The provider config of each secret manager the connector opened. */
const secretManagerConfigs: unknown[] = [];

beforeEach(async () => {
  const actual = await vi.importActual<typeof SecretManagerClientModule>(
    "@p0security/connector-secret-manager-client"
  );
  snowflake = fakeSession();
  snowflake.on("ALTER USER", () => [{ token_secret: TOKEN }]);
  secrets = fakeSecrets(actual);
  secrets.values.set(PRIVATE_KEY_SECRET, PRIVATE_KEY);
  signIns.length = 0;
  secretManagerConfigs.length = 0;
});

const role = () => roleRouter(t).createCaller({ logger: createLogger() });
const objects = () => objectsRouter(t).createCaller({ logger: createLogger() });

describe("provisionUser", () => {
  it("signs in as the connector, with the key from its secret", async () => {
    await role().provisionUser({ userBody: NAME, context });

    expect(signIns[0]).toEqual({
      account: "ORG-ACCT",
      username: "P0_AI_CONNECTOR",
      role: "P0_AI_CONNECTOR",
      warehouse: "P0_AI_WH",
      privateKey: PRIVATE_KEY,
    });
  });

  it("mints the user when none exists", async () => {
    await expect(
      role().provisionUser({ userBody: NAME, context })
    ).resolves.toBe(NAME);

    expect(snowflake.statements[0]).toMatch(/^SHOW USERS LIKE/);
    expect(snowflake.statements).toContain(
      `GRANT ROLE "${NAME}" TO USER "${NAME}"`
    );
    expect(secrets.values.get(context.secretName)).toBe(TOKEN);
  });

  it("stores the token in AWS Secrets Manager for an install on AWS", async () => {
    const awsContext: RequestContext = {
      ...context,
      secrets: {
        manager: "aws",
        region: "us-west-2",
        privateKeySecretId: PRIVATE_KEY_SECRET,
      },
      secretName: "p0/access-token/snowflake-ai/ORG-ACCT/4f2a9c",
    };

    await expect(
      role().provisionUser({ userBody: NAME, context: awsContext })
    ).resolves.toBe(NAME);

    expect(secretManagerConfigs).toContainEqual({
      provider: "aws",
      region: "us-west-2",
    });
    expect(secrets.values.get(awsContext.secretName)).toBe(TOKEN);
  });

  it("mints nothing when the user and its secret exist", async () => {
    snowflake.on("SHOW USERS", () => [{ name: NAME }]);
    secrets.existing.add(context.secretName);

    await expect(
      role().provisionUser({ userBody: NAME, context })
    ).resolves.toBe(NAME);

    expect(snowflake.statements).toHaveLength(1);
  });

  it.each(["ALICE", "P0_AGENT_", "p0_agent_r1", 'P0_AGENT_R1"'])(
    "refuses the user name %j",
    async (userBody) => {
      await expect(
        role().provisionUser({ userBody, context })
      ).rejects.toThrow();
      expect(snowflake.statements).toEqual([]);
    }
  );

  it.each([
    { account: "evil.example.com/x" },
    { warehouse: "WH; DROP" },
    { mcpServer: "P0_AI.MCP" },
    { secretName: "projects/other/secrets/x" },
    // AWS's token prefix, but the install keeps secrets in GCP.
    { secretName: "p0/access-token/snowflake-ai/ORG-ACCT/4f2a9c" },
    // GCP's token prefix, but the install keeps secrets in AWS.
    {
      secrets: {
        manager: "aws" as const,
        region: "us-west-2",
        privateKeySecretId: "p0/install/snowflake-ai/ORG-ACCT/private-key",
      },
    },
    // Under the token prefix, but the connector's own key.
    {
      secretName: "p0_access-token_snowflake-ai_ORG-ACCT_key",
      secrets: {
        ...context.secrets,
        privateKeySecretId: "p0_access-token_snowflake-ai_ORG-ACCT_key",
      },
    },
  ])("refuses the request context %j", async (override) => {
    await expect(
      role().provisionUser({
        userBody: NAME,
        context: { ...context, ...override },
      })
    ).rejects.toThrow();
    expect(signIns).toEqual([]);
  });
});

describe("setPoliciesForUser", () => {
  it("grants each customer role to the wrapper role", async () => {
    await role().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [{ role: "ANALYST" }, { role: "Reporting" }],
      context,
    });

    expect(snowflake.statements).toEqual([
      `GRANT ROLE "ANALYST" TO ROLE "${NAME}"`,
      `GRANT ROLE "Reporting" TO ROLE "${NAME}"`,
    ]);
  });

  it("disables the user when no policies remain", async () => {
    await role().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [],
      context,
    });

    expect(snowflake.statements).toEqual([
      `ALTER USER IF EXISTS "${NAME}" SET DISABLED = TRUE`,
    ]);
  });

  it("refuses a user outside the P0 namespace", async () => {
    await expect(
      role().setPoliciesForUser({
        userId: "ACCOUNTADMIN_USER",
        userBody: "ACCOUNTADMIN_USER",
        policies: [],
        context,
      })
    ).rejects.toThrow();
    expect(snowflake.statements).toEqual([]);
  });

  it("refuses a role name that is not a plain identifier", async () => {
    await expect(
      role().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ role: 'X" TO ROLE PUBLIC; --' }],
        context,
      })
    ).rejects.toThrow();
    expect(snowflake.statements).toEqual([]);
  });

  it("grants a database entry on every schema, table and view in it", async () => {
    await objects().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [{ privilege: "SELECT", object: "SALES" }],
      context,
    });

    expect(snowflake.statements).toEqual([
      `GRANT USAGE ON DATABASE "SALES" TO ROLE "${NAME}"`,
      `GRANT USAGE ON ALL SCHEMAS IN DATABASE "SALES" TO ROLE "${NAME}"`,
      `GRANT SELECT ON ALL TABLES IN DATABASE "SALES" TO ROLE "${NAME}"`,
      `GRANT SELECT ON ALL VIEWS IN DATABASE "SALES" TO ROLE "${NAME}"`,
    ]);
  });

  it("grants a write on a schema's tables only, never its views", async () => {
    await objects().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [{ privilege: "INSERT", object: "SALES.RAW" }],
      context,
    });

    expect(snowflake.statements).toEqual([
      `GRANT USAGE ON DATABASE "SALES" TO ROLE "${NAME}"`,
      `GRANT USAGE ON SCHEMA "SALES"."RAW" TO ROLE "${NAME}"`,
      `GRANT INSERT ON ALL TABLES IN SCHEMA "SALES"."RAW" TO ROLE "${NAME}"`,
    ]);
  });

  it("grants a table entry on the table", async () => {
    await objects().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [{ privilege: "UPDATE", object: "SALES.RAW.ORDERS" }],
      context,
    });

    expect(snowflake.statements).toEqual([
      `GRANT USAGE ON DATABASE "SALES" TO ROLE "${NAME}"`,
      `GRANT USAGE ON SCHEMA "SALES"."RAW" TO ROLE "${NAME}"`,
      `GRANT UPDATE ON TABLE "SALES"."RAW"."ORDERS" TO ROLE "${NAME}"`,
    ]);
  });

  const noTable = new ConnectorError({
    type: "object_not_found",
    message: "Table does not exist",
    payload: {},
  });

  it("grants SELECT on a view when no table has the name", async () => {
    snowflake.failOn("GRANT SELECT ON TABLE", noTable);

    await objects().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [{ privilege: "SELECT", object: "SALES.RAW.ORDERS_V" }],
      context,
    });

    expect(snowflake.statements.slice(-1)).toEqual([
      `GRANT SELECT ON VIEW "SALES"."RAW"."ORDERS_V" TO ROLE "${NAME}"`,
    ]);
  });

  it("refuses a write on a view", async () => {
    snowflake.failOn("GRANT DELETE ON TABLE", noTable);

    await expect(
      objects().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ privilege: "DELETE", object: "SALES.RAW.ORDERS_V" }],
        context,
      })
    ).rejects.toThrow("can be granted only on tables");
    expect(snowflake.statements.join("\n")).not.toContain("ON VIEW");
  });

  it("refuses a privilege outside SELECT, INSERT, UPDATE and DELETE", async () => {
    await expect(
      objects().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ privilege: "OWNERSHIP" as "SELECT", object: "SALES" }],
        context,
      })
    ).rejects.toThrow();
    expect(snowflake.statements).toEqual([]);
  });
});

describe("deleteUser", () => {
  it("deletes the secret, and drops the role and the user", async () => {
    secrets.existing.add(context.secretName);
    snowflake.on("SHOW ROLES", () => [{ name: NAME }]);

    await role().deleteUser({ userId: NAME, userBody: NAME, context });

    expect(snowflake.statements).toEqual([
      `SHOW ROLES LIKE '${NAME}'`,
      ...Object.values(dropRoleStatements(context, NAME)),
      `DROP USER IF EXISTS "${NAME}"`,
    ]);
    expect(secrets.existing.has(context.secretName)).toBe(false);
  });

  it("revokes a grant that has run out, with an over-long comment", async () => {
    await expect(
      role().deleteUser({
        userId: NAME,
        userBody: NAME,
        context: { ...context, daysToExpiry: -3, comment: "x".repeat(5000) },
      })
    ).resolves.toBeNull();
  });

  it("succeeds when the secret is already gone", async () => {
    await expect(
      role().deleteUser({ userId: NAME, userBody: NAME, context })
    ).resolves.toBeNull();
  });
});

describe("list", () => {
  const {
    requestId,
    warehouse,
    daysToExpiry,
    comment,
    secretName,
    ...install
  } = context;

  it("lists roles, leaving out names the connector would refuse", async () => {
    snowflake.on("SHOW ROLES", () => [
      { name: "ANALYST" },
      { name: "has space" },
      // Created quoted: P0 would upper-case it into another role.
      { name: "analysts" },
    ]);

    await expect(
      role().list({ query: { type: "role", context: install } })
    ).resolves.toEqual([{ key: "ANALYST", value: "ANALYST" }]);
  });

  it("lists warehouses", async () => {
    snowflake.on("SHOW WAREHOUSES", () => [{ name: "ANALYTICS_WH" }]);

    await expect(
      objects().list({ query: { type: "warehouse", context: install } })
    ).resolves.toEqual([{ key: "ANALYTICS_WH", value: "ANALYTICS_WH" }]);
  });

  it("lists objects from ACCOUNT_USAGE, grouped by kind", async () => {
    snowflake.on("\nSELECT DATABASE_NAME", () => [
      { NAME: "SALES", KIND: "Database" },
      { NAME: "SALES.RAW", KIND: "Schema" },
      { NAME: "SALES.RAW.ORDERS", KIND: "Table" },
      { NAME: "SALES.RAW.ORDERS_V", KIND: "View" },
      { NAME: "SALES.RAW.my table", KIND: "Table" },
      // Created quoted: P0 would upper-case it into another table.
      { NAME: "SALES.RAW.orders", KIND: "Table" },
      // A table row with no catalog or schema.
      { NAME: null, KIND: "Table" },
    ]);

    await expect(
      objects().list({ query: { type: "object", context: install } })
    ).resolves.toEqual([
      { key: "SALES", value: "SALES", group: "Database" },
      { key: "SALES.RAW", value: "SALES.RAW", group: "Schema" },
      { key: "SALES.RAW.ORDERS", value: "SALES.RAW.ORDERS", group: "Table" },
      { key: "SALES.RAW.ORDERS_V", value: "SALES.RAW.ORDERS_V", group: "View" },
    ]);
  });
});

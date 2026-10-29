import { ConnectorError, createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  PRIVATE_KEY,
  PRIVATE_KEY_SECRET,
  fakeSecrets,
  fakeSession,
  install,
} from "../../__tests__/fakes.ts";
import { t } from "../../router.ts";
import type * as ClientModule from "../../snowflake/client.ts";
import { router } from "../handler.ts";

let snowflake = fakeSession();
let secrets: ReturnType<typeof fakeSecrets>;
const sdk = { connectError: undefined as unknown };

vi.mock("../../snowflake/client.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof ClientModule>();
  return {
    ...actual,
    withSnowflake: async (
      _signIn: unknown,
      _logger: unknown,
      use: (session: typeof snowflake.session) => Promise<unknown>
    ) => {
      if (sdk.connectError) throw actual.toConnectorError(sdk.connectError);
      return await use(snowflake.session);
    },
  };
});

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SecretManagerClientModule>();
    return { ...actual, createSecretManagerClient: async () => secrets.client };
  }
);

const answerEverything = () => {
  snowflake.on("SELECT CURRENT_USER", () => [
    { USER_NAME: "P0_AI_CONNECTOR", ROLE_NAME: "P0_AI_CONNECTOR" },
  ]);
  snowflake.on("SELECT IS_ROLE_IN_SESSION", () => [
    { USERADMIN: true, SECURITYADMIN: true },
  ]);
  snowflake.on("SHOW MCP SERVERS", () => [{ name: "P0_SQL_V1" }]);
  snowflake.on("SHOW AUTHENTICATION POLICIES", () => [
    { name: "P0_AGENT_AUTH" },
  ]);
};

beforeEach(async () => {
  const actual = await vi.importActual<typeof SecretManagerClientModule>(
    "@p0security/connector-secret-manager-client"
  );
  snowflake = fakeSession();
  secrets = fakeSecrets(actual);
  secrets.values.set(PRIVATE_KEY_SECRET, PRIVATE_KEY);
  sdk.connectError = undefined;
  answerEverything();
});

const validate = () =>
  router(t).createCaller({ logger: createLogger() }).get(install);

const stepOf = async () => {
  const error = await validate().catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("install validation", () => {
  it("passes, and reports who the connector signed in as", async () => {
    await expect(validate()).resolves.toEqual({
      user: "P0_AI_CONNECTOR",
      role: "P0_AI_CONNECTOR",
    });
    expect(snowflake.statements.slice(-2)).toEqual([
      `SHOW MCP SERVERS LIKE 'P0_SQL_V1' IN SCHEMA "P0_AI"."MCP"`,
      `SHOW AUTHENTICATION POLICIES LIKE 'P0_AGENT_AUTH' IN SCHEMA "P0_AI"."MCP"`,
    ]);
  });

  it("fails at private_key when the key secret is missing", async () => {
    secrets.values.clear();

    expect(await stepOf()).toMatchObject({
      type: "object_not_found",
      payload: { step: "private_key", account: "ORG-ACCT" },
    });
  });

  it("fails at private_key, without quoting it, when the key is malformed", async () => {
    const bad =
      "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----";
    secrets.values.set(PRIVATE_KEY_SECRET, bad);

    const data = await stepOf();
    expect(data).toMatchObject({
      type: "validation_error",
      payload: { step: "private_key" },
    });
    expect(JSON.stringify(data)).not.toContain("not-a-key");
  });

  it("fails at sign_in when Snowflake refuses the key", async () => {
    sdk.connectError = Object.assign(new Error("JWT token is invalid"), {
      code: "390144",
    });

    expect(await stepOf()).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "sign_in" },
    });
  });

  it("fails at admin_roles without SECURITYADMIN", async () => {
    snowflake.on("SELECT IS_ROLE_IN_SESSION", () => [
      { USERADMIN: true, SECURITYADMIN: false },
    ]);

    expect(await stepOf()).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "admin_roles" },
    });
  });

  it("fails at account_usage when ACCOUNT_USAGE is unreadable", async () => {
    snowflake.failOn(
      "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE",
      Object.assign(new Error("Insufficient privileges"), {
        code: "003001",
        sqlState: "42501",
      })
    );

    expect(await stepOf()).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "account_usage" },
    });
  });

  it("fails at mcp_server when only a near-match exists", async () => {
    snowflake.on("SHOW MCP SERVERS", () => [{ name: "P0XSQL" }]);

    expect(await stepOf()).toMatchObject({
      type: "object_not_found",
      payload: { step: "mcp_server" },
    });
  });

  it("fails at agent_auth_policy when the policy is missing", async () => {
    snowflake.on("SHOW AUTHENTICATION POLICIES", () => []);

    expect(await stepOf()).toMatchObject({
      type: "object_not_found",
      payload: { step: "agent_auth_policy" },
    });
  });
});

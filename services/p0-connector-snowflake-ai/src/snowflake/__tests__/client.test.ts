import { ConnectorError } from "@p0security/connector";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TOKEN, capturingLogger } from "../../__tests__/fakes.ts";
import { statementKind, toConnectorError, withSnowflake } from "../client.ts";

type Complete = (error: unknown, statement: unknown, rows?: unknown[]) => void;

type FakeSdk = {
  options: Record<string, unknown>[];
  connectError: unknown;
  executeError: unknown;
  rows: unknown[];
  destroyed: number;
};

const sdk = vi.hoisted(
  (): FakeSdk => ({
    options: [],
    connectError: undefined,
    executeError: undefined,
    rows: [],
    destroyed: 0,
  })
);

vi.mock("snowflake-sdk", () => ({
  default: {
    configure: () => undefined,
    createConnection: (options: Record<string, unknown>) => {
      sdk.options.push(options);
      const connection = {
        connect: (callback: (error: unknown, c: unknown) => void) => {
          callback(sdk.connectError, connection);
          return connection;
        },
        execute: ({ complete }: { complete: Complete }) => {
          complete(sdk.executeError, { getQueryId: () => "qid-1" }, sdk.rows);
        },
        destroy: (callback: (error: unknown) => void) => {
          sdk.destroyed++;
          callback(undefined);
        },
      };
      return connection;
    },
  },
}));

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

const signIn = {
  account: "ORG-ACCT",
  username: "P0_AI_CONNECTOR",
  role: "P0_AI_CONNECTOR",
  warehouse: "P0_AI_WH",
  privateKey,
};

beforeEach(() => {
  sdk.options.length = 0;
  sdk.connectError = undefined;
  sdk.executeError = undefined;
  sdk.rows = [];
  sdk.destroyed = 0;
});

describe("withSnowflake", () => {
  it("signs in with the key pair as the connector's user and role", async () => {
    const { logger } = capturingLogger();

    await withSnowflake(signIn, logger, async () => undefined);

    expect(sdk.options).toEqual([
      expect.objectContaining({
        account: "ORG-ACCT",
        username: "P0_AI_CONNECTOR",
        authenticator: "SNOWFLAKE_JWT",
        role: "P0_AI_CONNECTOR",
        warehouse: "P0_AI_WH",
      }),
    ]);
  });

  it("returns rows, and logs neither the rows nor the statement's text", async () => {
    const { logger, lines } = capturingLogger();
    sdk.rows = [{ token_secret: TOKEN }];

    const rows = await withSnowflake(signIn, logger, (session) =>
      session.query(
        `ALTER USER "P0_AGENT_R1" ADD PROGRAMMATIC ACCESS TOKEN "P0_GRANT"`
      )
    );

    expect(rows).toEqual([{ token_secret: TOKEN }]);
    const logged = lines.join("\n");
    expect(logged).toContain("ALTER USER");
    expect(logged).not.toContain(TOKEN);
    expect(logged).not.toContain("P0_AGENT_R1");
    expect(logged).not.toContain("PRIVATE KEY");
  });

  it("destroys the connection when the work fails", async () => {
    const { logger } = capturingLogger();

    await expect(
      withSnowflake(signIn, logger, async () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");
    expect(sdk.destroyed).toBe(1);
  });

  it("maps a failed statement to a ConnectorError", async () => {
    const { logger } = capturingLogger();
    sdk.executeError = Object.assign(new Error("Object does not exist"), {
      code: "002003",
      sqlState: "02000",
    });

    const error = await withSnowflake(signIn, logger, (session) =>
      session.execute(`DROP ROLE "X"`)
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toMatchObject({
      type: "object_not_found",
      payload: { code: "002003", sqlState: "02000", statement: "DROP ROLE" },
    });
    expect(sdk.destroyed).toBe(1);
  });

  it("refuses a key that is not an unencrypted PKCS8 PEM, without quoting it", async () => {
    const { logger } = capturingLogger();
    const bad =
      "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----";

    const error = await withSnowflake(
      { ...signIn, privateKey: bad },
      logger,
      async () => undefined
    ).catch((e: unknown) => e);

    expect((error as ConnectorError).data.type).toBe("validation_error");
    expect(JSON.stringify((error as ConnectorError).data)).not.toContain(
      "not-a-key"
    );
    expect(sdk.options).toEqual([]);
  });

  it("maps a refused sign-in", async () => {
    const { logger } = capturingLogger();
    sdk.connectError = Object.assign(new Error("JWT token is invalid"), {
      code: "390144",
    });

    const error = await withSnowflake(
      signIn,
      logger,
      async () => undefined
    ).catch((e: unknown) => e);

    expect((error as ConnectorError).data.type).toBe("insufficient_privileges");
  });
});

describe("toConnectorError", () => {
  it.each([
    [{ code: "002002", sqlState: "42710" }, "already_exists"],
    [{ code: "003001", sqlState: "42501" }, "insufficient_privileges"],
    [{ code: "002043", sqlState: "02000" }, "object_not_found"],
    [{ code: "001003", sqlState: "42000" }, "unknown"],
    [{ code: 401001 }, "upstream_unavailable"],
    [{}, "unknown"],
  ])("maps %j to %s", (fields, type) => {
    expect(
      toConnectorError(Object.assign(new Error("x"), fields)).data.type
    ).toBe(type);
  });

  it("passes a ConnectorError through", () => {
    const error = new ConnectorError({
      type: "validation_error",
      message: "m",
      payload: {},
    });
    expect(toConnectorError(error)).toBe(error);
  });
});

describe("statementKind", () => {
  it("keeps only the first two words", () => {
    expect(statementKind(`  grant usage ON WAREHOUSE "X" TO ROLE "Y"`)).toBe(
      "GRANT USAGE"
    );
  });
});

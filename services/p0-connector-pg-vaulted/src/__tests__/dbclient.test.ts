import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import knex, { type Knex } from "knex";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { type ClientDependencies, newClient } from "../dbclient.ts";
import {
  CONNECTOR_ENV,
  MANAGER,
  MANAGER_SECRET,
  dataOf,
  errorOf,
  fakeSecretStore,
} from "./fakes.ts";
import { target } from "./fixtures.ts";

const { host, port, database } = target;

let vault = fakeSecretStore();
/** The config of every client built. Each is a real client, which connects
 * on its first statement, so none does. */
let built: Knex.Config[] = [];
let clients: Knex[] = [];

const recordingKnex = (config: Knex.Config) => {
  built.push(config);
  const client = knex(config);
  clients.push(client);
  return client;
};

beforeEach(() => {
  vault = fakeSecretStore();
  built = [];
  clients = [];
});

afterEach(async () => {
  await Promise.all(clients.map((client) => client.destroy()));
});

const signIn = (
  overrides: ClientDependencies = {},
  managerSecret = MANAGER_SECRET
) =>
  newClient({ host, port, database, managerSecret }, "rds", {
    env: CONNECTOR_ENV,
    connectSecretManager: vault.connectSecretManager,
    knex: recordingKnex,
    ...overrides,
  });

/** Who each client signs in as, and where. */
const signIns = () =>
  built.map(({ connection }) => {
    const { user, password, host, port, database } =
      connection as Knex.PgConnectionConfig;
    return { user, password, host, port, database };
  });

describe("newClient on RDS", () => {
  it("signs in with the manager secret's username and password, read in the connector's region, over verified TLS", async () => {
    await signIn();

    expect(vault.reads).toEqual([
      {
        config: { provider: "aws", region: "us-east-1" },
        ref: "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
      },
    ]);
    expect(signIns()).toEqual([
      {
        user: "p0_manager",
        password: "correct-horse-battery-staple",
        host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
        port: 5432,
        database: "postgres",
      },
    ]);
    expect((built[0]?.connection as Knex.PgConnectionConfig).ssl).toMatchObject(
      { rejectUnauthorized: true }
    );
  });

  it.each([
    [
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
      "us-east-1",
    ],
    [
      "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
      "ap-southeast-2",
    ],
    [
      "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
      "cn-north-1",
    ],
    [
      "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
      "us-gov-west-1",
    ],
  ])(
    "reads the secret RDS manages %s in its ARN's region, %s, whatever the connector's",
    async (managerSecret, region) => {
      vault = fakeSecretStore({ [managerSecret]: JSON.stringify(MANAGER) });

      await signIn({ env: { AWS_REGION: "eu-central-1" } }, managerSecret);

      expect(vault.reads).toEqual([
        { config: { provider: "aws", region }, ref: managerSecret },
      ]);
      expect(signIns().map(({ user }) => user)).toEqual(["p0_manager"]);
    }
  );

  it("reads a secret RDS manages with no region in the connector's environment", async () => {
    const managerSecret =
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123";
    vault = fakeSecretStore({ [managerSecret]: JSON.stringify(MANAGER) });

    await signIn({ env: {} }, managerSecret);

    expect(vault.reads).toEqual([
      { config: { provider: "aws", region: "us-west-2" }, ref: managerSecret },
    ]);
  });

  it.each([{}, { AWS_REGION: "" }])(
    "fails, and reads nothing, when the connector's environment %j has no region",
    async (env) => {
      const data = await dataOf(signIn({ env }));

      expect(data).toEqual({
        type: "validation_error",
        message:
          "The connector's AWS_REGION environment variable is not set, so it does not know the region to read the manager secret in. AWS Lambda sets it.",
        payload: {},
      });
      expect(vault.reads).toEqual([]);
      expect(built).toEqual([]);
    }
  );

  it("fails as not found when the manager secret does not exist", async () => {
    vault = fakeSecretStore({});

    const data = await dataOf(signIn());

    expect(data).toEqual({
      type: "object_not_found",
      message: "The manager secret does not exist or has no value.",
      payload: {},
    });
    expect(built).toEqual([]);
  });

  it.each([
    [
      "may not be read",
      new UnauthorizedError("aws"),
      "insufficient_privileges",
    ],
    [
      "cannot be reached",
      new Error("getaddrinfo ENOTFOUND"),
      "upstream_unavailable",
    ],
  ])("fails when the manager secret %s", async (_, fail, type) => {
    vault.state.fail = fail;

    const data = await dataOf(signIn());

    expect(data.type).toBe(type);
    expect(built).toEqual([]);
  });

  it.each([
    ["is not JSON", "p0_manager:correct-horse-battery-staple"],
    ["is not an object", JSON.stringify("correct-horse-battery-staple")],
    ["has no password", JSON.stringify({ username: "p0_manager" })],
    ["has no username", JSON.stringify({ password: MANAGER.password })],
    [
      "has a password that is not text",
      JSON.stringify({ username: "p0_manager", password: 12345678 }),
    ],
    ["has an empty username", JSON.stringify({ ...MANAGER, username: "" })],
  ])(
    "fails as a validation error when the secret's value %s",
    async (_, value) => {
      vault = fakeSecretStore({ [MANAGER_SECRET]: value });

      const data = await dataOf(signIn());

      expect(data).toEqual({
        type: "validation_error",
        message:
          "The manager secret's value must be a JSON object with a username and a password.",
        payload: {},
      });
      expect(built).toEqual([]);
    }
  );

  it("reads a binary value, and ignores the keys AWS adds for RDS", async () => {
    vault = fakeSecretStore({
      [MANAGER_SECRET]: Buffer.from(
        JSON.stringify({
          engine: "postgres",
          host: "another.example.com",
          port: 6543,
          dbname: "other",
          username: "rds_admin",
          password: "s3cr3t-from-rds",
        })
      ),
    });

    await signIn();

    expect(signIns()).toEqual([
      {
        user: "rds_admin",
        password: "s3cr3t-from-rds",
        host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
        port: 5432,
        database: "postgres",
      },
    ]);
  });

  it.each([
    [
      "the secret manager's error quotes the secret",
      () => {
        const value = JSON.stringify(MANAGER);
        vault.state.fail = new Error(`unexpected response ${value}`, {
          cause: new Error(value),
        });
      },
    ],
    [
      "the secret's value is not JSON",
      () => {
        vault = fakeSecretStore({
          [MANAGER_SECRET]: `password=${MANAGER.password}`,
        });
      },
    ],
  ])("holds no password in its error when %s", async (_, arrange) => {
    arrange();

    const error = await errorOf(signIn());

    expect(inspect(error, { depth: 10 })).not.toContain(MANAGER.password);
  });
});

describe("newClient on localhost", () => {
  it("signs in as the local test server's superuser, without TLS, and reads no secret", async () => {
    await newClient(
      {
        host: "localhost",
        port: 5432,
        database,
        managerSecret: MANAGER_SECRET,
      },
      "localhost",
      { connectSecretManager: vault.connectSecretManager, knex: recordingKnex }
    );

    expect(vault.reads).toEqual([]);
    expect(signIns()).toEqual([
      {
        user: "pspladmin",
        password: "psqlpass",
        host: "localhost",
        port: 5432,
        database: "postgres",
      },
    ]);
    expect((built[0]?.connection as Knex.PgConnectionConfig).ssl).toBe(false);
  });
});

describe("a client whose connection fails", () => {
  it("rejects with the driver's error", async () => {
    const client = await newClient(
      { host: "127.0.0.1", port: 1, database, managerSecret: MANAGER_SECRET },
      "localhost"
    );
    clients.push(client);

    const error = await errorOf(client.raw("SELECT 1"));

    expect(error).toMatchObject({ code: "ECONNREFUSED" });
  });
});

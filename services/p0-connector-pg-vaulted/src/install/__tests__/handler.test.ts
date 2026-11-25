import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";

import {
  CONNECTOR_ENV,
  MANAGER,
  MANAGER_SECRET,
  capturingLogger,
  dataOf,
  errorOf,
  fakeDatabase,
  fakeSecretStore,
  networkError,
  pgError,
  withoutProbeName,
} from "../../__tests__/fakes.ts";
import { target } from "../../__tests__/fixtures.ts";
import type { ClientDependencies } from "../../dbclient.ts";
import { t } from "../../router.ts";
import { router } from "../handler.ts";

const HOST = "orders.cluster-abc123.us-east-1.rds.amazonaws.com";

let db = fakeDatabase();
let vault = fakeSecretStore();
let log = capturingLogger();

beforeEach(() => {
  db = fakeDatabase();
  vault = fakeSecretStore();
  log = capturingLogger();
});

const validation = (overrides: ClientDependencies = {}) =>
  router(t, {
    env: CONNECTOR_ENV,
    connectSecretManager: vault.connectSecretManager,
    knex: db.knex,
    ...overrides,
  }).createCaller({ logger: log.logger });

const validate = (overrides: ClientDependencies = {}) =>
  validation(overrides).get({ target });

describe("install validation input", () => {
  it("refuses an input with no target", async () => {
    // @ts-expect-error -- the input is { target }
    await expect(validation().get({})).rejects.toThrow("target");
  });

  it.each([0, 65536, 5432.5])("refuses the port %j", async (port) => {
    await expect(
      validation().get({ target: { ...target, port } })
    ).rejects.toThrow("port");
  });

  it.each([
    ["a name P0 does not give", "orders-manager"],
    [
      "a name with another leaf",
      "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/manager",
    ],
    [
      "a name with no p0manager leaf",
      "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod",
    ],
    [
      "a name under another prefix",
      "p0/secrets/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
    ],
    ["a name with no vpc id", "p0/install/postgres/orders-prod/p0manager"],
    [
      "a name with an uppercase vpc id",
      "p0/install/postgres/vpc-0A1B2C3D/orders-prod/p0manager",
    ],
    [
      "a name with a target id P0 does not give",
      "p0/install/postgres/vpc-0a1b2c3d/-orders/p0manager",
    ],
    [
      "the ARN of a secret RDS does not manage",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
    ],
    [
      "the ARN of a secret P0 names",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager-AbCdEf",
    ],
    [
      "an RDS secret's name with no ARN",
      "rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with an uppercase uuid",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0A1B2C3D-4E5F-6789-ABCD-EF0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with no suffix",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    ],
    [
      "an RDS secret's ARN with a short suffix",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC12",
    ],
    [
      "an RDS secret's ARN with a uuid cut short",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef01234567-AbC123",
    ],
    [
      "an RDS secret's ARN of another kind",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!proxy-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with no account",
      "arn:aws:secretsmanager:us-east-1::secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN in an unknown partition",
      "arn:aws-iso:secretsmanager:us-iso-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an ARN of another service",
      "arn:aws:ssm:us-east-1:123456789012:parameter/rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
  ])("refuses %s as the manager secret", async (_, managerSecret) => {
    await expect(
      validation().get({ target: { ...target, managerSecret } })
    ).rejects.toThrow("managerSecret must be a name");
  });
});

describe("install validation", () => {
  it.each([
    "p0/install/postgres/vpc-0a1b2c3d/O/p0manager",
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-zzzzzz",
  ])("signs in with the manager secret %s", async (managerSecret) => {
    vault = fakeSecretStore({ [managerSecret]: JSON.stringify(MANAGER) });

    await expect(
      validation().get({ target: { ...target, managerSecret } })
    ).resolves.toEqual({ grantableRoles: ["analyst", "reporting"] });
    expect(vault.reads.map(({ ref }) => ref)).toEqual([managerSecret]);
  });

  it("returns the grantable roles once every check has passed", async () => {
    await expect(validate()).resolves.toEqual({
      grantableRoles: ["analyst", "reporting"],
    });
  });

  it("reads the manager secret in the connector's region, and signs in with it", async () => {
    await validate();

    expect(vault.reads).toEqual([
      {
        config: { provider: "aws", region: "us-east-1" },
        ref: "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
      },
    ]);
    expect(db.signIns).toEqual([
      {
        host: HOST,
        port: 5432,
        database: "postgres",
        user: "p0_manager",
        password: "correct-horse-battery-staple",
      },
    ]);
  });

  it("runs the checks in order, proves the reassign with a probe role, and leaves no role behind", async () => {
    await validate();

    expect(withoutProbeName(db.calls)).toEqual([
      "ping",
      "canCreateRole",
      "canSignalBackend",
      "grantableRoles",
      "hasGrantOptions",
      "BEGIN",
      'CREATE ROLE "<probe>" NOLOGIN',
      'GRANT "<probe>" TO current_user WITH INHERIT TRUE',
      'GRANT "analyst" TO current_user WITH SET TRUE',
      'REASSIGN OWNED BY "<probe>" TO "analyst"',
      "ROLLBACK",
      "close",
    ]);
    expect([...db.roles]).toEqual([]);
  });

  it("grants itself the roles without options before PostgreSQL 16", async () => {
    db = fakeDatabase({ hasGrantOptions: false });

    await validate();

    expect(withoutProbeName(db.calls).slice(5, 11)).toEqual([
      "BEGIN",
      'CREATE ROLE "<probe>" NOLOGIN',
      'GRANT "<probe>" TO current_user',
      'GRANT "analyst" TO current_user',
      'REASSIGN OWNED BY "<probe>" TO "analyst"',
      "ROLLBACK",
    ]);
  });

  it("with no grantable role, passes once the probe role can be created", async () => {
    db = fakeDatabase({ grantableRoles: [] });

    await expect(validate()).resolves.toEqual({ grantableRoles: [] });
    expect(withoutProbeName(db.calls).slice(5)).toEqual([
      "BEGIN",
      'CREATE ROLE "<probe>" NOLOGIN',
      "ROLLBACK",
      "close",
    ]);
    expect([...db.roles]).toEqual([]);
  });

  it("leaves out a role whose name no policy can hold, and reassigns to the first it keeps", async () => {
    db = fakeDatabase({ grantableRoles: ["Sales Team", "analyst"] });

    await expect(validate()).resolves.toEqual({ grantableRoles: ["analyst"] });
    expect(withoutProbeName(db.calls)).toContain(
      'REASSIGN OWNED BY "<probe>" TO "analyst"'
    );
  });
});

describe("manager_secret", () => {
  it.each([{}, { AWS_REGION: "" }])(
    "fails, and reads nothing, when the connector's environment %j has no region",
    async (env) => {
      const data = await dataOf(validate({ env }));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(
        "The connector's AWS_REGION environment variable is not set, so it does not know the region to read the manager secret in. AWS Lambda sets it."
      );
      expect(data.payload).toEqual({ step: "manager_secret", host: HOST });
      expect(vault.reads).toEqual([]);
      expect(db.signIns).toEqual([]);
    }
  );

  it("fails as not found when the manager secret does not exist", async () => {
    vault = fakeSecretStore({});

    const data = await dataOf(validate());

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({ step: "manager_secret", host: HOST });
    expect(db.signIns).toEqual([]);
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

    const data = await dataOf(validate());

    expect(data.type).toBe(type);
    expect(data.payload).toEqual({ step: "manager_secret", host: HOST });
    expect(db.signIns).toEqual([]);
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

      const data = await dataOf(validate());

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ step: "manager_secret", host: HOST });
      expect(db.signIns).toEqual([]);
    }
  );
});

describe("sign_in", () => {
  it("fails as insufficient privileges when PostgreSQL refuses the password", async () => {
    db.failOn("ping", pgError("28P01"));

    const data = await dataOf(validate());

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({
      sqlState: "28P01",
      step: "sign_in",
      host: HOST,
    });
    expect(db.calls).toEqual(["ping", "close"]);
  });

  it("fails as unavailable when PostgreSQL cannot be reached", async () => {
    db.failOn("ping", networkError("ECONNREFUSED"));

    const data = await dataOf(validate());

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      code: "ECONNREFUSED",
      step: "sign_in",
      host: HOST,
    });
    expect(data.message).not.toContain("10.0.0.7");
  });
});

describe("the privilege checks", () => {
  it("fails at create_role when the manager cannot create roles, and checks nothing after it", async () => {
    db = fakeDatabase({ canCreateRole: false });

    const data = await dataOf(validate());

    expect(data).toEqual({
      type: "insufficient_privileges",
      message: "The manager cannot create roles. Give it CREATEROLE.",
      payload: { step: "create_role", host: HOST },
    });
    expect(db.calls).toEqual(["ping", "canCreateRole", "close"]);
  });

  it("fails at signal_backend when the manager cannot end sessions, and checks nothing after it", async () => {
    db = fakeDatabase({ canSignalBackend: false });

    const data = await dataOf(validate());

    expect(data).toEqual({
      type: "insufficient_privileges",
      message:
        "The manager cannot end other logins' sessions. Grant it pg_signal_backend.",
      payload: { step: "signal_backend", host: HOST },
    });
    expect(db.calls).toEqual([
      "ping",
      "canCreateRole",
      "canSignalBackend",
      "close",
    ]);
  });

  it("names the step whose statement PostgreSQL cancelled", async () => {
    db.failOn("canSignalBackend", pgError("57014"));

    const data = await dataOf(validate());

    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      sqlState: "57014",
      step: "signal_backend",
      host: HOST,
    });
  });

  it.each(["CREATE ROLE", 'GRANT "p0v_', 'GRANT "analyst"', "REASSIGN OWNED"])(
    "fails at reassign_owned when PostgreSQL refuses %j, and leaves no role behind",
    async (statement) => {
      db.failOn(statement, pgError("42501"));

      const data = await dataOf(validate());

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        sqlState: "42501",
        step: "reassign_owned",
        host: HOST,
      });
      expect(db.calls.slice(-2)).toEqual(["ROLLBACK", "close"]);
      expect(db.calls.at(-3)).toContain(statement);
      expect([...db.roles]).toEqual([]);
    }
  );
});

describe("the manager's password", () => {
  const SECRET_VALUE = JSON.stringify(MANAGER);

  /** Everything a failed call shows: the error with its causes, and the log. */
  const shownBy = async (call: Promise<unknown>) => {
    const error = await errorOf(call);
    return `${inspect(error, { depth: 10 })}\n${log.lines.join("")}`;
  };

  it("is in no error and no log line when PostgreSQL's error quotes it", async () => {
    db.failOn(
      "ping",
      pgError("28P01", `ALTER ROLE x PASSWORD '${MANAGER.password}'`)
    );

    const shown = await shownBy(validate());

    expect(shown).toContain("connector request errored");
    expect(shown).toContain("28P01");
    expect(shown).not.toContain(MANAGER.password);
  });

  it("is in no error and no log line when the secret manager's error quotes the secret", async () => {
    vault.state.fail = new Error(`unexpected response ${SECRET_VALUE}`, {
      cause: new Error(SECRET_VALUE),
    });

    const shown = await shownBy(validate());

    expect(shown).toContain("connector request errored");
    expect(shown).toContain("The connector could not read the manager secret.");
    expect(shown).not.toContain(MANAGER.password);
  });

  it("is in no error and no log line when the secret's value is not JSON", async () => {
    vault = fakeSecretStore({
      [MANAGER_SECRET]: `password=${MANAGER.password}`,
    });

    const shown = await shownBy(validate());

    expect(shown).toContain("connector request errored");
    expect(shown).toContain("must be a JSON object");
    expect(shown).not.toContain(MANAGER.password);
  });

  it("is in no log line of a validation that passes", async () => {
    await validate();

    const logged = log.lines.join("");
    expect(logged).toContain("validated the PostgreSQL target");
    expect(logged).not.toContain(MANAGER.password);
    expect(logged).not.toContain(MANAGER.username);
    expect(logged).not.toContain(MANAGER_SECRET);
  });
});

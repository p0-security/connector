import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MANAGER,
  MANAGER_SECRET_ARN,
  MANAGER_TARGET_ID,
  capturingLogger,
  dataOf,
  env,
  errorOf,
  fakeDatabase,
  fakeSecretStore,
  networkError,
  pgError,
  withoutProbeName,
} from "../../__tests__/fakes.ts";
import { target } from "../../__tests__/fixtures.ts";
import type { Dependencies } from "../../dependencies.ts";
import { t } from "../../router.ts";
import { installValidation } from "../definition.ts";
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

const validation = (overrides: Dependencies = {}) =>
  router(t, {
    env,
    connectSecretManager: vault.connectSecretManager,
    connect: db.connect,
    ...overrides,
  }).createCaller({ logger: log.logger });

const validate = (overrides: Dependencies = {}) =>
  validation(overrides).get({ target });

const mappingOf = (mapping: unknown) => ({
  MANAGER_SECRET_ARNS: JSON.stringify(mapping),
});

const entry = (arn: string, targetId = MANAGER_TARGET_ID) => ({
  arn,
  targetId,
});

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

  it("the result schema accepts grantable roles", () => {
    const validated = { grantableRoles: ["analyst", "reporting"] };

    expect(installValidation.parse(validated)).toEqual(validated);
  });
});

describe("install validation", () => {
  it("returns the grantable roles once every check has passed", async () => {
    await expect(validate()).resolves.toEqual({
      grantableRoles: ["analyst", "reporting"],
    });
  });

  it("reads the manager secret in the region its ARN names, and signs in with it", async () => {
    await validate();

    expect(vault.reads).toEqual([
      {
        config: { provider: "aws", region: "us-east-1" },
        ref: "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
      },
    ]);
    expect(db.signIns).toEqual([
      {
        host: HOST,
        port: 5432,
        database: "postgres",
        username: "p0_manager",
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
      ["format", "CREATE ROLE %I NOLOGIN", "<probe>"],
      "CREATE ROLE <probe> NOLOGIN",
      ["format", "GRANT %I TO current_user WITH INHERIT TRUE", "<probe>"],
      "GRANT <probe> TO current_user WITH INHERIT TRUE",
      ["format", "GRANT %I TO current_user WITH SET TRUE", "analyst"],
      "GRANT analyst TO current_user WITH SET TRUE",
      ["format", "REASSIGN OWNED BY %I TO %I", "<probe>", "analyst"],
      "REASSIGN OWNED BY <probe> TO analyst",
      "ROLLBACK",
      "close",
    ]);
    expect([...db.roles]).toEqual([]);
  });

  it("grants itself the roles without options before PostgreSQL 16", async () => {
    db = fakeDatabase({ hasGrantOptions: false });

    await validate();

    expect(withoutProbeName(db.calls).slice(5, 15)).toEqual([
      "BEGIN",
      ["format", "CREATE ROLE %I NOLOGIN", "<probe>"],
      "CREATE ROLE <probe> NOLOGIN",
      ["format", "GRANT %I TO current_user", "<probe>"],
      "GRANT <probe> TO current_user",
      ["format", "GRANT %I TO current_user", "analyst"],
      "GRANT analyst TO current_user",
      ["format", "REASSIGN OWNED BY %I TO %I", "<probe>", "analyst"],
      "REASSIGN OWNED BY <probe> TO analyst",
      "ROLLBACK",
    ]);
  });

  it("with no grantable role, passes once the probe role can be created", async () => {
    db = fakeDatabase({ grantableRoles: [] });

    await expect(validate()).resolves.toEqual({ grantableRoles: [] });
    expect(withoutProbeName(db.calls).slice(5)).toEqual([
      "BEGIN",
      ["format", "CREATE ROLE %I NOLOGIN", "<probe>"],
      "CREATE ROLE <probe> NOLOGIN",
      "ROLLBACK",
      "close",
    ]);
    expect([...db.roles]).toEqual([]);
  });

  it("leaves out a role whose name no policy can hold, and reassigns to the first it keeps", async () => {
    db = fakeDatabase({ grantableRoles: ["Sales Team", "analyst"] });

    await expect(validate()).resolves.toEqual({ grantableRoles: ["analyst"] });
    expect(withoutProbeName(db.calls)).toContain(
      "REASSIGN OWNED BY <probe> TO analyst"
    );
  });
});

describe("manager_mapping", () => {
  it.each([
    ["is not set", {}],
    ["is empty", { MANAGER_SECRET_ARNS: "" }],
    ["is not JSON", { MANAGER_SECRET_ARNS: "{" }],
    ["is not an object", mappingOf([MANAGER_SECRET_ARN])],
    ["maps a host to an ARN alone", mappingOf({ [HOST]: MANAGER_SECRET_ARN })],
    [
      "maps a host to a secret's name",
      mappingOf({ [HOST]: entry("orders-manager") }),
    ],
    [
      "maps a host to an ARN of another service",
      mappingOf({
        [HOST]: entry(
          "arn:aws:ssm:us-east-1:123456789012:parameter/orders-manager"
        ),
      }),
    ],
    [
      "maps a host to an ARN in an unknown partition",
      mappingOf({
        [HOST]: entry(
          "arn:evil:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf"
        ),
      }),
    ],
    [
      "maps a host to an ARN whose region is not a region",
      mappingOf({
        [HOST]: entry(
          "arn:aws:secretsmanager:us-east-1.example.com/:123456789012:secret:orders-manager-AbCdEf"
        ),
      }),
    ],
    [
      "maps a host to an ARN whose account is not 12 digits",
      mappingOf({
        [HOST]: entry(
          "arn:aws:secretsmanager:us-east-1:12345:secret:orders-manager-AbCdEf"
        ),
      }),
    ],
    [
      "maps a host to an ARN with more after the secret's name",
      mappingOf({ [HOST]: entry(`${MANAGER_SECRET_ARN}:extra`) }),
    ],
    [
      "maps a host to an entry with no target id",
      mappingOf({ [HOST]: { arn: MANAGER_SECRET_ARN } }),
    ],
    [
      "maps a host to an entry with no ARN",
      mappingOf({ [HOST]: { targetId: MANAGER_TARGET_ID } }),
    ],
    [
      "maps a host to an empty target id",
      mappingOf({ [HOST]: entry(MANAGER_SECRET_ARN, "") }),
    ],
    [
      "maps a host to a target id with a slash",
      mappingOf({ [HOST]: entry(MANAGER_SECRET_ARN, "orders/prod") }),
    ],
    [
      "maps a host to a target id that starts with a hyphen",
      mappingOf({ [HOST]: entry(MANAGER_SECRET_ARN, "-orders") }),
    ],
    [
      "maps a host to a target id of 64 characters",
      mappingOf({ [HOST]: entry(MANAGER_SECRET_ARN, "a".repeat(64)) }),
    ],
    [
      "maps another host to something that is not an entry",
      mappingOf({ [HOST]: entry(MANAGER_SECRET_ARN), "other.example.com": 7 }),
    ],
  ])("fails as a validation error when the variable %s", async (_, env) => {
    const data = await dataOf(validate({ env }));

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({ step: "manager_mapping", host: HOST });
    expect(data.message).toContain("MANAGER_SECRET_ARNS");
    expect(vault.reads).toEqual([]);
    expect(db.signIns).toEqual([]);
  });

  it("fails as not found when the mapping has no entry for the target's host", async () => {
    const data = await dataOf(
      validate({
        env: mappingOf({ "billing.example.com": entry(MANAGER_SECRET_ARN) }),
      })
    );

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({ step: "manager_mapping", host: HOST });
    expect(vault.reads).toEqual([]);
  });

  it("finds the host whatever its case", async () => {
    const env = mappingOf({ [HOST.toUpperCase()]: entry(MANAGER_SECRET_ARN) });

    await expect(validate({ env })).resolves.toEqual({
      grantableRoles: ["analyst", "reporting"],
    });
    expect(vault.reads.map(({ ref }) => ref)).toEqual([MANAGER_SECRET_ARN]);
  });

  it("reads the secret in the region of an ARN in another partition", async () => {
    const arn =
      "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:p0/orders-manager-AbCdEf";
    vault = fakeSecretStore({ [arn]: JSON.stringify(MANAGER) });

    await validate({
      env: mappingOf({ [HOST]: entry(arn) }),
      connectSecretManager: vault.connectSecretManager,
    });

    expect(vault.reads).toEqual([
      { config: { provider: "aws", region: "us-gov-west-1" }, ref: arn },
    ]);
  });
});

describe("sign_in", () => {
  it("fails as not found when the manager secret does not exist", async () => {
    vault = fakeSecretStore({});

    const data = await dataOf(validate());

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({ step: "sign_in", host: HOST });
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
    expect(data.payload).toEqual({ step: "sign_in", host: HOST });
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
      vault = fakeSecretStore({ [MANAGER_SECRET_ARN]: value });

      const data = await dataOf(validate());

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ step: "sign_in", host: HOST });
      expect(db.signIns).toEqual([]);
    }
  );

  it("reads a binary value, and ignores the keys AWS adds for RDS", async () => {
    vault = fakeSecretStore({
      [MANAGER_SECRET_ARN]: Buffer.from(
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

    await validate();

    expect(db.signIns).toEqual([
      {
        host: HOST,
        port: 5432,
        database: "postgres",
        username: "rds_admin",
        password: "s3cr3t-from-rds",
      },
    ]);
  });

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

  it.each(["CREATE ROLE", "GRANT p0v_", "GRANT analyst", "REASSIGN OWNED"])(
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
      [MANAGER_SECRET_ARN]: `password=${MANAGER.password}`,
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
    expect(logged).not.toContain(MANAGER_SECRET_ARN);
  });
});

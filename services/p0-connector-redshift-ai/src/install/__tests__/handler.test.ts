import { ConnectorError, createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it } from "vitest";

import { fakeDataApi, install } from "../../__tests__/fakes.ts";
import { publicCanCreate, validateInstall } from "../handler.ts";

const ARN = "arn:aws:redshift-serverless:us-west-2:123456789012:workgroup/ca41";
const USER = "IAMR:p0-redshift-ai-connector";

let api = fakeDataApi();
let lookup: () => unknown;

const serverless = () => ({
  send: async () => lookup(),
});

/** An admin with every role and permission, one grantable table, and
 * `public` closed to PUBLIC. */
const answerEverything = () => {
  lookup = () => ({ workgroup: { workgroupArn: ARN } });
  api.on("SELECT current_user", () => [{ user_name: USER }]);
  api.on("SELECT usesuper", () => [{ usesuper: false }]);
  api.on("SELECT role_name", () => [
    { role_name: "sys:secadmin" },
    { role_name: "p0_connector_admin" },
  ]);
  api.on("SELECT system_privilege", () => [
    { system_privilege: "ACCESS SYSTEM TABLE" },
    { system_privilege: "ALTER TABLE" },
    { system_privilege: "DROP SCHEMA" },
    { system_privilege: "DROP FUNCTION" },
    { system_privilege: "DROP PROCEDURE" },
  ]);
  api.on("SELECT count(*) AS n FROM svv_relation_privileges", () => [{ n: 1 }]);
  api.on("SHOW DATABASES", () => [
    { database_name: "dev", database_type: "local" },
    { database_name: "awsdatacatalog", database_type: "auto mounted catalog" },
  ]);
  api.on("SHOW SCHEMAS", () => [
    { schema_name: "public", schema_acl: "rdsdb=UCDA/rdsdb~=U/rdsdb" },
  ]);
};

beforeEach(() => {
  api = fakeDataApi();
  answerEverything();
});

const validate = (context = install) =>
  validateInstall(context, createLogger(), {
    client: api.client,
    serverless: serverless(),
    wait: async () => {},
  });

const failureOf = async (context = install) => {
  const error = await validate(context).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("install validation", () => {
  it("passes, and returns the ARN and the connector's user", async () => {
    await expect(validate()).resolves.toEqual({
      arn: ARN,
      user: USER,
      warnings: [],
    });
  });

  it("only reads", async () => {
    await validate();
    for (const { sql } of api.statements) {
      expect(sql).toMatch(/^(SELECT|SHOW) /);
    }
  });

  it("fails at target when the workgroup is missing", async () => {
    lookup = () => {
      throw Object.assign(new Error("nope"), {
        name: "ResourceNotFoundException",
      });
    };
    const data = await failureOf();
    expect(data.payload).toMatchObject({ step: "target", target: "analytics" });
    expect(api.statements).toEqual([]);
  });

  it("fails at sign_in when the Data API refuses the role", async () => {
    api.on("SELECT current_user", () => ({
      error: "IAM role not authorized to get credentials",
    }));
    const data = await failureOf();
    expect(data).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "sign_in" },
    });
  });

  it("passes a superuser without reading its roles", async () => {
    api.on("SELECT usesuper", () => [{ usesuper: true }]);
    api.on("SELECT count(*) AS n FROM svv_relation_privileges", () => [
      { n: 0 },
    ]);
    await expect(validate()).resolves.toMatchObject({ warnings: [] });
    expect(api.statements.map(({ sql }) => sql)).not.toContainEqual(
      expect.stringMatching(
        /svv_user_grants|svv_system_privileges|svv_relation/
      )
    );
  });

  it("fails at admin_roles without sys:secadmin", async () => {
    api.on("SELECT role_name", () => [{ role_name: "p0_connector_admin" }]);
    const data = await failureOf();
    expect(data).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "admin_roles" },
    });
    expect(data.message).toContain("sys:secadmin");
  });

  it("fails at admin_roles naming each missing permission", async () => {
    api.on("SELECT system_privilege", () => [
      { system_privilege: "alter table" },
    ]);
    const data = await failureOf();
    expect(data.payload).toMatchObject({ step: "admin_roles" });
    expect(data.message).toContain(
      "ACCESS SYSTEM TABLE, DROP SCHEMA, DROP FUNCTION, DROP PROCEDURE"
    );
  });

  it("reads permissions held by the user or its roles", async () => {
    await validate();
    expect(api.statements.map(({ sql }) => sql)).toContain(
      `SELECT system_privilege FROM svv_system_privileges WHERE identity_name IN ('${USER}', 'sys:secadmin', 'p0_connector_admin')`
    );
  });

  it("checks the object owner when one is set", async () => {
    api.on("SELECT usename FROM pg_user", () => [{ usename: "etl" }]);
    await expect(
      validate({ ...install, objectOwner: "etl" })
    ).resolves.toBeDefined();
    expect(api.statements.map(({ sql }) => sql)).toContain(
      "SELECT usename FROM pg_user WHERE usename = 'etl'"
    );
  });

  it("fails at object_owner when that user is missing", async () => {
    const data = await failureOf({ ...install, objectOwner: "gone" });
    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { step: "object_owner" },
    });
  });

  it("warns when nothing is grantable", async () => {
    api.on("SELECT count(*) AS n FROM svv_relation_privileges", () => [
      { n: 0 },
    ]);
    api.on("SELECT count(*) AS n FROM (", () => [{ n: 0 }]);
    await expect(validate()).resolves.toMatchObject({
      warnings: [{ check: "grantable_objects", database: "dev" }],
    });
  });

  it("counts objects the connector owns as grantable", async () => {
    api.on("SELECT count(*) AS n FROM svv_relation_privileges", () => [
      { n: 0 },
    ]);
    api.on("SELECT count(*) AS n FROM (", () => [{ n: 2 }]);
    await expect(validate()).resolves.toMatchObject({ warnings: [] });
  });

  it("warns for each local database where PUBLIC can create in public", async () => {
    api.on("SHOW DATABASES", () => [
      { database_name: "dev", database_type: "local" },
      { database_name: "other", database_type: "local" },
      { database_name: "Bad Name", database_type: "local" },
    ]);
    api.on("SHOW SCHEMAS", () => [
      { schema_name: "public", schema_acl: "rdsdb=UCDA/rdsdb~=UC/rdsdb" },
    ]);
    await expect(validate()).resolves.toMatchObject({
      warnings: [
        { check: "public_create", database: "dev" },
        { check: "public_create", database: "other" },
      ],
    });
    expect(api.statements.map(({ sql }) => sql)).toContain(
      'SHOW SCHEMAS FROM DATABASE "other";'
    );
  });
});

describe("publicCanCreate", () => {
  it.each([
    ["rdsdb=UCDA/rdsdb~=UC/rdsdb", true],
    ["rdsdb=UCDA/rdsdb~=U/rdsdb", false],
    ["etl=UC/rdsdb", false],
    [null, false],
  ])("%j is %s", (acl, expected) => {
    expect(publicCanCreate(acl)).toBe(expected);
  });
});

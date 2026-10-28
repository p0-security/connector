import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";
import { afterEach, expect, expectTypeOf, it, vi } from "vitest";

import * as connector from "../connector.ts";
import type {
  ClickHouseConnectorRouter,
  ClickHouseInstallValidation,
  ClickHousePolicy,
  ClickHouseRefusalReason,
  ClickHouseRequestContext,
  OrganizationCredentials,
} from "../connector.ts";
import { LOAD_TIMEOUT_MS, ORGANIZATION_ID } from "./fixtures.ts";

// The control plane imports `./connector` to build its typed client. It has
// no pattern to give, and shouldn't load the handlers or either cloud's
// secret-manager SDK to get it. Either of these stops this file from loading
// if `./connector` starts to.
vi.mock("../router.ts", () => {
  throw new Error("./connector loaded the router");
});
vi.mock("@p0security/secret-manager-client", () => {
  throw new Error("./connector loaded the secret manager client");
});

vi.setConfig({ testTimeout: LOAD_TIMEOUT_MS });

afterEach(() => {
  vi.unstubAllEnvs();
});

it("./connector serves the contract's values, and loads no router", () => {
  expect(Object.keys(connector).sort()).toEqual([
    "CLICKHOUSE_LEVEL_PRIVILEGES",
    "CLICKHOUSE_ORGANIZATION_ID_MESSAGE",
    "CLICKHOUSE_ORGANIZATION_ID_PATTERN",
    "CLICKHOUSE_REFUSAL_REASONS",
    "CLICKHOUSE_REQUIRED_PERMISSIONS",
    "ClickHouseConnectorSpec",
    "clickhouseRefusalReason",
    "consoleSpec",
    "installInput",
    "installValidation",
    "organizationCredentials",
    "requestContext",
    "secretPointer",
    "sqlSpec",
  ]);
  expect(
    connector.CLICKHOUSE_ORGANIZATION_ID_PATTERN.test(ORGANIZATION_ID)
  ).toBe(true);
});

it("loads without DOMAIN_ALLOW_PATTERN", async () => {
  vi.stubEnv("DOMAIN_ALLOW_PATTERN", undefined);
  vi.resetModules();

  await expect(import("../connector.ts")).resolves.toHaveProperty(
    "installValidation"
  );
});

// CONTRACT.md B3 and B8: the permissions the install probes, in its order. The app
// pins its installer's list to this one.
it("./connector lists the key's permissions in the order the install checks them", () => {
  expect(connector.CLICKHOUSE_REQUIRED_PERMISSIONS).toEqual([
    "control-plane:organization:view",
    "control-plane:organization:manage",
    "control-plane:service:view",
    "control-plane:service:view-query-api-endpoints",
    "control-plane:service:manage-query-api-endpoints",
    "control-plane:organization:view-api-keys",
  ]);
});

// CONTRACT.md B3: the level table, for the app's test-only pin of its own copy.
it("./connector serves the level table", () => {
  expect(connector.CLICKHOUSE_LEVEL_PRIVILEGES).toEqual({
    read: ["SELECT", "dictGet"],
    write: [
      "SELECT",
      "dictGet",
      "INSERT",
      "ALTER UPDATE",
      "ALTER DELETE",
      "TRUNCATE",
    ],
    admin: [
      "SELECT",
      "dictGet",
      "INSERT",
      "ALTER UPDATE",
      "ALTER DELETE",
      "TRUNCATE",
      "CREATE",
      "DROP",
      "ALTER",
      "OPTIMIZE",
    ],
  });
});

it("./connector serves each access's parsers", () => {
  expect(
    connector.sqlSpec.policy({
      type: "sql",
      level: "read",
      object: { database: "analytics", table: "v_users" },
    })
  ).toEqual({
    type: "sql",
    level: "read",
    object: { database: "analytics", table: "v_users" },
  });
  expect(
    connector.consoleSpec.policy({
      type: "console",
      consoleRole: "service-reader",
    })
  ).toEqual({ type: "console", consoleRole: "service-reader" });
  expect(() =>
    connector.sqlSpec.policy({ type: "console", consoleRole: "service-reader" })
  ).toThrow();
  expect(connector.ClickHouseConnectorSpec).toEqual({
    sql: connector.sqlSpec,
    console: connector.consoleSpec,
  });
});

// The contract (CONTRACT.md, and its build amendment B1), written out by hand.
// The control plane compiles against the types the schemas infer, so a
// schema change fails `typecheck` here until this copy moves with it.
type SecretPointer =
  | { manager: "aws"; region: string; secretId: string }
  | { manager: "gcp"; projectId: string; secretId: string };

type Credentials = { organizationId: string; apiKeySecret: SecretPointer };

type ServiceReport =
  | {
      id: string;
      name: string;
      status: "console-only" | "not-ready";
      reason: string;
    }
  | { id: string; name: string; status: "ready" };

type InstallValidation = {
  organizationName: string;
  apiKeyId: string;
  apiKeyUuid: string;
  allowedDomains: string;
  services: ServiceReport[];
};

type RequestContext = {
  requestId: string;
  organization: Credentials;
  serviceId: string;
  description: string;
};

type Policy =
  | {
      type: "console";
      consoleRole:
        | "service-admin"
        | "service-reader"
        | "sql-console-admin"
        | "sql-console-readonly";
    }
  | {
      type: "sql";
      level: "admin" | "read" | "write";
      object: { database?: string; table?: string };
    };

type RefusalReason =
  "ambiguous_member" | "domain_not_allowed" | "not_member" | "not_p0_role";

it("./connector serves the contract's types", () => {
  expectTypeOf<OrganizationCredentials>().toEqualTypeOf<Credentials>();
  expectTypeOf<ClickHouseInstallValidation>().toEqualTypeOf<InstallValidation>();
  expectTypeOf<ClickHouseRequestContext>().toEqualTypeOf<RequestContext>();
  expectTypeOf<ClickHousePolicy>().toEqualTypeOf<Policy>();
  expectTypeOf<ClickHouseRefusalReason>().toEqualTypeOf<RefusalReason>();
});

// Where P0's typed client finds the install: under the `clickhouse` namespace.
type Inputs = inferRouterInputs<ClickHouseConnectorRouter>["clickhouse"];
type Outputs = inferRouterOutputs<ClickHouseConnectorRouter>["clickhouse"];

it("./connector serves the router's type", () => {
  expectTypeOf<
    Inputs["install"]["validation"]["get"]
  >().toEqualTypeOf<Credentials>();
  expectTypeOf<
    Outputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallValidation>();
});

// What P0's lifecycle sends each access, and gets back: the role name is the
// resource, the email is the user, one policy of the access's own type.
type Accesses = Inputs["accesses"];

it("./connector serves each access's routes", () => {
  expectTypeOf<keyof Accesses>().toEqualTypeOf<"console" | "sql">();
  expectTypeOf<Accesses["sql"]["createAccessResource"]>().toEqualTypeOf<{
    resourceBody: string;
    context: RequestContext;
  }>();
  expectTypeOf<Accesses["sql"]["addPoliciesToResource"]>().toEqualTypeOf<{
    resourceId: string;
    policies: Extract<Policy, { type: "sql" }>[];
    context: RequestContext;
  }>();
  expectTypeOf<
    Accesses["console"]["addPoliciesToResource"]["policies"]
  >().toEqualTypeOf<Extract<Policy, { type: "console" }>[]>();
  expectTypeOf<Accesses["console"]["bindAccessResource"]>().toEqualTypeOf<{
    userId: string;
    userBody: string;
    resourceId: string;
    context: RequestContext;
  }>();
  expectTypeOf<
    Outputs["accesses"]["sql"]["createAccessResource"]
  >().toEqualTypeOf<string>();
  expectTypeOf<Outputs["accesses"]["console"]["identifyUser"]>().toEqualTypeOf<
    string | null
  >();
});

import type { ResourceRootSchemaOf } from "@p0security/connector-core";
import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";
import { expect, expectTypeOf, it, vi } from "vitest";

import * as connector from "../connector.ts";
import type {
  HarborAdminState,
  HarborConnectorRouter,
  HarborInstallValidation,
  HarborInstance,
  HarborRefusalReason,
  HarborRole,
  projectRoleSpec,
  systemAdminSpec,
} from "../connector.ts";

// The control plane imports `./connector` to build its typed client, and
// shouldn't load the handlers or the secret manager client to get it. Either
// of these stops this file from loading if `./connector` starts to.
vi.mock("../router.ts", () => {
  throw new Error("./connector loaded the router");
});
vi.mock("@p0security/connector-secret-manager-client", () => {
  throw new Error("./connector loaded the secret manager client");
});

it("./connector serves the schemas, and loads no router", () => {
  expect(Object.keys(connector).sort()).toEqual([
    "HARBOR_REFUSAL_REASONS",
    "harborAdminState",
    "harborInstance",
    "harborRefusalReason",
    "harborRole",
    "installValidation",
    "projectRoleSpec",
    "systemAdminSpec",
  ]);
});

// The connector contract on INT-255, written out by hand. The control plane
// compiles against the types the schemas infer, so a schema change that moves
// one of them fails `typecheck` here until this copy moves with it, which is
// the moment to remember that the control plane's pin has to move too.
type Role =
  "developer" | "guest" | "limitedGuest" | "maintainer" | "projectAdmin";

type SecretPointer =
  | { manager: "aws"; region: string; secretId: string }
  | { manager: "gcp"; projectId: string; secretId: string };

// INT-536: `secret` points at the Harbor admin credential.
type Instance = { url: string; secret: SecretPointer };

type RequestContext = {
  url: string;
  secret: SecretPointer;
  requestId: string;
  email: string;
  priorRole: Role | null;
};

type UserBody = { instanceId: string; userId: string };

type Policy = { project: string; role: Role | null };

type ListerQuery =
  | { type: "direct-role"; context: Instance; project: string; userId: string }
  | { type: "member"; context: Instance; email: string }
  // A18: with a `project`, the query asks about that one project.
  | { type: "project"; context: Instance; project?: string };

type ListerResponse = { key: string; value: string; group?: string }[];

type InstallValidation = {
  harborVersion: string;
  authMode: string;
  allowedEmailDomainPattern: string;
};

// A17: the closed set of `payload.reason`s P0 words its copy from.
type RefusalReason =
  | "admin_not_harbor_admin"
  | "admin_signin_expired"
  | "admin_token_rejected"
  | "domain_not_allowed"
  | "domain_pattern_unusable"
  | "duplicate_email"
  | "no_user"
  | "project_gone";

type Schema = ResourceRootSchemaOf<typeof projectRoleSpec>;

// INT-536: the system administrator access.
type AdminState = "auth" | "flag_and_auth" | "flag" | "none";

type SystemAdminRequestContext = {
  url: string;
  secret: SecretPointer;
  requestId: string;
  email: string;
  wasSystemAdmin: boolean;
};

type SystemAdminPolicy = { systemAdmin: boolean };

type SystemAdminListerQuery = {
  type: "admin-state";
  context: Instance;
  email: string;
};

type SystemAdminSchema = ResourceRootSchemaOf<typeof systemAdminSpec>;

it("./connector serves the contract's types", () => {
  expectTypeOf<HarborRole>().toEqualTypeOf<Role>();
  expectTypeOf<HarborInstance>().toEqualTypeOf<Instance>();
  expectTypeOf<Schema["RequestContext"]>().toEqualTypeOf<RequestContext>();
  expectTypeOf<Schema["UserBody"]>().toEqualTypeOf<UserBody>();
  expectTypeOf<Schema["UserId"]>().toEqualTypeOf<string>();
  expectTypeOf<Schema["Policy"]>().toEqualTypeOf<Policy>();
  expectTypeOf<Schema["ListerQuery"]>().toEqualTypeOf<ListerQuery>();
  expectTypeOf<Schema["ListerResponse"]>().toEqualTypeOf<ListerResponse>();
  expectTypeOf<HarborInstallValidation>().toEqualTypeOf<InstallValidation>();
  expectTypeOf<HarborRefusalReason>().toEqualTypeOf<RefusalReason>();
});

it("./connector serves the system administrator access's types", () => {
  expectTypeOf<HarborAdminState>().toEqualTypeOf<AdminState>();
  expectTypeOf<
    SystemAdminSchema["RequestContext"]
  >().toEqualTypeOf<SystemAdminRequestContext>();
  expectTypeOf<SystemAdminSchema["UserBody"]>().toEqualTypeOf<UserBody>();
  expectTypeOf<SystemAdminSchema["UserId"]>().toEqualTypeOf<string>();
  expectTypeOf<
    SystemAdminSchema["Policy"]
  >().toEqualTypeOf<SystemAdminPolicy>();
  expectTypeOf<
    SystemAdminSchema["ListerQuery"]
  >().toEqualTypeOf<SystemAdminListerQuery>();
  expectTypeOf<
    SystemAdminSchema["ListerResponse"]
  >().toEqualTypeOf<ListerResponse>();
});

it("./connector parses exactly the refusal reasons", () => {
  for (const reason of connector.HARBOR_REFUSAL_REASONS) {
    expect(connector.harborRefusalReason.safeParse(reason).success).toBe(true);
  }
  expect(connector.harborRefusalReason.safeParse("other").success).toBe(false);
});

it("./connector lists every refusal reason", () => {
  expect([...connector.HARBOR_REFUSAL_REASONS].sort()).toEqual([
    "admin_not_harbor_admin",
    "admin_signin_expired",
    "admin_token_rejected",
    "domain_not_allowed",
    "domain_pattern_unusable",
    "duplicate_email",
    "no_user",
    "project_gone",
  ]);
});

// Where P0's typed client finds each call: under the `harbor` namespace, with
// the accesses keyed `projectRole` and `systemAdmin`.
type Inputs = inferRouterInputs<HarborConnectorRouter>["harbor"];
type Outputs = inferRouterOutputs<HarborConnectorRouter>["harbor"];

it("./connector serves the router's type", () => {
  expectTypeOf<
    Inputs["install"]["validation"]["get"]
  >().toEqualTypeOf<Instance>();
  expectTypeOf<
    Outputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallValidation>();
  expectTypeOf<Inputs["accesses"]["projectRole"]["list"]>().toEqualTypeOf<{
    query: ListerQuery;
  }>();
  expectTypeOf<Inputs["accesses"]["systemAdmin"]["list"]>().toEqualTypeOf<{
    query: SystemAdminListerQuery;
  }>();
});

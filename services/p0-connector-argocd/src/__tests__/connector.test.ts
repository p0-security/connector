import type { ResourceRootSchemaOf } from "@p0security/connector";
import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";
import { expect, expectTypeOf, it, vi } from "vitest";

import * as connector from "../connector.ts";
import type {
  ArgoCdConnectorRouter,
  ArgoCdInstallStep,
  ArgoCdInstallValidation,
  ArgoCdInstance,
  ArgoCdRefusalReason,
  globalRoleSpec,
  projectRoleSpec,
} from "../connector.ts";

// The control plane imports `./connector` to build its typed client, and
// shouldn't load the handlers or the secret manager client to get it. Either
// of these stops this file from loading if `./connector` starts to.
vi.mock("../router.ts", () => {
  throw new Error("./connector loaded the router");
});
vi.mock("@p0security/secret-manager-client", () => {
  throw new Error("./connector loaded the secret manager client");
});

it("./connector serves the schemas, and loads no router", () => {
  expect(Object.keys(connector).sort()).toEqual([
    "ARGOCD_INSTALL_STEPS",
    "ARGOCD_REFUSAL_REASONS",
    "argoCdInstallStep",
    "argoCdInstallValidation",
    "argoCdInstance",
    "argoCdRefusalReason",
    "globalRoleSpec",
    "projectRoleSpec",
  ]);
});

// The contract, written out by hand. The control plane compiles against the
// types the schemas infer, so a schema change that moves one of them fails
// `typecheck` here until this copy moves with it, which is the moment to
// remember that the control plane's pin has to move too.
type SecretPointer =
  | { manager: "aws"; region: string; secretId: string }
  | { manager: "gcp"; projectId: string; secretId: string };

type Instance = {
  url: string;
  managingApp: string;
  namespace: string;
  secret: SecretPointer;
};

type UserBody = { instanceId: string; email: string };

type ListerResponse = { key: string; value: string; group?: string }[];

type GlobalRoleRequestContext = {
  url: string;
  managingApp: string;
  namespace: string;
  secret: SecretPointer;
  requestId: string;
  role: string;
};

type GlobalRolePolicy = { role: string | null };

type GlobalRoleListerQuery =
  | { type: "held"; context: Instance; email: string; role: string }
  | { type: "role"; context: Instance; role?: string };

// The closed set of `payload.reason`s P0 words its copy from.
type RefusalReason =
  | "already_held"
  | "connector_role"
  | "default_role"
  | "domain_not_allowed"
  | "domain_pattern_unusable"
  | "not_an_email"
  | "policy_not_loaded"
  | "project_not_found"
  | "role_not_found"
  | "self_check_failed";

type ProjectRoleRequestContext = {
  url: string;
  managingApp: string;
  namespace: string;
  secret: SecretPointer;
  requestId: string;
  project: string;
  role: string;
};

type ProjectRolePolicy = { project: string; role: string | null };

type ProjectRoleListerQuery =
  | {
      type: "held";
      context: Instance;
      email: string;
      project: string;
      role: string;
    }
  | { type: "project"; context: Instance; project?: string }
  | { type: "role"; context: Instance; project: string; role?: string };

// What install validation answers once every check passed.
type InstallValidation = {
  argoCdVersion: string;
  allowedEmailDomainPattern: string;
};

// The closed set of `payload.step`s a failed install validation names, in
// the order the checks run. P0 reads them.
const INSTALL_STEPS = [
  "pattern",
  "secret",
  "reachable",
  "version",
  "account",
  "managing_app",
  "rbac_config_map",
  "scopes",
  "p0_policy",
  "policy_loaded",
  "projects",
  "self_check",
  "patch",
] as const;

type GlobalRole = ResourceRootSchemaOf<typeof globalRoleSpec>;
type ProjectRole = ResourceRootSchemaOf<typeof projectRoleSpec>;

it("./connector serves the contract's types", () => {
  expectTypeOf<ArgoCdInstance>().toEqualTypeOf<Instance>();
  expectTypeOf<ArgoCdRefusalReason>().toEqualTypeOf<RefusalReason>();
  expectTypeOf<ArgoCdInstallValidation>().toEqualTypeOf<InstallValidation>();
  expectTypeOf<ArgoCdInstallStep>().toEqualTypeOf<
    (typeof INSTALL_STEPS)[number]
  >();
  expectTypeOf<
    GlobalRole["RequestContext"]
  >().toEqualTypeOf<GlobalRoleRequestContext>();
  expectTypeOf<GlobalRole["UserBody"]>().toEqualTypeOf<UserBody>();
  expectTypeOf<GlobalRole["UserId"]>().toEqualTypeOf<string>();
  expectTypeOf<GlobalRole["Policy"]>().toEqualTypeOf<GlobalRolePolicy>();
  expectTypeOf<
    GlobalRole["ListerQuery"]
  >().toEqualTypeOf<GlobalRoleListerQuery>();
  expectTypeOf<GlobalRole["ListerResponse"]>().toEqualTypeOf<ListerResponse>();
  expectTypeOf<
    ProjectRole["RequestContext"]
  >().toEqualTypeOf<ProjectRoleRequestContext>();
  expectTypeOf<ProjectRole["UserBody"]>().toEqualTypeOf<UserBody>();
  expectTypeOf<ProjectRole["UserId"]>().toEqualTypeOf<string>();
  expectTypeOf<ProjectRole["Policy"]>().toEqualTypeOf<ProjectRolePolicy>();
  expectTypeOf<
    ProjectRole["ListerQuery"]
  >().toEqualTypeOf<ProjectRoleListerQuery>();
  expectTypeOf<ProjectRole["ListerResponse"]>().toEqualTypeOf<ListerResponse>();
});

it("./connector parses exactly the refusal reasons", () => {
  for (const reason of connector.ARGOCD_REFUSAL_REASONS) {
    expect(connector.argoCdRefusalReason.safeParse(reason).success).toBe(true);
  }
  expect(connector.argoCdRefusalReason.safeParse("other").success).toBe(false);
});

it("./connector lists the install steps in the order they run", () => {
  expect(connector.ARGOCD_INSTALL_STEPS).toEqual(INSTALL_STEPS);
  for (const step of INSTALL_STEPS) {
    expect(connector.argoCdInstallStep.safeParse(step).success).toBe(true);
  }
  expect(connector.argoCdInstallStep.safeParse("other").success).toBe(false);
  expect(
    connector.argoCdInstallValidation.safeParse({
      argoCdVersion: "v3.5.5+2f9b0d1",
      allowedEmailDomainPattern: "example\\.com",
    }).success
  ).toBe(true);
  expect(
    connector.argoCdInstallValidation.safeParse({ argoCdVersion: "v3.5.5" })
      .success
  ).toBe(false);
  expect(
    connector.argoCdInstallValidation.safeParse({
      allowedEmailDomainPattern: "example\\.com",
    }).success
  ).toBe(false);
});

// Where P0's typed client finds each call: under the `argocd` namespace, with
// each access under its key.
type Inputs = inferRouterInputs<ArgoCdConnectorRouter>["argocd"];
type Outputs = inferRouterOutputs<ArgoCdConnectorRouter>["argocd"];

it("./connector serves the router's type", () => {
  expectTypeOf<Inputs["metadata"]["get"]>().toEqualTypeOf<void>();
  // The input is what the instance parser returns, so P0 sends the
  // namespace even when it is the default.
  expectTypeOf<
    Inputs["install"]["validation"]["get"]
  >().toEqualTypeOf<Instance>();
  expectTypeOf<
    Outputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallValidation>();
  expectTypeOf<Outputs["metadata"]["get"]>().toHaveProperty("connectorVersion");
  expectTypeOf<
    Outputs["accesses"]["globalRole"]["list"]
  >().toEqualTypeOf<ListerResponse>();
  expectTypeOf<
    Outputs["accesses"]["globalRole"]["provisionUser"]
  >().toEqualTypeOf<string>();
});

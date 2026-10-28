import type { ResourceRootSchemaOf } from "@p0security/connector";
import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";
import { expect, expectTypeOf, it, vi } from "vitest";

import * as connector from "../connector.ts";
import type {
  LaunchDarklyAccount,
  LaunchDarklyConnectorRouter,
  LaunchDarklyInstallValidation,
  LaunchDarklyRefusalReason,
  LaunchDarklyRequestContext,
  LaunchDarklyUserBody,
  baseRoleSpec,
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
    "LAUNCHDARKLY_REFUSAL_REASONS",
    "account",
    "baseRoleSpec",
    "installInput",
    "installValidation",
    "launchDarklyRefusalReason",
    "secretPointer",
  ]);
});

// The connector contract on INT-713, written out by hand. The control plane
// compiles against the types the schemas infer, so a schema change that moves
// one of them fails `typecheck` here until this copy moves with it.
type SecretPointer =
  | { manager: "aws"; region: string; secretId: string }
  | { manager: "gcp"; projectId: string; secretId: string };

type Account = {
  instance: "commercial" | "eu" | "federal";
  accountId: string;
  secret: SecretPointer;
};

type InstallInput = {
  instance: "commercial" | "eu" | "federal";
  secret: SecretPointer;
};

type InstallValidation = {
  accountId: string;
  tokenKind: "personal" | "service";
  tokenOwnerMemberId: string | null;
  domainPattern: string;
};

type RefusalReason =
  | "base_role_ignored"
  | "domain_not_allowed"
  | "domain_pattern_unusable"
  | "member_changed"
  | "own_member";

type UserBody = { memberId: string; accountId: string };

type RequestContext = {
  instance: "commercial" | "eu" | "federal";
  accountId: string;
  secret: SecretPointer;
  requestId: string;
  email: string;
  operation: "grant" | "revoke";
};

/** `RequestContext` with an access's own fields, as one object type. */
type ContextWith<Fields> = {
  [Key in keyof (RequestContext & Fields)]: (RequestContext & Fields)[Key];
};

type ListerQuery =
  | { type: "member-state"; context: Account; memberId: string }
  | { type: "member"; context: Account; email: string };

type ListerResponse = { key: string; value: string; group?: string }[];

type BaseRole = "admin" | "reader" | "writer";

it("./connector serves the account, install and refusal types", () => {
  expectTypeOf<LaunchDarklyAccount>().toEqualTypeOf<Account>();
  expectTypeOf<LaunchDarklyInstallValidation>().toEqualTypeOf<InstallValidation>();
  expectTypeOf<LaunchDarklyRefusalReason>().toEqualTypeOf<RefusalReason>();
  expectTypeOf<LaunchDarklyUserBody>().toEqualTypeOf<UserBody>();
  expectTypeOf<LaunchDarklyRequestContext>().toEqualTypeOf<RequestContext>();
});

it("./connector serves the base-role access's types", () => {
  type BaseRoleSchema = ResourceRootSchemaOf<typeof baseRoleSpec>;
  expectTypeOf<BaseRoleSchema["UserBody"]>().toEqualTypeOf<UserBody>();
  expectTypeOf<BaseRoleSchema["UserId"]>().toEqualTypeOf<string>();
  expectTypeOf<BaseRoleSchema["ListerQuery"]>().toEqualTypeOf<ListerQuery>();
  expectTypeOf<
    BaseRoleSchema["ListerResponse"]
  >().toEqualTypeOf<ListerResponse>();

  expectTypeOf<BaseRoleSchema["Policy"]>().toEqualTypeOf<BaseRole>();
  expectTypeOf<BaseRoleSchema["RequestContext"]>().toEqualTypeOf<
    ContextWith<{ role: BaseRole; priorRole: BaseRole | "no_access" }>
  >();
});

it("./connector lists every refusal reason, and parses exactly them", () => {
  expect([...connector.LAUNCHDARKLY_REFUSAL_REASONS].sort()).toEqual([
    "base_role_ignored",
    "domain_not_allowed",
    "domain_pattern_unusable",
    "member_changed",
    "own_member",
  ]);
  expect(connector.launchDarklyRefusalReason.safeParse("other").success).toBe(
    false
  );
});

// The member id `me` is LaunchDarkly's name for the caller, so the contract
// refuses it everywhere a member id goes.
it("./connector's user body refuses `me` as a member id", () => {
  for (const memberId of ["me", "ME"]) {
    expect(() =>
      connector.baseRoleSpec.userBody({ memberId, accountId: "a" })
    ).toThrow();
  }
});

// Where P0's typed client finds install validation: under the `launchdarkly`
// namespace.
type Inputs = inferRouterInputs<LaunchDarklyConnectorRouter>["launchdarkly"];
type Outputs = inferRouterOutputs<LaunchDarklyConnectorRouter>["launchdarkly"];

it("./connector serves the router's type", () => {
  expectTypeOf<
    Inputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallInput>();
  expectTypeOf<
    Outputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallValidation>();
});

import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";
import { expect, expectTypeOf, it, vi } from "vitest";

import * as connector from "../connector.ts";
import type {
  MiroConnectorRouter,
  MiroInstallInput,
  MiroInstallValidation,
  MiroPriorRole,
  MiroRefusalReason,
  MiroRequestContext,
  MiroTeam,
  MiroUserBody,
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
    "MIRO_REFUSAL_REASONS",
    "boardSpec",
    "installInput",
    "installValidation",
    "miroRefusalReason",
    "secretPointer",
    "team",
  ]);
});

// The connector contract, written out by hand. The app's contract test
// (INT-1111) holds its copies to these, and the control plane compiles
// against the types the schemas infer, so a schema change that moves one of
// them fails `typecheck` here until this copy moves with it.
type SecretPointer =
  | { manager: "aws"; region: string; secretId: string }
  | { manager: "gcp"; projectId: string; secretId: string };

type Team = { teamId: string; secret: SecretPointer };

type InstallInput = { secret: SecretPointer };

type InstallValidation = { teamId: string; shareableBoards: number };

type RefusalReason =
  "board_not_shareable" | "member_changed" | "not_in_team" | "pending_invite";

type PriorRole =
  "commenter" | "coowner" | "editor" | "none" | "owner" | "viewer";

type RequestContext = {
  teamId: string;
  secret: SecretPointer;
  boardId: string;
  email: string;
  operation: "grant" | "revoke";
  priorRole: PriorRole;
  requestId: string;
  role: "commenter" | "editor" | "viewer";
};

type UserBody = { boardId: string; memberId: string; teamId: string };

it("./connector serves the board access's request context and user body", () => {
  expectTypeOf<MiroPriorRole>().toEqualTypeOf<PriorRole>();
  expectTypeOf<MiroRequestContext>().toEqualTypeOf<RequestContext>();
  expectTypeOf<MiroUserBody>().toEqualTypeOf<UserBody>();
});

it("./connector serves the team, install and refusal types", () => {
  expectTypeOf<MiroTeam>().toEqualTypeOf<Team>();
  expectTypeOf<MiroInstallInput>().toEqualTypeOf<InstallInput>();
  expectTypeOf<MiroInstallValidation>().toEqualTypeOf<InstallValidation>();
  expectTypeOf<MiroRefusalReason>().toEqualTypeOf<RefusalReason>();
});

it("./connector lists every refusal reason, and parses exactly them", () => {
  expect([...connector.MIRO_REFUSAL_REASONS].sort()).toEqual([
    "board_not_shareable",
    "member_changed",
    "not_in_team",
    "pending_invite",
  ]);
  expect(connector.miroRefusalReason.safeParse("other").success).toBe(false);
});

// A team id is decimal digits, as Miro's ids are, and never a number.
it("./connector's team refuses a team id that isn't Miro's", () => {
  const secret = { manager: "aws", region: "us-west-2", secretId: "s" };
  for (const teamId of ["", "../teams", "3458764688635236553x", 42]) {
    expect(connector.team.safeParse({ teamId, secret }).success).toBe(false);
  }
});

// Where P0's typed client finds install validation: under the `miro-ai`
// namespace.
type Inputs = inferRouterInputs<MiroConnectorRouter>["miro-ai"];
type Outputs = inferRouterOutputs<MiroConnectorRouter>["miro-ai"];

it("./connector serves the router's type", () => {
  expectTypeOf<
    Inputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallInput>();
  expectTypeOf<
    Outputs["install"]["validation"]["get"]
  >().toEqualTypeOf<InstallValidation>();
});

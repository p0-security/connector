import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { ACCESSES } from "../accesses/common/policies.ts";
import {
  fakeMember,
  newFakeLaunchDarkly,
} from "../launchdarkly/__tests__/fake-launchdarkly.ts";
import { connectorRouter } from "../router.ts";
import { readToken } from "../secrets.ts";
import {
  ACCOUNT,
  EMAIL,
  MEMBER_ID,
  ROLE_ID,
  TOKEN,
  logger,
} from "./fixtures.ts";

// The secret manager is `secrets.test.ts`'s business.
vi.mock("../secrets.ts");

const connector = connectorRouter.createCaller({ logger });
const accesses = connector.launchdarkly.accesses;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readToken).mockResolvedValue(TOKEN);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the connector's router", () => {
  // Everything P0 can ask of the connector is in this list. tRPC has no
  // public way to list a router's procedures, so this reads its definition.
  it("exposes the base-role access, install validation and metadata, under one namespace", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      ...ACCESSES.flatMap((access) =>
        [
          "deleteUser",
          "identifyUser",
          "list",
          "provisionUser",
          "setPoliciesForUser",
        ].map((procedure) => `launchdarkly.accesses.${access}.${procedure}`)
      ).sort(),
      "launchdarkly.install.validation.get",
      "launchdarkly.metadata.get",
    ]);
  });

  it("reports the workspace's version", async () => {
    await expect(connector.launchdarkly.metadata.get()).resolves.toMatchObject({
      connectorVersion: packageJson.version,
    });
  });

  it.each(ACCESSES)("answers the list queries on %s", async (access) => {
    newFakeLaunchDarkly({
      members: [
        fakeMember({ _id: MEMBER_ID, email: EMAIL, customRoles: [ROLE_ID] }),
      ],
    });

    await expect(
      accesses[access].list({
        query: { type: "member-state", context: ACCOUNT, memberId: MEMBER_ID },
      })
    ).resolves.toEqual([
      { key: "role", value: "reader" },
      { key: ROLE_ID, value: ROLE_ID, group: "role" },
    ]);
  });

  it("refuses a query that doesn't parse, before it reaches a primitive", async () => {
    const launchDarkly = newFakeLaunchDarkly();

    await expect(
      accesses["base-role"].list({
        query: { type: "member-state", context: ACCOUNT, memberId: "../me" },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(launchDarkly.calls()).toEqual([]);
  });
});

// `me` is LaunchDarkly's name for the caller: `GET` and `PATCH
// /members/me` would read and change the access token's own member.
describe("the member id `me`", () => {
  const base = {
    ...ACCOUNT,
    requestId: "req-1",
    email: EMAIL,
    operation: "grant",
  };
  const INPUTS = {
    "base-role": {
      context: { ...base, role: "writer", priorRole: "reader" },
      policies: ["writer"],
    },
  };

  it.each(ACCESSES)(
    "is refused on %s, in every procedure, before any primitive runs",
    async (access) => {
      const launchDarkly = newFakeLaunchDarkly();
      const { context, policies } = INPUTS[access];
      const procedures = accesses[access];
      const userBody = { memberId: "me", accountId: ACCOUNT.accountId };
      const setPolicies = { userId: "me", userBody, policies, context };

      for (const call of [
        // @ts-expect-error -- the roles are strings here, not base roles.
        () => procedures.setPoliciesForUser(setPolicies),
        // @ts-expect-error -- the roles are strings here, not base roles.
        () => procedures.provisionUser({ userBody, context }),
        // @ts-expect-error -- the roles are strings here, not base roles.
        () => procedures.identifyUser({ userBody, context }),
        // @ts-expect-error -- the roles are strings here, not base roles.
        () => procedures.deleteUser({ userId: "ME", userBody, context }),
      ]) {
        await expect(call()).rejects.toMatchObject({ code: "BAD_REQUEST" });
      }
      expect(readToken).not.toHaveBeenCalled();
      expect(launchDarkly.calls()).toEqual([]);
    }
  );
});

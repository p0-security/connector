import type { Logger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  HARBOR_HOST,
  ID_TOKEN,
  INSTANCE,
  connectorError,
  logger,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeUser,
  ORIGIN,
  newFakeHarbor,
} from "../../../harbor/__tests__/fake-harbor.ts";
import { type ConnectHarbor, harborClientFor } from "../../../harbor/client.ts";
import { schema } from "../definition.ts";
import { adminStateOf, newSystemAdminPrimitives } from "../handler.ts";

const API = `${ORIGIN}/api/v2.0`;

const user = (id: number, email: string, sysadmin_flag = false): FakeUser => ({
  user_id: id,
  username: `user${id}`,
  email,
  sysadmin_flag,
});

const connect = vi.fn<ConnectHarbor>(async ({ url }, log: Logger) =>
  harborClientFor({ url, idToken: ID_TOKEN, logger: log })
);

const listAdminState = (email: string) =>
  newSystemAdminPrimitives(logger, connect).list({
    type: "admin-state",
    context: INSTANCE,
    email,
  });

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "example\\.com");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("the admin-state lister", () => {
  const harborWith = (users: FakeUser[]) =>
    newFakeHarbor({
      users,
      projects: [],
    });

  it.each([
    [false, "none"],
    [true, "flag"],
  ])(
    "reads a user whose flag is %s as %s, by their id",
    async (flag, state) => {
      const harbor = harborWith([user(42, "Alice@Example.com", flag)]);
      await expect(listAdminState("alice@example.com")).resolves.toEqual([
        { key: "42", value: state },
      ]);
      expect(harbor.calls()).toEqual([
        `GET ${API}/users?email=alice%40example.com&page=1&page_size=100`,
      ]);
      expect(connect).toHaveBeenCalledTimes(1);
    }
  );

  it("answers [] for an email no Harbor user has", async () => {
    harborWith([user(43, "joalice@example.com", true)]);
    await expect(listAdminState("alice@example.com")).resolves.toEqual([]);
  });

  it("refuses an email two users share", async () => {
    harborWith([user(42, "alice@example.com"), user(44, "ALICE@example.com")]);
    const error = await connectorError(() =>
      listAdminState("alice@example.com")
    );
    expect(error.data.payload).toMatchObject({
      reason: "duplicate_email",
      host: HARBOR_HOST,
    });
  });

  it("refuses an email outside the allowlist before calling Harbor", async () => {
    const harbor = harborWith([]);
    const error = await connectorError(() => listAdminState("eve@evil.com"));
    expect(error.data.payload).toEqual({ reason: "domain_not_allowed" });
    expect(connect).not.toHaveBeenCalled();
    expect(harbor.calls()).toEqual([]);
  });
});

describe("adminStateOf", () => {
  it.each([
    [false, false, "none"],
    [true, false, "flag"],
    [false, true, "auth"],
    [true, true, "flag_and_auth"],
  ] as const)(
    "reads flag %s and group %s as %s",
    (sysadminFlag, adminRoleInAuth, state) => {
      expect(adminStateOf({ sysadminFlag, adminRoleInAuth })).toBe(state);
    }
  );
});

describe("the request context", () => {
  const CONTEXT = {
    ...INSTANCE,
    requestId: "req-1",
    email: "alice@example.com",
    wasSystemAdmin: false,
  };

  it("parses with the instance and the recorded prior state", () => {
    expect(schema.requestContext.parse(CONTEXT)).toEqual(CONTEXT);
  });

  it.each([
    ["no wasSystemAdmin", { wasSystemAdmin: undefined }],
    ["a null wasSystemAdmin", { wasSystemAdmin: null }],
    ["a string wasSystemAdmin", { wasSystemAdmin: "false" }],
    ["no secret", { secret: undefined }],
    ["a secret pointer of another shape", { secret: { manager: "vault" } }],
  ])("refuses %s", (_, change) => {
    expect(
      schema.requestContext.safeParse({ ...CONTEXT, ...change }).success
    ).toBe(false);
  });

  it.each([[{ systemAdmin: "true" }], [{}], [{ systemAdmin: null }]])(
    "refuses a policy that isn't a boolean (%j)",
    (policy) => {
      expect(schema.policy.safeParse(policy).success).toBe(false);
    }
  );
});

describe("the primitives P0 calls around a grant", () => {
  const primitives = () => newSystemAdminPrimitives(logger, connect);

  it("validates no user namespace", () => {
    expect(
      primitives().validation({
        ...INSTANCE,
        requestId: "req-1",
        email: "alice@example.com",
        wasSystemAdmin: false,
      })
    ).toEqual({ user: null });
  });

  // P0 never gets here, since getUser always answers, and the connector
  // never creates Harbor users.
  it("refuses to create a user, and calls nothing", async () => {
    const harbor = newFakeHarbor({ users: [], projects: [] });

    const { data } = await connectorError(() =>
      primitives().createUser(
        {
          ...INSTANCE,
          requestId: "req-1",
          email: "alice@example.com",
          wasSystemAdmin: false,
        },
        { instanceId: "p0-harbor", userId: "42" }
      )
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "P0 asked the Harbor connector to create a Harbor user, which it never does.",
      payload: { requestId: "req-1" },
    });
    expect(harbor.fetch).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });
});

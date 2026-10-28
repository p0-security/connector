import type { Logger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AWS_SECRET,
  HARBOR_HOST,
  ID_TOKEN,
  INSTANCE,
  NEVER_SHOWN,
  connectorError,
  logger,
  recordLogger,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeHarborState,
  type FakeUser,
  ORIGIN,
  newFakeHarbor,
  sentJson,
} from "../../../harbor/__tests__/fake-harbor.ts";
import { type ConnectHarbor, harborClientFor } from "../../../harbor/client.ts";
import { newSystemAdminPrimitives } from "../handler.ts";

const API = `${ORIGIN}/api/v2.0`;
const USER_ID = "42";
const EMAIL = "alice@example.com";

const user = (id: number, email: string, sysadmin_flag = false): FakeUser => ({
  user_id: id,
  username: `user${id}`,
  email,
  sysadmin_flag,
});

/** Alice is user 42, and the admin account is user 9, an administrator. */
const harborWith = (overrides: Partial<FakeHarborState> = {}) =>
  newFakeHarbor({
    users: [
      user(42, EMAIL),
      user(43, "bob@example.com"),
      user(9, "harbor-automation@example.com", true),
    ],
    projects: [],
    caller: 9,
    ...overrides,
  });

type Harbor = ReturnType<typeof harborWith>;

const flagOf = (harbor: Harbor, id = 42) =>
  harbor.state.users.find(({ user_id }) => user_id === id)?.sysadmin_flag;

/** Connects with a token, without the secret manager or the provider. */
const connectAs = (idToken = ID_TOKEN) =>
  vi.fn<ConnectHarbor>(async ({ url }, log: Logger) =>
    harborClientFor({ url, idToken, logger: log })
  );

/** Runs `before` as the fake receives the sysadmin `PUT`, then answers it. */
const onWrite = (harbor: Harbor, before: () => void) => {
  const fake = harbor.fetch.getMockImplementation();
  harbor.fetch.mockImplementation(async (url, init) => {
    if (init?.method === "PUT") before();
    return fake?.(url, init) ?? new Response(null, { status: 500 });
  });
};

const context = (wasSystemAdmin = false, email = EMAIL) => ({
  ...INSTANCE,
  requestId: "req-1",
  email,
  wasSystemAdmin,
});

const setAdmin = (
  systemAdmin: boolean,
  {
    wasSystemAdmin = false,
    email = EMAIL,
    connect = connectAs(),
    policies,
  }: {
    wasSystemAdmin?: boolean;
    email?: string;
    connect?: ConnectHarbor;
    policies?: { systemAdmin: boolean }[];
  } = {}
) =>
  newSystemAdminPrimitives(logger, connect).setPoliciesForUser(
    context(wasSystemAdmin, email),
    USER_ID,
    { instanceId: "p0-harbor", userId: USER_ID },
    policies ?? [{ systemAdmin }]
  );

const writes = (harbor: Harbor) =>
  harbor.calls().filter((call) => call.startsWith("PUT"));

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "example\\.com");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("a grant", () => {
  it("confirms the user, sets the flag, and reads it back, connecting once", async () => {
    const harbor = harborWith();
    const connect = connectAs();

    await setAdmin(true, { connect });

    expect(flagOf(harbor)).toBe(true);
    expect(harbor.calls()).toEqual([
      `GET ${API}/users?email=alice%40example.com&page=1&page_size=100`,
      `PUT ${API}/users/42/sysadmin`,
      `GET ${API}/users?q=user_id%3D42&page=1&page_size=100`,
    ]);
    const put = harbor.fetch.mock.calls[1]?.[1];
    expect(sentJson(put)).toEqual({ sysadmin_flag: true });
    expect(new Headers(put?.headers).get("authorization")).toBe(
      `Bearer ${ID_TOKEN}`
    );
    expect(connect).toHaveBeenCalledTimes(1);
    expect(connect).toHaveBeenCalledWith(
      expect.objectContaining({ url: INSTANCE.url, secret: INSTANCE.secret }),
      expect.anything()
    );
  });

  it("leaves a user who has the flag already as they are, without a write", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;

    await setAdmin(true);

    expect(writes(harbor)).toEqual([]);
  });

  // A revoke leaves the flag of a user P0 recorded as an administrator, so a
  // grant for one whose flag was cleared since the stage would never end.
  it("refuses a grant P0 recorded as for an administrator, before reading a secret or calling Harbor", async () => {
    const harbor = harborWith();
    const connect = connectAs();

    const error = await connectorError(() =>
      setAdmin(true, { wasSystemAdmin: true, connect })
    );

    expect(error.data).toEqual({
      type: "validation_error",
      message:
        "P0 recorded that this user was already a Harbor system administrator when it staged the request, and the revoke would leave the flag in place, so the connector won't grant it. Request access again.",
      payload: { requestId: "req-1" },
    });
    expect(connect).not.toHaveBeenCalled();
    expect(harbor.calls()).toEqual([]);
    expect(flagOf(harbor)).toBe(false);
  });

  it("refuses an email outside the allowlist before any secret is read or Harbor is called", async () => {
    const harbor = harborWith();
    const connect = connectAs();

    const error = await connectorError(() =>
      setAdmin(true, { email: "eve@evil.com", connect })
    );

    expect(error.data.payload).toEqual({ reason: "domain_not_allowed" });
    expect(connect).not.toHaveBeenCalled();
    expect(harbor.calls()).toEqual([]);
  });

  it.each([
    ["no Harbor user has the email", [user(43, "bob@example.com")]],
    ["the email belongs to another user now", [user(77, EMAIL)]],
  ])("refuses as no_user when %s, writing nothing", async (_, users) => {
    const harbor = harborWith({
      users: [...users, user(9, "harbor-automation@example.com", true)],
    });
    const error = await connectorError(() => setAdmin(true));
    expect(error.data).toEqual({
      type: "validation_error",
      message: `The Harbor user for ${EMAIL} on ${HARBOR_HOST} no longer exists, or its email changed. Request access again.`,
      payload: { reason: "no_user", host: HARBOR_HOST, userId: 42 },
    });
    expect(writes(harbor)).toEqual([]);
  });

  it("refuses an email two Harbor users share", async () => {
    const harbor = harborWith({
      users: [
        user(42, EMAIL),
        user(44, "ALICE@example.com"),
        user(9, "harbor-automation@example.com", true),
      ],
    });
    const error = await connectorError(() => setAdmin(true));
    expect(error.data.payload).toMatchObject({
      reason: "duplicate_email",
      userIds: "42,44",
    });
    expect(writes(harbor)).toEqual([]);
  });

  it("refuses as no_user when the user goes between the check and the write", async () => {
    const harbor = harborWith();
    onWrite(harbor, () => {
      harbor.state.users = harbor.state.users.filter(
        ({ user_id }) => user_id !== 42
      );
    });
    const error = await connectorError(() => setAdmin(true));
    expect(error.data.payload).toMatchObject({ reason: "no_user" });
  });

  it("says the admin account isn't an administrator when Harbor answers it 403", async () => {
    const harbor = harborWith();
    const admin = harbor.state.users.find(({ user_id }) => user_id === 9);
    if (admin) admin.sysadmin_flag = false;

    const error = await connectorError(() => setAdmin(true));

    expect(error.data).toEqual({
      type: "validation_error",
      message: `The admin account the connector signs in to Harbor at ${HARBOR_HOST} with isn't a Harbor system administrator. Make it one on Harbor's Users page.`,
      payload: {
        reason: "admin_not_harbor_admin",
        host: HARBOR_HOST,
        status: 403,
      },
    });
    expect(flagOf(harbor)).toBe(false);
  });

  it("says Harbor didn't accept the token when Harbor answers it 401", async () => {
    harborWith();
    const error = await connectorError(() =>
      setAdmin(true, { connect: connectAs("other.token.x") })
    );
    expect(error.data.payload).toEqual({
      reason: "admin_token_rejected",
      host: HARBOR_HOST,
      status: 401,
    });
    expect(error.data.message).toContain(
      "didn't accept the ID token the connector minted for its admin account"
    );
  });

  it("passes on the connection's own failure", async () => {
    harborWith();
    const failure = new Error("the provider's refusal");
    const connect = vi.fn<ConnectHarbor>(async () => {
      throw failure;
    });
    await expect(setAdmin(true, { connect })).rejects.toBe(failure);
  });

  it("fails as dependency_violation when Harbor accepts the write but the flag isn't set", async () => {
    const harbor = harborWith();
    const fake = harbor.fetch.getMockImplementation();
    harbor.fetch.mockImplementation(async (url, init) =>
      init?.method === "PUT"
        ? new Response(null, { status: 200 })
        : (fake?.(url, init) ?? new Response(null, { status: 500 }))
    );

    const error = await connectorError(() => setAdmin(true));

    expect(error.data).toEqual({
      type: "dependency_violation",
      message: `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42's system administrator flag, but the user list shows the flag not set. Check the user on Harbor's Users page, then retry the grant.`,
      payload: { host: HARBOR_HOST, userId: 42 },
    });
  });
});

describe("a revoke", () => {
  it("clears the flag P0 set, and reads it back", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;

    await setAdmin(false);

    expect(flagOf(harbor)).toBe(false);
    expect(harbor.calls()).toEqual([
      `GET ${API}/users?q=user_id%3D42&page=1&page_size=100`,
      `PUT ${API}/users/42/sysadmin`,
      `GET ${API}/users?q=user_id%3D42&page=1&page_size=100`,
    ]);
    expect(sentJson(harbor.fetch.mock.calls[1]?.[1])).toEqual({
      sysadmin_flag: false,
    });
  });

  it("leaves a user who was an administrator before P0 granted, reading no secret and calling nothing", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;
    const connect = connectAs();

    await setAdmin(false, { wasSystemAdmin: true, connect });

    expect(flagOf(harbor)).toBe(true);
    expect(connect).not.toHaveBeenCalled();
    expect(harbor.calls()).toEqual([]);
  });

  it("skips the allowlist and the identity check", async () => {
    const harbor = harborWith({
      users: [user(42, "alice@elsewhere.org", true)],
    });
    harbor.state.users.push(user(9, "harbor-automation@example.com", true));

    await setAdmin(false, { email: "alice@elsewhere.org" });

    expect(flagOf(harbor)).toBe(false);
    expect(harbor.calls().some((call) => call.includes("email="))).toBe(false);
  });

  it.each([
    ["the user doesn't have the flag", [user(42, EMAIL)]],
    ["the user doesn't exist", [] as FakeUser[]],
  ])("is already done when %s, without a write", async (_, users) => {
    const harbor = harborWith({
      users: [...users, user(9, "harbor-automation@example.com", true)],
    });

    await setAdmin(false);

    expect(writes(harbor)).toEqual([]);
  });

  it("is done when the user goes between the read and the write", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;
    onWrite(harbor, () => {
      harbor.state.users = harbor.state.users.filter(
        ({ user_id }) => user_id !== 42
      );
    });

    await expect(setAdmin(false)).resolves.toBeUndefined();
  });

  // A 404 from something in front of Harbor isn't Harbor saying the user is
  // gone: the user list still shows them with the flag.
  it("fails when the write answers 404 but the user is still there with the flag", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;
    const fake = harbor.fetch.getMockImplementation();
    harbor.fetch.mockImplementation(async (url, init) =>
      init?.method === "PUT"
        ? new Response(null, { status: 404 })
        : (fake?.(url, init) ?? new Response(null, { status: 500 }))
    );

    const error = await connectorError(() => setAdmin(false));

    expect(error.data).toMatchObject({
      type: "dependency_violation",
      message: expect.stringContaining("shows the flag still set"),
    });
  });

  it("says the admin account isn't an administrator when Harbor answers it 403", async () => {
    const harbor = harborWith();
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;
    const admin = harbor.state.users.find(({ user_id }) => user_id === 9);
    if (admin) admin.sysadmin_flag = false;

    const error = await connectorError(() => setAdmin(false));

    expect(error.data.payload).toMatchObject({
      reason: "admin_not_harbor_admin",
    });
    expect(flagOf(harbor)).toBe(true);
  });
});

describe("setPoliciesForUser", () => {
  it.each([[[]], [[{ systemAdmin: true }, { systemAdmin: false }]]])(
    "refuses anything but exactly one policy (%j)",
    async (policies) => {
      const harbor = harborWith();
      const error = await connectorError(() => setAdmin(true, { policies }));
      expect(error.data).toMatchObject({
        type: "unknown",
        payload: { requestId: "req-1", nPolicies: policies.length },
      });
      expect(harbor.calls()).toEqual([]);
    }
  );

  it("logs no email, token or secret", async () => {
    const harbor = harborWith();
    const seen = recordLogger();
    await setAdmin(true);
    const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
    if (alice) alice.sysadmin_flag = true;
    await setAdmin(false);
    const text = seen.seen();
    for (const secret of [
      ...NEVER_SHOWN,
      EMAIL,
      ID_TOKEN,
      AWS_SECRET.secretId,
    ]) {
      expect(text).not.toContain(secret);
    }
  });
});

/** Answers the sysadmin `PUT` with `status`, running `after` first; the fake answers the rest. */
const answerWrite = (harbor: Harbor, status: number, after = () => {}) => {
  const fake = harbor.fetch.getMockImplementation();
  harbor.fetch.mockImplementation(async (url, init) => {
    if (init?.method !== "PUT") {
      return fake?.(url, init) ?? new Response(null, { status: 500 });
    }
    after();
    return new Response(null, { status });
  });
};

const withoutAlice = (harbor: Harbor) => () => {
  harbor.state.users = harbor.state.users.filter(
    ({ user_id }) => user_id !== 42
  );
};

const giveAliceTheFlag = (harbor: Harbor) => {
  const alice = harbor.state.users.find(({ user_id }) => user_id === 42);
  if (alice) alice.sysadmin_flag = true;
};

const SYSADMIN_503 = {
  type: "upstream_unavailable",
  message: `${HARBOR_HOST} answered PUT /api/v2.0/users/{user_id}/sysadmin with 503. Check that Harbor is running, and try again.`,
  payload: { host: HARBOR_HOST, status: 503 },
};

describe("a grant's write", () => {
  it("fails as Harbor's own failure, not no_user, when the write answers 503", async () => {
    const harbor = harborWith();
    answerWrite(harbor, 503);

    const error = await connectorError(() => setAdmin(true));

    expect(error.data).toEqual(SYSADMIN_503);
  });

  it("fails as dependency_violation when the write is accepted but the user list no longer shows the user", async () => {
    const harbor = harborWith();
    answerWrite(harbor, 200, withoutAlice(harbor));

    const error = await connectorError(() => setAdmin(true));

    expect(error.data).toEqual({
      type: "dependency_violation",
      message: `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42's system administrator flag, but the user list shows no such user. Check the user on Harbor's Users page, then retry the grant.`,
      payload: { host: HARBOR_HOST, userId: 42 },
    });
  });
});

describe("a revoke's write", () => {
  it("fails as Harbor's own failure when the write answers 503", async () => {
    const harbor = harborWith();
    giveAliceTheFlag(harbor);
    answerWrite(harbor, 503);

    const error = await connectorError(() => setAdmin(false));

    expect(error.data).toEqual(SYSADMIN_503);
    expect(flagOf(harbor)).toBe(true);
  });

  it("is done when the write is accepted and the user list no longer shows the user", async () => {
    const harbor = harborWith();
    giveAliceTheFlag(harbor);
    answerWrite(harbor, 200, withoutAlice(harbor));

    await expect(setAdmin(false)).resolves.toBeUndefined();
  });

  it("says to retry the revoke when the write is accepted but the flag is still set", async () => {
    const harbor = harborWith();
    giveAliceTheFlag(harbor);
    answerWrite(harbor, 200);

    const error = await connectorError(() => setAdmin(false));

    expect(error.data).toEqual({
      type: "dependency_violation",
      message: `Harbor at ${HARBOR_HOST} accepted the change to Harbor user 42's system administrator flag, but the user list shows the flag still set. Check the user on Harbor's Users page, then retry the revoke.`,
      payload: { host: HARBOR_HOST, userId: 42 },
    });
  });
});

describe("setPoliciesForUser's policy count", () => {
  it("says how many policies it got", async () => {
    harborWith();
    const error = await connectorError(() => setAdmin(true, { policies: [] }));
    expect(error.data.message).toBe(
      "Expected exactly 1 policy for Harbor system administrator, got 0"
    );
  });
});

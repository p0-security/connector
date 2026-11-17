import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_ID,
  APP_INPUT,
  KEYS,
  answer,
  connectorError,
  logger,
  stubOkta,
} from "../../../__tests__/fixtures.ts";
import { readPrivateKey } from "../../../secrets.ts";
import { addRole, findUserId, removeRole } from "../assignment.ts";

vi.mock("../../../secrets.ts");

const EMAIL = "ada@example.com";
const USER = { id: "00u1ada", status: "ACTIVE", profile: { login: EMAIL } };
const ROLE = "p0-pool-1";
const OTHER = "AdminRole";
const INPUT = { ...APP_INPUT, userId: USER.id, role: ROLE };
const APP_USER = `/api/v1/apps/${APP_ID}/users/${USER.id}`;

const oktaWith = ({
  users = [USER],
  appUser,
}: {
  users?: object[];
  appUser?: { samlRoles?: string[] | null; managedByP0?: boolean };
}) =>
  stubOkta({
    "POST /oauth2/v1/token": () =>
      answer(200, { access_token: "at", token_type: "Bearer" }),
    "GET /api/v1/users": () => answer(200, users),
    [`GET /api/v1/users/${USER.id}`]: () => answer(200, USER),
    [`GET ${APP_USER}`]: () =>
      appUser === undefined
        ? answer(404, { errorCode: "E0000007" })
        : answer(200, { id: USER.id, profile: appUser }),
    [`POST /api/v1/apps/${APP_ID}/users`]: () => answer(200, {}),
    [`POST ${APP_USER}`]: () => answer(200, {}),
    [`DELETE ${APP_USER}`]: () => new Response(null, { status: 204 }),
  });

const writes = (okta: ReturnType<typeof stubOkta>) =>
  okta.fetch.mock.calls
    .filter(
      ([url, init]) =>
        init?.method !== "GET" && new URL(url).pathname !== "/oauth2/v1/token"
    )
    .map(([url, init]) => ({
      call: `${init?.method} ${new URL(url).pathname}`,
      body:
        init?.body === undefined ? undefined : JSON.parse(init.body as string),
    }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readPrivateKey).mockResolvedValue({ key: KEYS.privateKey });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("findUserId", () => {
  it("finds the user by email", async () => {
    const okta = oktaWith({});

    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBe(USER.id);

    const url = new URL(okta.fetch.mock.calls[1][0]);
    expect(url.searchParams.get("search")).toBe(`profile.email eq "${EMAIL}"`);
  });

  it("skips deactivated users", async () => {
    oktaWith({
      users: [{ ...USER, id: "00u0old", status: "DEPROVISIONED" }, USER],
    });

    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBe(USER.id);
  });

  it("finds no user when the only one is deactivated", async () => {
    oktaWith({ users: [{ ...USER, status: "DEPROVISIONED" }] });

    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBeNull();
  });

  it("fails when more than one user has the email", async () => {
    oktaWith({ users: [USER, { ...USER, id: "00u2ada" }] });

    const error = await connectorError(() =>
      findUserId(APP_INPUT, EMAIL, logger)
    );

    expect(error.data.type).toBe("validation_error");
  });
});

describe("addRole", () => {
  it("doesn't search for the user", async () => {
    const okta = oktaWith({ appUser: { samlRoles: [OTHER] } });

    await addRole(INPUT, logger);

    const paths = okta.fetch.mock.calls.map(([url]) => new URL(url).pathname);
    expect(paths).not.toContain("/api/v1/users");
  });

  it("assigns an unassigned user, marked managedByP0", async () => {
    const okta = oktaWith({});

    await expect(addRole(INPUT, logger)).resolves.toBeNull();

    expect(writes(okta)).toEqual([
      {
        call: `POST /api/v1/apps/${APP_ID}/users`,
        body: {
          credentials: { userName: EMAIL },
          id: USER.id,
          profile: { managedByP0: true, samlRoles: [ROLE] },
          scope: "USER",
        },
      },
    ]);
  });

  it("adds the role to the user's other roles", async () => {
    const okta = oktaWith({ appUser: { samlRoles: [OTHER] } });

    await addRole(INPUT, logger);

    expect(writes(okta)).toEqual([
      {
        call: `POST ${APP_USER}`,
        body: { profile: { samlRoles: [OTHER, ROLE] } },
      },
    ]);
  });

  it("adds the role to a user with no roles", async () => {
    const okta = oktaWith({ appUser: { samlRoles: null } });

    await addRole(INPUT, logger);

    expect(writes(okta)).toEqual([
      { call: `POST ${APP_USER}`, body: { profile: { samlRoles: [ROLE] } } },
    ]);
  });

  it("writes nothing when the user has the role", async () => {
    const okta = oktaWith({ appUser: { samlRoles: [OTHER, ROLE] } });

    await addRole(INPUT, logger);

    expect(writes(okta)).toEqual([]);
  });
});

describe("removeRole", () => {
  it("removes the role and keeps the user's other roles", async () => {
    const okta = oktaWith({
      appUser: { managedByP0: true, samlRoles: [OTHER, ROLE] },
    });

    await expect(removeRole(INPUT, logger)).resolves.toBeNull();

    expect(writes(okta)).toEqual([
      { call: `POST ${APP_USER}`, body: { profile: { samlRoles: [OTHER] } } },
    ]);
  });

  it("unassigns a user P0 assigned when no role is left", async () => {
    const okta = oktaWith({
      appUser: { managedByP0: true, samlRoles: [ROLE] },
    });

    await removeRole(INPUT, logger);

    expect(writes(okta)).toEqual([
      { call: `DELETE ${APP_USER}`, body: undefined },
    ]);
  });

  it("keeps a user P0 didn't assign, with no roles", async () => {
    const okta = oktaWith({ appUser: { samlRoles: [ROLE] } });

    await removeRole(INPUT, logger);

    expect(writes(okta)).toEqual([
      { call: `POST ${APP_USER}`, body: { profile: { samlRoles: [] } } },
    ]);
  });

  it.each([
    ["the user isn't assigned", {}],
    ["the user doesn't have the role", { appUser: { samlRoles: [OTHER] } }],
  ])("writes nothing when %s", async (_, state) => {
    const okta = oktaWith(state);

    await expect(removeRole(INPUT, logger)).resolves.toBeNull();

    expect(writes(okta)).toEqual([]);
  });

  it("maps a refused write", async () => {
    stubOkta({
      "POST /oauth2/v1/token": () =>
        answer(200, { access_token: "at", token_type: "Bearer" }),
      "GET /api/v1/users": () => answer(200, [USER]),
      [`GET ${APP_USER}`]: () =>
        answer(200, { profile: { samlRoles: [OTHER, ROLE] } }),
      [`POST ${APP_USER}`]: () => answer(403, { errorCode: "E0000006" }),
    });

    const error = await connectorError(() => removeRole(INPUT, logger));

    expect(error.data).toMatchObject({
      payload: { code: "E0000006", status: 403 },
      type: "insufficient_privileges",
    });
  });

  it("names a role that the app doesn't list", async () => {
    const cause = "samlRoles: 'AdminRole' is not a valid value";
    stubOkta({
      "POST /oauth2/v1/token": () =>
        answer(200, { access_token: "at", token_type: "Bearer" }),
      "GET /api/v1/users": () => answer(200, [USER]),
      [`GET ${APP_USER}`]: () =>
        answer(200, { profile: { samlRoles: [OTHER] } }),
      [`POST ${APP_USER}`]: () =>
        answer(400, {
          errorCode: "E0000001",
          errorSummary: "Api validation failed: samlRoles",
          errorCauses: [{ errorSummary: cause }],
        }),
    });

    const error = await connectorError(() => addRole(INPUT, logger));

    expect(error.data).toMatchObject({
      payload: { code: "E0000001", status: 400 },
      type: "validation_error",
    });
    expect(error.message).toContain(cause);
    expect(error.message).toContain("refresh the app's data");
  });
});

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
import { addRole, removeRole } from "../assignment.ts";

vi.mock("../../../secrets.ts");

const EMAIL = "ada@example.com";
const USER = { id: "00u1ada", status: "ACTIVE", profile: { login: EMAIL } };
const ROLE = "p0-pool-1";
const OTHER = "AdminRole";
const INPUT = { ...APP_INPUT, email: EMAIL, role: ROLE };
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

describe("addRole", () => {
  it("finds the user by email", async () => {
    const okta = oktaWith({ appUser: { samlRoles: [ROLE] } });

    await addRole(INPUT, logger);

    const url = new URL(okta.fetch.mock.calls[1][0]);
    expect(url.searchParams.get("search")).toBe(`profile.email eq "${EMAIL}"`);
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

  it("fails when Okta has no user with the email", async () => {
    oktaWith({ users: [] });

    const error = await connectorError(() => addRole(INPUT, logger));

    expect(error.data.type).toBe("object_not_found");
  });

  it("fails when more than one user has the email", async () => {
    oktaWith({ users: [USER, { ...USER, id: "00u2ada" }] });

    const error = await connectorError(() => addRole(INPUT, logger));

    expect(error.data.type).toBe("validation_error");
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
    ["the user is gone", { users: [] }],
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
});

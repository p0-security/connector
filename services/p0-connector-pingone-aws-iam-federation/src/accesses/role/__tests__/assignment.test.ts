import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APP_INPUT,
  CLIENT_SECRET,
  ENVIRONMENT_ID,
  answer,
  connectorError,
  logger,
  stubPingOne,
} from "../../../__tests__/fixtures.ts";
import { readClientSecret } from "../../../secrets.ts";
import { addRole, findUserId, removeRole } from "../assignment.ts";

vi.mock("../../../secrets.ts");

const API = `api.pingone.com/v1/environments/${ENVIRONMENT_ID}`;
const LIST_USERS = `GET ${API}/users`;
const EMAIL = "ada@example.com";
const USER_ID = "7898a07d-7fb9-4a89-b78c-1ada520cc8bc";
const PATCH_USER = `PATCH ${API}/users/${USER_ID}`;
const ROLE =
  "arn:aws:iam::123456789012:role/p0-pool-1,arn:aws:iam::123456789012:saml-provider/pingone";
const OTHER =
  "arn:aws:iam::123456789012:role/admin,arn:aws:iam::123456789012:saml-provider/pingone";
const ASSIGNMENT = { ...APP_INPUT, email: EMAIL, role: ROLE };

const pingOne = (users: object[]) =>
  stubPingOne({
    [`POST auth.pingone.com/${ENVIRONMENT_ID}/as/token`]: () =>
      answer(200, { access_token: "at", token_type: "Bearer" }),
    [LIST_USERS]: () => answer(200, { _embedded: { users } }),
    [PATCH_USER]: () => answer(200, {}),
  });

const userWith = (awsRoles?: unknown) => ({
  id: USER_ID,
  username: "ada",
  email: EMAIL,
  ...(awsRoles === undefined ? {} : { awsRoles }),
});

const patchBody = (stub: ReturnType<typeof pingOne>) =>
  JSON.parse(
    stub.fetch.mock.calls[stub.calls().indexOf(PATCH_USER)]?.[1]?.body as string
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readClientSecret).mockResolvedValue(CLIENT_SECRET);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("findUserId", () => {
  it("filters users by the quoted email", async () => {
    const stub = pingOne([userWith()]);

    await expect(
      findUserId(APP_INPUT, 'a"b\\c@example.com', logger)
    ).resolves.toBe(USER_ID);

    const url = new URL(stub.fetch.mock.calls[1]?.[0]);
    expect(url.searchParams.get("filter")).toBe(
      'email eq "a\\"b\\\\c@example.com"'
    );
  });

  it("returns null when PingOne has no such user", async () => {
    pingOne([]);

    await expect(findUserId(APP_INPUT, EMAIL, logger)).resolves.toBeNull();
  });

  it("refuses an email that more than one user has", async () => {
    pingOne([userWith(), { ...userWith(), id: "other" }]);

    const error = await connectorError(() =>
      findUserId(APP_INPUT, EMAIL, logger)
    );

    expect(error.data).toMatchObject({
      payload: { count: 2 },
      type: "validation_error",
    });
  });
});

describe("addRole", () => {
  it("adds the role beside the user's other roles", async () => {
    const stub = pingOne([userWith([OTHER])]);

    await addRole(ASSIGNMENT, logger);

    expect(patchBody(stub)).toEqual({ awsRoles: [OTHER, ROLE] });
  });

  it("starts the list for a user without roles", async () => {
    const stub = pingOne([userWith()]);

    await addRole(ASSIGNMENT, logger);

    expect(patchBody(stub)).toEqual({ awsRoles: [ROLE] });
  });

  it("does nothing when the user has the role", async () => {
    const stub = pingOne([userWith([ROLE])]);

    await addRole(ASSIGNMENT, logger);

    expect(stub.calls()).not.toContain(PATCH_USER);
  });

  it("fails when PingOne has no such user", async () => {
    pingOne([]);

    const error = await connectorError(() => addRole(ASSIGNMENT, logger));

    expect(error.data.type).toBe("object_not_found");
  });

  it("refuses a role attribute that isn't a list", async () => {
    const stub = pingOne([userWith(OTHER)]);

    const error = await connectorError(() => addRole(ASSIGNMENT, logger));

    expect(error.data.type).toBe("validation_error");
    expect(stub.calls()).not.toContain(PATCH_USER);
  });

  it("maps PingOne's refusal of the update", async () => {
    stubPingOne({
      [`POST auth.pingone.com/${ENVIRONMENT_ID}/as/token`]: () =>
        answer(200, { access_token: "at", token_type: "Bearer" }),
      [LIST_USERS]: () => answer(200, { _embedded: { users: [userWith()] } }),
      [PATCH_USER]: () => answer(403, { code: "ACCESS_FAILED" }),
    });

    const error = await connectorError(() => addRole(ASSIGNMENT, logger));

    expect(error.data).toMatchObject({
      payload: { code: "ACCESS_FAILED", status: 403 },
      type: "insufficient_privileges",
    });
  });
});

describe("removeRole", () => {
  it("removes only the role", async () => {
    const stub = pingOne([userWith([OTHER, ROLE])]);

    await removeRole(ASSIGNMENT, logger);

    expect(patchBody(stub)).toEqual({ awsRoles: [OTHER] });
  });

  it("writes an empty list when the last role goes", async () => {
    const stub = pingOne([userWith([ROLE])]);

    await removeRole(ASSIGNMENT, logger);

    expect(patchBody(stub)).toEqual({ awsRoles: [] });
  });

  it.each([
    ["the user is gone", []],
    ["the user doesn't have the role", [userWith([OTHER])]],
  ])("does nothing when %s", async (_, users) => {
    const stub = pingOne(users);

    await expect(removeRole(ASSIGNMENT, logger)).resolves.toBeNull();

    expect(stub.calls()).not.toContain(PATCH_USER);
  });
});

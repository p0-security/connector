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
import { connectorRouter } from "../../../router.ts";
import { readPrivateKey } from "../../../secrets.ts";

vi.mock("../../../secrets.ts");

// The read-change-write itself is `assignment.test.ts`'s business. These
// tests prove each perimeter route reaches it, or does nothing.

const EMAIL = "ada@example.com";
const USER = { id: "00u1ada", status: "ACTIVE", profile: { login: EMAIL } };
const ROLE = "p0-pool-1";
const CONTEXT = { requestId: "request-1", ...APP_INPUT };
const APP_USER = `/api/v1/apps/${APP_ID}/users/${USER.id}`;

const role = () =>
  connectorRouter.createCaller({ logger })["okta-aws-iam-federation"].accesses
    .role;

const okta = (users: object[] = [USER]) =>
  stubOkta({
    "POST /oauth2/v1/token": () =>
      answer(200, { access_token: "at", token_type: "Bearer" }),
    "GET /api/v1/users": () => answer(200, users),
    [`GET ${APP_USER}`]: () =>
      answer(200, { profile: { managedByP0: true, samlRoles: [ROLE] } }),
    [`POST ${APP_USER}`]: () => answer(200, {}),
    [`DELETE ${APP_USER}`]: () => new Response(null, { status: 204 }),
  });

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(readPrivateKey).mockResolvedValue({ key: KEYS.privateKey });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("role access", () => {
  it("provisions an existing user to their Okta ID", async () => {
    okta();

    await expect(
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    ).resolves.toBe(USER.id);
  });

  it("refuses to provision a user Okta doesn't have", async () => {
    okta([]);

    const error = await connectorError(() =>
      role().provisionUser({ context: CONTEXT, userBody: EMAIL })
    );

    expect(error.data.type).toBe("object_not_found");
  });

  it("uses the label as the resource, with no Okta call", async () => {
    const calls = okta();

    await expect(
      role().createAccessResource({ context: CONTEXT, resourceBody: ROLE })
    ).resolves.toBe(ROLE);
    await role().addPoliciesToResource({
      context: CONTEXT,
      policies: [null],
      resourceId: ROLE,
    });
    await role().deleteAccessResource({ context: CONTEXT, resourceId: ROLE });

    expect(calls.calls()).toEqual([]);
  });

  it("unbinds by removing the label", async () => {
    const calls = okta();

    await role().unbindAccessResource({
      context: CONTEXT,
      resourceId: ROLE,
      userBody: EMAIL,
      userId: USER.id,
    });

    expect(calls.calls()).toContain(`DELETE ${APP_USER}`);
  });

  it("binds by adding the label", async () => {
    const calls = okta();

    await role().bindAccessResource({
      context: CONTEXT,
      resourceId: "p0-pool-2",
      userBody: EMAIL,
      userId: USER.id,
    });

    expect(calls.calls()).toContain(`POST ${APP_USER}`);
  });
});

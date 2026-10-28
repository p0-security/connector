import { createLogger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import packageJson from "../../package.json" with { type: "json" };
import { connectorRouter, t } from "../router.ts";
import {
  type FakeDockerHub,
  failing,
  newFakeDockerHub,
} from "./fake-docker-hub.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  TOKEN,
  UUID,
} from "./fixtures.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getOrgAccessToken = vi.hoisted(() => vi.fn());
vi.mock("../secrets.ts", () => ({ getOrgAccessToken }));

// Read when the first email is checked, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

// An address the pattern doesn't allow: what a requestor's is to a
// connector whose pattern was tightened after their grant.
const OUTSIDER = "mallory@evil.com";

// Someone P0 invites has no standing member.
const INVITED = {
  ...CREDENTIALS,
  requestId: "req-1",
  standingMember: null,
  grantCompleted: false,
};
const STANDING = {
  ...INVITED,
  standingMember: {
    username: "alice",
    uuid: UUID,
    priorRole: "member" as const,
  },
};

type Context = typeof INVITED | typeof STANDING;

const logger = createLogger();
logger.level = "silent";
const connector = t.createCallerFactory(connectorRouter)({ logger });
const { role } = connector.docker.accesses;

let hub: FakeDockerHub;
let versions = 0;

beforeEach(() => {
  hub = newFakeDockerHub({ org: "acme", token: TOKEN });
  vi.stubGlobal("fetch", hub.fetch);
  getOrgAccessToken.mockReset();
  // A new version of the secret each test, so each starts without a cached JWT.
  getOrgAccessToken.mockResolvedValue({
    token: TOKEN,
    version: `version-${++versions}`,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** A grant, as P0 sends it. */
const granting = (context: Context, email = EMAIL) => ({
  userId: email,
  userBody: email,
  policies: [{ role: "editor" as const }],
  context,
});

/** A revoke, as P0 sends it once the grant has completed. */
const revoking = (context: Context, email = EMAIL) => ({
  userId: email,
  userBody: email,
  policies: [{ role: null }],
  context: { ...context, grantCompleted: true },
});

const lookup = (type: "invite" | "member", email = EMAIL) =>
  role.list({ query: { type, context: CREDENTIALS, email } });

describe("the connector's router", () => {
  // Everything P0 can ask of the connector is in this list.
  it("exposes the role access, install validation and metadata, under one namespace", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "docker.accesses.role.deleteUser",
      "docker.accesses.role.identifyUser",
      "docker.accesses.role.list",
      "docker.accesses.role.provisionUser",
      "docker.accesses.role.setPoliciesForUser",
      "docker.install.validation.get",
      "docker.metadata.get",
    ]);
  });

  it("reports the workspace's version", async () => {
    await expect(connector.docker.metadata.get()).resolves.toMatchObject({
      connectorVersion: packageJson.version,
    });
  });

  it("refuses input that doesn't parse, before it reaches a primitive", async () => {
    await expect(
      connector.docker.install.validation.get({ ...CREDENTIALS, org: "../x" })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(lookup("member", "alice")).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(getOrgAccessToken).not.toHaveBeenCalled();
    expect(hub.calls).toEqual([]);
  });
});

// What P0 does with a request, in the order it does it.
describe("through the router", () => {
  it("validates an install, reporting the deployment's pattern", async () => {
    await expect(
      connector.docker.install.validation.get(CREDENTIALS)
    ).resolves.toEqual({
      tokenAccepted: true,
      canReadMembers: true,
      canInvite: true,
      allowedDomains: ALLOWED_PATTERN,
    });
    expect(getOrgAccessToken).toHaveBeenCalledWith(CREDENTIALS.tokenSecret);
  });

  // What P0 gets when a check can't be made: the first two say to try again,
  // and the last carries Docker Hub's reason.
  it.each([
    [
      429,
      "TOO_MANY_REQUESTS",
      "Docker Hub is rate limiting the connector for acme. Retry in a few minutes.",
    ],
    [
      503,
      "SERVICE_UNAVAILABLE",
      "Docker Hub couldn't answer the connector's request right now. Retry in a few minutes, and check dockerstatus.com if it keeps failing.",
    ],
    [
      400,
      "PRECONDITION_FAILED",
      "Docker Hub refused the connector's request for acme (400): bad request",
    ],
  ])(
    "answers a %s on an install check with %s",
    async (status, code, message) => {
      hub.intercept((call) =>
        call.path === "/v2/orgs/acme/members"
          ? failing(status, "bad request")
          : undefined
      );

      await expect(
        connector.docker.install.validation.get(CREDENTIALS)
      ).rejects.toMatchObject({ code, message });
    }
  );

  it("invites someone who isn't a member, then cancels the invite", async () => {
    await expect(lookup("member")).resolves.toEqual([]);

    await expect(
      role.provisionUser({ userBody: EMAIL, context: INVITED })
    ).resolves.toBe(EMAIL);
    await expect(
      role.setPoliciesForUser(granting(INVITED))
    ).resolves.toBeNull();
    await expect(lookup("invite")).resolves.toEqual([
      { key: "invite-1", value: "editor" },
    ]);

    await expect(
      role.identifyUser({ userBody: EMAIL, context: INVITED })
    ).resolves.toBe(EMAIL);
    await expect(
      role.setPoliciesForUser(revoking(INVITED))
    ).resolves.toBeNull();
    await expect(
      role.deleteUser({ userId: EMAIL, userBody: EMAIL, context: INVITED })
    ).resolves.toBeNull();
    expect(hub.invites).toEqual([]);
  });

  it("sets a standing member's role, then puts their prior role back", async () => {
    const alice = { username: "alice", uuid: UUID, email: EMAIL };
    hub.members.push({ ...alice, role: "member" });

    await expect(lookup("member")).resolves.toEqual([
      { key: "alice", value: UUID, group: "member" },
    ]);

    await role.provisionUser({ userBody: EMAIL, context: STANDING });
    await role.setPoliciesForUser(granting(STANDING));
    expect(hub.members).toEqual([{ ...alice, role: "editor" }]);

    await role.identifyUser({ userBody: EMAIL, context: STANDING });
    await role.setPoliciesForUser(revoking(STANDING));
    await role.deleteUser({
      userId: EMAIL,
      userBody: EMAIL,
      context: STANDING,
    });
    expect(hub.members).toEqual([{ ...alice, role: "member" }]);
  });

  // P0 revokes through identifyUser, setPoliciesForUser and deleteUser. A
  // standing member who has left must get through all three.
  it("revokes for a standing member who has left the org", async () => {
    await expect(
      role.identifyUser({ userBody: EMAIL, context: STANDING })
    ).resolves.toBe(EMAIL);
    await expect(
      role.setPoliciesForUser(revoking(STANDING))
    ).resolves.toBeNull();
    await expect(
      role.deleteUser({ userId: EMAIL, userBody: EMAIL, context: STANDING })
    ).resolves.toBeNull();
    expect(hub.writes()).toEqual([]);
  });

  describe("for an email outside the allowed domains", () => {
    it("refuses a grant and both lookups with a message for the requestor", async () => {
      const refused = {
        code: "PRECONDITION_FAILED",
        message:
          "Your email domain isn't allowed for Docker Hub organization acme. Ask your P0 admin to check the connector's allowed domains.",
      };

      for (const context of [INVITED, STANDING]) {
        await expect(
          role.setPoliciesForUser(granting(context, OUTSIDER))
        ).rejects.toMatchObject(refused);
      }
      for (const type of ["member", "invite"] as const) {
        await expect(lookup(type, OUTSIDER)).rejects.toMatchObject(refused);
      }
      expect(hub.calls).toEqual([]);
    });

    // Tightening the pattern can't strand access granted under the old one.
    it("still revokes", async () => {
      hub.invites.push({ id: "invite-1", invitee: OUTSIDER, role: "editor" });

      await expect(
        role.identifyUser({ userBody: OUTSIDER, context: INVITED })
      ).resolves.toBe(OUTSIDER);
      await expect(
        role.setPoliciesForUser(revoking(INVITED, OUTSIDER))
      ).resolves.toBeNull();
      await expect(
        role.deleteUser({
          userId: OUTSIDER,
          userBody: OUTSIDER,
          context: INVITED,
        })
      ).resolves.toBeNull();
      expect(hub.invites).toEqual([]);
    });
  });

  it("reports a token Docker Hub refuses as the install's to fix", async () => {
    getOrgAccessToken.mockResolvedValue({
      token: "dckr_oat_revoked",
      version: "a-revoked-version",
    });

    await expect(
      role.setPoliciesForUser(granting(INVITED))
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

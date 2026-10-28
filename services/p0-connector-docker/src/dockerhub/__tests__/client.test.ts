import { ConnectorError } from "@p0security/connector-core";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeDockerHub,
  JWT_LIFETIME_MS,
  failing,
  isCall,
  jwtExpiringAt,
  newFakeDockerHub,
} from "../../__tests__/fake-docker-hub.ts";
import {
  AWS_SECRET,
  CREDENTIALS,
  EMAIL,
  GCP_SECRET,
  TOKEN,
  UUID,
} from "../../__tests__/fixtures.ts";
import {
  UNFIT_JWTS,
  newRecordingLogger,
  thrown,
} from "../../__tests__/helpers.ts";
import type { TokenSecret } from "../../accesses/role/definition.ts";
import type { OrgAccessToken } from "../../secrets.ts";
import { DockerHubError } from "../api.ts";
import { newDockerHubClient } from "../client.ts";
import { TokenRejectedError } from "../errors.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getOrgAccessToken = vi.hoisted(() =>
  vi.fn<(tokenSecret: TokenSecret) => Promise<OrgAccessToken>>()
);
vi.mock("../../secrets.ts", () => ({ getOrgAccessToken }));

const ALICE = { username: "alice", uuid: UUID, email: EMAIL, role: "member" };

const MINUTE = 60 * 1000;
const INVITES = "/v2/orgs/acme/invites";
const TOKEN_EXCHANGE = "/v2/auth/token";

let hub: FakeDockerHub;
let logs: ReturnType<typeof newRecordingLogger>;
let versions = 0;
/** The version the secret is at. A new one each test, so each starts without a cached JWT. */
let version: string;

/** The secret is rotated: the same pointer now reads a new version. */
const rotateSecret = () => {
  version = `version-${++versions}`;
};

/** A client, as each call to the connector builds one. */
const newClient = (
  identity: { org?: string; tokenSecret?: TokenSecret } = {}
) => newDockerHubClient({ ...CREDENTIALS, log: logs.log, ...identity });

/** One call to the connector that makes one request to Docker Hub. */
const callOnce = () => newClient().findInvites(EMAIL);

beforeEach(() => {
  // Only the clock: a JWT's lifetime is measured with `Date.now()`.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-12T09:00:00Z"));
  hub = newFakeDockerHub({ org: "acme", token: TOKEN });
  vi.stubGlobal("fetch", hub.fetch);
  logs = newRecordingLogger();
  rotateSecret();
  getOrgAccessToken.mockReset();
  getOrgAccessToken.mockImplementation(async () => ({ token: TOKEN, version }));
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("the secret", () => {
  // So a rotated secret, or a pulled read grant, takes effect on the next call.
  it("is read by every call to the connector, even with a JWT cached", async () => {
    await callOnce();
    await callOnce();

    expect(getOrgAccessToken).toHaveBeenCalledTimes(2);
    expect(getOrgAccessToken).toHaveBeenCalledWith(AWS_SECRET);
    expect(hub.exchanges()).toHaveLength(1);
  });

  it("is read once per call, however many requests the call makes", async () => {
    const client = newClient();

    await client.findInvites(EMAIL);
    await client.findMembersByEmail(EMAIL);
    await client.findInvites(EMAIL);

    expect(getOrgAccessToken).toHaveBeenCalledTimes(1);
  });

  it("fails the call when it can't be read, and Docker Hub isn't asked", async () => {
    const error = new ConnectorError({
      type: "insufficient_privileges",
      message: "not allowed to read the secret",
      payload: { secretId: "docker-oat", manager: "aws" },
    });
    getOrgAccessToken.mockRejectedValue(error);

    await expect(callOnce()).rejects.toBe(error);
    expect(hub.calls).toEqual([]);
  });

  // A read grant pulled while a JWT is still good.
  it("fails the next call when it can no longer be read", async () => {
    await callOnce();
    getOrgAccessToken.mockRejectedValue(new Error("access denied"));

    await expect(callOnce()).rejects.toThrow("access denied");
    expect(hub.apiCalls()).toHaveLength(1);
  });
});

describe("the JWT", () => {
  it("is exchanged for the token, as the org, and sent as a bearer", async () => {
    await callOnce();

    expect(hub.calls.map(({ method, path }) => `${method} ${path}`)).toEqual([
      `POST ${TOKEN_EXCHANGE}`,
      `GET ${INVITES}`,
    ]);
    expect(hub.exchanges()[0]?.body).toEqual({
      identifier: "acme",
      secret: TOKEN,
    });
    expect(hub.bearers()).toEqual([hub.jwts[0]]);
  });

  // The token goes to the exchange, and nowhere else.
  it("is the only credential a call to the API carries", async () => {
    await callOnce();

    expect(hub.exchanges()[0]?.headers).not.toHaveProperty("authorization");
    for (const { url, headers, rawBody } of hub.apiCalls()) {
      expect(`${url} ${JSON.stringify(headers)} ${rawBody}`).not.toContain(
        TOKEN
      );
    }
  });

  it("is reused by the calls that follow", async () => {
    await callOnce();
    await callOnce();
    await callOnce();

    expect(hub.exchanges()).toHaveLength(1);
    expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[0], hub.jwts[0]]);
  });

  describe("when the secret is rotated", () => {
    // The old JWT would still work for up to 15 minutes.
    it("is exchanged again on the next call, for the new version", async () => {
      await callOnce();

      rotateSecret();
      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
      expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[1]]);
    });

    it("is then reused for that version", async () => {
      await callOnce();
      rotateSecret();
      await callOnce();

      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
    });

    // A failed exchange is evicted, but only its own entry: by the time this
    // one fails, the cache holds the new version's JWT.
    it("is kept when the old version's exchange fails after it", async () => {
      // The first exchange gets a 503, which arrives when the test lets it.
      let deliverFailure = () => {};
      const held = new Promise<void>((resolve) => {
        deliverFailure = resolve;
      });
      hub.intercept((call) =>
        isCall("POST", TOKEN_EXCHANGE)(call) && hub.exchanges().length === 1
          ? failing(503)
          : undefined
      );
      vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
        const response = await hub.fetch(...args);
        if (response.status === 503) await held;
        return response;
      });

      const beforeRotation = callOnce();
      rotateSecret();
      await callOnce();
      deliverFailure();
      await expect(beforeRotation).rejects.toMatchObject({ status: 503 });

      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
      expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[0]]);
    });
  });

  describe("with an `exp`", () => {
    it("is still used just over a minute before it expires", async () => {
      await callOnce();

      vi.advanceTimersByTime(JWT_LIFETIME_MS - MINUTE - 1);
      await callOnce();

      expect(hub.exchanges()).toHaveLength(1);
    });

    // A call that starts in the last minute could outlive it.
    it("is exchanged again a minute before it expires", async () => {
      await callOnce();

      vi.advanceTimersByTime(JWT_LIFETIME_MS - MINUTE);
      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
      expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[1]]);
    });

    it("is kept for as long as its own `exp` says, not for 14 minutes", async () => {
      const lifetime = 5 * MINUTE;
      hub = newFakeDockerHub({
        org: "acme",
        token: TOKEN,
        jwt: (n) => jwtExpiringAt(Date.now() + lifetime, n),
      });
      vi.stubGlobal("fetch", hub.fetch);
      await callOnce();

      vi.advanceTimersByTime(lifetime - MINUTE);
      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
    });
  });

  describe.each([
    ["isn't a JWT", () => "an-opaque-token"],
    [
      "has no `exp`",
      () =>
        `e30.${Buffer.from(JSON.stringify({ sub: "acme" })).toString("base64url")}.c2ln`,
    ],
    ["has a payload that isn't JSON", () => "e30.bm90LWpzb24.c2ln"],
  ])("when it %s", (_case, jwt) => {
    beforeEach(() => {
      hub = newFakeDockerHub({ org: "acme", token: TOKEN, jwt });
      vi.stubGlobal("fetch", hub.fetch);
    });

    it("is still used just under 14 minutes on", async () => {
      await callOnce();

      vi.advanceTimersByTime(14 * MINUTE - 1);
      await callOnce();

      expect(hub.exchanges()).toHaveLength(1);
    });

    it("is exchanged again once it's 14 minutes old", async () => {
      await callOnce();

      vi.advanceTimersByTime(14 * MINUTE);
      await callOnce();

      expect(hub.exchanges()).toHaveLength(2);
    });
  });

  // A JWT is for one org.
  it("isn't shared between orgs", async () => {
    await callOnce();
    // The fake only knows acme, so this exchange is refused. It was asked.
    await expect(
      newClient({ org: "other-org" }).findInvites(EMAIL)
    ).rejects.toBeInstanceOf(TokenRejectedError);

    expect(hub.exchanges().map(({ body }) => body)).toEqual([
      { identifier: "acme", secret: TOKEN },
      { identifier: "other-org", secret: TOKEN },
    ]);
  });

  it.each<[string, TokenSecret]>([
    ["another secret", { ...AWS_SECRET, secretId: "another-oat" }],
    ["another region", { ...AWS_SECRET, region: "eu-west-1" }],
    ["Google Secret Manager", { ...GCP_SECRET, projectId: AWS_SECRET.region }],
  ])("isn't shared with a pointer to %s", async (_case, tokenSecret) => {
    await callOnce();
    await newClient({ tokenSecret }).findInvites(EMAIL);

    expect(hub.exchanges()).toHaveLength(2);
    expect(getOrgAccessToken).toHaveBeenLastCalledWith(tokenSecret);
  });

  // The same secret id can exist in two Google projects.
  it("isn't shared between two Google pointers to different projects", async () => {
    await newClient({ tokenSecret: GCP_SECRET }).findInvites(EMAIL);
    await newClient({
      tokenSecret: { ...GCP_SECRET, projectId: "acme-staging" },
    }).findInvites(EMAIL);

    expect(hub.exchanges()).toHaveLength(2);
  });
});

describe("calls that arrive together", () => {
  it("share one exchange when there's no JWT yet", async () => {
    await Promise.all([callOnce(), callOnce(), callOnce()]);

    expect(hub.exchanges()).toHaveLength(1);
    expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[0], hub.jwts[0]]);
  });

  it("share one exchange when the JWT has just expired", async () => {
    await callOnce();
    vi.advanceTimersByTime(JWT_LIFETIME_MS);

    await Promise.all([callOnce(), callOnce()]);

    expect(hub.exchanges()).toHaveLength(2);
  });

  it("share a failed exchange's error", async () => {
    hub.intercept((call) =>
      isCall("POST", TOKEN_EXCHANGE)(call) ? failing(503) : undefined
    );

    const results = await Promise.allSettled([callOnce(), callOnce()]);

    expect(results.map(({ status }) => status)).toEqual([
      "rejected",
      "rejected",
    ]);
    expect(hub.exchanges()).toHaveLength(1);
  });

  // Otherwise one failure would be served until the container is replaced.
  it("don't leave a failed exchange behind for the next call", async () => {
    let failed = false;
    hub.intercept((call) => {
      if (failed || !isCall("POST", TOKEN_EXCHANGE)(call)) return undefined;
      failed = true;
      return failing(503);
    });
    await Promise.allSettled([callOnce(), callOnce()]);

    await expect(callOnce()).resolves.toEqual([]);
    expect(hub.exchanges()).toHaveLength(2);
  });
});

describe("a 401 on a cached JWT", () => {
  it("drops the JWT, exchanges the token again, and retries the call", async () => {
    hub.invites.push({ id: "invite-1", invitee: EMAIL, role: "editor" });
    await callOnce();

    hub.revokeJwts();
    await expect(callOnce()).resolves.toEqual([
      { id: "invite-1", invitee: EMAIL, role: "editor" },
    ]);

    expect(hub.calls.map(({ method, path }) => `${method} ${path}`)).toEqual([
      `POST ${TOKEN_EXCHANGE}`,
      `GET ${INVITES}`,
      `GET ${INVITES}`,
      `POST ${TOKEN_EXCHANGE}`,
      `GET ${INVITES}`,
    ]);
    expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[0], hub.jwts[1]]);
    expect(logs.info).toHaveBeenCalledWith(
      "Docker Hub refused the cached JWT; exchanging the token again"
    );
  });

  it("leaves the new JWT cached for the calls that follow", async () => {
    await callOnce();
    hub.revokeJwts();
    await callOnce();

    await callOnce();

    expect(hub.exchanges()).toHaveLength(2);
    expect(hub.bearers().at(-1)).toBe(hub.jwts[1]);
  });

  it("retries once, and no more", async () => {
    await callOnce();
    hub.intercept((call) =>
      isCall("GET", INVITES)(call) ? failing(401, "unauthorized") : undefined
    );

    const error = await thrown(callOnce);

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({ status: 401 });
    // The cached JWT, then the fresh one.
    expect(hub.bearers()).toEqual([hub.jwts[0], hub.jwts[0], hub.jwts[1]]);
  });

  it.each([403, 404, 500])("doesn't retry a %s", async (status) => {
    await callOnce();
    hub.intercept((call) =>
      isCall("GET", INVITES)(call) ? failing(status, "no") : undefined
    );

    await expect(callOnce()).rejects.toMatchObject({ status });

    expect(hub.exchanges()).toHaveLength(1);
    expect(hub.apiCalls()).toHaveLength(2);
  });
});

describe("a 401 on a JWT just exchanged", () => {
  // A fresh JWT that's refused won't be cured by another.
  it("isn't retried", async () => {
    hub.intercept((call) =>
      isCall("GET", INVITES)(call) ? failing(401, "unauthorized") : undefined
    );

    await expect(callOnce()).rejects.toMatchObject({ status: 401 });

    expect(hub.exchanges()).toHaveLength(1);
    expect(hub.apiCalls()).toHaveLength(1);
  });
});

describe("a token exchange that fails", () => {
  it.each([400, 401, 403])(
    "is a rejected token on a %s, and no request follows",
    async (status) => {
      hub.intercept((call) =>
        isCall("POST", TOKEN_EXCHANGE)(call) ? failing(status, "no") : undefined
      );

      const error = await thrown(callOnce);

      expect(error).toBeInstanceOf(TokenRejectedError);
      expect(error).toMatchObject({ status });
      expect(hub.apiCalls()).toEqual([]);
    }
  );

  it("is a rejected token when Docker Hub doesn't know it", async () => {
    getOrgAccessToken.mockResolvedValue({
      token: "dckr_oat_revoked",
      version,
    });

    await expect(callOnce()).rejects.toBeInstanceOf(TokenRejectedError);
  });

  it.each([429, 500])("is thrown as it is on a %s", async (status) => {
    hub.intercept((call) =>
      isCall("POST", TOKEN_EXCHANGE)(call) ? failing(status) : undefined
    );

    const error = await thrown(callOnce);

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({ status });
  });

  it("is tried again by the next call", async () => {
    getOrgAccessToken.mockResolvedValueOnce({
      token: "dckr_oat_revoked",
      version,
    });
    await expect(callOnce()).rejects.toBeInstanceOf(TokenRejectedError);

    await expect(callOnce()).resolves.toEqual([]);
    expect(hub.exchanges()).toHaveLength(2);
  });

  // `fetch` wouldn't send such a JWT, and its error for that would quote it.
  it.each(UNFIT_JWTS)(
    "is refused on a JWT with %s, which is never sent, repeated or kept",
    async (_case, unfit) => {
      // The first exchange answers the unfit JWT, and the next a good one.
      const issued = (n: number) =>
        jwtExpiringAt(Date.now() + JWT_LIFETIME_MS, n);
      hub = newFakeDockerHub({
        org: "acme",
        token: TOKEN,
        jwt: (n) => (n === 1 ? unfit(issued(n)) : issued(n)),
      });
      vi.stubGlobal("fetch", hub.fetch);

      const error = await thrown(callOnce);

      expect(error).toMatchObject({ data: { type: "unknown" } });
      expect(hub.apiCalls()).toEqual([]);
      // No part of it is in the error or in a log line.
      const said = inspect(
        [
          error,
          logs.info.mock.calls,
          logs.warn.mock.calls,
          logs.error.mock.calls,
        ],
        { depth: null, showHidden: true }
      );
      for (const part of issued(1).split(".")) {
        expect(said).not.toContain(part);
      }

      await expect(callOnce()).resolves.toEqual([]);
      expect(hub.exchanges()).toHaveLength(2);
      expect(hub.bearers()).toEqual([hub.jwts[1]]);
    }
  );
});

describe("isTokenAccepted", () => {
  it("is true when Docker Hub exchanges the token", async () => {
    await expect(newClient().isTokenAccepted()).resolves.toBe(true);
    expect(hub.exchanges()).toHaveLength(1);
  });

  // A cached JWT says the token worked some minutes ago.
  it("exchanges the token even when a JWT is cached", async () => {
    await callOnce();

    await expect(newClient().isTokenAccepted()).resolves.toBe(true);

    expect(hub.exchanges()).toHaveLength(2);
  });

  it("leaves its JWT for the requests that follow", async () => {
    const client = newClient();
    await client.isTokenAccepted();

    await client.findInvites(EMAIL);

    expect(hub.exchanges()).toHaveLength(1);
  });

  it("is false when Docker Hub refuses the token", async () => {
    getOrgAccessToken.mockResolvedValue({
      token: "dckr_oat_revoked",
      version,
    });

    await expect(newClient().isTokenAccepted()).resolves.toBe(false);
  });

  it("fails when Docker Hub can't say", async () => {
    hub.intercept((call) =>
      isCall("POST", TOKEN_EXCHANGE)(call) ? failing(503) : undefined
    );

    await expect(newClient().isTokenAccepted()).rejects.toMatchObject({
      status: 503,
    });
  });
});

describe("readOneMember", () => {
  it("asks for one member, and no more", async () => {
    hub.members.push(ALICE);

    await expect(newClient().readOneMember()).resolves.toBeUndefined();

    expect(hub.apiCalls().map(({ path, query }) => ({ path, query }))).toEqual([
      { path: "/v2/orgs/acme/members", query: { page: "1", page_size: "1" } },
    ]);
  });
});

describe("findMembersByEmail", () => {
  it("searches for the email, a full page at a time", async () => {
    hub.members.push(ALICE);

    await expect(newClient().findMembersByEmail(EMAIL)).resolves.toEqual([
      { username: "alice", uuid: UUID, email: EMAIL, role: "member" },
    ]);

    expect(hub.apiCalls().map(({ path, query }) => ({ path, query }))).toEqual([
      {
        path: "/v2/orgs/acme/members",
        query: { search: EMAIL, page: "1", page_size: "100" },
      },
    ]);
  });

  // The search also finds what only resembles the email.
  it("keeps only the members whose email is the email", async () => {
    hub.members.push(
      { ...ALICE, username: "malice", uuid: "u-1", email: "malice@acme.com" },
      {
        ...ALICE,
        username: "alice-evil",
        uuid: "u-2",
        email: "alice@acme.com.evil.com",
      },
      ALICE
    );

    const members = await newClient().findMembersByEmail(EMAIL);

    expect(members.map(({ username }) => username)).toEqual(["alice"]);
  });

  it("matches the email ignoring case", async () => {
    hub.members.push({ ...ALICE, email: "Alice@ACME.com" });

    const members = await newClient().findMembersByEmail("ALICE@acme.com");

    expect(members.map(({ username }) => username)).toEqual(["alice"]);
  });

  // Docker Hub shows no email for some members.
  it("passes over a member with no email", async () => {
    hub.intercept((call) =>
      isCall("GET", "/v2/orgs/acme/members")(call)
        ? {
            status: 200,
            body: {
              next: null,
              results: [
                { username: "alice-bot", uuid: "u-1", role: "Member" },
                { username: "alice", uuid: UUID, email: EMAIL, role: "Member" },
              ],
            },
          }
        : undefined
    );

    const members = await newClient().findMembersByEmail(EMAIL);

    expect(members.map(({ username }) => username)).toEqual(["alice"]);
  });

  // Which one P0 means is the caller's to refuse.
  it("returns every member with the email", async () => {
    hub.members.push(ALICE, { ...ALICE, username: "alice2", uuid: "u-2" });

    const members = await newClient().findMembersByEmail(EMAIL);

    expect(members.map(({ username }) => username)).toEqual([
      "alice",
      "alice2",
    ]);
  });

  describe("across pages", () => {
    const pagesAsked = () => hub.apiCalls().map(({ query }) => query.page);

    beforeEach(() => {
      hub = newFakeDockerHub({ org: "acme", token: TOKEN, maxPageSize: 2 });
      vi.stubGlobal("fetch", hub.fetch);
      // Four near misses, then the member, on the third page.
      for (const n of [1, 2, 3, 4]) {
        hub.members.push({
          username: `near-${n}`,
          uuid: `u-${n}`,
          email: `${n}.${EMAIL}`,
          role: "member",
        });
      }
      hub.members.push(ALICE);
    });

    it("asks for the next page until Docker Hub gives no `next`", async () => {
      const members = await newClient().findMembersByEmail(EMAIL);

      expect(members.map(({ username }) => username)).toEqual(["alice"]);
      expect(pagesAsked()).toEqual(["1", "2", "3"]);
    });

    // The JWT only ever goes to a URL the connector built.
    it("asks by page number, not at the link Docker Hub gave", async () => {
      hub.intercept((call) =>
        call.query.page === "1"
          ? {
              status: 200,
              body: {
                next: "https://hub.docker.example/steal?page=2",
                results: [
                  {
                    username: "near-1",
                    uuid: "u-1",
                    email: `1.${EMAIL}`,
                    role: "Member",
                  },
                ],
              },
            }
          : undefined
      );

      await newClient().findMembersByEmail(EMAIL);

      expect(pagesAsked()).toEqual(["1", "2", "3"]);
      for (const { url } of hub.calls) {
        expect(url.startsWith("https://hub.docker.com/v2/")).toBe(true);
      }
    });

    // A `next` that never ends still runs out of members.
    it("stops at an empty page, whatever `next` says", async () => {
      hub.intercept((call) =>
        isCall("GET", "/v2/orgs/acme/members")(call)
          ? {
              status: 200,
              body: {
                next: "https://hub.docker.com/v2/orgs/acme/members?page=2",
                results: [],
              },
            }
          : undefined
      );

      await expect(newClient().findMembersByEmail(EMAIL)).resolves.toEqual([]);
      expect(pagesAsked()).toEqual(["1"]);
    });
  });
});

describe("findMemberByUsername", () => {
  it("searches for the username, and returns that member", async () => {
    hub.members.push(ALICE);

    await expect(newClient().findMemberByUsername("alice")).resolves.toEqual({
      username: "alice",
      uuid: UUID,
      email: EMAIL,
      role: "member",
    });
    expect(hub.apiCalls()[0]?.query).toEqual({
      search: "alice",
      page: "1",
      page_size: "100",
    });
  });

  // The search matches a username's prefix too.
  it("isn't a member whose username only starts the same", async () => {
    hub.members.push({ ...ALICE, username: "alice2" });

    await expect(newClient().findMemberByUsername("alice")).resolves.toBeNull();
  });
});

describe("findInvites", () => {
  it("returns the pending invites to the email, ignoring case", async () => {
    hub.invites.push(
      { id: "invite-1", invitee: "bob@acme.com", role: "member" },
      { id: "invite-2", invitee: "Alice@Acme.com", role: "editor" },
      // An admin invited this one by Docker ID.
      { id: "invite-3", invitee: "alice", role: "owner" }
    );

    await expect(newClient().findInvites(EMAIL)).resolves.toEqual([
      { id: "invite-2", invitee: "Alice@Acme.com", role: "editor" },
    ]);
  });
});

describe("changes", () => {
  it("setRole PUTs the role on the member", async () => {
    hub.members.push({ ...ALICE });

    await newClient().setRole({ username: "alice", role: "editor" });

    expect(hub.writes()).toEqual([
      {
        method: "PUT",
        path: "/v2/orgs/acme/members/alice",
        body: { role: "editor" },
      },
    ]);
    expect(hub.members[0]?.role).toBe("editor");
  });

  it("removeMember DELETEs the member", async () => {
    hub.members.push({ ...ALICE });

    await newClient().removeMember("alice");

    expect(hub.writes()).toEqual([
      {
        method: "DELETE",
        path: "/v2/orgs/acme/members/alice",
        body: undefined,
      },
    ]);
    expect(hub.members).toEqual([]);
  });

  it("invite sends one invite, and says what Docker Hub did with it", async () => {
    await expect(
      newClient().invite({ email: EMAIL, role: "editor" })
    ).resolves.toEqual({ status: "invited" });

    expect(hub.writes()).toEqual([
      {
        method: "POST",
        path: "/v2/invites/bulk",
        body: { org: "acme", role: "editor", invitees: [EMAIL] },
      },
    ]);
    expect(hub.invites).toEqual([
      { id: "invite-1", invitee: EMAIL, role: "editor" },
    ]);
  });

  it("cancelInvite DELETEs the invite", async () => {
    hub.invites.push({ id: "invite-1", invitee: EMAIL, role: "editor" });

    await newClient().cancelInvite("invite-1");

    expect(hub.writes()).toEqual([
      { method: "DELETE", path: "/v2/invites/invite-1", body: undefined },
    ]);
    expect(hub.invites).toEqual([]);
  });

  it("dryRunInvite validates an invite without sending it", async () => {
    await expect(
      newClient().dryRunInvite({ email: "nobody@example.com", role: "member" })
    ).resolves.toBeUndefined();

    expect(hub.writes()[0]?.body).toEqual({
      org: "acme",
      role: "member",
      invitees: ["nobody@example.com"],
      dry_run: true,
    });
    expect(hub.invites).toEqual([]);
  });

  // Only whether Docker Hub took the call matters to a dry run.
  it("dryRunInvite takes any 2xx, whatever the body", async () => {
    hub.intercept((call) =>
      isCall("POST", "/v2/invites/bulk")(call) ? { status: 200 } : undefined
    );

    await expect(
      newClient().dryRunInvite({ email: "nobody@example.com", role: "member" })
    ).resolves.toBeUndefined();
  });
});

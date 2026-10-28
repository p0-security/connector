import { ConnectorError } from "@p0security/connector-core";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EMAIL, TOKEN, UUID } from "../../__tests__/fixtures.ts";
import {
  UNFIT_JWTS,
  newRecordingLogger,
  thrown,
} from "../../__tests__/helpers.ts";
import {
  DockerHubError,
  deleteInvite,
  deleteMember,
  exchangeToken,
  listInvites,
  listMembers,
  postDryRunInvite,
  postInvite,
  putMemberRole,
  readInviteResult,
} from "../api.ts";

// Stub the global `fetch` so no real network call is made.
const mockedFetch = vi.fn<typeof fetch>();
vi.stubGlobal("fetch", mockedFetch);

const respond = (
  status: number,
  body?: unknown,
  headers: Record<string, string> = {}
) =>
  mockedFetch.mockResolvedValueOnce(
    new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers }
    )
  );

const JWT = "eyJhbGciOiJSUzI1NiJ9.SENTINELb2d4e6.c2ln";
/** The marker in `JWT`, which a leak check still finds in a JWT cut in two. */
const [, JWT_MARKER = JWT] = JWT.split(".");

const MEMBER = {
  id: UUID.replaceAll("-", ""),
  uuid: UUID,
  username: "alice",
  full_name: "Alice",
  email: EMAIL,
  role: "Editor",
  groups: ["owners"],
  is_guest: false,
  type: "User",
  assigned_role: {
    id: "role-editor",
    name: "editor",
    label: "Editor",
    description: "",
    is_system: true,
  },
};

let logs: ReturnType<typeof newRecordingLogger>;
/** What every call to the org's API carries. */
let call: { log: (typeof logs)["log"]; jwt: string; org: string };

const sentHeaders = () =>
  Object.fromEntries(new Headers(mockedFetch.mock.calls[0]?.[1]?.headers));

beforeEach(() => {
  mockedFetch.mockReset();
  logs = newRecordingLogger();
  call = { log: logs.log, jwt: JWT, org: "acme" };
});

describe("exchangeToken", () => {
  const exchange = () =>
    exchangeToken({ log: logs.log, org: "acme", token: TOKEN });

  it("POSTs the org and the token, and returns the JWT", async () => {
    respond(200, { access_token: JWT });

    await expect(exchange()).resolves.toBe(JWT);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/auth/token",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ identifier: "acme", secret: TOKEN }),
      })
    );
    // There's no JWT yet to send.
    expect(sentHeaders()).not.toHaveProperty("authorization");
  });

  // A 307 or 308 would resend the body, and the token with it.
  it("tells fetch to fail on a redirect rather than follow it", async () => {
    respond(200, { access_token: JWT });

    await exchange();

    expect(mockedFetch.mock.calls[0]?.[1]?.redirect).toBe("error");
  });

  // Nothing promises Docker Hub's text never quotes the request.
  it("drops Docker Hub's own text when the exchange fails", async () => {
    respond(401, { message: `no such secret: ${TOKEN}`, detail: TOKEN });

    const error = await thrown(exchange);

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({ status: 401, dockerMessages: [] });
    expect(inspect(error, { depth: null })).not.toContain(TOKEN);
    expect(inspect(logs.warn.mock.calls, { depth: null })).not.toContain(TOKEN);
  });

  it.each([
    ["no JWT", {}],
    ["an empty JWT", { access_token: "" }],
    ["a JWT that isn't a string", { access_token: [JWT] }],
    ["no body", undefined],
  ])("fails as unknown on an answer with %s", async (_case, body) => {
    respond(200, body);

    const error = await thrown(exchange);

    expect(error).toMatchObject({
      data: {
        type: "unknown",
        message:
          "Docker Hub returned the token exchange's response in a shape the connector doesn't recognize.",
      },
    });
    // What Docker Hub did send is never repeated, in the error or the log.
    expect(inspect(error, { depth: null })).not.toContain(JWT);
    expect(inspect(logs.warn.mock.calls, { depth: null })).not.toContain(JWT);
  });

  // `fetch` won't send such a JWT, and its error for that quotes the whole
  // Authorization header. So the answer is refused here, wherever in the JWT
  // the character is.
  it.each(UNFIT_JWTS)(
    "fails as unknown on a JWT with %s, without repeating it",
    async (_case, unfit) => {
      respond(200, { access_token: unfit(JWT) });

      const error = await thrown(exchange);

      expect(error).toMatchObject({ data: { type: "unknown" } });
      expect(inspect(error, { depth: null, showHidden: true })).not.toContain(
        JWT_MARKER
      );
      for (const logged of [logs.info, logs.warn, logs.error]) {
        expect(inspect(logged.mock.calls, { depth: null })).not.toContain(
          JWT_MARKER
        );
      }
    }
  );

  it("takes a JWT in either base64 alphabet, padded or not", async () => {
    const jwt = "eyJhbGciOiJSUzI1NiJ9.a-b_c+d/e==.c2ln";
    respond(200, { access_token: jwt });

    await expect(exchange()).resolves.toBe(jwt);
  });
});

// What a request carries besides its body, whichever call sends it.
describe("a request", () => {
  it("asks for JSON", async () => {
    respond(200, { data: [] });

    await listInvites(call);

    expect(sentHeaders().accept).toBe("application/json");
  });

  it.each([
    [
      "a role",
      () => putMemberRole({ ...call, username: "alice", role: "editor" }),
    ],
    ["an invite", () => postInvite({ ...call, email: EMAIL, role: "editor" })],
  ])("says its body is JSON when it sends %s", async (_case, send) => {
    respond(202, { invitees: [{ invitee: EMAIL, status: "invited" }] });

    await send();

    expect(sentHeaders()["content-type"]).toBe("application/json");
  });

  it.each([
    ["a read", () => listInvites(call)],
    ["a removal", () => deleteMember({ ...call, username: "alice" })],
  ])("names no content type for %s, which has no body", async (_case, send) => {
    respond(200, { data: [] });

    await send();

    expect(sentHeaders()).not.toHaveProperty("content-type");
  });

  // Only the token exchange's body holds something a redirect could resend.
  it("lets fetch follow a redirect when it carries the JWT", async () => {
    respond(200, { data: [] });

    await listInvites(call);

    expect(mockedFetch.mock.calls[0]?.[1]?.redirect).toBe("follow");
  });
});

describe("listMembers", () => {
  it("GETs one page of the search with the JWT, and reads the members", async () => {
    respond(200, { count: 1, next: null, previous: null, results: [MEMBER] });

    await expect(
      listMembers({ ...call, search: EMAIL, page: 1, pageSize: 100 })
    ).resolves.toEqual({
      members: [
        { username: "alice", uuid: UUID, email: EMAIL, role: "editor" },
      ],
      hasNext: false,
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/orgs/acme/members?search=alice%40acme.com&page=1&page_size=100",
      expect.objectContaining({ method: "GET" })
    );
    expect(sentHeaders().authorization).toBe(`Bearer ${JWT}`);
  });

  // An unencoded `+` is a space, and `&` would start another parameter.
  it("encodes the search term", async () => {
    respond(200, { next: null, results: [] });

    await listMembers({
      ...call,
      search: "al+ice&page=9@acme.com",
      page: 2,
      pageSize: 100,
    });

    expect(mockedFetch.mock.calls[0]?.[0]).toBe(
      "https://hub.docker.com/v2/orgs/acme/members?search=al%2Bice%26page%3D9%40acme.com&page=2&page_size=100"
    );
  });

  it("leaves the search out when there's none", async () => {
    respond(200, { next: null, results: [] });

    await listMembers({ ...call, page: 1, pageSize: 1 });

    expect(mockedFetch.mock.calls[0]?.[0]).toBe(
      "https://hub.docker.com/v2/orgs/acme/members?page=1&page_size=1"
    );
  });

  it("says whether Docker Hub gave a next page", async () => {
    respond(200, {
      next: "https://hub.docker.com/v2/orgs/acme/members?page=2&page_size=100",
      results: [MEMBER],
    });

    await expect(
      listMembers({ ...call, page: 1, pageSize: 100 })
    ).resolves.toMatchObject({ hasNext: true });
  });

  // `PUT` takes a core role lower-case, and that's the form P0 records.
  it.each(["Owner", "Editor", "Member"])(
    "reads the %s role lower-case",
    async (role) => {
      respond(200, {
        next: null,
        results: [{ ...MEMBER, role, assigned_role: undefined }],
      });

      const { members } = await listMembers({
        ...call,
        page: 1,
        pageSize: 100,
      });

      expect(members[0]?.role).toBe(role.toLowerCase());
    }
  );

  // `role` only ever names a core role. This is how P0 recognises a
  // custom-role holder, and refuses their request.
  it("reads a custom role by its name, from assigned_role", async () => {
    respond(200, {
      next: null,
      results: [
        {
          ...MEMBER,
          role: "Member",
          assigned_role: {
            id: "role-1",
            name: "release-manager",
            label: "Release Manager",
            is_system: false,
          },
        },
      ],
    });

    const { members } = await listMembers({ ...call, page: 1, pageSize: 100 });

    expect(members[0]?.role).toBe("release-manager");
  });

  // Such a member never matches an email.
  it.each([
    ["missing", undefined],
    ["null", null],
  ])("reads a member whose email is %s", async (_case, email) => {
    respond(200, { next: null, results: [{ ...MEMBER, email }] });

    const { members } = await listMembers({ ...call, page: 1, pageSize: 100 });

    expect(members[0]).toMatchObject({ username: "alice", email: undefined });
  });

  it.each([
    ["no results", { next: null }],
    ["a member without a uuid", { results: [{ ...MEMBER, uuid: undefined }] }],
    ["a page that isn't JSON", "<html>Docker Hub</html>"],
  ])("fails as unknown on %s", async (_case, body) => {
    respond(200, body);

    const error = await thrown(() =>
      listMembers({ ...call, page: 1, pageSize: 100 })
    );

    expect(error).toMatchObject({
      data: {
        type: "unknown",
        message:
          "Docker Hub returned a page of org members in a shape the connector doesn't recognize.",
        payload: { what: "a page of org members" },
      },
    });
  });
});

describe("putMemberRole", () => {
  it("PUTs the role on the member", async () => {
    respond(200, MEMBER);

    await putMemberRole({ ...call, username: "alice", role: "editor" });

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/orgs/acme/members/alice",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ role: "editor" }),
      })
    );
    expect(sentHeaders().authorization).toBe(`Bearer ${JWT}`);
  });
});

describe("deleteMember", () => {
  it("DELETEs the member, and accepts an empty 204", async () => {
    respond(204);

    await expect(
      deleteMember({ ...call, username: "alice" })
    ).resolves.toBeUndefined();
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/orgs/acme/members/alice",
      expect.objectContaining({ method: "DELETE" })
    );
  });
});

describe("listInvites", () => {
  it("GETs the org's pending invites, with each role lower-case", async () => {
    respond(200, {
      data: [
        {
          id: "e36eca69-4cc8-4f17-9845-ae8c2b832691",
          invitee: EMAIL,
          inviter_username: "acme-oat",
          org: "acme",
          team: "",
          role: "Editor",
          created_at: "2026-10-12T09:00:00Z",
        },
      ],
    });

    await expect(listInvites(call)).resolves.toEqual([
      {
        id: "e36eca69-4cc8-4f17-9845-ae8c2b832691",
        invitee: EMAIL,
        role: "editor",
      },
    ]);
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/orgs/acme/invites",
      expect.objectContaining({ method: "GET" })
    );
  });

  // A grant compares the role, so an invite without one can't be read.
  it.each([
    ["the list", { results: [] }],
    ["an invite's role", { data: [{ id: "invite-1", invitee: EMAIL }] }],
  ])("fails as unknown on an answer without %s", async (_case, body) => {
    respond(200, body);

    await expect(listInvites(call)).rejects.toMatchObject({
      data: { type: "unknown", payload: { what: "the org's invites" } },
    });
  });
});

const INVITE = { email: EMAIL, role: "editor" } as const;

describe("postInvite", () => {
  it("POSTs one invitee with the role, and says what Docker Hub did with it", async () => {
    respond(202, { invitees: [{ invitee: EMAIL, status: "invited" }] });

    await expect(postInvite({ ...call, ...INVITE })).resolves.toEqual({
      status: "invited",
    });
    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/invites/bulk",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          org: "acme",
          role: "editor",
          invitees: [EMAIL],
        }),
      })
    );
    expect(sentHeaders().authorization).toBe(`Bearer ${JWT}`);
  });
});

describe("postDryRunInvite", () => {
  it("marks a dry run as one", async () => {
    respond(202);

    await postDryRunInvite({ ...call, ...INVITE });

    expect(mockedFetch.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({
        org: "acme",
        role: "editor",
        invitees: [EMAIL],
        dry_run: true,
      })
    );
  });
});

describe("readInviteResult", () => {
  const result = (invitees: unknown) =>
    readInviteResult(logs.log, { invitees });

  it.each(["invited", "existing_org_member"] as const)(
    "reads the %s status",
    (status) => {
      expect(result([{ invitee: EMAIL, status }])).toEqual({ status });
    }
  );

  it("reads any other status as a refusal, with the status as its reason", () => {
    expect(
      result([{ invitee: EMAIL, status: "invalid_email_or_docker_id" }])
    ).toEqual({ status: "refused", reason: "invalid_email_or_docker_id" });
  });

  // Docker Hub may echo a Docker ID where the email was sent.
  it("reads the reply's entry, whoever it names", () => {
    expect(result([{ invitee: "alice", status: "invited" }])).toEqual({
      status: "invited",
    });
  });

  // Without one, there's no telling whether the invite went out.
  it.each([
    ["no entry", { invitees: [] }],
    ["an entry without a status", { invitees: [{ invitee: EMAIL }] }],
    ["no list", {}],
  ])("fails as unknown on a reply with %s", (_case, reply) => {
    expect(() => readInviteResult(logs.log, reply)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({
          type: "unknown",
          payload: { what: "the invite's result" },
        }),
      })
    );
  });
});

describe("deleteInvite", () => {
  it("DELETEs the invite by id", async () => {
    respond(204);

    await deleteInvite({
      log: logs.log,
      jwt: JWT,
      id: "e36eca69-4cc8-4f17-9845-ae8c2b832691",
    });

    expect(mockedFetch).toHaveBeenCalledWith(
      "https://hub.docker.com/v2/invites/e36eca69-4cc8-4f17-9845-ae8c2b832691",
      expect.objectContaining({ method: "DELETE" })
    );
    expect(sentHeaders().authorization).toBe(`Bearer ${JWT}`);
  });
});

// A username comes from Docker Hub or from P0's record of it, and an invite
// id from Docker Hub. Neither may change which URL a call reaches.
describe("path segments", () => {
  it.each(["..", ".", ""])(
    "refuses %j as a username, without calling Docker Hub",
    async (username) => {
      const error = await thrown(() =>
        putMemberRole({ ...call, username, role: "editor" })
      );

      expect(error).toMatchObject({
        data: {
          type: "validation_error",
          message: `"${username}" isn't a valid Docker Hub name.`,
        },
      });
      expect(mockedFetch).not.toHaveBeenCalled();
    }
  );

  it("refuses a dot segment as an invite id", async () => {
    await expect(
      deleteInvite({ log: logs.log, jwt: JWT, id: ".." })
    ).rejects.toBeInstanceOf(ConnectorError);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("says which name it refused", async () => {
    const error = await thrown(() =>
      deleteInvite({ log: logs.log, jwt: JWT, id: ".." })
    );

    expect(error).toMatchObject({ data: { payload: { segment: ".." } } });
  });

  it("encodes anything else", async () => {
    respond(204);
    respond(204);

    await deleteMember({ ...call, username: "a/b?c#d" });
    await deleteInvite({
      log: logs.log,
      jwt: JWT,
      id: "../orgs/acme/members/alice",
    });

    expect(mockedFetch.mock.calls.map(([url]) => url)).toEqual([
      "https://hub.docker.com/v2/orgs/acme/members/a%2Fb%3Fc%23d",
      "https://hub.docker.com/v2/invites/..%2Forgs%2Facme%2Fmembers%2Falice",
    ]);
  });
});

describe("errors", () => {
  it("carries the status and Docker Hub's messages, but not the JWT", async () => {
    respond(400, { message: "bad request", errinfo: { role: "nope" } });

    const error = await thrown(() =>
      putMemberRole({ ...call, username: "alice", role: "editor" })
    );

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({
      name: "DockerHubError",
      status: 400,
      dockerMessages: ["bad request"],
      message:
        "Docker Hub PUT /v2/orgs/acme/members/alice failed (400): bad request",
    });
    expect(inspect(error, { depth: null, showHidden: true })).not.toContain(
      JWT
    );
  });

  // A refusal's text is quoted to the requestor.
  it("cuts the JWT out of a message that quotes the request back", async () => {
    respond(400, {
      message: `bad header "Authorization: Bearer ${JWT}"`,
      detail: `token ${JWT} is not valid here`,
    });

    const error = await thrown(() =>
      putMemberRole({ ...call, username: "alice", role: "editor" })
    );

    expect(error).toMatchObject({
      dockerMessages: [
        'bad header "Authorization: [redacted]"',
        "token [redacted] is not valid here",
      ],
    });
    expect(inspect(error, { depth: null, showHidden: true })).not.toContain(
      JWT
    );
  });

  it("cuts out every copy of the JWT, with its Bearer prefix or without", async () => {
    respond(400, {
      message: `got "Bearer ${JWT}", then ${JWT} and ${JWT} again`,
    });

    const error = await thrown(() => listInvites(call));

    expect(error).toMatchObject({
      dockerMessages: [
        'got "[redacted]", then [redacted] and [redacted] again',
      ],
    });
  });

  it("reads a `detail` as a message too", async () => {
    respond(403, { detail: "You do not have permission." });

    await expect(listInvites(call)).rejects.toMatchObject({
      status: 403,
      dockerMessages: ["You do not have permission."],
    });
  });

  it("carries Retry-After on a 429", async () => {
    respond(429, { message: "too many requests" }, { "Retry-After": "30" });

    await expect(listInvites(call)).rejects.toMatchObject({
      status: 429,
      retryAfter: "30",
    });
  });

  it("has no message for a body that isn't Docker Hub's", async () => {
    respond(502, "<html>Bad Gateway</html>");

    await expect(listInvites(call)).rejects.toMatchObject({
      status: 502,
      dockerMessages: [],
      message: "Docker Hub GET /v2/orgs/acme/invites failed (502): no message",
    });
  });

  it("logs a refusal with the request's own logger, without the JWT", async () => {
    respond(403, { message: "permission denied" });

    await thrown(() => listInvites(call));

    expect(logs.warn).toHaveBeenCalledWith(
      {
        method: "GET",
        path: "/v2/orgs/acme/invites",
        status: 403,
        dockerMessages: ["permission denied"],
        retryAfter: undefined,
      },
      "Docker Hub request returned a non-2xx response"
    );
    expect(inspect(logs.warn.mock.calls, { depth: null })).not.toContain(JWT);
  });
});

describe("a call Docker Hub doesn't answer", () => {
  it("has no status when the request fails", async () => {
    const failure = new TypeError("fetch failed");
    mockedFetch.mockRejectedValueOnce(failure);

    const error = await thrown(() => listInvites(call));

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({
      status: undefined,
      dockerMessages: ["fetch failed"],
    });
    // As text, never the error itself: its stack repeats its message.
    expect(logs.error).toHaveBeenCalledWith(
      {
        method: "GET",
        path: "/v2/orgs/acme/invites",
        failure: ["TypeError: fetch failed"],
      },
      "Docker Hub request failed"
    );
  });

  it("names no status in its message", async () => {
    mockedFetch.mockRejectedValueOnce(new TypeError("fetch failed"));

    await expect(listInvites(call)).rejects.toMatchObject({
      message: "Docker Hub GET /v2/orgs/acme/invites failed: fetch failed",
    });
  });

  // `fetch` keeps the network's own reason in the cause.
  it("logs the failure's causes too", async () => {
    mockedFetch.mockRejectedValueOnce(
      new TypeError("fetch failed", {
        cause: new Error("connect ECONNREFUSED 3.224.227.198:443"),
      })
    );

    await thrown(() => listInvites(call));

    expect(logs.error).toHaveBeenCalledWith(
      expect.objectContaining({
        failure: [
          "TypeError: fetch failed",
          "Error: connect ECONNREFUSED 3.224.227.198:443",
        ],
      }),
      "Docker Hub request failed"
    );
  });

  it("logs the failure and four causes under it, and no more", async () => {
    let failure = new Error("level 7");
    for (const level of [6, 5, 4, 3, 2, 1, 0]) {
      failure = new Error(`level ${level}`, { cause: failure });
    }
    mockedFetch.mockRejectedValueOnce(failure);

    await thrown(() => listInvites(call));

    expect(logs.error).toHaveBeenCalledWith(
      expect.objectContaining({
        failure: [
          "Error: level 0",
          "Error: level 1",
          "Error: level 2",
          "Error: level 3",
          "Error: level 4",
        ],
      }),
      "Docker Hub request failed"
    );
  });

  // Nothing stops an error naming itself as its cause.
  it("logs a bounded list when a failure is its own cause", async () => {
    const failure = new TypeError("fetch failed");
    failure.cause = failure;
    mockedFetch.mockRejectedValueOnce(failure);

    const error = await thrown(() => listInvites(call));

    expect(error).toBeInstanceOf(DockerHubError);
    expect(logs.error).toHaveBeenCalledWith(
      expect.objectContaining({
        failure: new Array<string>(5).fill("TypeError: fetch failed"),
      }),
      "Docker Hub request failed"
    );
  });

  // `fetch` quotes a header value it won't send.
  it.each([
    [
      "its message",
      () =>
        new TypeError(
          `Headers.append: "Bearer ${JWT}" is an invalid header value.`
        ),
      'Headers.append: "[redacted]" is an invalid header value.',
    ],
    [
      "its cause",
      () =>
        new TypeError("fetch failed", {
          cause: new Error(`"Bearer ${JWT}" is an invalid header value.`),
        }),
      "fetch failed",
    ],
  ])(
    "keeps the JWT out of the error and the log when the failure quotes it in %s",
    async (_case, failure, message) => {
      mockedFetch.mockRejectedValueOnce(failure());

      const error = await thrown(() => listInvites(call));

      expect(error).toMatchObject({
        status: undefined,
        dockerMessages: [message],
      });
      expect(inspect(error, { depth: null, showHidden: true })).not.toContain(
        JWT
      );
      expect(logs.error).toHaveBeenCalledTimes(1);
      expect(
        inspect(logs.error.mock.calls, { depth: null, showHidden: true })
      ).not.toContain(JWT);
    }
  );

  // The headers arrived, and then the connection dropped.
  it("has no status when the body fails mid-stream", async () => {
    const body = new ReadableStream<Uint8Array>({
      start: (controller) => {
        controller.enqueue(new TextEncoder().encode('{"data": ['));
        controller.error(new TypeError("terminated"));
      },
    });
    mockedFetch.mockResolvedValueOnce(new Response(body, { status: 200 }));

    const error = await thrown(() => listInvites(call));

    expect(error).toBeInstanceOf(DockerHubError);
    expect(error).toMatchObject({
      status: undefined,
      dockerMessages: ["terminated"],
    });
  });
});

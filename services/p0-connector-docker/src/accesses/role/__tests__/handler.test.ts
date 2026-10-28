import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeDockerHub,
  type HubCall,
  type HubReply,
  failing,
  isCall,
  newFakeDockerHub,
} from "../../../__tests__/fake-docker-hub.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  TOKEN,
  UUID,
} from "../../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
} from "../../../__tests__/helpers.ts";
import type { CoreRole } from "../definition.ts";
import { newRolePrimitives } from "../handler.ts";

/**
 * The primitives, against a Docker Hub that remembers: an org's members and
 * invites behind a stubbed `fetch`, so a second run of a call meets what the
 * first one left.
 */

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getOrgAccessToken = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ getOrgAccessToken }));

// Read when the first email is checked, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

// A domain the pattern doesn't allow.
const OUTSIDER = "mallory@evil.com";

type RoleContext = Parameters<
  ReturnType<typeof newRolePrimitives>["setPoliciesForUser"]
>[0];

/** Alice, already in the org as a member when she asked. */
const STANDING = {
  username: "alice",
  uuid: UUID,
  priorRole: "member",
} as const;

const MEMBER: RoleContext = {
  ...CREDENTIALS,
  requestId: "req-1",
  standingMember: STANDING,
  grantCompleted: false,
};

// Someone P0 invites has no standing member.
const INVITED: RoleContext = { ...MEMBER, standingMember: null };

/** The same request, once P0 has finished granting it. */
const granted = (context: RoleContext): RoleContext => ({
  ...context,
  grantCompleted: true,
});

const alice = (role = "member") => ({
  username: "alice",
  uuid: UUID,
  email: EMAIL,
  role,
});

const DOMAIN_NOT_ALLOWED =
  "Your email domain isn't allowed for Docker Hub organization acme. Ask your P0 admin to check the connector's allowed domains.";
const ACCOUNT_CHANGED =
  "Your Docker account changed after you requested access. Request access again.";
const JOINED_SINCE_REQUEST =
  "You joined acme after you requested access. Request access again.";
const PENDING_INVITE =
  "You have a pending invite to acme. Accept it, or ask an owner of acme to cancel it. Then request again.";
const MORE_THAN_ONE_MEMBER =
  "More than one member of acme has the email alice@acme.com. Ask your Docker Hub admin to fix this.";

const A_MEMBER = /^\/v2\/orgs\/acme\/members\/[^/]+$/;
const AN_INVITE = /^\/v2\/invites\/invite-/;
const BULK_INVITE = "/v2/invites/bulk";

let hub: FakeDockerHub;
let logs: ReturnType<typeof newRecordingLogger>;
let perimeter: ReturnType<typeof newRolePrimitives>;
let versions = 0;

/** Docker Hub answering one endpoint some other way. */
const answering = (
  method: string,
  path: RegExp | string,
  reply: (call: HubCall) => HubReply
) =>
  hub.intercept((call) =>
    isCall(method, path)(call) ? reply(call) : undefined
  );

beforeEach(() => {
  hub = newFakeDockerHub({ org: "acme", token: TOKEN });
  vi.stubGlobal("fetch", hub.fetch);
  // A new version of the secret each test, so each starts without a cached JWT.
  const version = `version-${++versions}`;
  getOrgAccessToken.mockReset();
  getOrgAccessToken.mockResolvedValue({ token: TOKEN, version });
  logs = newRecordingLogger();
  perimeter = newRolePrimitives(logs.log);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const grant = (
  role: CoreRole = "editor",
  { context = INVITED, email = EMAIL } = {}
) => perimeter.setPoliciesForUser(context, email, email, [{ role }]);

const revoke = ({ context = INVITED, email = EMAIL } = {}) =>
  perimeter.setPoliciesForUser(context, email, email, [{ role: null }]);

const listOf = (type: "invite" | "member", email = EMAIL) =>
  perimeter.list({ type, context: CREDENTIALS, email });

/** The connector asked nothing of the vault or of Docker Hub. */
const expectNothingAsked = () => {
  expect(getOrgAccessToken).not.toHaveBeenCalled();
  expect(hub.calls).toEqual([]);
};

describe("validation", () => {
  // The perimeter's own check on a user can't tell a grant from a revoke, so
  // it gets none to run. The primitives check the allowed domains themselves.
  it("gives the perimeter no check to run on the user", () => {
    expect(perimeter.validation(INVITED)).toEqual({ user: null });
  });
});

describe("createUser", () => {
  // The router never gets here, since getUser never returns null.
  it("returns the email, and asks nothing", async () => {
    await expect(perimeter.createUser(INVITED, EMAIL)).resolves.toBe(EMAIL);

    expectNothingAsked();
  });
});

describe("deleteUser", () => {
  // Removing a standing member would take away more than P0 gave.
  it.each([
    ["someone P0 invited", granted(INVITED)],
    ["a standing member", granted(MEMBER)],
  ])("changes nothing for %s", async (_case, context) => {
    hub.members.push(alice("editor"));

    await expect(
      perimeter.deleteUser(context, EMAIL, EMAIL)
    ).resolves.toBeUndefined();

    expectNothingAsked();
  });
});

// What the pattern gates: a grant and both lookups. A revoke isn't gated, so
// tightening the pattern can't strand access granted earlier. The one thing a
// revoke can't do past it is raise a role, which is covered further down.
describe("the allowed domains", () => {
  it.each([
    ["someone P0 would invite", INVITED],
    ["a standing member", MEMBER],
  ])(
    "refuse a grant to %s, before anything is asked",
    async (_case, context) => {
      const data = await connectorError(() =>
        grant("editor", { context, email: OUTSIDER })
      );

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(DOMAIN_NOT_ALLOWED);
      expect(data.payload).toEqual({
        reason: "domain_not_allowed",
        org: "acme",
        email: OUTSIDER,
      });
      expectNothingAsked();
    }
  );

  it.each(["member", "invite"] as const)(
    "refuse the %s lookup, before anything is asked",
    async (type) => {
      const data = await connectorError(() => listOf(type, OUTSIDER));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(DOMAIN_NOT_ALLOWED);
      expectNothingAsked();
    }
  );

  it("don't stop a revoke cancelling an invite", async () => {
    hub.invites.push({ id: "invite-9", invitee: OUTSIDER, role: "editor" });

    await expect(revoke({ email: OUTSIDER })).resolves.toBeUndefined();

    expect(hub.invites).toEqual([]);
  });

  it("don't stop a revoke removing someone P0 invited", async () => {
    hub.members.push({ ...alice("editor"), email: OUTSIDER });

    await expect(
      revoke({ context: granted(INVITED), email: OUTSIDER })
    ).resolves.toBeUndefined();

    expect(hub.members).toEqual([]);
  });

  it("don't stop a revoke lowering a standing member's role", async () => {
    hub.members.push({ ...alice("owner"), email: OUTSIDER });

    await expect(
      revoke({ context: MEMBER, email: OUTSIDER })
    ).resolves.toBeUndefined();

    expect(hub.members[0]?.role).toBe("member");
  });
});

describe("setPoliciesForUser", () => {
  it.each([
    ["no policy", []],
    ["two policies", [{ role: "editor" as const }, { role: null }]],
  ])("refuses %s as unknown, a P0 bug", async (_case, policies) => {
    const data = await connectorError(() =>
      perimeter.setPoliciesForUser(INVITED, EMAIL, EMAIL, policies)
    );

    expect(data.type).toBe("unknown");
    expect(data.message).toBe(
      `Expected exactly 1 policy for a Docker Hub role, got ${policies.length}`
    );
    expectNothingAsked();
  });
});

describe("a grant to a standing member", () => {
  const grantToAlice = (role: CoreRole = "editor") =>
    grant(role, { context: MEMBER });

  it("looks their username up, then PUTs the requested role on it", async () => {
    hub.members.push(alice("member"));

    await expect(grantToAlice("editor")).resolves.toBeUndefined();

    expect(
      hub.apiCalls().map(({ method, path, query }) => ({
        method,
        path,
        search: query.search,
      }))
    ).toEqual([
      { method: "GET", path: "/v2/orgs/acme/members", search: "alice" },
      { method: "PUT", path: "/v2/orgs/acme/members/alice", search: undefined },
    ]);
    expect(hub.writes()[0]?.body).toEqual({ role: "editor" });
    expect(hub.members).toEqual([alice("editor")]);
  });

  it("gives the same outcome when run twice", async () => {
    hub.members.push(alice("member"));

    await expect(grantToAlice("owner")).resolves.toBeUndefined();
    await expect(grantToAlice("owner")).resolves.toBeUndefined();

    expect(hub.members).toEqual([alice("owner")]);
    expect(hub.invites).toEqual([]);
  });

  // The same mailbox, however either side capitalises it.
  it("takes the account's Docker email as the requestor's, ignoring case", async () => {
    hub.members.push({ ...alice("member"), email: "Alice@ACME.com" });

    await expect(grantToAlice("editor")).resolves.toBeUndefined();

    expect(hub.members[0]?.role).toBe("editor");
  });

  // P0 sends both an email and a username. Without this tie, an allowed
  // email could be paired with anyone's username.
  describe("whose account isn't the requestor's", () => {
    it("writes nothing when the account's Docker email is outside the allowed domains", async () => {
      const mallory = {
        username: "mallory",
        uuid: "mallory-uuid",
        email: OUTSIDER,
        role: "member",
      };
      hub.members.push(mallory);

      // An allowed email, with a standing member that names Mallory's account.
      const data = await connectorError(() =>
        grant("owner", {
          email: EMAIL,
          context: {
            ...MEMBER,
            standingMember: {
              username: "mallory",
              uuid: "mallory-uuid",
              priorRole: "member",
            },
          },
        })
      );

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(ACCOUNT_CHANGED);
      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual([mallory]);
    });

    it.each([
      ["another allowed address", "bob@acme.com"],
      ["no address Docker Hub shows", undefined],
    ])(
      "is refused when the account's Docker email is %s",
      async (_case, email) => {
        hub.members.push(alice("member"));
        answering("GET", "/v2/orgs/acme/members", () => ({
          status: 200,
          body: {
            next: null,
            results: [{ username: "alice", uuid: UUID, email, role: "Member" }],
          },
        }));

        const data = await connectorError(() => grantToAlice());

        expect(data.message).toBe(ACCOUNT_CHANGED);
        expect(hub.writes()).toEqual([]);
      }
    );
  });

  // A username can come to name another account. A role must never land on
  // one nobody approved.
  describe("whose account changed", () => {
    it.each([
      ["the username names another account", "another-uuid"],
      ["the username is gone", undefined],
    ])("is refused when %s, and changes nothing", async (_case, uuid) => {
      if (uuid) hub.members.push({ ...alice("member"), uuid });
      const before = structuredClone(hub.members);

      const data = await connectorError(() => grantToAlice());

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(ACCOUNT_CHANGED);
      expect(data.payload).toEqual({
        reason: "account_changed",
        org: "acme",
        email: EMAIL,
        username: "alice",
        uuid: UUID,
      });
      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual(before);
    });

    // Nobody is invited in their place either.
    it("is refused the same way when run twice", async () => {
      hub.members.push({ ...alice("member"), uuid: "another-uuid" });

      const first = await connectorError(() => grantToAlice());
      const second = await connectorError(() => grantToAlice());

      expect(second).toEqual(first);
      expect(hub.writes()).toEqual([]);
      expect(hub.invites).toEqual([]);
    });

    // The search also finds `alice2`.
    it("isn't fooled by a username that only starts the same", async () => {
      hub.members.push({ ...alice("member"), username: "alice2" });

      const data = await connectorError(() => grantToAlice());

      expect(data.message).toBe(ACCOUNT_CHANGED);
      expect(hub.writes()).toEqual([]);
    });
  });

  // They left between the lookup and the PUT.
  it("fails as object_not_found when the PUT finds nobody", async () => {
    hub.members.push(alice("member"));
    answering("PUT", A_MEMBER, () => failing(404, "not found"));

    const data = await connectorError(() => grantToAlice());

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({
      org: "acme",
      query: "acme/alice",
      status: 404,
    });
  });

  it("surfaces Docker Hub's reason for refusing the role", async () => {
    hub.members.push(alice("member"));
    answering("PUT", A_MEMBER, () => failing(400, "seat limit reached"));

    const data = await connectorError(() => grantToAlice());

    expect(data.type).toBe("validation_error");
    expect(data.message).toBe(
      "Docker Hub refused the connector's request for acme (400): seat limit reached"
    );
  });
});

// This path only ever invites. It never sets a role.
describe("a grant to someone who isn't a member", () => {
  it("looks for a member, then for an invite, then invites them at their email", async () => {
    await expect(grant("editor")).resolves.toBeUndefined();

    expect(
      hub.apiCalls().map(({ method, path }) => `${method} ${path}`)
    ).toEqual([
      "GET /v2/orgs/acme/members",
      "GET /v2/orgs/acme/invites",
      `POST ${BULK_INVITE}`,
    ]);
    expect(hub.writes()[0]?.body).toEqual({
      org: "acme",
      role: "editor",
      invitees: [EMAIL],
    });
    expect(hub.invites).toEqual([
      { id: "invite-1", invitee: EMAIL, role: "editor" },
    ]);
  });

  // The second run finds the invite the first one sent.
  it("sends one invite when run twice", async () => {
    await expect(grant("editor")).resolves.toBeUndefined();
    await expect(grant("editor")).resolves.toBeUndefined();

    expect(hub.writes()).toHaveLength(1);
    expect(hub.invites).toHaveLength(1);
  });

  describe("with a pending invite already", () => {
    it("changes nothing when the invite gives the same role", async () => {
      hub.invites.push({
        id: "invite-9",
        invitee: "Alice@Acme.com",
        role: "Editor",
      });

      await expect(grant("editor")).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
    });

    // Changing it would mean cancelling an invite someone else may have sent.
    it("is refused when the invite gives another role, however often it runs", async () => {
      hub.invites.push({ id: "invite-9", invitee: EMAIL, role: "member" });

      const first = await connectorError(() => grant("owner"));
      const second = await connectorError(() => grant("owner"));

      expect(first.type).toBe("validation_error");
      expect(first.message).toBe(PENDING_INVITE);
      expect(first.payload).toEqual({
        reason: "pending_invite",
        org: "acme",
        email: EMAIL,
      });
      expect(second).toEqual(first);
      expect(hub.writes()).toEqual([]);
      expect(hub.invites).toEqual([
        { id: "invite-9", invitee: EMAIL, role: "member" },
      ]);
    });

    // Whichever of them is P0's, the other isn't.
    it("is refused when one invite gives the role and another doesn't", async () => {
      hub.invites.push(
        { id: "invite-8", invitee: EMAIL, role: "editor" },
        { id: "invite-9", invitee: EMAIL, role: "member" }
      );

      const data = await connectorError(() => grant("editor"));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(PENDING_INVITE);
      expect(hub.writes()).toEqual([]);
    });

    it("isn't one for somebody else", async () => {
      hub.invites.push({
        id: "invite-9",
        invitee: "bob@acme.com",
        role: "owner",
      });

      await expect(grant("editor")).resolves.toBeUndefined();

      expect(hub.invites.map(({ invitee }) => invitee)).toEqual([
        "bob@acme.com",
        EMAIL,
      ]);
    });
  });

  // They joined in the moment between approval and the grant. They request
  // again, as a member.
  describe("who has joined since approval", () => {
    it("is refused, and their role isn't touched", async () => {
      hub.members.push(alice("member"));

      const data = await connectorError(() => grant("owner"));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(JOINED_SINCE_REQUEST);
      expect(data.payload).toEqual({
        reason: "joined_since_request",
        org: "acme",
        email: EMAIL,
      });
      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual([alice("member")]);
    });

    it("is refused the same way when run twice", async () => {
      hub.members.push(alice("member"));

      const first = await connectorError(() => grant("owner"));
      const second = await connectorError(() => grant("owner"));

      expect(second).toEqual(first);
      expect(hub.writes()).toEqual([]);
    });

    it("is refused when more than one member has their email", async () => {
      hub.members.push(alice("member"), {
        ...alice("owner"),
        username: "alice-admin",
        uuid: "another-uuid",
      });

      const data = await connectorError(() => grant("editor"));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(MORE_THAN_ONE_MEMBER);
      expect(hub.writes()).toEqual([]);
    });
  });

  // Their Docker account is in the org under another email.
  describe("whom Docker Hub calls an existing member", () => {
    beforeEach(() => {
      answering("POST", BULK_INVITE, () => ({
        status: 202,
        // Docker Hub may echo a Docker ID where the email was sent.
        body: {
          invitees: [{ invitee: "alice", status: "existing_org_member" }],
        },
      }));
    });

    it("is refused, saying what to check", async () => {
      const data = await connectorError(() => grant("editor"));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(
        "Docker Hub says you're already in acme, but no member has the email alice@acme.com. Your Docker account probably uses a different email. Ask your Docker Hub admin to check it."
      );
      expect(data.payload).toEqual({
        reason: "member_under_another_email",
        org: "acme",
        email: EMAIL,
      });
    });

    // The account it means was never checked against the requestor.
    it("sets nobody's role", async () => {
      hub.members.push({ ...alice("member"), email: "alice@personal.example" });

      await connectorError(() => grant("owner"));

      expect(hub.writes().map(({ method }) => method)).toEqual(["POST"]);
      expect(hub.members[0]?.role).toBe("member");
    });
  });

  describe("whose invite Docker Hub refuses", () => {
    it.each(["invalid_email_or_docker_id", "seat_limit_reached"])(
      "is a validation_error naming the status %s",
      async (status) => {
        answering("POST", BULK_INVITE, () => ({
          status: 202,
          body: { invitees: [{ invitee: EMAIL, status }] },
        }));

        const data = await connectorError(() => grant("editor"));

        expect(data.type).toBe("validation_error");
        expect(data.message).toBe(
          `Docker Hub refused the invite to acme: ${status}.`
        );
        expect(data.payload).toEqual({
          reason: "invite_refused",
          org: "acme",
          email: EMAIL,
          dockerReason: status,
        });
      }
    );

    it.each([
      [400, "no seats available", "no seats available"],
      [409, "conflict", "conflict"],
      [400, undefined, "HTTP 400"],
    ])(
      "is a validation_error with Docker Hub's reason on a %s",
      async (status, message, reason) => {
        answering("POST", BULK_INVITE, () => failing(status, message));

        const first = await connectorError(() => grant("editor"));
        const second = await connectorError(() => grant("editor"));

        expect(first.type).toBe("validation_error");
        expect(first.message).toBe(
          `Docker Hub refused the invite to acme: ${reason}.`
        );
        expect(second).toEqual(first);
        expect(hub.invites).toEqual([]);
      }
    );

    // Docker Hub's own text may end in a full stop, or have one inside.
    it.each([
      ["no seats available.", "no seats available."],
      ["v1.2 limit reached", "v1.2 limit reached."],
      ["v1.2 limit reached.", "v1.2 limit reached."],
    ])(
      "ends Docker Hub's reason %j with one full stop",
      async (reason, ending) => {
        answering("POST", BULK_INVITE, () => failing(400, reason));

        const data = await connectorError(() => grant("editor"));

        expect(data.message).toBe(
          `Docker Hub refused the invite to acme: ${ending}`
        );
        expect(data.payload).toMatchObject({ dockerReason: reason });
      }
    );

    // Docker Hub took the call, and there's no telling what it did with it.
    // So not a validation_error, which says nothing was written.
    it("is unknown when Docker Hub gives the invitee no status", async () => {
      answering("POST", BULK_INVITE, () => ({
        status: 202,
        body: { invitees: [] },
      }));

      const data = await connectorError(() => grant("editor"));

      expect(data.type).toBe("unknown");
    });

    // Not a refusal of the invite: the token can't invite at all.
    it("is insufficient_privileges on a 403", async () => {
      answering("POST", BULK_INVITE, () => failing(403, "permission denied"));

      const data = await connectorError(() => grant("editor"));

      expect(data.type).toBe("insufficient_privileges");
    });
  });
});

describe("a revoke for a standing member", () => {
  const revokeAlice = (context = MEMBER) => revoke({ context });

  it("PUTs the prior role back", async () => {
    hub.members.push(alice("editor"));

    await expect(revokeAlice()).resolves.toBeUndefined();

    expect(hub.writes()).toEqual([
      {
        method: "PUT",
        path: "/v2/orgs/acme/members/alice",
        body: { role: "member" },
      },
    ]);
    expect(hub.members).toEqual([alice("member")]);
  });

  // Always, even if someone changed the role by hand in between.
  it("puts the prior role back whatever the role is now", async () => {
    hub.members.push(alice("owner"));

    await revokeAlice();

    expect(hub.members).toEqual([alice("member")]);
  });

  it("changes nothing when they already have the prior role", async () => {
    hub.members.push(alice("member"));

    await expect(revokeAlice()).resolves.toBeUndefined();

    expect(hub.writes()).toEqual([]);
  });

  // The second run finds the prior role in place.
  it("writes once when run twice, and never removes them", async () => {
    hub.members.push(alice("editor"));

    await expect(revokeAlice()).resolves.toBeUndefined();
    await expect(revokeAlice(granted(MEMBER))).resolves.toBeUndefined();

    expect(hub.writes().map(({ method }) => method)).toEqual(["PUT"]);
    expect(hub.members).toEqual([alice("member")]);
  });

  // A revoke must not fail because the person is already gone.
  describe("who is gone", () => {
    it("changes nothing when they've left the org", async () => {
      await expect(revokeAlice()).resolves.toBeUndefined();
      await expect(revokeAlice()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
    });

    // The account that holds the username now was never given anything.
    it("changes nothing when their username names another account", async () => {
      const stranger = { ...alice("owner"), uuid: "another-uuid" };
      hub.members.push(stranger);

      await expect(revokeAlice()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual([stranger]);
    });

    it("changes nothing when they leave between the lookup and the PUT", async () => {
      hub.members.push(alice("editor"));
      answering("PUT", A_MEMBER, () => failing(404, "not found"));

      await expect(revokeAlice()).resolves.toBeUndefined();
    });

    it("doesn't touch anyone else with their email, even after a completed grant", async () => {
      const namesake = {
        ...alice("owner"),
        username: "alice-admin",
        uuid: "another-uuid",
      };
      hub.members.push(namesake);
      hub.invites.push({ id: "invite-9", invitee: EMAIL, role: "editor" });

      await expect(revokeAlice(granted(MEMBER))).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual([namesake]);
      expect(hub.invites).toHaveLength(1);
    });
  });

  // An admin lowered their role during the grant, so putting the prior role
  // back would raise it. That has to pass the same checks as a grant, and
  // when it doesn't, they keep the lower role and the revoke still succeeds.
  describe("whose prior role is higher than their role now", () => {
    const WAS_EDITOR: RoleContext = {
      ...MEMBER,
      standingMember: { ...STANDING, priorRole: "editor" },
    };

    it("puts the prior role back when the grant's checks pass", async () => {
      hub.members.push(alice("member"));

      await expect(revokeAlice(WAS_EDITOR)).resolves.toBeUndefined();

      expect(hub.members).toEqual([alice("editor")]);
    });

    it("leaves the lower role when the email is outside the allowed domains", async () => {
      hub.members.push({ ...alice("member"), email: OUTSIDER });

      await expect(
        revoke({ context: WAS_EDITOR, email: OUTSIDER })
      ).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members[0]?.role).toBe("member");
    });

    it("leaves the lower role when the account's Docker email isn't the requestor's", async () => {
      hub.members.push({ ...alice("member"), email: OUTSIDER });

      await expect(revokeAlice(WAS_EDITOR)).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members[0]?.role).toBe("member");
      expect(logs.warn).toHaveBeenCalledWith(
        { priorRole: "editor", liveRole: "member" },
        "left the lower role in place: restoring the prior role would raise it, and the grant's checks don't pass"
      );
    });

    it("leaves the lower role when Docker Hub shows no email for the account", async () => {
      hub.members.push(alice("member"));
      answering("GET", "/v2/orgs/acme/members", () => ({
        status: 200,
        body: {
          next: null,
          results: [{ username: "alice", uuid: UUID, role: "Member" }],
        },
      }));

      await expect(revokeAlice(WAS_EDITOR)).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members[0]?.role).toBe("member");
    });

    it("gives the same outcome when run twice", async () => {
      hub.members.push({ ...alice("member"), email: OUTSIDER });

      await expect(revokeAlice(WAS_EDITOR)).resolves.toBeUndefined();
      await expect(revokeAlice(WAS_EDITOR)).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
    });
  });

  // A custom role has no rank, so leaving one is treated as a raise.
  describe("who holds a custom role now", () => {
    it("puts the prior role back when the grant's checks pass", async () => {
      hub.members.push(alice("release-manager"));

      await expect(revokeAlice()).resolves.toBeUndefined();

      expect(hub.members).toEqual([alice("member")]);
    });

    it("leaves the custom role when they don't", async () => {
      hub.members.push({ ...alice("release-manager"), email: OUTSIDER });

      await expect(revokeAlice()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
    });
  });

  // Docker Hub won't demote an org's last owner, for one.
  it("surfaces Docker Hub's reason when the prior role can't go back", async () => {
    hub.members.push(alice("owner"));
    answering("PUT", A_MEMBER, () =>
      failing(400, "cannot change the role of the last owner")
    );

    const data = await connectorError(() => revokeAlice());

    expect(data.type).toBe("validation_error");
    expect(data.message).toBe(
      "Docker Hub refused the connector's request for acme (400): cannot change the role of the last owner"
    );
  });
});

describe("a revoke for someone P0 invited", () => {
  describe("whose invite is still pending", () => {
    beforeEach(() => {
      hub.invites.push({
        id: "invite-1",
        invitee: "Alice@ACME.com",
        role: "editor",
      });
    });

    it("cancels the invite, found by email alone", async () => {
      await expect(revoke()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([
        { method: "DELETE", path: "/v2/invites/invite-1", body: undefined },
      ]);
      expect(hub.invites).toEqual([]);
    });

    it("cancels every pending invite to the email, and nobody else's", async () => {
      hub.invites.push(
        { id: "invite-2", invitee: "bob@acme.com", role: "owner" },
        { id: "invite-3", invitee: EMAIL, role: "owner" }
      );

      await revoke();

      expect(hub.invites).toEqual([
        { id: "invite-2", invitee: "bob@acme.com", role: "owner" },
      ]);
    });

    // The second run finds no invite, and the grant never completed.
    it("gives the same outcome when run twice", async () => {
      await expect(revoke()).resolves.toBeUndefined();
      await expect(revoke()).resolves.toBeUndefined();

      expect(hub.writes()).toHaveLength(1);
    });

    // The org goes back to how it was before the grant, in one run.
    it("cancels the invite and removes the member with the email, after a completed grant", async () => {
      hub.members.push(alice("owner"));
      const revokeGranted = () => revoke({ context: granted(INVITED) });

      await expect(revokeGranted()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([
        { method: "DELETE", path: "/v2/invites/invite-1", body: undefined },
        {
          method: "DELETE",
          path: "/v2/orgs/acme/members/alice",
          body: undefined,
        },
      ]);
      expect(hub.invites).toEqual([]);
      expect(hub.members).toEqual([]);

      await expect(revokeGranted()).resolves.toBeUndefined();
      expect(hub.writes()).toHaveLength(2);
    });

    // A rollback of a failed grant never removes anyone.
    it("cancels the invite but keeps the member with the email, when the grant never completed", async () => {
      hub.members.push(alice("owner"));

      await expect(revoke()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([
        { method: "DELETE", path: "/v2/invites/invite-1", body: undefined },
      ]);
      expect(hub.invites).toEqual([]);
      expect(hub.members).toEqual([alice("owner")]);

      await expect(revoke()).resolves.toBeUndefined();
      expect(hub.writes()).toHaveLength(1);
    });

    it("fails when the invite can't be cancelled", async () => {
      answering("DELETE", AN_INVITE, () => failing(403, "permission denied"));

      const data = await connectorError(() => revoke());

      expect(data.type).toBe("insufficient_privileges");
      expect(hub.invites).toHaveLength(1);
    });

    // A validation_error says nothing was written, and by then one was.
    it("isn't a validation_error when Docker Hub refuses a cancel after another went through", async () => {
      hub.invites.push({ id: "invite-3", invitee: EMAIL, role: "owner" });
      answering("DELETE", "/v2/invites/invite-3", () =>
        failing(409, "conflict")
      );

      const data = await connectorError(() => revoke());

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toBe(
        "Docker Hub refused to cancel one of the pending invites to acme: conflict"
      );
      expect(data.payload).toEqual({ org: "acme", email: EMAIL, cancelled: 1 });
      expect(hub.invites.map(({ id }) => id)).toEqual(["invite-3"]);
    });

    it("is a validation_error when Docker Hub refuses the first cancel", async () => {
      answering("DELETE", AN_INVITE, () => failing(409, "conflict"));

      const data = await connectorError(() => revoke());

      expect(data.type).toBe("validation_error");
    });

    // The refusal comes before the cancel, so it still means nothing was written.
    it("cancels nothing when more than one member has the email, after a completed grant", async () => {
      hub.members.push(alice("owner"), {
        ...alice("owner"),
        username: "alice-admin",
        uuid: "another-uuid",
      });

      const data = await connectorError(() =>
        revoke({ context: granted(INVITED) })
      );

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(MORE_THAN_ONE_MEMBER);
      expect(hub.writes()).toEqual([]);
    });

    // Docker Hub refuses to remove an org's last owner. A run with nothing
    // left to cancel writes nothing, so its refusal is a validation_error.
    it.each([400, 409])(
      "isn't a validation_error when Docker Hub refuses the removal with a %s after the invite was cancelled",
      async (status) => {
        hub.members.push(alice("owner"));
        answering("DELETE", A_MEMBER, () =>
          failing(status, "cannot remove the last owner.")
        );
        const revokeGranted = () => revoke({ context: granted(INVITED) });

        const data = await connectorError(revokeGranted);

        expect(data.type).toBe("dependency_violation");
        expect(data.message).toBe(
          "Docker Hub refused to remove alice from acme: cannot remove the last owner. P0 cancelled the pending invite to alice@acme.com, but alice is still a member of acme."
        );
        expect(data.payload).toEqual({
          org: "acme",
          email: EMAIL,
          username: "alice",
          cancelled: 1,
        });
        expect(hub.invites).toEqual([]);
        expect(hub.members).toEqual([alice("owner")]);

        expect((await connectorError(revokeGranted)).type).toBe(
          "validation_error"
        );
      }
    );

    it("says how many invites it cancelled before Docker Hub refused the removal", async () => {
      hub.invites.push({ id: "invite-3", invitee: EMAIL, role: "owner" });
      hub.members.push(alice("owner"));
      answering("DELETE", A_MEMBER, () => failing(400, "last owner"));

      const data = await connectorError(() =>
        revoke({ context: granted(INVITED) })
      );

      expect(data.message).toBe(
        "Docker Hub refused to remove alice from acme: last owner. P0 cancelled 2 pending invites to alice@acme.com, but alice is still a member of acme."
      );
      expect(data.payload).toMatchObject({ cancelled: 2 });
    });

    // Gone by the time it's cancelled: it may have been accepted meanwhile.
    describe("and is gone by the time it's cancelled", () => {
      beforeEach(() => {
        answering("DELETE", AN_INVITE, () => {
          hub.invites.length = 0;
          hub.members.push(alice("editor"));
          return failing(404, "not found");
        });
      });

      it("removes the member who accepted it, after a completed grant", async () => {
        await expect(
          revoke({ context: granted(INVITED) })
        ).resolves.toBeUndefined();

        expect(hub.members).toEqual([]);
      });

      it("removes nobody when the grant never completed", async () => {
        await expect(revoke()).resolves.toBeUndefined();

        expect(hub.members).toEqual([alice("editor")]);
      });
    });
  });

  // They accepted the invite.
  describe("who is a member now, after a completed grant", () => {
    const revokeGranted = () => revoke({ context: granted(INVITED) });

    beforeEach(() => {
      hub.members.push(alice("editor"));
    });

    it("removes them from the org, whatever their role is now", async () => {
      hub.members[0] = alice("owner");

      await expect(revokeGranted()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([
        {
          method: "DELETE",
          path: "/v2/orgs/acme/members/alice",
          body: undefined,
        },
      ]);
      expect(hub.members).toEqual([]);
    });

    it("leaves every other member alone", async () => {
      const bob = {
        username: "bob",
        uuid: "bob-uuid",
        email: "bob@acme.com",
        role: "owner",
      };
      hub.members.push(bob);

      await revokeGranted();

      expect(hub.members).toEqual([bob]);
    });

    it("gives the same outcome when run twice", async () => {
      await expect(revokeGranted()).resolves.toBeUndefined();
      await expect(revokeGranted()).resolves.toBeUndefined();

      expect(hub.writes()).toHaveLength(1);
    });

    it("is done when they leave between the lookup and the DELETE", async () => {
      answering("DELETE", A_MEMBER, () => failing(404, "not found"));

      await expect(revokeGranted()).resolves.toBeUndefined();
    });

    // Docker Hub refuses to remove an org's last owner.
    it("surfaces Docker Hub's reason for refusing to remove them", async () => {
      answering("DELETE", A_MEMBER, () =>
        failing(400, "cannot remove the last owner")
      );

      const data = await connectorError(() => revokeGranted());

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(
        "Docker Hub refused the connector's request for acme (400): cannot remove the last owner"
      );
      expect(hub.members).toHaveLength(1);
    });

    // The revoke fails loudly, so a person can sort out which is which.
    it("fails when more than one member has their email, and removes neither", async () => {
      hub.members.push({
        ...alice("owner"),
        username: "alice-admin",
        uuid: "another-uuid",
      });

      const data = await connectorError(() => revokeGranted());

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(MORE_THAN_ONE_MEMBER);
      expect(hub.members).toHaveLength(2);
    });
  });

  // A rollback of a failed grant, or a revoke of a request that never
  // finished granting: whoever holds the email joined some other way.
  describe("who is a member, when the grant never completed", () => {
    it("removes nobody, and asks Docker Hub for no members", async () => {
      hub.members.push(alice("owner"));

      await expect(revoke()).resolves.toBeUndefined();
      await expect(revoke()).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
      expect(hub.members).toEqual([alice("owner")]);
      expect(hub.apiCalls().map(({ path }) => path)).toEqual([
        "/v2/orgs/acme/invites",
        "/v2/orgs/acme/invites",
      ]);
    });
  });

  describe("who is gone", () => {
    it("changes nothing, however often it runs", async () => {
      await expect(
        revoke({ context: granted(INVITED) })
      ).resolves.toBeUndefined();
      await expect(
        revoke({ context: granted(INVITED) })
      ).resolves.toBeUndefined();

      expect(hub.writes()).toEqual([]);
    });
  });
});

describe("a grant and then a revoke", () => {
  it("leave a standing member as they were", async () => {
    hub.members.push(alice("member"));

    await grant("owner", { context: MEMBER });
    expect(hub.members).toEqual([alice("owner")]);
    await revoke({ context: granted(MEMBER) });

    expect(hub.members).toEqual([alice("member")]);
  });

  it("leave someone P0 invited with no invite", async () => {
    await grant("editor");
    expect(hub.invites).toHaveLength(1);
    await revoke({ context: granted(INVITED) });

    expect(hub.invites).toEqual([]);
    expect(hub.members).toEqual([]);
  });

  it("remove someone who accepted P0's invite", async () => {
    await grant("editor");
    // They accept: the invite becomes a membership.
    hub.invites.length = 0;
    hub.members.push(alice("editor"));

    await revoke({ context: granted(INVITED) });

    expect(hub.members).toEqual([]);
  });

  // P0 rolls a refused grant back with a revoke, and the grant never
  // completed. The member it was refused for joined some other way.
  it("leave someone else's membership alone when the grant was refused", async () => {
    hub.members.push(alice("owner"));

    const data = await connectorError(() => grant("editor"));
    expect(data.message).toBe(JOINED_SINCE_REQUEST);
    await expect(revoke()).resolves.toBeUndefined();

    expect(hub.writes()).toEqual([]);
    expect(hub.members).toEqual([alice("owner")]);
  });

  // The same rollback, when it was Docker Hub that refused the invite.
  it("leave a member with the email alone when the invite was refused", async () => {
    answering("POST", BULK_INVITE, () => failing(400, "no seats available"));
    await connectorError(() => grant("editor"));
    // Someone with the email joins, on their own, before the rollback runs.
    hub.members.push(alice("member"));

    await expect(revoke()).resolves.toBeUndefined();

    expect(hub.members).toEqual([alice("member")]);
  });
});

describe("list", () => {
  describe("member", () => {
    it("is the member with the email: username, uuid, and role", async () => {
      hub.members.push({ ...alice("editor"), email: "Alice@Acme.com" });

      await expect(listOf("member")).resolves.toEqual([
        { key: "alice", value: UUID, group: "editor" },
      ]);
    });

    // P0 then invites them. A pending invitee isn't a member.
    it("is empty when no member has the email", async () => {
      hub.members.push({ ...alice("editor"), email: "malice@acme.com" });
      hub.invites.push({ id: "invite-1", invitee: EMAIL, role: "editor" });

      await expect(listOf("member")).resolves.toEqual([]);
    });

    // How P0 recognises a custom-role holder, and refuses their request.
    it("reports a custom role by its name", async () => {
      hub.members.push(alice("release-manager"));

      await expect(listOf("member")).resolves.toEqual([
        { key: "alice", value: UUID, group: "release-manager" },
      ]);
    });

    it("refuses more than one member with the email", async () => {
      hub.members.push(alice("member"), {
        ...alice("owner"),
        username: "alice-admin",
        uuid: "another-uuid",
      });

      const data = await connectorError(() => listOf("member"));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe(MORE_THAN_ONE_MEMBER);
      expect(data.payload).toEqual({
        reason: "more_than_one_member",
        org: "acme",
        email: EMAIL,
      });
    });

    it("maps a failed lookup through the Docker Hub error mapping", async () => {
      answering("GET", "/v2/orgs/acme/members", () => failing(502));

      const data = await connectorError(() => listOf("member"));

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({ org: "acme", status: 502 });
    });
  });

  describe("invite", () => {
    it("is the pending invite to the email: its id and its role", async () => {
      hub.invites.push({ id: "invite-1", invitee: EMAIL, role: "Editor" });

      await expect(listOf("invite")).resolves.toEqual([
        { key: "invite-1", value: "editor" },
      ]);
    });

    // A member has no pending invite.
    it("is empty when there's none", async () => {
      hub.members.push(alice("editor"));
      hub.invites.push({
        id: "invite-1",
        invitee: "bob@acme.com",
        role: "owner",
      });

      await expect(listOf("invite")).resolves.toEqual([]);
    });

    it("maps a failed lookup through the Docker Hub error mapping", async () => {
      answering("GET", "/v2/orgs/acme/invites", () =>
        failing(403, "permission denied")
      );

      const data = await connectorError(() => listOf("invite"));

      expect(data.type).toBe("insufficient_privileges");
    });
  });
});

// P0 tries these again, and the second run has to finish what the first
// couldn't.
describe.each([
  ["a 5xx", failing(503), "upstream_unavailable"],
  [
    "a 429",
    failing(429, "too many requests", { "Retry-After": "30" }),
    "rate_limited",
  ],
  [
    "no answer",
    { throws: new TypeError("fetch failed") },
    "upstream_unavailable",
  ],
] as const)("a write that gets %s", (_case, reply, type) => {
  /** Docker Hub failing one endpoint the first time it's asked, then answering as usual. */
  const failingOnce = (method: string, path: RegExp | string) => {
    let failed = false;
    hub.intercept((call) => {
      if (failed || !isCall(method, path)(call)) return undefined;
      failed = true;
      return reply;
    });
  };

  it(`fails a standing member's grant as ${type}, and sets the role when run again`, async () => {
    hub.members.push(alice("member"));
    failingOnce("PUT", A_MEMBER);

    const data = await connectorError(() =>
      grant("editor", { context: MEMBER })
    );

    expect(data.type).toBe(type);
    expect(hub.members).toEqual([alice("member")]);

    await expect(grant("editor", { context: MEMBER })).resolves.toBeUndefined();
    expect(hub.members).toEqual([alice("editor")]);
  });

  it(`fails an invite as ${type}, and sends one invite when run again`, async () => {
    failingOnce("POST", BULK_INVITE);

    const data = await connectorError(() => grant("editor"));

    expect(data.type).toBe(type);
    expect(hub.invites).toEqual([]);

    await expect(grant("editor")).resolves.toBeUndefined();
    expect(hub.invites).toEqual([
      { id: "invite-1", invitee: EMAIL, role: "editor" },
    ]);
  });

  it(`fails a removal as ${type}, and removes the member when run again`, async () => {
    const revokeGranted = () => revoke({ context: granted(INVITED) });
    hub.members.push(alice("editor"));
    failingOnce("DELETE", A_MEMBER);

    const data = await connectorError(revokeGranted);

    expect(data.type).toBe(type);
    expect(hub.members).toEqual([alice("editor")]);

    await expect(revokeGranted()).resolves.toBeUndefined();
    expect(hub.members).toEqual([]);
  });

  // Only a 400 or a 409 says Docker Hub refused the cancel.
  it(`fails a cancel after another went through as ${type}, and cancels the rest when run again`, async () => {
    hub.invites.push(
      { id: "invite-1", invitee: EMAIL, role: "editor" },
      { id: "invite-3", invitee: EMAIL, role: "owner" }
    );
    failingOnce("DELETE", "/v2/invites/invite-3");

    const data = await connectorError(() => revoke());

    expect(data.type).toBe(type);
    expect(hub.invites.map(({ id }) => id)).toEqual(["invite-3"]);

    await expect(revoke()).resolves.toBeUndefined();
    expect(hub.invites).toEqual([]);
  });
});

describe("a failure that isn't Docker Hub refusing the request", () => {
  // The requestor can't fix the token, so it's never a validation_error.
  it.each([400, 401, 403])(
    "is insufficient_privileges when the token exchange is refused with a %s, on a grant and on a revoke",
    async (status) => {
      answering("POST", "/v2/auth/token", () => failing(status, "no"));

      expect((await connectorError(() => grant())).type).toBe(
        "insufficient_privileges"
      );
      expect((await connectorError(() => revoke())).type).toBe(
        "insufficient_privileges"
      );
    }
  );

  it("is the vault's own error when the secret can't be read", async () => {
    const error = new ConnectorError({
      type: "insufficient_privileges",
      message: "not allowed to read the secret",
      payload: { secretId: "docker-oat", manager: "aws" },
    });
    getOrgAccessToken.mockRejectedValue(error);

    await expect(grant()).rejects.toBe(error);
    await expect(revoke()).rejects.toBe(error);
    expect(hub.calls).toEqual([]);
  });

  it("is let through as it is when it's a bug", async () => {
    const bug = new TypeError("undefined is not a function");
    getOrgAccessToken.mockRejectedValue(bug);

    await expect(grant()).rejects.toBe(bug);
  });
});

import { inspect } from "node:util";
import { describe, expect, it } from "vitest";

import {
  AWS_SECRET,
  CREDENTIALS,
  EMAIL,
  GCP_SECRET,
  TOKEN,
  UUID,
} from "../../../__tests__/fixtures.ts";
import { orgCredentials, spec } from "../definition.ts";

const STANDING_MEMBER = { username: "alice", uuid: UUID, priorRole: "member" };

// Someone P0 invites has no standing member.
const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  standingMember: null,
  grantCompleted: false,
};

// The org becomes a URL path segment, so nothing that could change the URL
// gets in: no `/`, and no `.` or `..` for fetch to resolve away.
describe("the organization name", () => {
  const parse = (org: unknown) => orgCredentials.parse({ ...CREDENTIALS, org });

  it.each([
    ["lower-case letters", "acme"],
    ["digits, hyphens and underscores", "acme-corp_2"],
    ["a leading digit", "0acme"],
    ["two characters", "ab"],
    ["255 characters", "a".repeat(255)],
  ])("accepts %s", (_case, org) => {
    expect(parse(org).org).toBe(org);
  });

  it.each([
    ["a single character", "a"],
    ["256 characters", "a".repeat(256)],
    ["an upper-case letter", "Acme"],
    ["a leading hyphen", "-acme"],
    ["a slash", "acme/x"],
    ["a dot", "acme.io"],
    ["a dot segment", ".."],
    ["an empty string", ""],
  ])("rejects %s", (_case, org) => {
    expect(() => parse(org)).toThrow();
  });

  it("is checked wherever the credentials go", () => {
    expect(() => spec.requestContext({ ...CONTEXT, org: "../x" })).toThrow();
    expect(() =>
      spec.listerQuery({
        type: "member",
        context: { ...CREDENTIALS, org: "a/b" },
        email: EMAIL,
      })
    ).toThrow();
  });

  it("says what a name it rejects has to be", () => {
    const { error } = orgCredentials.safeParse({ ...CREDENTIALS, org: "Acme" });

    expect(error?.issues).toMatchObject([
      { path: ["org"], message: "must be a Docker Hub organization name" },
    ]);
  });
});

// The requestor's P0 email is the only identity the connector takes. Nothing
// a requestor could type, a Docker username say, gets in as the user.
describe("the user", () => {
  const PARSERS = [
    ["body", spec.userBody],
    ["id", spec.userId],
  ] as const;

  it.each(PARSERS)("its %s is the requestor's email", (_case, parse) => {
    expect(parse(EMAIL)).toBe(EMAIL);
  });

  it.each(PARSERS)("its %s can't be a Docker username", (_case, parse) => {
    expect(() => parse("alice")).toThrow();
  });
});

// The connector only ever sets a core role: neither the role to grant nor the
// role to put back can name anything else.
describe("the roles", () => {
  it.each(["member", "editor", "owner", null])("a policy takes %s", (role) => {
    expect(spec.policy({ role })).toEqual({ role });
  });

  it.each(["release-manager", "Owner", ""])("a policy rejects %j", (role) => {
    expect(() => spec.policy({ role })).toThrow();
  });

  // Taking access back is said with `null`, never by saying nothing.
  it("a policy has to say its role", () => {
    expect(() => spec.policy({})).toThrow();
  });

  it.each(["member", "editor", "owner"])(
    "a standing member's prior role can be %s",
    (priorRole) => {
      const standingMember = { ...STANDING_MEMBER, priorRole };
      expect(
        spec.requestContext({ ...CONTEXT, standingMember }).standingMember
      ).toEqual(standingMember);
    }
  );

  // P0 refuses a custom-role holder at request time. `null` is a policy's
  // way to take access back, and no role to put back.
  it.each(["release-manager", "Owner", null])(
    "a standing member's prior role can't be %j",
    (priorRole) => {
      expect(() =>
        spec.requestContext({
          ...CONTEXT,
          standingMember: { ...STANDING_MEMBER, priorRole },
        })
      ).toThrow();
    }
  );
});

describe("the request context", () => {
  // `null` says P0 will invite. Leaving it out says nothing.
  it("requires the standing member, even when it's null", () => {
    const { standingMember: _omitted, ...withoutIt } = CONTEXT;
    expect(spec.requestContext(CONTEXT).standingMember).toBeNull();
    expect(() => spec.requestContext(withoutIt)).toThrow();
  });

  // A revoke that can't tell would have to guess whether it may remove a member.
  it("requires grantCompleted", () => {
    const { grantCompleted: _omitted, ...withoutIt } = CONTEXT;
    expect(() => spec.requestContext(withoutIt)).toThrow();
    expect(() =>
      spec.requestContext({ ...CONTEXT, grantCompleted: "yes" })
    ).toThrow();
  });

  it("requires the request's id", () => {
    const { requestId: _omitted, ...withoutIt } = CONTEXT;
    expect(() => spec.requestContext(withoutIt)).toThrow();
  });

  // A grant acts on the username, and the uuid is how it tells the username
  // still names the same account.
  it.each(["username", "uuid"])(
    "rejects a standing member with an empty %s",
    (field) => {
      expect(() =>
        spec.requestContext({
          ...CONTEXT,
          standingMember: { ...STANDING_MEMBER, [field]: "" },
        })
      ).toThrow();
    }
  );
});

describe("the token secret", () => {
  it.each([AWS_SECRET, GCP_SECRET])(
    "points into the $manager secret manager",
    (tokenSecret) => {
      expect(
        orgCredentials.parse({ ...CREDENTIALS, tokenSecret }).tokenSecret
      ).toEqual(tokenSecret);
    }
  );

  it.each([
    ["an AWS pointer without its region", { ...AWS_SECRET, region: undefined }],
    [
      "a Google pointer without its project",
      { ...GCP_SECRET, projectId: undefined },
    ],
    ["a pointer without its secret id", { ...AWS_SECRET, secretId: "" }],
    ["another secret manager", { ...AWS_SECRET, manager: "azure" }],
  ])("rejects %s", (_case, tokenSecret) => {
    expect(() =>
      orgCredentials.parse({ ...CREDENTIALS, tokenSecret })
    ).toThrow();
  });

  it("carries only a pointer, whatever else P0 sends beside it", () => {
    const parsed = spec.requestContext({
      ...CONTEXT,
      tokenSecret: { ...AWS_SECRET, value: TOKEN },
    });
    expect(parsed.tokenSecret).toEqual(AWS_SECRET);
  });

  const thrown = (run: () => unknown): unknown => {
    try {
      run();
    } catch (error) {
      return error;
    }
    throw new Error("expected the call to throw");
  };

  // P0 sends where the token is, never the token.
  it.each([
    [
      "the install's credentials",
      (tokenSecret: unknown) =>
        orgCredentials.parse({ ...CREDENTIALS, tokenSecret }),
    ],
    [
      "the request context",
      (tokenSecret: unknown) =>
        spec.requestContext({ ...CONTEXT, tokenSecret }),
    ],
    [
      "a list query's context",
      (tokenSecret: unknown) =>
        spec.listerQuery({
          type: "member",
          context: { ...CREDENTIALS, tokenSecret },
          email: EMAIL,
        }),
    ],
  ])("refuses the token itself in %s, without repeating it", (_case, parse) => {
    const error = thrown(() => parse(TOKEN));

    expect(inspect(error, { depth: null })).not.toContain(TOKEN);
    expect(JSON.stringify(error)).not.toContain(TOKEN);
  });
});

describe("a list query", () => {
  it.each(["member", "invite"])(
    "for a %s carries the credentials as its context",
    (type) => {
      const query = { type, context: CREDENTIALS, email: EMAIL };
      expect(spec.listerQuery(query)).toEqual(query);
    }
  );

  it("rejects credentials beside the context instead of in it", () => {
    expect(() =>
      spec.listerQuery({ ...CREDENTIALS, type: "member", email: EMAIL })
    ).toThrow();
  });

  it.each(["member", "invite"])(
    "for a %s can't ask about a Docker username",
    (type) => {
      expect(() =>
        spec.listerQuery({ type, context: CREDENTIALS, email: "alice" })
      ).toThrow();
    }
  );

  it("rejects a type the connector doesn't answer", () => {
    expect(() =>
      spec.listerQuery({ type: "team", context: CREDENTIALS, email: EMAIL })
    ).toThrow();
  });
});

// P0 reads what `list` returned with this.
describe("a list response", () => {
  it("keeps each item's key and value, and its group when it has one", () => {
    const items = [
      { key: "alice", value: UUID, group: "editor" },
      { key: "invite-1", value: "editor" },
    ];
    expect(spec.listerResponse(items)).toEqual(items);
  });

  it.each([
    ["key", { value: UUID, group: "editor" }],
    ["value", { key: "alice", group: "editor" }],
  ])("rejects an item without its %s", (_field, item) => {
    expect(() => spec.listerResponse([item])).toThrow();
  });
});

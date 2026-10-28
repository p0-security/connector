import { describe, expect, it } from "vitest";

import { spec } from "../definition.ts";

const CREDENTIALS = {
  org: "acme",
  appId: "123456",
  privateKey: {
    manager: "aws",
    secretId: "arn:aws:secretsmanager:us-west-2:123456789012:secret:gh-app-key",
    region: "us-west-2",
  },
};

const CONTEXT = { ...CREDENTIALS, requestId: "req-1", githubUserId: "583231" };

// The users and the request context are shared with the `role` access, whose
// tests cover their formats.
describe("the shared user schema", () => {
  it("takes the bare login as the user body and the user id", () => {
    expect(spec.userBody("octocat")).toBe("octocat");
    expect(spec.userId("octocat")).toBe("octocat");
  });

  it("requires the GitHub user id in the request context", () => {
    expect(spec.requestContext(CONTEXT)).toEqual(CONTEXT);
    const { githubUserId: _githubUserId, ...withoutId } = CONTEXT;
    expect(() => spec.requestContext(withoutId)).toThrow();
  });
});

describe("policy", () => {
  it.each(["member", "maintainer"])(
    "is a team's id and the %s membership to leave the user with on it",
    (role) => {
      expect(spec.policy({ teamId: "7", role })).toEqual({ teamId: "7", role });
    }
  );

  it("takes a null role, for no membership", () => {
    expect(spec.policy({ teamId: "7", role: null })).toEqual({
      teamId: "7",
      role: null,
    });
  });

  it.each([
    ["a role that isn't a team role", { teamId: "7", role: "admin" }],
    ["a membership without its team", { role: "member" }],
    ["a team without a role", { teamId: "7" }],
    // A slug can be renamed onto another team.
    ["a team named by its slug", { team: "platform", role: "member" }],
  ])("rejects %s", (_case, policy) => {
    expect(() => spec.policy(policy)).toThrow();
  });
});

// The id becomes a URL path segment, and is matched against the number
// GitHub returns.
describe("the team id", () => {
  const parse = (teamId: unknown) => spec.policy({ teamId, role: "member" });

  it.each([
    ["a small id", "7"],
    ["the largest safe integer", String(Number.MAX_SAFE_INTEGER)],
  ])("accepts %s", (_case, teamId) => {
    expect(() => parse(teamId)).not.toThrow();
  });

  it.each([
    ["a number", 7],
    ["a slug", "platform"],
    ["an id with a leading zero", "07"],
    ["a path", "7/memberships"],
    ["a dot segment", ".."],
    ["an id past the largest safe integer", "9007199254740993"],
  ])("rejects %s", (_case, teamId) => {
    expect(() => parse(teamId)).toThrow();
  });

  it("applies to list queries", () => {
    expect(() =>
      spec.listerQuery({
        type: "team-membership",
        context: CREDENTIALS,
        teamId: "platform",
        login: "octocat",
      })
    ).toThrow("must be a GitHub team id");
  });
});

// The slug becomes a URL path segment, so nothing that could change the URL
// gets in: no `/`, and no `.` or `..` for fetch to resolve away.
describe("the team slug", () => {
  const parse = (team: string) =>
    spec.listerQuery({ type: "team-id", context: CREDENTIALS, team });

  it.each([
    ["a slug with hyphens", "on-call"],
    ["a slug with underscores and digits", "team_2"],
    ["a slug with characters outside ASCII", "équipe"],
  ])("accepts %s", (_case, team) => {
    expect(() => parse(team)).not.toThrow();
  });

  it.each([
    ["an empty slug", ""],
    ["an org/team pair", "acme/platform"],
    ["a slug of .", "."],
    ["a slug of ..", ".."],
    ["a slug with a space", "on call"],
  ])("rejects %s", (_case, team) => {
    expect(() => parse(team)).toThrow("must be a GitHub team slug");
  });
});

describe("listerQuery", () => {
  it.each([
    ["the team listing", { type: "team" }],
    ["a team id lookup", { type: "team-id", team: "platform" }],
    [
      "a team membership read",
      { type: "team-membership", teamId: "7", login: "octocat" },
    ],
    ["a member lookup", { type: "member", email: "octocat@acme.com" }],
    ["an account lookup", { type: "account", login: "octocat" }],
  ])("parses %s", (_case, lookup) => {
    const query = { context: CREDENTIALS, ...lookup };
    expect(spec.listerQuery(query)).toEqual(query);
  });

  it("rejects a team membership read without a login", () => {
    expect(() =>
      spec.listerQuery({
        type: "team-membership",
        context: CREDENTIALS,
        teamId: "7",
      })
    ).toThrow();
  });

  it("rejects a query without credentials", () => {
    expect(() => spec.listerQuery({ type: "team" })).toThrow();
  });

  // The `role` access's lookups stay with the `role` access.
  it.each(["repository", "role", "direct-role", "repository-id"])(
    "rejects the role access's %s query",
    (type) => {
      expect(() =>
        spec.listerQuery({
          type,
          context: CREDENTIALS,
          repo: "api",
          login: "octocat",
        })
      ).toThrow();
    }
  );
});

describe("setPoliciesForUser", () => {
  it("parses the membership to leave the user with", () => {
    const input = {
      userId: "octocat",
      userBody: "octocat",
      policies: [{ teamId: "7", role: "member" }],
      context: CONTEXT,
    };
    expect(spec.setPoliciesForUser(input)).toEqual(input);
  });

  it("rejects a membership without its team", () => {
    expect(() =>
      spec.setPoliciesForUser({
        userId: "octocat",
        userBody: "octocat",
        policies: [{ role: "member" }],
        context: CONTEXT,
      })
    ).toThrow();
  });
});

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

describe("policy", () => {
  it.each([true, false])(
    "is a repo, a branch, and whether the user can bypass its reviews (%s)",
    (allowed) => {
      const policy = { repo: "api", branch: "main", allowed };
      expect(spec.policy(policy)).toEqual(policy);
    }
  );

  it.each(["release/2026.10", "feature/a/b", "v1.2", "user_name-x"])(
    "takes the branch %s",
    (branch) => {
      expect(spec.policy({ repo: "api", branch, allowed: true }).branch).toBe(
        branch
      );
    }
  );

  // What `git check-ref-format --branch` refuses, and the wildcard characters
  // a protection rule's pattern uses.
  it.each([
    "",
    "release/*",
    "main?",
    "[ab]",
    "a..b",
    "a b",
    "a\tb",
    "a~1",
    "a^1",
    "a:b",
    "a\\b",
    "a@{1}",
    "@",
    "-main",
    "main.",
    "main.lock",
    "release/.hidden",
    "release/v1.lock",
    "/main",
    "main/",
    "a//b",
    ".",
    "..",
  ])("refuses the branch %j", (branch) => {
    expect(() => spec.policy({ repo: "api", branch, allowed: true })).toThrow();
  });

  it("refuses a repo name that could change the URL", () => {
    expect(() =>
      spec.policy({ repo: "..", branch: "main", allowed: true })
    ).toThrow();
  });

  it("requires `allowed`", () => {
    expect(() => spec.policy({ repo: "api", branch: "main" })).toThrow();
  });
});

describe("listerQuery", () => {
  it("reads one user's bypass of one branch", () => {
    const query = {
      type: "bypass-allowance",
      context: CREDENTIALS,
      repo: "api",
      branch: "release/2026.10",
      login: "octocat",
    };
    expect(spec.listerQuery(query)).toEqual(query);
  });

  it("lists one repo's protected branches", () => {
    const query = {
      type: "protected-branch",
      context: CREDENTIALS,
      repo: "api",
    };
    expect(spec.listerQuery(query)).toEqual(query);
  });

  it("answers the shared user lookups", () => {
    const query = { type: "account", context: CREDENTIALS, login: "octocat" };
    expect(spec.listerQuery(query)).toEqual(query);
  });

  it("refuses a wildcard branch", () => {
    expect(() =>
      spec.listerQuery({
        type: "bypass-allowance",
        context: CREDENTIALS,
        repo: "api",
        branch: "release/*",
        login: "octocat",
      })
    ).toThrow();
  });
});

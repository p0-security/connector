import { inspect } from "node:util";
import { describe, expect, it } from "vitest";

import { appCredentials } from "../../common/definition.ts";
import { spec } from "../definition.ts";

const AWS_KEY = {
  manager: "aws",
  secretId: "arn:aws:secretsmanager:us-west-2:123456789012:secret:gh-app-key",
  region: "us-west-2",
};
const GCP_KEY = {
  manager: "gcp",
  secretId: "projects/acme-prod/secrets/github-app-key",
  projectId: "acme-prod",
};
const CREDENTIALS = { org: "acme", appId: "123456", privateKey: AWS_KEY };

const CONTEXT = { ...CREDENTIALS, requestId: "req-1", githubUserId: "583231" };

describe("userBody", () => {
  it("is the bare login", () => {
    expect(spec.userBody("octocat")).toBe("octocat");
  });

  it("rejects the old object body", () => {
    expect(() =>
      spec.userBody({ org: "acme", repo: "api", login: "octocat" })
    ).toThrow();
  });
});

// Each of these becomes a URL path segment, so nothing that could change the
// URL gets in: no `/`, and no `.` or `..` for fetch to resolve away.
describe("GitHub name formats", () => {
  const directRole = {
    context: CREDENTIALS,
    type: "direct-role",
    repo: "api",
    login: "octocat",
  };
  const parse = (override: { org?: string; repo?: string; login?: string }) => {
    const { org, ...fields } = override;
    return spec.listerQuery({
      ...directRole,
      ...fields,
      ...(org !== undefined ? { context: { ...CREDENTIALS, org } } : {}),
    });
  };

  it.each([
    ["an org with hyphens", { org: "acme-corp" }],
    ["a 39-character org", { org: "a".repeat(39) }],
    ["a login with hyphens", { login: "octo-cat" }],
    ["an Enterprise Managed User login", { login: "octocat_acme" }],
    ["a repo with dots and underscores", { repo: "api.v2_beta-1" }],
    ["a repo starting with a dot", { repo: ".github" }],
    ["a 100-character repo", { repo: "r".repeat(100) }],
  ])("accepts %s", (_case, override) => {
    expect(() => parse(override)).not.toThrow();
  });

  it.each([
    ["an org/repo pair as the repo", { repo: "acme/api" }],
    ["a repo of .", { repo: "." }],
    ["a repo of ..", { repo: ".." }],
    ["a 101-character repo", { repo: "r".repeat(101) }],
    ["an empty repo", { repo: "" }],
    ["a login of ..", { login: ".." }],
    ["a login with a slash", { login: "octo/cat" }],
    ["a login starting with a hyphen", { login: "-octocat" }],
    ["a 40-character login", { login: "a".repeat(40) }],
    ["an org with a slash", { org: "acme/x" }],
    ["an org with an underscore", { org: "acme_corp" }],
    ["an org of ..", { org: ".." }],
  ])("rejects %s", (_case, override) => {
    expect(() => parse(override)).toThrow();
  });

  it("applies to the user body", () => {
    expect(spec.userBody("octocat_acme")).toBe("octocat_acme");
    expect(() => spec.userBody("..")).toThrow();
    expect(() => spec.userBody("octo/cat")).toThrow();
  });

  it("applies to the request context", () => {
    expect(() => spec.requestContext({ ...CONTEXT, org: "../x" })).toThrow();
  });

  it("applies to the policy's repo", () => {
    expect(() => spec.policy({ repo: "acme/api", role: "push" })).toThrow();
    expect(() => spec.policy({ repo: "..", role: "push" })).toThrow();
  });

  it("applies to list queries", () => {
    const directRole = {
      context: CREDENTIALS,
      type: "direct-role",
      repo: "api",
      login: "octocat",
    };
    expect(() => spec.listerQuery({ ...directRole, repo: "." })).toThrow();
    expect(() => spec.listerQuery({ ...directRole, login: ".." })).toThrow();
    expect(() =>
      spec.listerQuery({
        context: { ...CREDENTIALS, org: "a/b" },
        type: "repository",
      })
    ).toThrow();
  });

  it("applies to the user id", () => {
    expect(spec.userId("octocat_acme")).toBe("octocat_acme");
    expect(() => spec.userId("..")).toThrow();
  });
});

describe("userId", () => {
  it("is a non-empty string", () => {
    expect(spec.userId("octocat")).toBe("octocat");
    expect(() => spec.userId("")).toThrow();
  });
});

describe("policy", () => {
  it("is a repo and the role to leave the user with on it", () => {
    expect(spec.policy({ repo: "api", role: "triage_plus" })).toEqual({
      repo: "api",
      role: "triage_plus",
    });
  });

  // A revoke to someone who had no direct role before the grant.
  it("takes a null role, for no direct role", () => {
    expect(spec.policy({ repo: "api", role: null })).toEqual({
      repo: "api",
      role: null,
    });
  });

  it.each([
    ["a bare role", "push"],
    ["an empty role", { repo: "api", role: "" }],
    ["no role at all", { repo: "api" }],
    ["no repo", { role: "push" }],
  ])("rejects %s", (_case, policy) => {
    expect(() => spec.policy(policy)).toThrow();
  });
});

describe("requestContext", () => {
  it("parses a pointer into either vault", () => {
    expect(spec.requestContext(CONTEXT)).toEqual(CONTEXT);
    expect(spec.requestContext({ ...CONTEXT, privateKey: GCP_KEY })).toEqual({
      ...CONTEXT,
      privateKey: GCP_KEY,
    });
  });

  it("carries only a pointer, never key material", () => {
    const parsed = spec.requestContext({
      ...CONTEXT,
      privateKey: { ...AWS_KEY, pem: "-----BEGIN RSA PRIVATE KEY-----" },
    });
    expect(parsed.privateKey).toEqual(AWS_KEY);
  });

  // A login can change hands, but the GitHub user id can't.
  it("requires the GitHub user id", () => {
    const { githubUserId: _githubUserId, ...withoutGithubUserId } = CONTEXT;
    expect(() => spec.requestContext(withoutGithubUserId)).toThrow();
  });

  it.each([
    ["a login", "octocat"],
    ["a number", 583231],
    ["an empty string", ""],
    ["a negative id", "-1"],
    ["a 17-digit id", "1".repeat(17)],
    // One past Number.MAX_SAFE_INTEGER, which parses to the same number as it.
    ["an id above the largest safe integer", "9007199254740992"],
    // `String` would write it back without the zero, and match nothing.
    ["an id with a leading zero", "0583231"],
    ["an id of zero", "0"],
    ["a path", "583231/../1"],
  ])("rejects %s as the GitHub user id", (_case, githubUserId) => {
    expect(() => spec.requestContext({ ...CONTEXT, githubUserId })).toThrow();
  });

  it("accepts the largest safe integer as the GitHub user id", () => {
    const githubUserId = String(Number.MAX_SAFE_INTEGER);
    expect(spec.requestContext({ ...CONTEXT, githubUserId }).githubUserId).toBe(
      githubUserId
    );
  });

  it.each([
    ["an AWS pointer without its region", { manager: "aws" }],
    ["a Google pointer without its project", { manager: "gcp" }],
    [
      "a Google pointer with a region in place of its project",
      { manager: "gcp", region: "us-central1" },
    ],
    [
      "a pointer into a vault the connector doesn't know",
      { manager: "azure", region: "westus" },
    ],
  ])("rejects %s", (_case, pointer) => {
    expect(() =>
      spec.requestContext({
        ...CONTEXT,
        privateKey: { ...pointer, secretId: "github-app-key" },
      })
    ).toThrow();
  });
});

// Google's client reads a resource name as it is, so one in another project
// would read a secret the pointer's project doesn't name.
describe("a Google pointer's secret", () => {
  const parse = (secretId: string) =>
    spec.requestContext({ ...CONTEXT, privateKey: { ...GCP_KEY, secretId } });

  it.each([
    ["its resource name", "projects/acme-prod/secrets/github-app-key"],
    ["its ID alone", "github-app-key"],
    ["a 255-character ID", "a".repeat(255)],
  ])("accepts %s", (_case, secretId) => {
    expect(() => parse(secretId)).not.toThrow();
  });

  it.each([
    [
      "a resource name in another project",
      "projects/acme-other/secrets/github-app-key",
    ],
    [
      "a version's resource name",
      "projects/acme-prod/secrets/github-app-key/versions/1",
    ],
    ["an ID with a slash", "github/app-key"],
    ["an ID with a dot", "github.app-key"],
    ["a 256-character ID", "a".repeat(256)],
  ])("rejects %s", (_case, secretId) => {
    expect(() => parse(secretId)).toThrow();
  });
});

describe("the private key pointer", () => {
  const SENTINEL = "SENTINEL-key-body-7f3a9c";
  const PEM = `-----BEGIN RSA PRIVATE KEY-----\n${SENTINEL}\n-----END RSA PRIVATE KEY-----`;

  const thrown = (run: () => unknown): unknown => {
    try {
      run();
    } catch (error) {
      return error;
    }
    throw new Error("expected the call to throw");
  };

  // P0 sends where the key is, never the key: the connector reads it itself.
  it.each([
    [
      "the install's credentials",
      (privateKey: unknown) =>
        appCredentials.parse({ ...CREDENTIALS, privateKey }),
    ],
    [
      "the request context",
      (privateKey: unknown) => spec.requestContext({ ...CONTEXT, privateKey }),
    ],
    [
      "a list query's context",
      (privateKey: unknown) =>
        spec.listerQuery({
          type: "repository",
          context: { ...CREDENTIALS, privateKey },
        }),
    ],
  ])("refuses the key itself in %s, without repeating it", (_case, parse) => {
    const error = thrown(() => parse(PEM));

    expect(inspect(error, { depth: null })).not.toContain(SENTINEL);
    expect(JSON.stringify(error)).not.toContain(SENTINEL);
  });

  // The secret id is any non-empty string, so a key pasted into it is sent to
  // the vault as a name and quoted back in the not-found message. See
  // key-containment.test.ts.
  it.fails("refuses a key pasted where the secret id goes", () => {
    expect(() =>
      spec.requestContext({
        ...CONTEXT,
        privateKey: { ...AWS_KEY, secretId: PEM },
      })
    ).toThrow();
  });
});

describe("listerQuery", () => {
  it.each([
    { type: "repository" },
    { type: "role" },
    { type: "direct-role", repo: "api", login: "octocat" },
    { type: "member", email: "octocat@acme.com" },
    { type: "account", login: "octocat" },
    { type: "repository-id", repo: "api" },
  ])(
    "parses a $type query carrying the credentials as its context",
    (query) => {
      expect(spec.listerQuery({ context: CREDENTIALS, ...query })).toEqual({
        context: CREDENTIALS,
        ...query,
      });
    }
  );

  it("rejects credentials beside the context instead of in it", () => {
    expect(() =>
      spec.listerQuery({ ...CREDENTIALS, type: "repository" })
    ).toThrow();
  });

  it("rejects a direct-role query without a login", () => {
    expect(() =>
      spec.listerQuery({
        context: CREDENTIALS,
        type: "direct-role",
        repo: "api",
      })
    ).toThrow();
  });

  it("rejects an account query without a valid login", () => {
    expect(() =>
      spec.listerQuery({ context: CREDENTIALS, type: "account" })
    ).toThrow();
    expect(() =>
      spec.listerQuery({ context: CREDENTIALS, type: "account", login: ".." })
    ).toThrow();
  });

  it("rejects a repository-id query without a valid repo", () => {
    expect(() =>
      spec.listerQuery({ context: CREDENTIALS, type: "repository-id" })
    ).toThrow();
    expect(() =>
      spec.listerQuery({
        context: CREDENTIALS,
        type: "repository-id",
        repo: "..",
      })
    ).toThrow();
  });

  it("rejects a query without credentials", () => {
    expect(() =>
      spec.listerQuery({ type: "repository", context: { org: "acme" } })
    ).toThrow();
  });

  it("rejects an unknown type", () => {
    expect(() =>
      spec.listerQuery({ context: CREDENTIALS, type: "team" })
    ).toThrow();
  });
});

describe("setPoliciesForUser", () => {
  // A revoke sends the role from before the grant as the policy.
  it("parses the role to leave the user with", () => {
    const args = {
      userId: "octocat",
      userBody: "octocat",
      policies: [{ repo: "api", role: "pull" }],
      context: CONTEXT,
    };
    expect(spec.setPoliciesForUser(args)).toEqual(args);
  });

  it("rejects a role without its repo", () => {
    expect(() =>
      spec.setPoliciesForUser({
        userId: "octocat",
        userBody: "octocat",
        policies: ["pull"],
        context: CONTEXT,
      })
    ).toThrow();
  });
});

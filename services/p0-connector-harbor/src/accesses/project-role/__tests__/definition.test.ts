import { inspect } from "node:util";
import { describe, expect, it } from "vitest";

import { harborRole, instance, schema, spec } from "../definition.ts";

const GCP_SECRET = {
  manager: "gcp",
  projectId: "acme-vault",
  secretId: "harbor-admin",
};
const AWS_SECRET = {
  manager: "aws",
  region: "us-west-2",
  // A partial ARN, which is how a secret in another account is named.
  secretId: "arn:aws:secretsmanager:us-west-2:123456789012:secret:harbor-admin",
};
const INSTANCE = { url: "https://harbor.example.com", secret: GCP_SECRET };

const CONTEXT = {
  ...INSTANCE,
  requestId: "req-1",
  email: "alice@example.com",
  priorRole: null,
};

// Stands in for a credential: the admin credential's secret, or a password in a URL.
const SENTINEL = "SENTINEL-credential-secret-7f3a9c";

describe("harborRole", () => {
  it.each(["projectAdmin", "maintainer", "developer", "guest", "limitedGuest"])(
    "accepts %s",
    (role) => {
      expect(harborRole.parse(role)).toBe(role);
    }
  );

  it.each([
    ["a role Harbor doesn't have", "owner"],
    ["a role in another case", "ProjectAdmin"],
    ["Harbor's display name", "Project Admin"],
    ["a Harbor role id", 1],
    ["an empty role", ""],
  ])("rejects %s", (_case, role) => {
    expect(() => harborRole.parse(role)).toThrow();
  });
});

describe("userBody", () => {
  it("is the instance's id and the Harbor user id", () => {
    const body = { instanceId: "p0-harbor", userId: "42" };
    expect(spec.userBody(body)).toEqual(body);
  });

  it.each([
    ["a bare user id", "42"],
    ["no instance id", { userId: "42" }],
    ["an empty instance id", { instanceId: "", userId: "42" }],
    ["no user id", { instanceId: "p0-harbor" }],
    ["a username as the user id", { instanceId: "p0-harbor", userId: "alice" }],
    ["a numeric user id", { instanceId: "p0-harbor", userId: 42 }],
  ])("rejects %s", (_case, body) => {
    expect(() => spec.userBody(body)).toThrow();
  });
});

describe("userId", () => {
  it("is Harbor's user id as a decimal string", () => {
    expect(spec.userId("42")).toBe("42");
  });

  it("accepts the largest safe integer", () => {
    const userId = String(Number.MAX_SAFE_INTEGER);
    expect(spec.userId(userId)).toBe(userId);
  });

  it.each([
    ["a username", "alice"],
    ["a number", 42],
    ["an empty string", ""],
    ["a negative id", "-1"],
    ["a fraction", "4.2"],
    ["a 17-digit id", "1".repeat(17)],
    // One past Number.MAX_SAFE_INTEGER: the first id that another id, the one
    // after it, also parses to.
    ["an id above the largest safe integer", "9007199254740992"],
    // `String` would write it back without the zero, and match nothing.
    ["an id with a leading zero", "042"],
    ["an id of zero", "0"],
    ["an id in exponent form", "1e3"],
    ["an id after a space", " 42"],
    ["an id before a space", "42 "],
    ["an id before a newline", "42\n"],
    ["a path", "42/../1"],
  ])("rejects %s", (_case, userId) => {
    expect(() => spec.userId(userId)).toThrow();
  });

  it("reports a malformed id once", () => {
    expect(schema.userId.safeParse("alice").error?.issues).toHaveLength(1);
  });
});

// A project name becomes a URL path segment, so nothing that could change the
// URL gets in: no `/`, and no `.` or `..` for fetch to resolve away.
describe("project names", () => {
  // `safeParse`, so a name the pattern itself choked on would fail the test.
  const parse = (project: string) =>
    schema.policy.safeParse({ project, role: "guest" });

  it.each([
    ["a plain name", "library"],
    ["a one-character name", "a"],
    ["an all-digit name", "2026"],
    ["a name with single separators", "team-a.images_v2"],
    ["a 255-character name", "p".repeat(255)],
  ])("accepts %s", (_case, project) => {
    expect(parse(project).data).toEqual({ project, role: "guest" });
  });

  it.each([
    ["an empty name", ""],
    ["a 256-character name", "p".repeat(256)],
    ["an upper-case name", "Library"],
    ["a project/repository pair", "library/nginx"],
    ["a name of .", "."],
    ["a name of ..", ".."],
    ["a path", "../library"],
    ["a name starting with a separator", "-library"],
    ["a name ending with a separator", "library."],
    ["two separators in a row", "team--a"],
    ["a name with a space", "team a"],
    ["a name before a newline", "library\n"],
    ["a name with .. on a second line", "library\n.."],
    ["an encoded slash", "team%2Fa"],
  ])("rejects %s", (_case, project) => {
    expect(parse(project).success).toBe(false);
  });

  // The length check refuses an over-long name alone. The pattern would
  // report the first of these a second time, and overflows the stack on the
  // second.
  it.each([
    ["a 256-character name that also breaks the pattern", "P".repeat(256)],
    ["an 8 MB name", `${"a.".repeat(4_000_000)}a`],
  ])("reports %s once", (_case, project) => {
    expect(parse(project).error?.issues).toHaveLength(1);
  });

  it("applies to a direct-role query", () => {
    const query = { type: "direct-role", context: INSTANCE, userId: "42" };
    expect(() => spec.listerQuery({ ...query, project: ".." })).toThrow();
    expect(() =>
      spec.listerQuery({ ...query, project: "library/nginx" })
    ).toThrow();
  });
});

describe("policy", () => {
  it("is a project and the role to leave the user with on it", () => {
    const policy = { project: "library", role: "maintainer" };
    expect(spec.policy(policy)).toEqual(policy);
  });

  // A revoke: no P0 grant is open on the project any more.
  it("takes a null role, for no open grant", () => {
    const policy = { project: "library", role: null };
    expect(spec.policy(policy)).toEqual(policy);
  });

  it.each([
    ["a bare role", "maintainer"],
    ["a role Harbor doesn't have", { project: "library", role: "owner" }],
    ["a Harbor role id", { project: "library", role: 4 }],
    ["an empty role", { project: "library", role: "" }],
    ["no role at all", { project: "library" }],
    ["no project", { role: "maintainer" }],
  ])("rejects %s", (_case, policy) => {
    expect(() => spec.policy(policy)).toThrow();
  });
});

describe("the instance URL", () => {
  // `safeParse`, so a URL the parser itself choked on would fail the test.
  const parse = (url: unknown) => instance.safeParse({ ...INSTANCE, url });

  it.each([
    ["a host", "https://harbor.example.com"],
    ["a port", "https://localhost:8443"],
    ["an IP address", "https://10.0.0.7"],
  ])("takes https with %s, unchanged", (_case, url) => {
    expect(parse(url).data?.url).toBe(url);
  });

  // Whatever spelling P0 sends, callers build on the one origin.
  it.each([
    ["a trailing slash", "https://harbor.example.com/"],
    ["the default port", "https://harbor.example.com:443"],
    ["upper case", "HTTPS://Harbor.Example.COM"],
    ["no slashes after the scheme", "https:harbor.example.com"],
    ["backslashes for slashes", "https:\\\\harbor.example.com\\"],
    ["whitespace around it", "  https://harbor.example.com\n"],
    ["a tab and a newline inside it", "https://harbor\t.example\n.com"],
    ["an empty query and fragment", "https://harbor.example.com/?#"],
  ])("takes %s, as the origin", (_case, url) => {
    expect(parse(url).data?.url).toBe("https://harbor.example.com");
  });

  // The admin account's ID token goes to this URL on every call.
  it.each([
    ["plain http", "http://harbor.example.com"],
    ["a scheme that only starts with https", "httpss://harbor.example.com/"],
    ["another scheme", "ftp://harbor.example.com"],
    ["no scheme", "harbor.example.com"],
    ["a scheme-relative URL", "//harbor.example.com"],
    ["an empty string", ""],
    ["no URL at all", undefined],
  ])("rejects %s", (_case, url) => {
    expect(parse(url).success).toBe(false);
  });

  // An instance is an origin. A caller appends the API path to it, which a
  // query or a fragment would swallow.
  it.each([
    ["a path", "https://harbor.example.com/harbor"],
    ["Harbor's API path", "https://harbor.example.com/api/v2.0"],
    ["a second slash", "https://harbor.example.com//"],
    ["a query", "https://harbor.example.com/?page=1"],
    ["a fragment", "https://harbor.example.com/#projects"],
  ])("rejects %s", (_case, url) => {
    expect(parse(url).success).toBe(false);
  });

  // A URL gets logged and quoted, so it is no place for a credential, and
  // refusing one must not repeat it. The last two don't parse as URLs at all:
  // `new URL` throws on them, with an error that carries its input.
  it.each([
    [
      "a username and password",
      `https://robot$p0-connector:${SENTINEL}@harbor.example.com`,
    ],
    ["a username alone", `https://${SENTINEL}@harbor.example.com`],
    ["a password alone", `https://:${SENTINEL}@harbor.example.com`],
    ["a password and no host", `https://robot:${SENTINEL}@`],
    [
      "a password and a port that isn't one",
      `https://robot:${SENTINEL}@harbor.example.com:port`,
    ],
  ])("rejects %s, without repeating it", (_case, url) => {
    const { success, error } = parse(url);

    expect(success).toBe(false);
    expect(inspect(error, { depth: null })).not.toContain(SENTINEL);
    expect(JSON.stringify(error)).not.toContain(SENTINEL);
  });

  it("applies to the request context and to a list query's context", () => {
    const url = "http://harbor.example.com";
    expect(() => spec.requestContext({ ...CONTEXT, url })).toThrow();
    expect(() =>
      spec.listerQuery({ type: "project", context: { ...INSTANCE, url } })
    ).toThrow();
  });
});

describe("requestContext", () => {
  it.each([
    ["GCP Secret Manager", GCP_SECRET],
    ["AWS Secrets Manager", AWS_SECRET],
  ])("parses a pointer into %s", (_case, secret) => {
    const context = { ...CONTEXT, secret };
    expect(spec.requestContext(context)).toEqual(context);
  });

  it.each(["requestId", "email", "url", "secret"])("requires %s", (field) => {
    const { [field]: _omitted, ...rest }: Record<string, unknown> = CONTEXT;
    expect(() => spec.requestContext(rest)).toThrow();
  });

  it("rejects an empty email", () => {
    expect(() => spec.requestContext({ ...CONTEXT, email: "" })).toThrow();
  });

  // Whether an email is acceptable is the connector's allowlist's call, not
  // the parser's.
  it("takes the email as P0 holds it, whatever its shape", () => {
    const email = "alice";
    expect(spec.requestContext({ ...CONTEXT, email }).email).toBe(email);
  });

  // The parser drops fields it doesn't name, so a revoke could never restore
  // a prior role the schema left out.
  it.each([
    ["the prior role", "developer"],
    ["a null prior role, for a user who had none", null],
  ])("keeps %s", (_case, priorRole) => {
    expect(spec.requestContext({ ...CONTEXT, priorRole }).priorRole).toBe(
      priorRole
    );
  });

  // A missing prior role must not read as "had none", which removes the
  // member on a revoke.
  it("rejects a context without a prior role", () => {
    const { priorRole: _priorRole, ...context } = CONTEXT;
    expect(() => spec.requestContext(context)).toThrow();
    expect(() =>
      spec.requestContext({ ...context, priorRole: undefined })
    ).toThrow();
  });

  it("rejects a prior role Harbor doesn't have", () => {
    expect(() =>
      spec.requestContext({ ...CONTEXT, priorRole: "owner" })
    ).toThrow();
  });
});

describe("the secret pointer", () => {
  const CREDENTIAL = {
    issuer: "https://idp.example.com",
    clientId: "harbor",
    clientSecret: SENTINEL,
    refreshToken: SENTINEL,
  };

  const parse = (secret: unknown) =>
    instance.safeParse({ ...INSTANCE, secret });

  it.each([
    ["a GCP secret name of letters, digits, _ and -", "Harbor_admin-2"],
    ["a 255-character GCP secret name", "s".repeat(255)],
  ])("accepts %s", (_case, secretId) => {
    const secret = { ...GCP_SECRET, secretId };
    expect(parse(secret).data?.secret).toEqual(secret);
  });

  it.each([
    [
      "a GCP project id of 6 characters",
      { ...GCP_SECRET, projectId: "acme-1" },
    ],
    [
      "a GCP project id of 30 characters",
      { ...GCP_SECRET, projectId: `a${"b".repeat(29)}` },
    ],
    ["an AWS region", { ...AWS_SECRET, region: "eu-central-1" }],
    ["an AWS GovCloud region", { ...AWS_SECRET, region: "us-gov-west-1" }],
  ])("accepts %s", (_case, secret) => {
    expect(parse(secret).data?.secret).toEqual(secret);
  });

  it.each([
    ["a GCP pointer with an empty project", { ...GCP_SECRET, projectId: "" }],
    ["a GCP pointer without its project", { manager: "gcp", secretId: "x" }],
    ["a GCP pointer with an empty secret id", { ...GCP_SECRET, secretId: "" }],
    [
      "a GCP pointer without a secret id",
      { manager: "gcp", projectId: "acme-vault" },
    ],
    // The project is a segment of the path the read is sent to.
    [
      "a GCP project that carries a path of its own",
      { ...GCP_SECRET, projectId: "p/secrets/other/versions/3:access#" },
    ],
    ["a GCP project of five characters", { ...GCP_SECRET, projectId: "acme1" }],
    [
      "a GCP project of 31 characters",
      { ...GCP_SECRET, projectId: `a${"b".repeat(30)}` },
    ],
    ["a GCP project in upper case", { ...GCP_SECRET, projectId: "Acme-Vault" }],
    [
      "a GCP project that starts with a digit",
      { ...GCP_SECRET, projectId: "1acme-vault" },
    ],
    [
      "a GCP project that ends in a hyphen",
      { ...GCP_SECRET, projectId: "acme-vault-" },
    ],
    [
      "a GCP project with a domain",
      { ...GCP_SECRET, projectId: "example.com:vault" },
    ],
    [
      "a GCP project with a trailing newline",
      { ...GCP_SECRET, projectId: "acme-vault\n" },
    ],
    // The region is a label of the host the read is sent to.
    [
      "an AWS region that carries a host",
      { ...AWS_SECRET, region: "us-west-2.evil.example" },
    ],
    ["an AWS region with a path", { ...AWS_SECRET, region: "us-west-2/x" }],
    ["an AWS region in upper case", { ...AWS_SECRET, region: "US-WEST-2" }],
    ["an AWS region with a space", { ...AWS_SECRET, region: "us west 2" }],
    [
      "an AWS region with a trailing newline",
      { ...AWS_SECRET, region: "us-west-2\n" },
    ],
    [
      "a 256-character GCP secret name",
      { ...GCP_SECRET, secretId: "s".repeat(256) },
    ],
    // The secret manager client reads a full resource name as it stands,
    // whatever the pointer's own project.
    [
      "a GCP secret id that names another project",
      { ...GCP_SECRET, secretId: "projects/other/secrets/harbor-admin" },
    ],
    [
      "a GCP secret id that names a version",
      { ...GCP_SECRET, secretId: "harbor-admin/versions/3" },
    ],
    ["an AWS pointer with an empty region", { ...AWS_SECRET, region: "" }],
    ["an AWS pointer without its region", { manager: "aws", secretId: "x" }],
    ["an AWS pointer with an empty secret id", { ...AWS_SECRET, secretId: "" }],
    [
      "an AWS pointer located by a GCP project",
      { manager: "aws", projectId: "acme-vault", secretId: "harbor-admin" },
    ],
    ["another secret manager", { ...GCP_SECRET, manager: "azure" }],
  ])("rejects %s", (_case, secret) => {
    expect(parse(secret).success).toBe(false);
  });

  // P0 sends where the credential is, never the credential: the connector
  // reads it itself.
  it.each([
    ["the admin credential's JSON", JSON.stringify(CREDENTIAL)],
    ["the admin credential", CREDENTIAL],
  ])("rejects %s where the pointer goes", (_case, secret) => {
    expect(parse(secret).success).toBe(false);
  });

  it.each([
    ["a GCP", GCP_SECRET],
    ["an AWS", AWS_SECRET],
  ])("drops a credential sent beside %s pointer", (_case, pointer) => {
    expect(parse({ ...pointer, ...CREDENTIAL }).data?.secret).toEqual(pointer);
  });

  it("rejects a credential pasted where the GCP secret id goes", () => {
    const secretId = JSON.stringify(CREDENTIAL);
    expect(parse({ ...GCP_SECRET, secretId }).success).toBe(false);
  });

  // The AWS secret id is any non-empty string, because it can be a name or a
  // partial ARN. So a credential pasted into it parses, and whatever reads
  // the secret sends it to Secrets Manager as a name.
  it.fails("rejects a credential pasted where the AWS secret id goes", () => {
    const secretId = JSON.stringify(CREDENTIAL);
    expect(parse({ ...AWS_SECRET, secretId }).success).toBe(false);
  });
});

describe("listerQuery", () => {
  it.each([
    { type: "project" },
    { type: "project", project: "library" },
    { type: "member", email: "alice@example.com" },
    { type: "direct-role", project: "library", userId: "42" },
  ])("parses a $type query carrying the instance as its context", (query) => {
    expect(spec.listerQuery({ context: INSTANCE, ...query })).toEqual({
      context: INSTANCE,
      ...query,
    });
  });

  // `list` gets no request context: a query's context is the instance alone.
  it("drops what a request context adds to the instance", () => {
    const parsed = spec.listerQuery({ type: "project", context: CONTEXT });
    expect(parsed.context).toEqual(INSTANCE);
  });

  it("rejects the instance beside the context instead of in it", () => {
    expect(() => spec.listerQuery({ ...INSTANCE, type: "project" })).toThrow();
  });

  it("rejects a context without the secret pointer", () => {
    expect(() =>
      spec.listerQuery({ type: "project", context: { url: INSTANCE.url } })
    ).toThrow();
  });

  // A18: the project is held to Harbor's rule, as everywhere else.
  it.each(["", "..", "Library", "library/nginx", "a".repeat(256)])(
    "rejects a project query for the project %j",
    (project) => {
      expect(() =>
        spec.listerQuery({ type: "project", context: INSTANCE, project })
      ).toThrow();
    }
  );

  it("rejects a member query without an email", () => {
    const query = { type: "member", context: INSTANCE };
    expect(() => spec.listerQuery(query)).toThrow();
    expect(() => spec.listerQuery({ ...query, email: "" })).toThrow();
  });

  it.each([
    ["no project", { userId: "42" }],
    ["no user id", { project: "library" }],
    ["a username as the user id", { project: "library", userId: "alice" }],
  ])("rejects a direct-role query with %s", (_case, fields) => {
    expect(() =>
      spec.listerQuery({ type: "direct-role", context: INSTANCE, ...fields })
    ).toThrow();
  });

  it("rejects an unknown type", () => {
    expect(() =>
      spec.listerQuery({ type: "role", context: INSTANCE })
    ).toThrow();
  });
});

describe("listerResponse", () => {
  it("is a list of items", () => {
    const items = [
      { key: "42", value: "alice" },
      { key: "library", value: "library", group: "Projects" },
    ];
    expect(spec.listerResponse(items)).toEqual(items);
    expect(spec.listerResponse([])).toEqual([]);
  });

  // A lookup answers with an item too: a Harbor user is `{ key, value }`, not
  // Harbor's own row.
  it("rejects a Harbor user row", () => {
    expect(() =>
      spec.listerResponse([{ user_id: 42, username: "alice" }])
    ).toThrow();
  });

  it("rejects a user id that is still a number", () => {
    expect(() => spec.listerResponse([{ key: 42, value: "alice" }])).toThrow();
  });
});

describe("identifyUser", () => {
  it("parses the user body and the request context", () => {
    const args = {
      userBody: { instanceId: "p0-harbor", userId: "42" },
      context: CONTEXT,
    };
    expect(spec.identifyUser(args)).toEqual(args);
  });
});

describe("setPoliciesForUser", () => {
  const USER_BODY = { instanceId: "p0-harbor", userId: "42" };

  it("parses a grant", () => {
    const args = {
      userId: "42",
      userBody: USER_BODY,
      policies: [{ project: "library", role: "maintainer" }],
      context: { ...CONTEXT, priorRole: "guest" },
    };
    expect(spec.setPoliciesForUser(args)).toEqual(args);
  });

  // A revoke sends a null role, and the role to restore in the context.
  it("parses a revoke", () => {
    const args = {
      userId: "42",
      userBody: USER_BODY,
      policies: [{ project: "library", role: null }],
      context: { ...CONTEXT, priorRole: "guest" },
    };
    expect(spec.setPoliciesForUser(args)).toEqual(args);
  });

  // Its user body names the user by id, so the context has to carry the email.
  it("rejects a context without the email", () => {
    const { email: _email, ...context } = CONTEXT;
    expect(() =>
      spec.setPoliciesForUser({
        userId: "42",
        userBody: USER_BODY,
        policies: [{ project: "library", role: "maintainer" }],
        context,
      })
    ).toThrow();
  });

  it("rejects a role without its project", () => {
    expect(() =>
      spec.setPoliciesForUser({
        userId: "42",
        userBody: USER_BODY,
        policies: ["maintainer"],
        context: CONTEXT,
      })
    ).toThrow();
  });
});

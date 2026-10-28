// The URL and secret pointer cases are a copy of
// services/p0-connector-harbor/src/accesses/project-role/__tests__/definition.test.ts,
// with Argo CD's names.
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";

import { instance } from "../instance.ts";

const GCP_SECRET = {
  manager: "gcp",
  projectId: "acme-vault",
  secretId: "argocd-token",
};
const AWS_SECRET = {
  manager: "aws",
  region: "us-west-2",
  // A partial ARN, which is how a secret in another account is named.
  secretId: "arn:aws:secretsmanager:us-west-2:123456789012:secret:argocd-token",
};
const INSTANCE = {
  url: "https://argocd.example.com",
  managingApp: "platform/argocd",
  namespace: "argocd",
  secret: GCP_SECRET,
};

// Stands in for a credential: the API token, or a password in a URL.
const SENTINEL = "SENTINEL-argocd-token-3e81b2";

describe("instance", () => {
  it("parses an instance, unchanged", () => {
    expect(instance.parse(INSTANCE)).toStrictEqual(INSTANCE);
  });

  it.each(["url", "managingApp", "secret"])("requires %s", (field) => {
    const { [field]: _omitted, ...rest }: Record<string, unknown> = INSTANCE;
    expect(instance.safeParse(rest).success).toBe(false);
  });

  // Argo CD installs into `argocd` unless someone chose otherwise.
  it("takes argocd as the namespace when none is given", () => {
    const { namespace: _namespace, ...rest } = INSTANCE;
    expect(instance.parse(rest).namespace).toBe("argocd");
  });

  it("drops fields it doesn't name", () => {
    expect(instance.parse({ ...INSTANCE, admin: true })).toStrictEqual(
      INSTANCE
    );
  });
});

describe("the managing app", () => {
  const parse = (managingApp: unknown) =>
    instance.safeParse({ ...INSTANCE, managingApp });

  it.each([
    ["a project and an app", "default/argocd"],
    ["dots and hyphens in both", "platform.prod/argo-cd.rbac"],
    ["digits", "p0/app-1"],
    ["253 characters on each side", `${"p".repeat(253)}/${"a".repeat(253)}`],
  ])("takes %s, unchanged", (_case, managingApp) => {
    expect(parse(managingApp).data?.managingApp).toBe(managingApp);
  });

  // Each half becomes part of an Argo CD API path or query, so each is held
  // to the Kubernetes name rule Argo CD holds them to.
  it.each([
    ["an app alone", "argocd"],
    ["an empty project", "/argocd"],
    ["an empty app", "default/"],
    ["a third segment", "default/argocd/extra"],
    ["upper case", "Default/ArgoCD"],
    ["an underscore", "default/argo_cd"],
    ["a leading hyphen", "default/-argocd"],
    ["a trailing dot", "default/argocd."],
    ["two dots in a row", "default/argo..cd"],
    ["a path traversal", "../argocd"],
    ["a space", "default/argo cd"],
    ["a trailing newline", "default/argocd\n"],
    ["a query", "default/argocd?project=x"],
    ["254 characters in the app", `default/${"a".repeat(254)}`],
    ["254 characters in the project", `${"p".repeat(254)}/argocd`],
    ["an empty string", ""],
    ["a number", 7],
  ])("rejects %s", (_case, managingApp) => {
    expect(parse(managingApp).success).toBe(false);
  });

  // The length check stops the parse before the pattern runs.
  it("rejects a name of a few megabytes without running out of stack", () => {
    expect(parse(`default/${"a".repeat(4_000_000)}`).success).toBe(false);
  });
});

describe("the namespace", () => {
  const parse = (namespace: unknown) =>
    instance.safeParse({ ...INSTANCE, namespace });

  it.each([
    ["argocd", "argocd"],
    ["a hyphen", "argo-cd"],
    ["digits", "argocd2"],
    ["63 characters", "n".repeat(63)],
  ])("takes %s, unchanged", (_case, namespace) => {
    expect(parse(namespace).data?.namespace).toBe(namespace);
  });

  // A namespace is a Kubernetes label: no dots, at most 63 characters.
  it.each([
    ["a dot", "argo.cd"],
    ["upper case", "ArgoCD"],
    ["a leading hyphen", "-argocd"],
    ["a trailing hyphen", "argocd-"],
    ["64 characters", "n".repeat(64)],
    ["a slash", "argocd/x"],
    ["an empty string", ""],
    ["null", null],
  ])("rejects %s", (_case, namespace) => {
    expect(parse(namespace).success).toBe(false);
  });
});

describe("the instance URL", () => {
  // `safeParse`, so a URL the parser itself choked on would fail the test.
  const parse = (url: unknown) => instance.safeParse({ ...INSTANCE, url });

  it.each([
    ["a host", "https://argocd.example.com"],
    ["a port", "https://localhost:8443"],
    ["an IP address", "https://10.0.0.7"],
  ])("takes https with %s, unchanged", (_case, url) => {
    expect(parse(url).data?.url).toBe(url);
  });

  // Whatever spelling P0 sends, callers build on the one origin.
  it.each([
    ["a trailing slash", "https://argocd.example.com/"],
    ["the default port", "https://argocd.example.com:443"],
    ["upper case", "HTTPS://ArgoCD.Example.COM"],
    ["whitespace around it", "  https://argocd.example.com\n"],
    ["an empty query and fragment", "https://argocd.example.com/?#"],
  ])("takes %s, as the origin", (_case, url) => {
    expect(parse(url).data?.url).toBe("https://argocd.example.com");
  });

  // The API token goes to this URL on every call.
  it.each([
    ["plain http", "http://argocd.example.com"],
    ["a scheme that only starts with https", "httpss://argocd.example.com/"],
    ["another scheme", "ftp://argocd.example.com"],
    ["no scheme", "argocd.example.com"],
    ["a scheme-relative URL", "//argocd.example.com"],
    ["an empty string", ""],
    ["no URL at all", undefined],
  ])("rejects %s", (_case, url) => {
    expect(parse(url).success).toBe(false);
  });

  // An instance is an origin. A caller appends the API path to it, which a
  // query or a fragment would swallow.
  it.each([
    ["a path", "https://argocd.example.com/argo-cd"],
    ["Argo CD's API path", "https://argocd.example.com/api/v1"],
    ["a second slash", "https://argocd.example.com//"],
    ["a query", "https://argocd.example.com/?page=1"],
    ["a fragment", "https://argocd.example.com/#applications"],
  ])("rejects %s", (_case, url) => {
    expect(parse(url).success).toBe(false);
  });

  // A URL gets logged and quoted, so it is no place for a credential, and
  // refusing one must not repeat it. The last two don't parse as URLs at all:
  // `new URL` throws on them, with an error that carries its input.
  it.each([
    [
      "a username and password",
      `https://p0-connector:${SENTINEL}@argocd.example.com`,
    ],
    ["a username alone", `https://${SENTINEL}@argocd.example.com`],
    ["a password alone", `https://:${SENTINEL}@argocd.example.com`],
    ["a password and no host", `https://p0:${SENTINEL}@`],
    [
      "a password and a port that isn't one",
      `https://p0:${SENTINEL}@argocd.example.com:port`,
    ],
  ])("rejects %s, without repeating it", (_case, url) => {
    const { success, error } = parse(url);

    expect(success).toBe(false);
    expect(inspect(error, { depth: null })).not.toContain(SENTINEL);
    expect(JSON.stringify(error)).not.toContain(SENTINEL);
  });
});

describe("the secret pointer", () => {
  const parse = (secret: unknown) =>
    instance.safeParse({ ...INSTANCE, secret });

  it.each([
    ["a GCP pointer", GCP_SECRET],
    ["an AWS pointer with a partial ARN", AWS_SECRET],
    [
      "a 255-character GCP secret name",
      { ...GCP_SECRET, secretId: "s".repeat(255) },
    ],
    ["an AWS GovCloud region", { ...AWS_SECRET, region: "us-gov-west-1" }],
  ])("accepts %s", (_case, secret) => {
    expect(parse(secret).data?.secret).toEqual(secret);
  });

  it.each([
    ["a GCP pointer without its project", { manager: "gcp", secretId: "x" }],
    ["a GCP pointer with an empty secret id", { ...GCP_SECRET, secretId: "" }],
    // The project is a segment of the path the read is sent to.
    [
      "a GCP project that carries a path of its own",
      { ...GCP_SECRET, projectId: "p/secrets/other/versions/3:access#" },
    ],
    [
      "a GCP project with a domain",
      { ...GCP_SECRET, projectId: "example.com:vault" },
    ],
    // A full resource name would be read whatever `projectId` says.
    [
      "a GCP secret given as a full resource name",
      { ...GCP_SECRET, secretId: "projects/other/secrets/argocd-token" },
    ],
    // The region is a label of the endpoint's host.
    [
      "an AWS region that carries a host of its own",
      { ...AWS_SECRET, region: "evil.example.com/" },
    ],
    ["an AWS pointer with an empty secret id", { ...AWS_SECRET, secretId: "" }],
    ["another secret manager", { manager: "azure", secretId: "x" }],
    ["no manager", { secretId: "x" }],
  ])("rejects %s", (_case, secret) => {
    expect(parse(secret).success).toBe(false);
  });

  // A credential pasted where the name goes must not come back in the
  // refusal.
  it("rejects a pointer without repeating it", () => {
    const { success, error } = parse({
      manager: "gcp",
      projectId: SENTINEL,
      secretId: `projects/${SENTINEL}`,
    });

    expect(success).toBe(false);
    expect(inspect(error, { depth: null })).not.toContain(SENTINEL);
  });
});

// The message is what P0 shows for a refused instance, so each rule says
// what it wants, once, without the value.
describe("a refusal's message", () => {
  it.each([
    [
      "a URL that isn't one",
      { url: "argocd" },
      "must be https://<host>[:<port>]",
    ],
    [
      "a URL with a path",
      { url: "https://argocd.example.com/argo-cd" },
      "must be https://<host>[:<port>]",
    ],
    [
      "a managing app without a project",
      { managingApp: "argocd" },
      "must be <project>/<application>",
    ],
    [
      "a managing app too long to check",
      { managingApp: `default/${"a".repeat(600)}` },
      "must be <project>/<application>",
    ],
    [
      "a namespace with a dot",
      { namespace: "argo.cd" },
      "must be a Kubernetes namespace",
    ],
    [
      "a namespace too long to check",
      { namespace: `-${"n".repeat(70)}` },
      "must be a Kubernetes namespace",
    ],
    [
      "a GCP project id",
      { secret: { ...GCP_SECRET, projectId: "Acme" } },
      "must be a Google Cloud project id",
    ],
    [
      "a GCP secret name",
      { secret: { ...GCP_SECRET, secretId: "a/b" } },
      "must be a Secret Manager secret name",
    ],
    [
      "an AWS region",
      { secret: { ...AWS_SECRET, region: "US-WEST-2" } },
      "must be an AWS region",
    ],
  ])("names what %s must be", (_case, change, message) => {
    const { error } = instance.safeParse({ ...INSTANCE, ...change });

    expect(error?.issues.map((issue) => issue.message)).toEqual([message]);
  });
});

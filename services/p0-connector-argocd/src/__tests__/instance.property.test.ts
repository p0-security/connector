/**
 * Property tests for the instance schema, which parses what P0 sends. Each
 * rule has an oracle written as plain checks on characters, apart from the
 * schema's own patterns, and inputs built to sit on both sides of every rule.
 *
 * The URL and secret pointer properties are a copy of
 * services/p0-connector-harbor/src/accesses/project-role/__tests__/definition.property.test.ts.
 *
 * A failure names the seed and the input: `PROPERTY_SEED=<n>` replays it.
 */
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { instance } from "../instance.ts";
import { propertySeed, seededRandom } from "./fixtures.ts";

const seed = propertySeed();
// Thousands of cases, which a loaded machine can take seconds over.
const OPTIONS = { timeout: 30_000 };

// Marks every value that mustn't come back in a refusal.
const MARK = "ZQJX";

const BASE = {
  url: "https://argocd.example.com",
  managingApp: "platform/argocd",
  namespace: "argocd",
  secret: { manager: "aws", region: "us-west-2", secretId: "argocd-token" },
};

const isLower = (c: string) => c >= "a" && c <= "z";
const isUpper = (c: string) => c >= "A" && c <= "Z";
const isDigit = (c: string) => c >= "0" && c <= "9";
const isAlnum = (c: string) => isLower(c) || isDigit(c);
const every = (text: string, allowed: (c: string) => boolean) =>
  [...text].every(allowed);

/** A DNS-1123 label: lowercase letters, digits and inner hyphens, 1 to 63. */
const isLabel = (text: string) =>
  text.length >= 1 &&
  text.length <= 63 &&
  isAlnum(text[0] ?? "") &&
  isAlnum(text[text.length - 1] ?? "") &&
  every(text, (c) => isAlnum(c) || c === "-");

/**
 * A DNS-1123 subdomain, as Kubernetes checks it: at most 253 characters, and
 * dot-separated parts that each start and end with a letter or a digit, with
 * hyphens between. Kubernetes holds the parts to no length of their own.
 */
const isSubdomain = (text: string) =>
  text.length >= 1 &&
  text.length <= 253 &&
  text
    .split(".")
    .every(
      (part) =>
        part.length >= 1 &&
        isAlnum(part[0] ?? "") &&
        isAlnum(part[part.length - 1] ?? "") &&
        every(part, (c) => isAlnum(c) || c === "-")
    );

const isGcpProjectId = (id: string) => {
  if (id.length < 6 || id.length > 30) return false;
  const first = id[0] ?? "";
  const last = id[id.length - 1] ?? "";
  return (
    isLower(first) &&
    (isLower(last) || isDigit(last)) &&
    every(id, (c) => isLower(c) || isDigit(c) || c === "-")
  );
};

const isGcpSecretName = (name: string) =>
  name.length >= 1 &&
  name.length <= 255 &&
  every(
    name,
    (c) => isLower(c) || isUpper(c) || isDigit(c) || c === "_" || c === "-"
  );

const isAwsRegion = (region: string) =>
  region.length >= 1 &&
  every(region, (c) => isLower(c) || isDigit(c) || c === "-");

/** The generators every test shares, on one seeded source. */
const generators = () => {
  const random = seededRandom(seed);
  const int = (below: number) => Math.floor(random() * below);
  const pick = <T>(items: readonly T[]): T => {
    const item = items[int(items.length)];
    if (item === undefined) throw new Error("picked from no items");
    return item;
  };
  const text = (alphabet: readonly string[], most: number) =>
    Array.from({ length: int(most + 1) }, () => pick(alphabet)).join("");
  /** Keys the schema doesn't know, to be stripped. */
  const extras = (): Record<string, unknown> =>
    random() < 0.5
      ? {}
      : {
          [pick(["extra", "admin", "debug", "token"])]: pick([
            1,
            "x",
            null,
            {},
          ]),
        };
  return { random, int, pick, text, extras };
};

/** Fails the test with the seed and the case. */
const fail = (what: string, input: unknown): never => {
  throw new Error(
    `${what} (PROPERTY_SEED=${seed}) for ${JSON.stringify(input)}`
  );
};

/** Fails the test when a refusal repeats something it was given. */
const expectNoEcho = (error: ZodError, markers: string[], input: unknown) => {
  const said = `${error.message} ${JSON.stringify(error.issues)}`;
  for (const marker of markers) {
    if (marker !== "" && said.includes(marker)) {
      fail("a refusal echoed a value", input);
    }
  }
};

describe(`the instance schema, over random input (PROPERTY_SEED=${seed})`, () => {
  it(
    "managingApp takes exactly two Kubernetes names around one slash, unchanged",
    OPTIONS,
    () => {
      const { pick, text, int } = generators();
      // The marker in lower case is a valid name, so it shows up in values
      // the schema takes as well as ones it refuses.
      const NAME = ["a", "z", "0", "9", "-", "."];
      const WILD = [...NAME, "A", "_", "/", " ", "?", "\n", "é"];
      const name = () =>
        pick([
          () => `${pick(["a", "1"])}${text(NAME, 8)}${pick(["a", "9"])}`,
          () => text(WILD, 6),
          () => `${MARK.toLowerCase()}${text(NAME, 4)}`,
          () => "a".repeat(pick([252, 253, 254])),
          () => `${"a".repeat(int(3))}${pick(["..", ".-", "-.", "."])}a`,
        ])();
      for (let i = 0; i < 4000; i++) {
        const managingApp = pick([
          () => `${name()}/${name()}`,
          () => `${name()}/${name()}`,
          () => name(),
          () => `${name()}/${name()}/${name()}`,
        ])();
        const input = { ...BASE, managingApp };

        const parsed = instance.safeParse(input);

        const parts = managingApp.split("/");
        const ok = parts.length === 2 && parts.every(isSubdomain);
        if (parsed.success !== ok) {
          fail("managingApp", managingApp.slice(0, 80));
        }
        if (parsed.success) {
          if (parsed.data.managingApp !== managingApp) {
            fail("managingApp changed", managingApp.slice(0, 80));
          }
          continue;
        }
        expectNoEcho(parsed.error, [MARK.toLowerCase()], managingApp);
      }
    }
  );

  it(
    "namespace takes exactly a Kubernetes label, unchanged, and argocd when there is none",
    OPTIONS,
    () => {
      const { pick, text, random } = generators();
      const LABEL = ["a", "z", "0", "9", "-"];
      const WILD = [...LABEL, ".", "A", "_", "/", " "];
      for (let i = 0; i < 4000; i++) {
        const given = random() < 0.9;
        const namespace = pick([
          () => `${pick(["a", "1"])}${text(LABEL, 8)}${pick(["a", "9"])}`,
          () => text(WILD, 6),
          () => `${MARK.toLowerCase()}${text(WILD, 3)}`,
          () => "n".repeat(pick([62, 63, 64])),
        ])();
        const { namespace: _default, ...rest } = BASE;
        const input = given ? { ...rest, namespace } : rest;

        const parsed = instance.safeParse(input);

        const ok = !given || isLabel(namespace);
        if (parsed.success !== ok) fail("namespace", input);
        if (parsed.success) {
          const expected = given ? namespace : "argocd";
          if (parsed.data.namespace !== expected) {
            fail(`namespace gave ${parsed.data.namespace}`, input);
          }
          continue;
        }
        expectNoEcho(parsed.error, [MARK.toLowerCase()], input);
      }
    }
  );

  it(
    "a secret pointer takes exactly each cloud's shapes, strips the rest, and a refusal echoes none of it",
    OPTIONS,
    () => {
      const { pick, text, extras } = generators();
      const ID = ["a", "z", "0", "9", "-", "_", "A", ".", ":", "/", " "];
      for (let i = 0; i < 4000; i++) {
        // Every value carries the marker, in a spelling its own rule may allow.
        const projectId = pick([
          () =>
            `${text(ID.slice(0, 5), 3)}${MARK.toLowerCase()}${text(ID.slice(0, 5), 6)}`,
          () => `${MARK.toLowerCase()}${text(ID, 5)}`,
          () => `${MARK.toLowerCase()}${"a".repeat(pick([1, 2, 25, 26, 27]))}`,
          () => `example.com:${MARK.toLowerCase()}`,
        ])();
        const region = `${text(ID.slice(0, 5), 4)}${MARK.toLowerCase()}${text(ID, 3)}`;
        const gcpSecretId = pick([
          () => `${MARK}${text(ID.slice(0, 7), 8)}`,
          () => `${MARK}${text(ID, 6)}`,
          () => `projects/p/secrets/${MARK}`,
          () => `${MARK}${"a".repeat(pick([250, 251, 252]))}`,
        ])();
        const awsSecretId = pick([
          `arn:aws:secretsmanager:us-west-2:1:secret:${MARK}`,
          MARK,
          "",
        ]);
        const manager = pick(["gcp", "aws", "aws", "gcp", "azure", "", null]);
        const secret =
          manager === "gcp"
            ? { manager, projectId, secretId: gcpSecretId, ...extras() }
            : { manager, region, secretId: awsSecretId, ...extras() };
        const input = { ...BASE, secret, ...extras() };

        const parsed = instance.safeParse(input);

        const expected =
          manager === "gcp"
            ? isGcpProjectId(projectId) && isGcpSecretName(gcpSecretId)
              ? { manager, projectId, secretId: gcpSecretId }
              : undefined
            : manager === "aws"
              ? isAwsRegion(region) && awsSecretId.length > 0
                ? { manager, region, secretId: awsSecretId }
                : undefined
              : undefined;
        if (parsed.success !== (expected !== undefined))
          fail("pointer", secret);
        if (parsed.success) {
          // Exactly the known keys, in the schema's order: unknown ones go.
          if (
            JSON.stringify(parsed.data) !==
            JSON.stringify({ ...BASE, secret: expected })
          ) {
            fail("pointer's shape", input);
          }
          continue;
        }
        if (!(parsed.error instanceof ZodError)) fail("not a ZodError", secret);
        const said = `${parsed.error.message} ${JSON.stringify(parsed.error.issues)}`;
        if (said.toUpperCase().includes(MARK))
          fail("a refusal echoed a value", secret);
      }
    }
  );

  // The URL is built from its parts, so what it should parse to is known
  // without asking a URL parser: https, a host, maybe a port, and nothing
  // else. The origin is `https://<host in lower case>`, with the port unless
  // it is https's own.
  it(
    "url takes exactly a bare https origin, and returns it in one spelling",
    OPTIONS,
    () => {
      const { pick, text, random } = generators();
      const LABEL = [..."abcxyz0189"];
      for (let i = 0; i < 4000; i++) {
        const scheme = pick([
          "https",
          "https",
          "https",
          "HTTPS",
          "http",
          "ftp",
          "argocd",
          "",
        ]);
        // `:@` and `@` are userinfo with nothing in it, which is none.
        const userinfo = pick([
          "",
          "",
          "",
          "user@",
          `user:${MARK}@`,
          `:${MARK}@`,
          ":@",
          "@",
        ]);
        const labels = Array.from(
          { length: Math.floor(random() * 3) },
          () => `${pick(LABEL)}${text([...LABEL, "-"], 4)}${pick(LABEL)}`
        );
        // The last label starts with a letter: a host that ends in a number
        // is an IPv4 address to a URL, and is spelled as one (`81` becomes
        // `0.0.0.81`), which is a rule of URLs and not of this schema.
        const lowerHost = [
          ...labels,
          `${pick([..."abcxyz"])}${text([...LABEL, "-"], 4)}${pick(LABEL)}`,
        ].join(".");
        const host = random() < 0.3 ? lowerHost.toUpperCase() : lowerHost;
        const port = pick([
          "",
          "",
          "",
          "443",
          "8443",
          "1",
          "65535",
          "65536",
          "99999",
          "0443",
        ]);
        const path = pick(["", "", "", "/", "/api", "/api/v1", "//", "/."]);
        const query = pick(["", "", "", "?a=1", "?x"]);
        const fragment = pick(["", "", "", "#top"]);
        const value = `${scheme}${scheme === "" ? "" : "://"}${userinfo}${host}${port === "" ? "" : `:${port}`}${path}${query}${fragment}`;

        const parsed = instance.shape.url.safeParse(value);

        const portNumber = port === "" ? undefined : Number(port);
        const bare =
          scheme.toLowerCase() === "https" &&
          every(userinfo, (c) => c === ":" || c === "@") &&
          (portNumber === undefined || portNumber <= 65535) &&
          // `/.` is a path that resolves to the root.
          (path === "" || path === "/" || path === "/.") &&
          query === "" &&
          fragment === "";
        if (parsed.success !== bare) fail("url", value);
        if (parsed.success) {
          const origin = `https://${lowerHost}${
            portNumber === undefined || portNumber === 443
              ? ""
              : `:${portNumber}`
          }`;
          if (parsed.data !== origin)
            fail(`url gave ${parsed.data}, not ${origin}`, value);
          continue;
        }
        const said = `${parsed.error.message} ${JSON.stringify(parsed.error.issues)}`;
        if (said.includes(MARK) || said.includes(lowerHost)) {
          fail("a refusal echoed the URL", value);
        }
      }
    }
  );

  it("names the seed it ran with", () => {
    expect(Number.isSafeInteger(seed)).toBe(true);
  });
});

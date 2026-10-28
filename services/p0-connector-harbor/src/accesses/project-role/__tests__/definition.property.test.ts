/**
 * Property tests for the schemas that parse what P0 sends. Each has an
 * oracle written as plain checks on characters, apart from the schema's own
 * patterns, and inputs built to sit on both sides of every rule.
 *
 * A failure names the seed and the input: `PROPERTY_SEED=<n>` replays it.
 */
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { instance, schema } from "../definition.ts";

/**
 * A seeded source of random numbers in [0, 1) (mulberry32), for property
 * tests: a failing case comes back with the same seed.
 */
const seededRandom = (seed: number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/** The seed a property test runs with: `PROPERTY_SEED`, or a new one. */
const propertySeed = () => {
  const given = process.env.PROPERTY_SEED;
  if (!given) return Math.floor(Math.random() * 2 ** 32);
  const seed = Number(given);
  if (!Number.isSafeInteger(seed)) {
    throw new Error(`PROPERTY_SEED isn't an integer: ${given}`);
  }
  return seed;
};

const seed = propertySeed();
// Thousands of cases, which a loaded machine can take seconds over.
const OPTIONS = { timeout: 30_000 };

const ROLES = [
  "projectAdmin",
  "maintainer",
  "developer",
  "guest",
  "limitedGuest",
];

// Marks every secret pointer value, so a refusal that echoes one shows.
const MARK = "ZQJX";

const isLower = (c: string) => c >= "a" && c <= "z";
const isUpper = (c: string) => c >= "A" && c <= "Z";
const isDigit = (c: string) => c >= "0" && c <= "9";
const every = (text: string, allowed: (c: string) => boolean) =>
  [...text].every(allowed);

/** Harbor's project name rule, by its characters. */
const isProjectName = (name: string) => {
  if (name.length < 1 || name.length > 255) return false;
  const isWord = (c: string) => isLower(c) || isDigit(c);
  const isSeparator = (c: string) => c === "." || c === "_" || c === "-";
  return [...name].every((c, i) => {
    if (isWord(c)) return true;
    if (!isSeparator(c)) return false;
    // A separator stands alone between two letters or digits.
    const before = name[i - 1];
    const after = name[i + 1];
    return (
      before !== undefined &&
      after !== undefined &&
      isWord(before) &&
      isWord(after)
    );
  });
};

/** A decimal string `Number` reads exactly and `String` writes back. */
const isUserId = (id: string) => {
  if (id.length < 1 || id.length > 16) return false;
  if (!every(id, isDigit) || id[0] === "0") return false;
  // Same length, so the order of the digits is the order of the numbers.
  return id.length < 16 || id <= "9007199254740991";
};

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
  /** Keys a schema doesn't know, to be stripped (A8). */
  const extras = (): Record<string, unknown> =>
    random() < 0.5
      ? {}
      : {
          [pick(["extra", "admin", "debug", "roles"])]: pick([
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

describe(`the schemas, over random input (PROPERTY_SEED=${seed})`, () => {
  it("userId takes exactly a canonical decimal a number holds", OPTIONS, () => {
    const { pick, text, int } = generators();
    const DIGITS = [..."0123456789"];
    for (let i = 0; i < 4000; i++) {
      const id = pick([
        () => text(DIGITS, 18),
        () => `${1 + int(9)}${text(DIGITS, 15)}`,
        // Around the largest safe integer.
        () => String(9007199254740991 - int(3)),
        () =>
          pick(["9007199254740992", "9007199254740993", "9999999999999999"]),
        () => text([...DIGITS, "-", "+", ".", "e", " ", "a"], 6),
      ])();

      const parsed = schema.userId.safeParse(id);

      if (parsed.success !== isUserId(id)) fail("userId", id);
      if (parsed.success && (parsed.data !== id || String(Number(id)) !== id)) {
        fail("userId changed", id);
      }
    }
  });

  it(
    "a policy takes exactly Harbor's project names and roles, and strips the rest",
    OPTIONS,
    () => {
      const { pick, text, extras, random } = generators();
      const NAME = ["a", "z", "0", "9", ".", "_", "-", "A", "/", " ", "é"];
      for (let i = 0; i < 4000; i++) {
        const project = pick([
          () => text(NAME.slice(0, 7), 8),
          () => text(NAME, 6),
          () => "a".repeat(pick([254, 255, 256, 300])),
          () => `${"a".repeat(253)}${pick(["-b", ".b", "--", "b-"])}`,
        ])();
        const role = pick([...ROLES, ...ROLES, null, "admin", "Guest", "", 3]);
        // Now and then the role is left out, which isn't a revoke.
        const withRole = random() < 0.9;
        const input = {
          project,
          ...(withRole ? { role } : {}),
          ...extras(),
        };

        const parsed = schema.policy.safeParse(input);

        const roleOk =
          withRole &&
          (role === null || (typeof role === "string" && ROLES.includes(role)));
        if (parsed.success !== (isProjectName(project) && roleOk)) {
          fail("policy", { ...input, project: project.slice(0, 40) });
        }
        if (
          parsed.success &&
          JSON.stringify(parsed.data) !== JSON.stringify({ project, role })
        ) {
          fail("policy's shape", input);
        }
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
        const input = {
          url: "https://harbor.example.com",
          secret,
          ...extras(),
        };

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
            JSON.stringify({
              url: "https://harbor.example.com",
              secret: expected,
            })
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
          "harbor",
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
        const path = pick(["", "", "", "/", "/api", "/api/v2.0", "//", "/."]);
        const query = pick(["", "", "", "?a=1", "?x"]);
        const fragment = pick(["", "", "", "#top"]);
        const value = `${scheme}${scheme === "" ? "" : "://"}${userinfo}${host}${port === "" ? "" : `:${port}`}${path}${query}${fragment}`;

        const parsed = schema.requestContext.shape.url.safeParse(value);

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

  it(
    "a request context needs its prior role, null or one of the five, and strips the rest",
    OPTIONS,
    () => {
      const { pick, extras, random } = generators();
      const base = {
        url: "https://harbor.example.com",
        secret: {
          manager: "aws",
          region: "us-west-2",
          secretId: "harbor-admin",
        },
        requestId: "req-1",
        email: "alice@example.com",
      };
      for (let i = 0; i < 2000; i++) {
        const priorRole = pick([
          ...ROLES,
          null,
          null,
          "none",
          "",
          "Guest",
          0,
          false,
        ]);
        // A3: a context without the key isn't "held none".
        const withKey = random() < 0.85;
        const input = {
          ...base,
          ...(withKey ? { priorRole } : {}),
          ...extras(),
        };

        const parsed = schema.requestContext.safeParse(input);

        const ok =
          withKey &&
          (priorRole === null ||
            (typeof priorRole === "string" && ROLES.includes(priorRole)));
        if (parsed.success !== ok) fail("request context", input);
        if (
          parsed.success &&
          JSON.stringify(parsed.data) !== JSON.stringify({ ...base, priorRole })
        ) {
          fail("request context's shape", input);
        }
      }
    }
  );

  it(
    "a user body takes a user id and an instance id, and strips the rest",
    OPTIONS,
    () => {
      const { pick, extras } = generators();
      for (let i = 0; i < 2000; i++) {
        const userId = pick([
          "42",
          "1",
          "007",
          "0",
          "-1",
          "4.2",
          "",
          "alice",
          "9007199254740992",
        ]);
        const instanceId = pick(["p0-harbor", "x", "", "  "]);
        const input = { instanceId, userId, ...extras() };

        const parsed = schema.userBody.safeParse(input);

        // `instanceId` is P0's own and only has to be there.
        const ok = isUserId(userId) && instanceId.length > 0;
        if (parsed.success !== ok) fail("user body", input);
        if (
          parsed.success &&
          JSON.stringify(parsed.data) !== JSON.stringify({ instanceId, userId })
        ) {
          fail("user body's shape", input);
        }
      }
    }
  );

  it("names the seed it ran with", () => {
    expect(Number.isSafeInteger(seed)).toBe(true);
  });
});

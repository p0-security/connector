import { describe, expect, it } from "vitest";

import { MAX_FIELD_LENGTH, parseAdminCredential } from "../admin-credential.ts";
import { propertySeed, seededRandom } from "./fixtures.ts";

// Each value has a marker of its own, so a problem that echoes one shows.
const VALID = {
  issuer: "https://accounts.example.com",
  clientId: "SENTINEL-client-id-3c1e",
  clientSecret: "SENTINEL-client-secret-8a4f",
  refreshToken: "SENTINEL-refresh-token-6d2b",
};

const SENTINELS = ["SENTINEL", "accounts.example.com"];

const problemOf = (json: unknown) => {
  const parsed = parseAdminCredential(json);
  if (parsed.ok) throw new Error("expected the parse to fail");
  return parsed.problem;
};

describe("parseAdminCredential", () => {
  it("reads the four fields", () => {
    expect(parseAdminCredential(VALID)).toEqual({
      ok: true,
      credential: VALID,
    });
  });

  it.each([
    [
      "a trailing slash",
      "https://accounts.example.com/",
      "https://accounts.example.com",
    ],
    [
      "a path",
      "https://idp.example.com/realms/p0/",
      "https://idp.example.com/realms/p0",
    ],
    ["a port", "https://idp.example.com:8443", "https://idp.example.com:8443"],
  ])(
    "takes an issuer with %s, without its trailing slash",
    (_, issuer, read) => {
      expect(parseAdminCredential({ ...VALID, issuer })).toEqual({
        ok: true,
        credential: { ...VALID, issuer: read },
      });
    }
  );

  it.each([
    ["http", "http://accounts.example.com"],
    ["a password", "https://user:SENTINEL-pw@accounts.example.com"],
    ["a query", "https://accounts.example.com?x=1"],
    ["an empty query", "https://accounts.example.com?"],
    ["a fragment", "https://accounts.example.com#x"],
    ["no URL at all", "SENTINEL-not-a-url"],
  ])("refuses an issuer with %s, naming the field only", (_, issuer) => {
    const problem = problemOf({ ...VALID, issuer });
    expect(problem).toBe(": issuer is missing or not valid");
  });

  it.each([
    ["blank", "  "],
    ["a line break", "SENTINEL\nx"],
    ["too long", "x".repeat(MAX_FIELD_LENGTH + 1)],
    ["a number", 7],
  ])("refuses a refresh token that is %s", (_, refreshToken) => {
    expect(problemOf({ ...VALID, refreshToken })).toBe(
      ": refreshToken is missing or not valid"
    );
  });

  it("names every missing field", () => {
    expect(problemOf({ issuer: VALID.issuer })).toBe(
      ": clientId, clientSecret, refreshToken are missing or not valid"
    );
  });

  // `client_id` instead of `clientId` is the likeliest mistake, and an
  // unknown key may be a value pasted in the wrong place: it isn't named.
  it("refuses a field it doesn't know, without naming it", () => {
    const { clientId, ...rest } = VALID;
    const problem = problemOf({ ...rest, client_id: clientId, SENTINEL: 1 });
    expect(problem).toBe(
      ": clientId is missing or not valid, and it has fields besides issuer, clientId, clientSecret and refreshToken"
    );
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["an array", [VALID]],
    ["a string", JSON.stringify(VALID)],
  ])("refuses %s as not an object", (_, json) => {
    expect(problemOf(json)).toBe(": it isn't a JSON object");
  });
});

describe("parseAdminCredential, as a property", () => {
  const seed = propertySeed();
  const random = seededRandom(seed);
  const pick = <T>(items: readonly T[]): T =>
    items[Math.floor(random() * items.length)] as T;

  const FIELDS = ["issuer", "clientId", "clientSecret", "refreshToken"];

  // Values each field takes, every one marked.
  const goodIssuers = [
    VALID.issuer,
    // Lowercase: `URL` lowers the host, and the issuer is compared as
    // written apart from a trailing slash.
    "https://idp.example.com/x/",
    "https://idp.example.com:8443/realms/p0",
  ];
  const goodSecrets = [
    "SENTINEL-a",
    " SENTINEL x ",
    `SENTINEL${"x".repeat(MAX_FIELD_LENGTH - 8)}`,
  ];
  // Values that break a rule, every one marked.
  const badValues = [
    "http://SENTINEL.example.com",
    "https://SENTINEL.example.com?",
    "https://SENTINEL.example.com?x=1",
    "https://SENTINEL.example.com#x",
    "https://SENTINEL.example.com#",
    "https://user:SENTINEL@idp.example.com",
    "https://SENTINEL@idp.example.com",
    `SENTINEL${"x".repeat(MAX_FIELD_LENGTH - 7)}`,
    "SENTINEL",
    "SENTINEL\r",
    "SENTINEL\nx",
    "",
    "   ",
    7,
    null,
    true,
    ["SENTINEL"],
    { SENTINEL: "SENTINEL" },
  ];
  const values = [...goodIssuers, ...goodSecrets, ...badValues];
  const keys = [...FIELDS, "SENTINEL_key", "client_id"];

  const filled = (value: unknown) =>
    typeof value === "string" &&
    value.length <= MAX_FIELD_LENGTH &&
    /\S/.test(value) &&
    !/[\r\n]/.test(value);

  // An https URL with no query, fragment, username or password.
  const isIssuer = (value: unknown) => {
    if (typeof value !== "string" || !value.startsWith("https://")) {
      return false;
    }
    const authority = value.slice("https://".length).split("/")[0] ?? "";
    return (
      !value.includes("?") && !value.includes("#") && !authority.includes("@")
    );
  };

  /** Half the cases are the four fields, mostly well formed. */
  const nearlyValid = () => {
    const json: Record<string, unknown> = {};
    for (const field of FIELDS) {
      const good = field === "issuer" ? goodIssuers : goodSecrets;
      json[field] = random() < 0.85 ? pick(good) : pick(values);
    }
    if (random() < 0.1) json[pick(["SENTINEL_key", "client_id"])] = "x";
    return json;
  };

  const anything = () => {
    const json: Record<string, unknown> = {};
    const size = Math.floor(random() * 7);
    for (let k = 0; k < size; k++) json[pick(keys)] = pick(values);
    return json;
  };

  it(
    "accepts exactly the well-formed secrets, and a problem never quotes a value or an unknown key",
    { timeout: 30_000 },
    () => {
      let accepted = 0;
      const CASES = 5000;
      for (let i = 0; i < CASES; i++) {
        const json = random() < 0.5 ? nearlyValid() : anything();
        const where = `seed ${seed}, case ${JSON.stringify(json).slice(0, 300)}`;
        const parsed = parseAdminCredential(json);
        const expected =
          Object.keys(json).every((key) => FIELDS.includes(key)) &&
          isIssuer(json.issuer) &&
          filled(json.clientId) &&
          filled(json.clientSecret) &&
          filled(json.refreshToken);
        expect(parsed.ok, where).toBe(expected);
        if (parsed.ok) {
          accepted++;
          expect(parsed.credential, where).toEqual({
            ...json,
            issuer: String(json.issuer).replace(/\/+$/, ""),
          });
        } else {
          for (const sentinel of SENTINELS) {
            expect(parsed.problem, where).not.toContain(sentinel);
          }
        }
      }
      // The generator reaches the accepting side often, not by luck.
      expect(accepted, `seed ${seed}`).toBeGreaterThan(CASES / 10);
    }
  );
});

describe("parseAdminCredential, at the edges of each rule", () => {
  it.each([
    ["a username alone", "https://SENTINEL-user@accounts.example.com"],
    ["a password alone", "https://:SENTINEL-pw@accounts.example.com"],
  ])("refuses an issuer with %s", (_, issuer) => {
    expect(problemOf({ ...VALID, issuer })).toBe(
      ": issuer is missing or not valid"
    );
  });

  it("takes an issuer with several trailing slashes, without any of them", () => {
    expect(
      parseAdminCredential({ ...VALID, issuer: "https://idp.example.com/p0//" })
    ).toEqual({
      ok: true,
      credential: { ...VALID, issuer: "https://idp.example.com/p0" },
    });
  });

  it("says only that there are other fields when the four are well formed", () => {
    expect(problemOf({ ...VALID, SENTINEL_key: "x" })).toBe(
      ": it has fields besides issuer, clientId, clientSecret and refreshToken"
    );
  });
});

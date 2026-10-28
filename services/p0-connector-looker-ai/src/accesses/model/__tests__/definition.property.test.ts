import { describe, expect, it } from "vitest";

import { type Random, fileSeed, forAll } from "../../../__tests__/generate.ts";
import { schema } from "../definition.ts";

const SEED = fileSeed();
const RUNS = 1500;
// Zod's refusals are slow, about half a millisecond each.
const TIMEOUT = 30_000;

const LOOKER_SUFFIX = ".looker.app";
const LABEL_CHARACTERS = "abcdefghijklmnopqrstuvwxyz0123456789-";

/**
 * The rule, written without a regular expression: `https://`, then one or
 * more non-empty labels of lower-case letters, digits and hyphens, then
 * `.looker.app`, and nothing else.
 */
const followsTheRule = (url: string) => {
  if (!url.startsWith("https://") || !url.endsWith(LOOKER_SUFFIX)) {
    return false;
  }
  const labels = url.slice("https://".length, -LOOKER_SUFFIX.length).split(".");
  return labels.every(
    (label) =>
      label.length > 0 &&
      [...label].every((character) => LABEL_CHARACTERS.includes(character))
  );
};

/** Pieces that build URLs near the rule's edge. */
const SCHEMES = [
  "https://",
  "https://",
  "https://",
  "http://",
  "HTTPS://",
  "https:/",
  "https:///",
  "//",
  "",
];
const HOST_CHARACTERS = [..."abcdefghijklmnopqrstuvwxyz0123456789-"];
const AWKWARD_HOST_CHARACTERS = [
  "A",
  "Z",
  "_",
  ".",
  "@",
  ":",
  "/",
  "\\",
  "#",
  "?",
  "%",
  " ",
  "\n",
  "\t",
  "\u0000",
  "\u2028",
  "é",
  "ı",
  "。",
  "．",
];
const SUFFIXES = [
  LOOKER_SUFFIX,
  LOOKER_SUFFIX,
  LOOKER_SUFFIX,
  ".looker.app.",
  ".looker.app/",
  ".looker.app:443",
  ".looker.app:8443",
  ".looker.app?x=1",
  ".looker.app#x",
  ".looker.app\n",
  ".looker.app.evil.com",
  ".LOOKER.APP",
  ".looker.com",
  "looker.app",
  "-looker.app",
  ".lookerXapp",
  "",
];

// Picks a valid scheme, labels and suffix more often than not, so that about
// a third of the URLs are valid.
const generateUrl = (random: Random) => {
  const scheme = random.chance(0.7) ? "https://" : random.pick(SCHEMES);
  const suffix = random.chance(0.6) ? LOOKER_SUFFIX : random.pick(SUFFIXES);
  const labels = Array.from(
    { length: random.int(random.chance(0.9) ? 1 : 0, 3) },
    () =>
      Array.from({ length: random.int(random.chance(0.9) ? 1 : 0, 8) }, () =>
        random.chance(0.05)
          ? random.pick(AWKWARD_HOST_CHARACTERS)
          : random.pick(HOST_CHARACTERS)
      ).join("")
  );
  const userInfo = random.chance(0.05) ? "admin@" : "";
  const tail = random.chance(0.05)
    ? random.pick(["@evil.com", "/", "/api", "%2e", "."])
    : "";
  return `${scheme}${userInfo}${labels.join(".")}${suffix}${tail}`;
};

const accepts = (baseUrl: string) =>
  schema.requestContext.safeParse({
    requestId: "r-1",
    baseUrl,
    secrets: {
      manager: "gcp",
      adminKeySecretId: "p0_install_looker_acme_admin-key",
      projectId: "acme-prod",
    },
  }).success;

describe("the instance URL, on generated input", () => {
  it(
    "accepts exactly the URLs the rule allows",
    async () => {
      const counts = await forAll(SEED, RUNS, generateUrl, (url) => {
        expect(accepts(url)).toBe(followsTheRule(url));
        return accepts(url) ? "accepted" : "refused";
      });

      // Both branches, often enough to mean something.
      expect(counts.accepted).toBeGreaterThan(RUNS / 10);
      expect(counts.refused).toBeGreaterThan(RUNS / 10);
    },
    TIMEOUT
  );

  // What the rule is for: the Admin key goes to a looker.app host and no
  // other, whatever a URL parser makes of the input.
  it(
    "only accepts a URL whose every API path stays on a looker.app host",
    async () => {
      const counts = await forAll(SEED, RUNS, generateUrl, (url) => {
        if (!accepts(url)) return "refused";
        const parsed = new URL(url);
        expect(parsed.origin).toBe(url);
        expect(parsed.protocol).toBe("https:");
        expect(parsed.port).toBe("");
        expect(parsed.username).toBe("");
        expect(parsed.password).toBe("");
        expect(parsed.hostname.endsWith(LOOKER_SUFFIX)).toBe(true);
        for (const path of ["/login", "/users/search?name=x", "/folders/1"]) {
          expect(new URL(`${url}/api/4.0${path}`).host).toBe(parsed.host);
        }
        return "accepted";
      });

      expect(counts.accepted).toBeGreaterThan(RUNS / 10);
      expect(counts.refused).toBeGreaterThan(RUNS / 10);
    },
    TIMEOUT
  );
});

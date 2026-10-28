import { describe, expect, it } from "vitest";

import { parseApiKey } from "../api-key.ts";
import { KEY_ID, KEY_SECRET } from "./fixtures.ts";

describe("parseApiKey", () => {
  it.each([
    ["a UUID key ID", KEY_ID],
    ["a console-style key ID", "mFhGq3LrT9xKp2Wz8YbN"],
  ])("takes %s", (_case, keyId) => {
    expect(parseApiKey({ keyId, keySecret: KEY_SECRET })).toEqual({
      ok: true,
      apiKey: { keyId, keySecret: KEY_SECRET },
    });
  });

  it.each([
    ["null", null],
    ["a string", KEY_SECRET],
    ["a number", 7],
    ["undefined, for text that isn't JSON", undefined],
  ])("refuses %s as not an object", (_case, json) => {
    expect(parseApiKey(json)).toEqual({
      ok: false,
      problem: ": it isn't a JSON object",
    });
  });

  it.each([
    ["an empty key ID", { keyId: "", keySecret: KEY_SECRET }, "keyId"],
    ["a key ID with a space", { keyId: "a b", keySecret: KEY_SECRET }, "keyId"],
    ["an empty key secret", { keyId: KEY_ID, keySecret: "" }, "keySecret"],
    [
      "a key secret with a space",
      { keyId: KEY_ID, keySecret: "a b" },
      "keySecret",
    ],
    [
      "a key secret that isn't ASCII",
      { keyId: KEY_ID, keySecret: "sécret" },
      "keySecret",
    ],
    [
      "a key secret over 1024 characters",
      { keyId: KEY_ID, keySecret: "x".repeat(1025) },
      "keySecret",
    ],
  ])(
    "refuses %s, naming the field and never its value",
    (_case, json, field) => {
      const parsed = parseApiKey(json);

      expect(parsed).toEqual({
        ok: false,
        problem: `: ${field} is missing or not valid`,
      });
      expect(JSON.stringify(parsed)).not.toContain(KEY_SECRET);
    }
  );
});

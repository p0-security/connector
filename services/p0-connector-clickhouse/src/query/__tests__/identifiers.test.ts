import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { quoteIdentifier, quoteTable } from "../identifiers.ts";

describe("quoteIdentifier", () => {
  // Each pair was created as a table on ClickHouse 26.8.30.8 with the quoted
  // form, and `system.tables` showed the name unchanged.
  it.each([
    ["users", "`users`"],
    ["odd name", "`odd name`"],
    ["ends\\", "`ends\\\\`"],
    ["we\\ird`na\\` me", "`we\\\\ird\\`na\\\\\\` me`"],
    ["x`; DROP TABLE y; --", "`x\\`; DROP TABLE y; --`"],
  ])("quotes %j as %s", (name, quoted) => {
    expect(quoteIdentifier(name)).toBe(quoted);
  });

  it("never lets a name close its quote", () => {
    for (const name of ["`", "\\", "\\`", "a\\\\`b", "``"]) {
      const inner = quoteIdentifier(name).slice(1, -1);
      // Every backtick inside is escaped by an odd run of backslashes.
      expect(inner.replace(/\\[\\`]/g, "")).not.toMatch(/[\\`]/);
    }
  });

  it.each([
    ["an empty name", ""],
    ["a NUL", "a\0b"],
    ["a line break", "a\nb"],
    ["a carriage return", "a\rb"],
    ["a name past 255 bytes", "é".repeat(128)],
  ])("refuses %s", (_case, name) => {
    expect(() => quoteIdentifier(name)).toThrow(ConnectorError);
  });

  it("takes a name of exactly 255 bytes", () => {
    expect(quoteIdentifier("a".repeat(255))).toBe(`\`${"a".repeat(255)}\``);
  });
});

describe("quoteTable", () => {
  it("quotes the database and the table apart", () => {
    expect(quoteTable({ database: "odd.db", table: "t" })).toBe("`odd.db`.`t`");
  });
});

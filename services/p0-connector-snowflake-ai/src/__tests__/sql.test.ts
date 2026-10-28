import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  objectNameParts,
  quoteIdentifier,
  quoteLiteral,
  quoteObjectName,
} from "../sql.ts";

const HOSTILE = [
  "",
  'A"; DROP USER X; --',
  "A B",
  "A.B",
  "1ABC",
  "A'B",
  "A\\B",
  "A;B",
  "IDENTIFIER('X')",
  "A\nB",
  "Ä",
  "A".repeat(256),
];

describe("quoteIdentifier", () => {
  it("quotes a plain identifier and keeps its case", () => {
    expect(quoteIdentifier("Sales_Reader$1")).toBe('"Sales_Reader$1"');
    expect(quoteIdentifier("_X")).toBe('"_X"');
  });

  it.each(HOSTILE)("refuses %j", (value) => {
    expect(() => quoteIdentifier(value)).toThrow(ConnectorError);
  });
});

describe("quoteObjectName", () => {
  it("quotes each part of a database, schema or object name", () => {
    expect(quoteObjectName("DB")).toBe('"DB"');
    expect(quoteObjectName("DB.S")).toBe('"DB"."S"');
    expect(quoteObjectName("DB.S.T")).toBe('"DB"."S"."T"');
  });

  it.each(["DB.S.T.X", "DB..T", ".DB", "DB.", 'DB."S"', "DB.S;T", "DB.S T"])(
    "refuses %j",
    (value) => {
      expect(() => quoteObjectName(value)).toThrow(ConnectorError);
      expect(() => objectNameParts(value)).toThrow(ConnectorError);
    }
  );
});

describe("quoteLiteral", () => {
  it("doubles quotes and backslashes", () => {
    expect(quoteLiteral("plain")).toBe("'plain'");
    expect(quoteLiteral("it's")).toBe("'it''s'");
    expect(quoteLiteral("a\\' OR 1=1 --")).toBe("'a\\\\'' OR 1=1 --'");
  });

  it("can't be closed early by any input", () => {
    for (const value of ["'", "\\'", "''", "\\\\'", "x'; DROP USER Y; --"]) {
      const literal = quoteLiteral(value);
      // Inside the outer quotes, every `'` is doubled and every `\` is
      // doubled, so no character can end the string.
      const body = literal.slice(1, -1);
      expect(body.replaceAll("''", "").replaceAll("\\\\", "")).not.toMatch(
        /['\\]/
      );
    }
  });
});

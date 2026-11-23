import { describe, expect, it } from "vitest";

import { ident } from "../identifier.ts";
import { dataOf } from "./fakes.ts";

describe("ident", () => {
  it("quotes a role name", () => {
    expect(ident("Reporting.read-only")).toBe('"Reporting.read-only"');
  });

  it.each(['analyst"; DROP ROLE x; --', "has space", "", "a".repeat(64)])(
    "refuses %j",
    async (name) => {
      const data = await dataOf(Promise.resolve().then(() => ident(name)));

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe("Invalid PostgreSQL role name");
    }
  );
});

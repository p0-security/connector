import { beforeEach, describe, expect, it } from "vitest";

import { dataOf } from "../../__tests__/fakes.ts";
import { LOGIN } from "../../__tests__/fixtures.ts";
import type { PgQuery } from "../client.ts";
import { execute } from "../statement.ts";

/** Every statement the server got, with its bindings. */
let sent: [sql: string, bindings?: readonly string[]][] = [];
/** What the server answers each statement with. */
let rows: unknown[] = [];

const query: PgQuery = async (sql, bindings) => {
  sent.push(bindings ? [sql, bindings] : [sql]);
  return rows;
};

beforeEach(() => {
  sent = [];
  rows = [{ statement: "WHAT THE SERVER BUILT" }];
});

describe("execute", () => {
  it("has PostgreSQL build the statement from bindings, then runs what it built", async () => {
    await execute(query, {
      template: "GRANT %I TO %I",
      args: ["analyst", LOGIN],
    });

    expect(sent).toEqual([
      [
        "SELECT format($1::text, $2::text, $3::text) AS statement",
        ["GRANT %I TO %I", "analyst", "p0v_0123456789abcdef0123456789abcdef"],
      ],
      ["WHAT THE SERVER BUILT"],
    ]);
  });

  it("sends a literal as it is, whatever it holds", async () => {
    const comment = `it's "quoted" \\ $$ ?\n; DROP ROLE x; --`;

    await execute(query, {
      template: "COMMENT ON ROLE %I IS %L",
      args: [LOGIN, comment],
    });

    expect(sent[0]).toEqual([
      "SELECT format($1::text, $2::text, $3::text) AS statement",
      ["COMMENT ON ROLE %I IS %L", LOGIN, comment],
    ]);
  });

  it.each(['analyst"; DROP ROLE x; --', "has space", "", "a".repeat(64)])(
    "refuses the name %j before it sends anything",
    async (name) => {
      const data = await dataOf(
        execute(query, { template: "GRANT %I TO %I", args: [name, LOGIN] })
      );

      expect(data.type).toBe("validation_error");
      expect(data.message).toBe("Invalid PostgreSQL role name");
      expect(sent).toEqual([]);
    }
  );

  it("refuses a name in any position", async () => {
    const data = await dataOf(
      execute(query, {
        template: "COMMENT ON ROLE %I IS %L",
        args: ["has space", "has space"],
      })
    );

    expect(data.type).toBe("validation_error");
    expect(sent).toEqual([]);
  });

  it.each([[[]], [[{ statement: null }]], [[{ statement: "" }]], [[{}]]])(
    "runs nothing when the server answers %j",
    async (answer) => {
      rows = answer;

      const data = await dataOf(
        execute(query, { template: "GRANT %I TO %I", args: ["analyst", LOGIN] })
      );

      expect(data.type).toBe("unknown");
      expect(sent).toHaveLength(1);
    }
  );
});

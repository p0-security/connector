import { ConnectorError } from "@p0security/connector";
import knex from "knex";
import { describe, expect, it } from "vitest";

import {
  MAX_IDENTIFIER_BYTES,
  ident,
  privilegeKeyword,
  tableIdent,
} from "../identifier.ts";

describe("ident", () => {
  // Every name the connector actually handles: P0-namespaced roles and the
  // identity-email forms. All fall inside the allowlist.
  const ACCEPTED = [
    "simple",
    "p0_test_user_1234",
    "UPPER_and_lower",
    "john.doe@p0.dev", // motivating case: dots stay literal, not split
    "sa@proj.iam", // Cloud SQL IAM service-account user
    "user+tag@example.com", // email plus-addressing
    "with-hyphen",
    "select", // reserved word — valid once quoted
    "a".repeat(MAX_IDENTIFIER_BYTES), // exactly at the byte limit
  ];

  it.each(ACCEPTED)("quotes %j losslessly", (name) => {
    expect(() => ident(name)).not.toThrow();
    const quoted = ident(name);

    // Decode a quoted identifier back to its logical value the way Postgres does:
    // strip the outer quotes, collapse each doubled "" to one ". Correctness of
    // `ident` is then the property `decode(ident(x)) === x` — the quoting is
    // lossless and unambiguous, which is exactly what makes it injection-proof.
    const decode = (quoted: string): string =>
      quoted.slice(1, -1).replace(/""/g, '"');

    // A well-formed quoted identifier is wrapped in quotes with every interior
    // quote doubled; a lone interior quote is a breakout. Asserting this alongside
    // the round-trip rules out a buggy quoting that happens to decode correctly.
    const expectWellFormed = (quoted: string) => {
      expect(quoted.startsWith('"')).toBe(true);
      expect(quoted.endsWith('"')).toBe(true);
      expect(quoted.slice(1, -1).replace(/""/g, "")).not.toContain('"');
    };

    expectWellFormed(quoted);
    expect(decode(quoted)).toBe(name);
  });

  it("produces the exact expected quoting", () => {
    expect(ident("simple")).toBe('"simple"');
    expect(ident("john.doe@p0.dev")).toBe('"john.doe@p0.dev"');
  });

  // The allowlist rejects every breakout attempt outright (each contains a
  // character outside `[A-Za-z0-9._@+-]`), so a payload never reaches the
  // quoting at all.
  const ATTACK_VECTORS = [
    `"; DROP ROLE victim; --`,
    `x" WITH SUPERUSER; --`,
    `role" TO attacker; GRANT "role`,
    `"";`,
    `a"; CREATE ROLE evil; "`,
    `'; DROP ROLE victim; --`,
    `\\"; DROP ROLE victim; --`,
    `back\\slash`,
    `tab\there`,
    `newline\nhere`,
  ];

  it.each(ATTACK_VECTORS)("rejects injection payload %j", (payload) => {
    expect(() => ident(payload)).toThrow(ConnectorError);
  });

  describe("rejects identifiers outside the allowlist", () => {
    it("rejects the empty string", () => {
      expect(() => ident("")).toThrow(ConnectorError);
    });

    it.each([
      ["space", "name with spaces"],
      ["double quote", 'a"b'],
      ["single quote", "a'b"],
      ["semicolon", "a;b"],
      ["backslash", "a\\b"],
      ["non-ASCII letter", "café"],
      ["null byte", "ab\0cd"],
      ["tab", "ab\tcd"],
      ["newline", "ab\ncd"],
      ["leading whitespace", " admin"],
      ["trailing whitespace", "admin "],
    ])("rejects a disallowed character (%s)", (_, name) => {
      expect(() => ident(name)).toThrow(ConnectorError);
    });

    it("rejects over-length identifiers", () => {
      // All-ASCII so the allowlist passes and only the byte-length guard fires.
      expect(() => ident("a".repeat(MAX_IDENTIFIER_BYTES + 1))).toThrow(
        ConnectorError
      );
    });
  });
});

describe("privilegeKeyword", () => {
  const ALLOWED = ["SELECT", "INSERT", "ALL PRIVILEGES"];

  it.each(ALLOWED)("passes %j through unquoted", (privilege) => {
    expect(privilegeKeyword(privilege, ALLOWED)).toBe(privilege);
  });

  // Callers are not expected to carry the allowlist, so any casing or spacing a
  // caller might send normalizes to the keyword instead of failing.
  it.each([
    ["lower case", "select", "SELECT"],
    ["mixed case", "Insert", "INSERT"],
    ["surrounding whitespace", "  select  ", "SELECT"],
    ["ALL as shorthand", "all", "ALL PRIVILEGES"],
    ["collapsible spacing", "all   privileges", "ALL PRIVILEGES"],
  ])("normalizes %s", (_, privilege, expected) => {
    expect(privilegeKeyword(privilege, ALLOWED)).toBe(expected);
  });

  // The keyword is interpolated into the statement rather than bound, so the
  // allowlist is the only thing standing between a caller and arbitrary SQL.
  it.each([
    ["a privilege outside the allowlist", "DELETE"],
    ["the empty string", ""],
    ["a statement terminator", `SELECT ON TABLE t TO attacker; --`],
    ["a nested clause", `SELECT, INSERT`],
    ["a quoted breakout", `SELECT" ON TABLE t TO attacker; --`],
  ])("rejects %s", (_, privilege) => {
    expect(() => privilegeKeyword(privilege, ALLOWED)).toThrow(ConnectorError);
  });
});

describe("tableIdent", () => {
  it("names a table in the search path", () => {
    expect(tableIdent("orders")).toBe(`"orders"`);
  });

  // The shape the backend actually sends: the SQL parser always yields a
  // relation, and the schema defaults to `public` before it gets here.
  it("names a schema-qualified table", () => {
    expect(tableIdent("public.orders")).toBe(`"public"."orders"`);
  });

  // A wildcard would have to compile to `ON ALL TABLES IN SCHEMA`, granting
  // every table in the schema — never what a parsed query asked for. It is the
  // one malformed target a caller might expect to work, so the rejection says
  // so explicitly instead of restating the expected form.
  it.each([
    ["a bare wildcard", "*"],
    ["a schema wildcard", "sales.*"],
    ["a wildcard in the schema position", "*.orders"],
    ["a wildcard within a name", "sales.ord*ers"],
  ])("rejects %s, naming wildcards as the reason", (_, table) => {
    expect(() => tableIdent(table)).toThrow(ConnectorError);
    expect(() => tableIdent(table)).toThrow(
      /Invalid Postgres table: wildcards are not supported/
    );
  });

  it.each([
    ["a three-part name", "db.sales.orders"],
    ["an empty relation", "sales."],
    ["an empty schema", ".orders"],
    ["the empty string", ""],
  ])("rejects %s as a malformed target", (_, table) => {
    expect(() => tableIdent(table)).toThrow(ConnectorError);
    expect(() => tableIdent(table)).toThrow(
      /Invalid Postgres table: expected a concrete/
    );
  });

  // A well-shaped target whose parts are not legal identifiers still fails, but
  // `ident` owns that rejection.
  it.each([
    ["an injection payload", `orders" TO attacker; --`],
    ["a space", "my orders"],
  ])("rejects %s as an invalid identifier", (_, table) => {
    expect(() => tableIdent(table)).toThrow(ConnectorError);
    expect(() => tableIdent(table)).toThrow(/Invalid Postgres identifier/);
  });
});

const pg = knex({ client: "pg" });
const sql = (raw: knex.Knex.Raw) => raw.toSQL().toNative().sql;

// The motivating input: an email-address role name. Every `.` must stay inside
// one quoted span, not split into a qualified name.
const EMAIL = "john.doe@p0.dev";

describe("ident() on the wire", () => {
  it("keeps a dotted identifier as one quoted span (the bug `ident` fixes)", () => {
    // `ident()`: the whole email is a single identifier — every dot literal.
    expect(sql(pg.raw(`CREATE ROLE ${ident(EMAIL)} WITH LOGIN`))).toBe(
      `CREATE ROLE "john.doe@p0.dev" WITH LOGIN`
    );

    // knex `??` for the same value: split on every dot into a 3-part qualified
    // name. This is the broken output `ident()` exists to replace.
    expect(sql(pg.raw(`CREATE ROLE ??`, [EMAIL]))).toBe(
      `CREATE ROLE "john"."doe@p0"."dev"`
    );
  });

  it("compiles the role-lifecycle statements", () => {
    expect(sql(pg.raw(`DROP ROLE IF EXISTS ${ident(EMAIL)}`))).toBe(
      `DROP ROLE IF EXISTS "john.doe@p0.dev"`
    );

    expect(
      sql(pg.raw(`GRANT ${ident("p0_test_role")} TO ${ident(EMAIL)}`))
    ).toBe(`GRANT "p0_test_role" TO "john.doe@p0.dev"`);

    expect(
      sql(pg.raw(`REVOKE ${ident("p0_test_role")} FROM ${ident(EMAIL)}`))
    ).toBe(`REVOKE "p0_test_role" FROM "john.doe@p0.dev"`);
  });

  it("emits a bare privilege keyword alongside quoted objects", () => {
    expect(
      sql(
        pg.raw(
          `GRANT ${privilegeKeyword("CREATE", ["CREATE"])} ON SCHEMA ${ident("public")} TO ${ident(EMAIL)}`
        )
      )
    ).toBe(`GRANT CREATE ON SCHEMA "public" TO "john.doe@p0.dev"`);
  });

  it("never lets an injection payload reach the wire", () => {
    // Each call drops an attacker-controlled role name into a different
    // statement. The payload tries to close `ident()`'s `"` and append its own
    // SQL — but the allowlist rejects it, so `ident()` throws before any SQL is
    // built and nothing reaches Postgres.

    // CREATE ROLE: escalate the newly created role to superuser.
    expect(() =>
      pg.raw(`CREATE ROLE ${ident(`x" WITH SUPERUSER; --`)}`)
    ).toThrow(ConnectorError);

    // GRANT ... TO <grantee>: end the statement, then drop an existing role.
    expect(() =>
      pg.raw(`GRANT p0_test_role TO ${ident(`v"; DROP ROLE postgres; --`)}`)
    ).toThrow(ConnectorError);

    // DROP ROLE: hijack an existing superuser instead of dropping the target.
    expect(() =>
      pg.raw(`DROP ROLE ${ident(`x"; ALTER ROLE postgres SUPERUSER; --`)}`)
    ).toThrow(ConnectorError);
  });
});

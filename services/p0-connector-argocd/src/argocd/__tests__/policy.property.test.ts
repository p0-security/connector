/**
 * Property tests for the policy model: the CSV line reader, `scopes`, the
 * overlap check (`holds`) and P0's own lines (`buildLine`, `parseP0Line`,
 * `addLine`, `removeLine`).
 *
 * Each property builds its input from parts it knows, so the oracle is the
 * parts: a line written from known fields must read back as those fields,
 * a policy written from known `g` edges must hold exactly what those edges
 * reach. The oracles are plain checks on characters and a fixpoint over the
 * edges, apart from the model's own code.
 *
 * Modelled on services/p0-connector-harbor/src/accesses/project-role/__tests__/definition.property.test.ts.
 * A failure names the seed and the input: `PROPERTY_SEED=<n>` replays it.
 */
import { describe, expect, it } from "vitest";

import { propertySeed, seededRandom } from "../../__tests__/fixtures.ts";
import {
  type Grant,
  PolicyLineError,
  addLine,
  buildLine,
  holds,
  parseCsvLine,
  parseP0Line,
  parsePolicy,
  parseScopes,
  removeLine,
} from "../policy.ts";

const seed = propertySeed();
// Thousands of cases, which a loaded machine can take seconds over.
const OPTIONS = { timeout: 60_000 };

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
  /** Whitespace Argo CD trims around a line or a field. */
  const space = () => text([" ", " ", "\t"], 2);
  return { random, int, pick, text, space };
};

/** Fails the test with the seed and the case. */
const fail = (what: string, input: unknown): never => {
  throw new Error(
    `${what} (PROPERTY_SEED=${seed}) for ${JSON.stringify(input)}`
  );
};

const isLower = (c: string) => c >= "a" && c <= "z";
const isUpper = (c: string) => c >= "A" && c <= "Z";
const isDigit = (c: string) => c >= "0" && c <= "9";
const every = (text: string, allowed: (c: string) => boolean) =>
  [...text].every(allowed);

/**
 * A field as a CSV writer would quote it: in quotes, with each quote
 * doubled. Leading space before the opening quote is allowed.
 */
const quoted = (field: string) => `"${field.replaceAll('"', '""')}"`;

describe(`the policy model, over random input (PROPERTY_SEED=${seed})`, () => {
  it(
    "a line written from fields reads back as those fields, less the space before an unquoted one",
    OPTIONS,
    () => {
      const { text, space, int, random } = generators();
      // No `,` or `"` here: those only go in quoted fields.
      const PLAIN = [..."aZ0:@._-*/", " "];
      const ANY = [...PLAIN, ",", '"', "#", "'"];
      for (let i = 0; i < 4000; i++) {
        const fields = Array.from({ length: 1 + int(6) }, () =>
          random() < 0.5 ? text(PLAIN, 6) : text(ANY, 6)
        );
        // A plain field may be quoted or not; any other must be.
        const quotes = fields.map(
          (field) =>
            !every(field, (c) => c !== "," && c !== '"') || random() < 0.4
        );
        const line = fields
          .map(
            (field, index) =>
              `${space()}${quotes[index] ? quoted(field) : field}`
          )
          .join(",");

        const read = parseCsvLine(line);

        // Go drops the space before a field, and keeps the rest: a quoted
        // field comes back exactly, an unquoted one less its leading space.
        const expected = fields.map((field, index) =>
          quotes[index] ? field : field.replace(/^[ \t]+/, "")
        );
        if (JSON.stringify(read) !== JSON.stringify(expected)) {
          fail(`read ${JSON.stringify(read)}`, line);
        }
      }
    }
  );

  it(
    "a line with no quotes reads as its comma-split, less each field's leading space; a stray quote refuses the line",
    OPTIONS,
    () => {
      const { text } = generators();
      const ALPHABET = [..."ag:@ ,\t#'", '"'];
      for (let i = 0; i < 6000; i++) {
        const line = text(ALPHABET, 14);

        const read = parseCsvLine(line);

        if (!line.includes('"')) {
          const expected = line
            .split(",")
            .map((field) => field.replace(/^[ \t]+/, ""));
          if (JSON.stringify(read) !== JSON.stringify(expected)) {
            fail(`read ${JSON.stringify(read)}`, line);
          }
          continue;
        }
        // With quotes it may read or not, but what it reads writes back.
        if (read === undefined) continue;
        const again = parseCsvLine(read.map(quoted).join(","));
        if (JSON.stringify(again) !== JSON.stringify(read)) {
          fail("didn't read back", line);
        }
      }
    }
  );

  it(
    "scopes reads a flow list, quoted or not, and an absent or blank one as [groups]",
    OPTIONS,
    () => {
      const { pick, text, space, int } = generators();
      const SCOPE = [..."abcgrouspemil_-."];
      const JUNK = [
        "groups",
        "[groups",
        "groups]",
        "[groups, [email]]",
        `["groups]`,
        `['email"]`,
        "{groups: email}",
        "[groups,]",
      ];
      for (let i = 0; i < 4000; i++) {
        const items = Array.from({ length: int(4) }, () => ({
          scope: pick(["groups", "email", "", text(SCOPE, 8)]),
          quote: pick(["", "'", '"']),
        }));
        const shape = pick(["list", "list", "list", "absent", "blank", "junk"]);
        const value =
          shape === "absent"
            ? undefined
            : shape === "blank"
              ? space()
              : shape === "junk"
                ? pick(JUNK)
                : `${space()}[${items
                    .map(
                      ({ scope, quote }) =>
                        `${space()}${quote}${scope}${quote}${space()}`
                    )
                    .join(",")}${items.length === 0 ? space() : ""}]${space()}`;

        const read = parseScopes(value);

        // An item left empty without quotes isn't one; `[]` is no scopes,
        // and so is one such item alone, since it is written as `[]`.
        const isBlank = ({ scope, quote }: { scope: string; quote: string }) =>
          scope === "" && quote === "";
        const expected =
          shape === "absent" || shape === "blank"
            ? ["groups"]
            : shape === "junk"
              ? undefined
              : items.length <= 1 && items.every(isBlank)
                ? []
                : items.some(isBlank)
                  ? undefined
                  : items.map(({ scope }) => scope);
        if (JSON.stringify(read) !== JSON.stringify(expected)) {
          fail(`scopes ${JSON.stringify(read)}`, value);
        }
      }
    }
  );

  it(
    "buildLine takes exactly a plain email and a strict role, and writes one g line that reads back",
    OPTIONS,
    () => {
      const { pick, text } = generators();
      const LOCAL = [..."aZ09._%+-", "'", ",", "#", " ", "\n", '"', "é"];
      const DOMAIN = [..."aZ09-.", ",", "#", " "];
      const ROLE = [..."aZ09:._-/*@", ",", "#", " ", "\n", '"', "\t", "é"];
      for (let i = 0; i < 6000; i++) {
        const email = pick([
          () => `${text(LOCAL.slice(0, 9), 8)}@${text(DOMAIN.slice(0, 6), 8)}`,
          () => `${text(LOCAL, 6)}@${text(DOMAIN, 6)}`,
          () => `${text(LOCAL, 6)}`,
          () => `a@${"b".repeat(pick([60, 63, 64]))}.com`,
          () => `${"a".repeat(pick([64, 65]))}@b.com`,
        ])();
        const role = pick([
          () => `role:${text(ROLE.slice(0, 11), 10)}`,
          () => `role:${text(ROLE, 6)}`,
          () => text(ROLE.slice(0, 11), 8),
          () =>
            pick(["role:p0-connector", "p0-connector", "role:", "role:admin"]),
          () => `role:${"a".repeat(pick([247, 248, 249]))}`,
        ])();

        let line: string | undefined;
        let error: unknown;
        try {
          line = buildLine(email, { kind: "global", role });
        } catch (thrown) {
          error = thrown;
        }

        const expectedOk = isEmail(email) && isWritableGlobalRole(role);
        if (error !== undefined && !(error instanceof PolicyLineError)) {
          fail("threw an untyped error", { email, role });
        }
        if ((line !== undefined) !== expectedOk) {
          fail(`built ${String(line)}`, { email, role });
        }
        if (line === undefined) continue;
        const lower = email.toLowerCase();
        if (line !== `g, ${lower}, ${role}`)
          fail(`built ${line}`, { email, role });
        if (line.includes("\n")) fail("built two lines", { email, role });
        if (
          JSON.stringify(parseCsvLine(line)) !==
          JSON.stringify(["g", lower, role])
        ) {
          fail("doesn't read as three fields", { email, role });
        }
        const back = parseP0Line(line);
        if (
          JSON.stringify(back) !==
          JSON.stringify({ email: lower, grant: { kind: "global", role } })
        ) {
          fail(`read back ${JSON.stringify(back)}`, { email, role });
        }
      }
    }
  );

  it(
    "buildLine takes exactly an AppProject's name and role name, and writes one g line that reads back",
    OPTIONS,
    () => {
      const { pick, text } = generators();
      const PROJECT = [..."az09-.", "A", "_", ":", ",", "#", " ", "\n"];
      const ROLE = [..."aZ09-_", ".", ":", ",", "#", " ", "\n", '"'];
      for (let i = 0; i < 6000; i++) {
        const email = pick(["alice@example.com", "Bob@Example.com", "bob"]);
        const project = pick([
          () => text(PROJECT.slice(0, 6), 10),
          () => text(PROJECT, 6),
          () => `a${"b".repeat(pick([251, 252, 253]))}`,
        ])();
        const role = pick([
          () => text(ROLE.slice(0, 6), 10),
          () => text(ROLE, 6),
          () => pick(["p0-connector", "role:admin", "a", "-a", "a_"]),
          () => `a${"b".repeat(pick([252, 253]))}`,
        ])();

        let line: string | undefined;
        let error: unknown;
        try {
          line = buildLine(email, { kind: "project", project, role });
        } catch (thrown) {
          error = thrown;
        }

        const expectedOk =
          isEmail(email) && isProjectName(project) && isProjectRole(role);
        if (error !== undefined && !(error instanceof PolicyLineError)) {
          fail("threw an untyped error", { email, project, role });
        }
        if ((line !== undefined) !== expectedOk) {
          fail(`built ${String(line)}`, { email, project, role });
        }
        if (line === undefined) continue;
        const lower = email.toLowerCase();
        const subject = `proj:${project}:${role}`;
        if (line !== `g, ${lower}, ${subject}`) {
          fail(`built ${line}`, { email, project, role });
        }
        if (
          JSON.stringify(parseCsvLine(line)) !==
          JSON.stringify(["g", lower, subject])
        ) {
          fail("doesn't read as three fields", { email, project, role });
        }
        const back = parseP0Line(line);
        if (
          JSON.stringify(back) !==
          JSON.stringify({
            email: lower,
            grant: { kind: "project", project, role },
          })
        ) {
          fail(`read back ${JSON.stringify(back)}`, { email, project, role });
        }
      }
    }
  );

  it("parseP0Line takes only P0's exact spelling of a line", OPTIONS, () => {
    const { pick, space } = generators();
    for (let i = 0; i < 3000; i++) {
      const email = pick(["alice@example.com", "Alice@example.com", "bob"]);
      const role = pick([
        "role:admin",
        "role:p0-connector",
        "admin",
        "role:a#b",
      ]);
      const separator = pick([", ", ", ", ",", " , ", ",  "]);
      const prefix = pick(["g", "g", "p", "G", " g"]);
      const after = pick(["", "", space(), ", x"]);
      const text = `${prefix}${separator}${email}${separator}${role}${after}`;

      const read = parseP0Line(text);

      const ok =
        prefix === "g" &&
        separator === ", " &&
        after === "" &&
        email === "alice@example.com" &&
        role === "role:admin";
      if ((read !== undefined) !== ok)
        fail(`read ${JSON.stringify(read)}`, text);
    }
  });

  it(
    "holds is exactly what the g edges and AppProject groups reach from the email or the default role, in policy keys only",
    OPTIONS,
    () => {
      const { pick, int, random, space } = generators();
      const EMAILS = ["alice@example.com", "bob@example.com"];
      const GLOBAL = ["role:a", "role:b", "role:c", "role:d", "role:admin"];
      const PROJECT_ROLES: [string, string][] = [
        ["shop", "deployer"],
        ["shop", "viewer"],
        ["web", "deployer"],
      ];
      const ROLES = [
        ...GLOBAL,
        ...PROJECT_ROLES.map(([project, role]) => `proj:${project}:${role}`),
      ];
      const SUBJECTS = [...EMAILS, ...ROLES, "Alice@example.com", "devs"];
      const POLICY_KEYS = ["policy.csv", "policy.team.csv", "policy.p0.csv"];
      const OTHER_KEYS = [
        "policy.matchMode",
        "policy.csv.bak",
        "xpolicy.csv",
        "scopes",
      ];
      for (let i = 0; i < 1500; i++) {
        const counted: [string, string][] = [];
        let refused = 0;
        const data: Record<string, string> = {};
        const write = (key: string, line: string) => {
          data[key] = `${data[key] ?? ""}${line}\n`;
        };
        for (let n = int(8); n > 0; n--) {
          const edge: [string, string] = [pick(SUBJECTS), pick(ROLES)];
          const fields = ["g", ...edge].map((field) =>
            random() < 0.2 ? quoted(field) : field
          );
          const line = `${space()}${fields.join(`,${space()}`)}${space()}`;
          // Most lines count; some are in a key Argo CD doesn't read, or
          // commented out, or have a field too many.
          const kind = pick([
            "counted",
            "counted",
            "counted",
            "key",
            "comment",
            "long",
          ]);
          if (kind === "counted") {
            counted.push(edge);
            write(pick(POLICY_KEYS), line);
          } else if (kind === "key") {
            write(pick(OTHER_KEYS), line);
          } else if (kind === "comment") {
            write(pick(POLICY_KEYS), `${space()}#${line}`);
          } else {
            write(pick(POLICY_KEYS), `${line}, extra`);
            refused++;
          }
          if (random() < 0.2)
            write(pick(POLICY_KEYS), pick(["", space(), "# x"]));
          if (random() < 0.1) {
            write(
              pick(POLICY_KEYS),
              `p, ${pick(ROLES)}, applications, get, */*, allow`
            );
          }
        }
        const defaultRole = random() < 0.3 ? pick(ROLES) : undefined;
        if (defaultRole !== undefined) {
          data["policy.default"] = `${space()}${defaultRole}${space()}`;
        }

        // Each AppProject role binds groups, which may name an email.
        const projects = ["shop", "web"].map((name) => ({
          name,
          roles: PROJECT_ROLES.filter(([project]) => project === name).map(
            ([, role]) => {
              const groups = Array.from({ length: int(3) }, () =>
                pick(SUBJECTS)
              );
              for (const group of groups) {
                counted.push([group, `proj:${name}:${role}`]);
              }
              return { name: role, groups };
            }
          ),
        }));

        const policy = parsePolicy({ data }, projects);

        if (policy.refusedLines.length !== refused) {
          fail(
            `${policy.refusedLines.length} refused lines, not ${refused}`,
            data
          );
        }

        // The oracle: a fixpoint over the counted edges.
        const reach = (from: string) => {
          const seen = new Set([from]);
          for (let grew = true; grew; ) {
            grew = false;
            for (const [subject, role] of counted) {
              if (seen.has(subject) && !seen.has(role)) {
                seen.add(role);
                grew = true;
              }
            }
          }
          return seen;
        };
        const everyone =
          defaultRole === undefined ? new Set() : reach(defaultRole);
        for (const email of [...EMAILS, "ALICE@example.com"]) {
          const mine = reach(email.toLowerCase());
          const grants: [string, Grant][] = [
            ...GLOBAL.map((role): [string, Grant] => [
              role,
              { kind: "global", role },
            ]),
            ...PROJECT_ROLES.map(([project, role]): [string, Grant] => [
              `proj:${project}:${role}`,
              { kind: "project", project, role },
            ]),
          ];
          for (const [role, grant] of grants) {
            const expected = mine.has(role) || everyone.has(role);
            if (holds(policy, email, grant) !== expected) {
              fail(`holds(${email}, ${role}) isn't ${String(expected)}`, {
                data,
                projects,
              });
            }
          }
        }
      }
    }
  );

  it(
    "addLine then removeLine leaves every other line as it was, and both are idempotent",
    OPTIONS,
    () => {
      const { pick, int, space } = generators();
      const OTHERS = [
        "g, carol@example.com, role:admin",
        "g, alice@example.com, role:admin-plus",
        "g,alice@example.com,role:admin",
        "# g, alice@example.com, role:admin",
        "p, role:admin, applications, get, */*, allow",
        "",
        "g, alice@example.com, role:admi",
      ];
      const ours = buildLine("Alice@Example.com", {
        kind: "global",
        role: "role:admin",
      });
      for (let i = 0; i < 3000; i++) {
        const lines = Array.from({ length: int(7) }, () =>
          pick([...OTHERS, `${space()}${ours}${space()}`])
        );
        const value = pick([
          () => undefined,
          () => lines.join("\n"),
          () => `${lines.join("\n")}\n`,
          () => lines.join("\r\n"),
        ])();
        const others = (value ?? "")
          .split("\n")
          .filter((line) => line.trim() !== ours);

        const added = addLine(value, ours);
        const removed = removeLine(added, ours);

        // Added: our line is there once at least, and the rest untouched.
        const addedLines = added.split("\n");
        if (!addedLines.some((line) => line.trim() === ours)) {
          fail("addLine didn't add", value);
        }
        if (addLine(added, ours) !== added)
          fail("addLine isn't idempotent", value);
        // Removed: no copy of ours, and the others in order, byte for byte.
        const left = removed.split("\n");
        if (left.some((line) => line.trim() === ours)) {
          fail("removeLine left a copy", value);
        }
        if (
          JSON.stringify(left.filter((line) => line !== "")) !==
          JSON.stringify(others.filter((line) => line !== ""))
        ) {
          fail(
            `removeLine changed another line: ${JSON.stringify(removed)}`,
            value
          );
        }
        if (removeLine(removed, ours) !== removed) {
          fail("removeLine isn't idempotent", value);
        }
        // A value with no copy of ours comes back as it was.
        if (
          value !== undefined &&
          !value.split("\n").some((line) => line.trim() === ours)
        ) {
          if (removeLine(value, ours) !== value)
            fail("removeLine changed it", value);
        }
      }
    }
  );

  it("names the seed it ran with", () => {
    expect(Number.isSafeInteger(seed)).toBe(true);
  });
});

/**
 * P0's email rule, by its characters: a local part of letters, digits and
 * `._%+-'`, up to 64; an `@`; and a domain of two or more dot-separated
 * labels of letters, digits and inner hyphens, each up to 63. At most 254 in
 * all. Either case: the line holds it in lower case.
 */
function isEmail(email: string): boolean {
  if (email.length > 254) return false;
  const parts = email.split("@");
  if (parts.length !== 2) return false;
  const [local = "", domain = ""] = parts;
  const isAlnum = (c: string) => isLower(c) || isUpper(c) || isDigit(c);
  if (local.length < 1 || local.length > 64) return false;
  if (!every(local, (c) => isAlnum(c) || "._%+-'".includes(c))) return false;
  const labels = domain.split(".");
  return (
    labels.length >= 2 &&
    labels.every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        isAlnum(label[0] ?? "") &&
        isAlnum(label[label.length - 1] ?? "") &&
        every(label, (c) => isAlnum(c) || c === "-")
    )
  );
}

/**
 * A global role P0 grants: `role:` and a name of printable ASCII other than
 * space, `,`, `#` and `"`, up to 253 in all, other than the connector's own.
 */
function isWritableGlobalRole(role: string): boolean {
  if (!role.startsWith("role:") || role === "role:p0-connector") return false;
  const name = role.slice("role:".length);
  return (
    name.length >= 1 &&
    role.length <= 253 &&
    every(
      name,
      (c) => c > " " && c <= "~" && c !== "," && c !== "#" && c !== '"'
    )
  );
}

/**
 * An AppProject's name: a Kubernetes object name, so dot-separated parts of
 * lowercase letters, digits and inner hyphens, at most 253 in all.
 */
function isProjectName(name: string): boolean {
  const isAlnum = (c: string) => isLower(c) || isDigit(c);
  return (
    name.length >= 1 &&
    name.length <= 253 &&
    name
      .split(".")
      .every(
        (part) =>
          part.length >= 1 &&
          isAlnum(part[0] ?? "") &&
          isAlnum(part[part.length - 1] ?? "") &&
          every(part, (c) => isAlnum(c) || c === "-")
      )
  );
}

/**
 * An AppProject role's name, as Argo CD checks it: letters, digits, `-` and
 * `_`, starting and ending with a letter or digit. At most 253.
 */
function isProjectRole(role: string): boolean {
  const isAlnum = (c: string) => isLower(c) || isUpper(c) || isDigit(c);
  return (
    role.length >= 1 &&
    role.length <= 253 &&
    isAlnum(role[0] ?? "") &&
    isAlnum(role[role.length - 1] ?? "") &&
    every(role, (c) => isAlnum(c) || c === "-" || c === "_")
  );
}

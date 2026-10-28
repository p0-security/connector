import { describe, expect, it } from "vitest";

import {
  type Grant,
  type P0Line,
  PolicyLineError,
  addLine,
  buildLine,
  holds,
  parseCsvLine,
  parseP0Line,
  parsePolicy,
  parseScopes,
  policyKeys,
  removeLine,
} from "../policy.ts";

const ADMIN: Grant = { kind: "global", role: "role:admin" };
const role = (name: string): Grant => ({ kind: "global", role: name });

const refusalOf = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    if (error instanceof PolicyLineError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
};

describe("parseCsvLine", () => {
  it.each<[line: string, fields: string[] | undefined]>([
    [
      "g, alice@example.com, role:admin",
      ["g", "alice@example.com", "role:admin"],
    ],
    [
      "g,alice@example.com,role:admin",
      ["g", "alice@example.com", "role:admin"],
    ],
    // Go keeps the space after a field, and inside quotes.
    [
      "g ,  alice@example.com\t, role:admin  ",
      ["g ", "alice@example.com\t", "role:admin  "],
    ],
    ['g, " role:admin "', ["g", " role:admin "]],
    ["g,\u00a0a,\ufeffb", ["g", "a", "\ufeffb"]],
    ["g,\va,\fb,Vc", ["g", "a", "b", "Vc"]],
    [
      'p, role:org, applications, *, "proj/*", allow',
      ["p", "role:org", "applications", "*", "proj/*", "allow"],
    ],
    ['g, "my, group", role:admin', ["g", "my, group", "role:admin"]],
    ['g, "say ""hi""", role:admin', ["g", 'say "hi"', "role:admin"]],
    ['g,   "a", role:x', ["g", "a", "role:x"]],
    ["g, a #b, role:x", ["g", "a #b", "role:x"]],
    ["g, a,", ["g", "a", ""]],
    // Go's reader refuses these.
    ['g, a"b, role:x', undefined],
    ['g, "a" , role:x', undefined],
    ['g, "a"b, role:x', undefined],
    ['g, "a, role:x', undefined],
  ])("reads %j", (line, fields) => {
    expect(parseCsvLine(line)).toEqual(fields);
  });
});

describe("policyKeys", () => {
  it("reads policy.csv first, then every other policy.*.csv key in order", () => {
    expect(
      policyKeys({
        "policy.z.csv": "",
        "policy.p0.csv": "",
        "policy.default": "",
        "policy.matchMode": "",
        "policy.csv.bak": "",
        "policy.a.csv": "",
        "policy.csv": "",
        "xpolicy.csv": "",
        scopes: "",
      })
    ).toEqual(["policy.csv", "policy.a.csv", "policy.p0.csv", "policy.z.csv"]);
  });

  it("has no policy.csv when there isn't one", () => {
    expect(policyKeys({ "policy.p0.csv": "" })).toEqual(["policy.p0.csv"]);
  });
});

describe("parseScopes", () => {
  it.each<[value: string | undefined, scopes: string[] | undefined]>([
    [undefined, ["groups"]],
    ["", ["groups"]],
    ["  \n", ["groups"]],
    ["[groups, email]", ["groups", "email"]],
    ["[email]", ["email"]],
    [" [ 'groups' , \"email\" ] ", ["groups", "email"]],
    ["[]", []],
    [
      "[groups, https://example.com/claims/email]",
      ["groups", "https://example.com/claims/email"],
    ],
    ["groups", undefined],
    ["[groups", undefined],
    ["[groups,]", undefined],
    ["[groups, , email]", undefined],
    ["['groups]", undefined],
    ["[']", undefined],
    ['[groups, "]', undefined],
    ["['gro'ups']", undefined],
    ["[[groups]]", undefined],
    ["- groups\n- email", undefined],
  ])("reads %j", (value, scopes) => {
    expect(parseScopes(value)).toEqual(scopes);
  });

  it("is read from argocd-rbac-cm", () => {
    expect(parsePolicy({ data: {} }).scopes).toEqual(["groups"]);
    expect(parsePolicy({ data: { scopes: "[groups, email]" } }).scopes).toEqual(
      ["groups", "email"]
    );
  });
});

describe("buildLine", () => {
  it("writes a g line, the email in lower case", () => {
    expect(buildLine("Alice.Smith+argo@Example.COM", ADMIN)).toBe(
      "g, alice.smith+argo@example.com, role:admin"
    );
    expect(buildLine("o'brien@sub.example.co", role("role:org/team-1"))).toBe(
      "g, o'brien@sub.example.co, role:org/team-1"
    );
  });

  it.each([
    "alice",
    "",
    "alice@example",
    "alice@example.com, role:admin",
    "alice@example.com\ng, bob@example.com",
    "#alice@example.com",
    "alice@example.com#",
    '"alice"@example.com',
    "alice @example.com",
    "alice@-example.com",
    "alice@example-.com",
    "alice@example..com",
    "p0-connector",
    "álice@example.com",
    `${"a".repeat(65)}@example.com`,
    `a@${"b".repeat(64)}.com`,
    `a@${Array.from({ length: 5 }, () => "b".repeat(63)).join(".")}`,
    // 255 characters.
    `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}`,
  ])("refuses the email %j", (email) => {
    const error = refusalOf(() => buildLine(email, ADMIN));
    expect(error.reason).toBe("email");
    expect(error.message).toBe("not a line P0 writes: bad email");
  });

  it.each([
    "admin",
    "role:",
    "role:a,b",
    "role:a#b",
    'role:a"b',
    "role:a b",
    "role:a\nb",
    "role:a\tb",
    "role:é",
    "proj:p:r",
    " role:admin",
    "role:admin ",
    `role:${"a".repeat(249)}`,
  ])("refuses the role %j", (name) => {
    expect(
      refusalOf(() => buildLine("alice@example.com", role(name))).reason
    ).toBe("role");
  });

  it("takes an email of 254 characters", () => {
    const longest = `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
    expect(longest).toHaveLength(254);
    expect(buildLine(longest, ADMIN)).toBe(`g, ${longest}, role:admin`);
  });

  it("takes a role of 253 characters", () => {
    const longest = `role:${"a".repeat(248)}`;
    expect(buildLine("a@b.co", role(longest))).toBe(`g, a@b.co, ${longest}`);
  });

  it("refuses the connector's own role", () => {
    const error = refusalOf(() =>
      buildLine("alice@example.com", role("role:p0-connector"))
    );
    expect(error.reason).toBe("connector_role");
    expect(error.name).toBe("PolicyLineError");
  });
});

describe("parseP0Line", () => {
  it("reads a line buildLine writes", () => {
    expect(parseP0Line("g, alice@example.com, role:admin")).toEqual({
      email: "alice@example.com",
      grant: ADMIN,
    });
  });

  it.each([
    "g,alice@example.com,role:admin",
    "g, alice@example.com, role:admin ",
    " g, alice@example.com, role:admin",
    "g, Alice@example.com, role:admin",
    "g, alice@example.com, role:p0-connector",
    "g, p0-connector, role:admin",
    "p, alice@example.com, role:admin",
    "g, alice@example.com, role:admin, x",
    "g, alice@example.com",
    "",
    "# g, alice@example.com, role:admin",
  ])("refuses %j", (text) => {
    expect(parseP0Line(text)).toBeUndefined();
  });
});

describe("addLine and removeLine", () => {
  const ours = buildLine("alice@example.com", ADMIN);
  const theirs = "g, alice@example.com, role:admin-plus";

  it("adds a line to an absent, empty or unterminated value", () => {
    expect(addLine(undefined, ours)).toBe(`${ours}\n`);
    expect(addLine("", ours)).toBe(`${ours}\n`);
    expect(addLine(theirs, ours)).toBe(`${theirs}\n${ours}\n`);
    expect(addLine(`${theirs}\n`, ours)).toBe(`${theirs}\n${ours}\n`);
  });

  it("leaves a value that has the line as it was", () => {
    expect(addLine(`${ours}\n${theirs}`, ours)).toBe(`${ours}\n${theirs}`);
    expect(addLine(`  ${ours}\r\n`, ours)).toBe(`  ${ours}\r\n`);
  });

  it("removes every copy of exactly the line, and nothing else", () => {
    const value = [
      ours,
      theirs,
      `  ${ours}\r`,
      "g,alice@example.com,role:admin",
      `# ${ours}`,
      "g, alice@example.com, role:admi",
      "g, bob@example.com, role:admin",
      "",
    ].join("\n");
    expect(removeLine(value, ours)).toBe(
      [
        theirs,
        "g,alice@example.com,role:admin",
        `# ${ours}`,
        "g, alice@example.com, role:admi",
        "g, bob@example.com, role:admin",
        "",
      ].join("\n")
    );
  });

  it("leaves a value without the line as it was", () => {
    expect(removeLine(undefined, ours)).toBe("");
    expect(removeLine(`${theirs}\n`, ours)).toBe(`${theirs}\n`);
    expect(removeLine(`${theirs}\n${ours}\n`, ours)).toBe(`${theirs}\n`);
  });

  it("takes only a line buildLine made", () => {
    // @ts-expect-error a string isn't a P0Line
    const untyped: P0Line = "g, alice@example.com, role:admin";
    expect(untyped).toBe(ours);
  });
});

describe("holds", () => {
  // Argo CD's own example, from its RBAC docs, and lines of P0's.
  const data = {
    "policy.csv": [
      "# Grant all members of 'my-org:team-alpha' the ability to sync apps",
      "p, my-org:team-alpha, applications, sync, my-project/*, allow",
      "g, my-org:team-beta, role:admin",
      "g, user@example.org, role:admin",
      "",
      "  g, carol@example.com, role:ops  ",
      "g, oscar@example.com , role:admin",
      'g, peggy@example.com, " role:admin"',
      'g, "dave@example.com", "role:ops"',
      "g, role:ops, role:deployer",
      "g, role:deployer, role:viewer",
      "g, role:viewer, role:ops",
      "# g, erin@example.com, role:admin",
      "g, frank@example.com, role:admin, extra",
      'g, "grace@example.com, role:admin',
      "g, Henry@Example.com, role:admin",
      "g, ivan@example.com, proj:shop:deployer",
    ].join("\n"),
    "policy.p0.csv": "g, judy@example.com, role:viewer\n",
    "policy.team.csv": "g,kim@example.com,role:team\r\n",
    "policy.csv.bak": "g, mallory@example.com, role:admin",
    "policy.default": " role:readonly ",
  };
  // Parsed in each test, so a mutation tool sees which test reads it.
  const policy = () => parsePolicy({ data });

  it.each<[email: string, grant: Grant, held: boolean]>([
    ["user@example.org", ADMIN, true],
    ["USER@example.org", ADMIN, true],
    ["user@example.org", role("role:ops"), false],
    // Through a chain, with a cycle in it.
    ["carol@example.com", role("role:ops"), true],
    ["carol@example.com", role("role:deployer"), true],
    ["carol@example.com", role("role:viewer"), true],
    ["carol@example.com", ADMIN, false],
    // Argo CD keeps the space after a field, so these name other subjects.
    ["oscar@example.com", ADMIN, false],
    ["peggy@example.com", ADMIN, false],
    ["dave@example.com", role("role:viewer"), true],
    // In another key: P0's own, and one whose lines end in \r.
    ["judy@example.com", role("role:viewer"), true],
    ["judy@example.com", ADMIN, false],
    ["kim@example.com", role("role:team"), true],
    // Everyone holds the default role.
    ["nobody@example.com", role("role:readonly"), true],
    ["nobody@example.com", ADMIN, false],
    // Not counted: a comment, a line Argo CD refuses, a key it doesn't read.
    ["erin@example.com", ADMIN, false],
    ["frank@example.com", ADMIN, false],
    ["grace@example.com", ADMIN, false],
    ["mallory@example.com", ADMIN, false],
    // Argo CD matches subjects as written: this line names Henry@Example.com.
    ["henry@example.com", ADMIN, false],
  ])("%s holds %j: %s", (email, grant, held) => {
    expect(holds(policy(), email, grant)).toBe(held);
  });

  it("can't see IdP groups: a group's line counts only for a subject that is the email", () => {
    // A member of my-org:team-beta holds role:admin in Argo CD, but the
    // connector can't know who is.
    expect(holds(policy(), "member-of-team-beta@example.com", ADMIN)).toBe(
      false
    );
  });

  it("counts what the default role inherits", () => {
    const withDefault = parsePolicy({
      data: {
        "policy.csv": "g, role:base, role:viewer\ng, role:viewer, role:base",
        "policy.default": "role:base",
      },
    });
    expect(holds(withDefault, "a@b.co", role("role:viewer"))).toBe(true);
    expect(holds(withDefault, "a@b.co", role("role:base"))).toBe(true);
    expect(holds(withDefault, "a@b.co", ADMIN)).toBe(false);
  });

  it("says where the lines Argo CD refuses are", () => {
    expect(policy().refusedLines).toEqual([
      { key: "policy.csv", line: 14 },
      { key: "policy.csv", line: 15 },
    ]);
    expect(
      parsePolicy({
        data: {
          "policy.a.csv": "x, a, b\n\n# fine\ng, a",
          "policy.b.csv": "p, role:x, applications, get, */*\n",
        },
      }).refusedLines
    ).toEqual([
      { key: "policy.a.csv", line: 1 },
      { key: "policy.a.csv", line: 4 },
      { key: "policy.b.csv", line: 1 },
    ]);
  });

  it("reads no default role from a blank or absent one", () => {
    expect(parsePolicy({ data: { "policy.default": "  " } }).defaultRole).toBe(
      undefined
    );
    expect(parsePolicy({ data: {} }).defaultRole).toBe(undefined);
    expect(
      holds(parsePolicy({ data: { "policy.default": "" } }), "a@b.co", role(""))
    ).toBe(false);
  });
});

describe("project roles", () => {
  const DEPLOYER: Grant = {
    kind: "project",
    project: "shop",
    role: "deployer",
  };

  it("builds a proj line and reads it back", () => {
    const line = buildLine("Alice@Example.com", DEPLOYER);
    expect(line).toBe("g, alice@example.com, proj:shop:deployer");
    expect(parseP0Line(line)).toEqual({
      email: "alice@example.com",
      grant: DEPLOYER,
    });
    expect(
      buildLine("a@b.co", {
        kind: "project",
        project: "a.b-1",
        role: "Ci_Bot-2",
      })
    ).toBe("g, a@b.co, proj:a.b-1:Ci_Bot-2");
  });

  it.each([
    "",
    "Shop",
    "shop:x",
    "shop,x",
    "shop#",
    "-shop",
    "shop-",
    "shop..x",
    "shop x",
    `a${"b".repeat(253)}`,
  ])("refuses the project %j", (project) => {
    expect(
      refusalOf(() =>
        buildLine("a@b.co", { kind: "project", project, role: "deployer" })
      ).reason
    ).toBe("project");
  });

  it.each(["", "-a", "a-", "_a", "a:b", "a,b", "a#b", "a b", "a.b", "a\nb"])(
    "refuses the role %j",
    (role) => {
      expect(
        refusalOf(() =>
          buildLine("a@b.co", { kind: "project", project: "shop", role })
        ).reason
      ).toBe("role");
    }
  );

  it("parseP0Line reads a global role that has proj: in its name", () => {
    expect(parseP0Line("g, alice@example.com, role:proj:a:b")).toEqual({
      email: "alice@example.com",
      grant: role("role:proj:a:b"),
    });
  });

  it.each([
    "g, alice@example.com, proj:shop",
    "g, alice@example.com, proj:shop:deployer:x",
    "g, alice@example.com, proj:Shop:deployer",
    "g, alice@example.com, proj::deployer",
    "g,alice@example.com,proj:shop:deployer",
  ])("parseP0Line refuses %j", (text) => {
    expect(parseP0Line(text)).toBeUndefined();
  });

  it("removeLine removes only the project line", () => {
    const ours = buildLine("alice@example.com", DEPLOYER);
    const value = [
      "g, alice@example.com, proj:shop:deployer",
      "g, alice@example.com, proj:shop:deployers",
      "g, alice@example.com, proj:shops:deployer",
      "g, alice@example.com, role:deployer",
    ].join("\n");
    expect(removeLine(value, ours)).toBe(
      [
        "g, alice@example.com, proj:shop:deployers",
        "g, alice@example.com, proj:shops:deployer",
        "g, alice@example.com, role:deployer",
      ].join("\n")
    );
  });

  describe("holds", () => {
    // Parsed in each test, so a mutation tool sees which test reads it.
    const policy = () =>
      parsePolicy(
        {
          data: {
            "policy.csv": [
              "g, alice@example.com, proj:shop:deployer",
              "g, bob@example.com, role:release",
              "g, role:release, proj:web:deployer",
            ].join("\n"),
          },
        },
        [
          {
            name: "shop",
            roles: [
              { name: "deployer", groups: ["my-org:shop-team"] },
              { name: "viewer", groups: ["carol@example.com", "role:release"] },
            ],
          },
          { name: "web", roles: [{ name: "deployer", groups: [] }] },
        ]
      );
    const grant = (project: string, role: string): Grant => ({
      kind: "project",
      project,
      role,
    });

    it.each<[email: string, grant: Grant, held: boolean]>([
      // A global g line for the project role.
      ["alice@example.com", grant("shop", "deployer"), true],
      ["alice@example.com", grant("shop", "viewer"), false],
      // An AppProject group that is the email.
      ["Carol@example.com", grant("shop", "viewer"), true],
      ["carol@example.com", grant("shop", "deployer"), false],
      // Through a global role, by a g line or by the project's groups.
      ["bob@example.com", grant("web", "deployer"), true],
      ["bob@example.com", grant("shop", "viewer"), true],
      ["bob@example.com", grant("shop", "deployer"), false],
      // A same-named role on another project isn't it.
      ["alice@example.com", grant("web", "deployer"), false],
    ])("%s holds %j: %s", (email, g, held) => {
      expect(holds(policy(), email, g)).toBe(held);
    });

    it("can't see IdP groups: a group in an AppProject role counts for no email", () => {
      expect(
        holds(
          policy(),
          "member-of-shop-team@example.com",
          grant("shop", "deployer")
        )
      ).toBe(false);
    });
  });
});

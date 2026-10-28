import { describe, expect, it } from "vitest";

import { parsePolicy } from "../policy.ts";
import { listRoles } from "../roles.ts";

describe("listRoles", () => {
  it("lists the built-ins when no line names a role", () => {
    expect(listRoles(parsePolicy({ data: {} }))).toEqual({
      global: ["role:admin", "role:readonly"],
      projects: [],
    });
  });

  it("lists every role a g or p line names, once and in order", () => {
    const policy = parsePolicy({
      data: {
        "policy.csv": [
          "p, role:deployer, applications, sync, */*, allow",
          "g, alice@example.com, role:viewer",
          "g, role:viewer, role:base",
          "g, role:subject-only, role:base",
          "g, role:too-many, role:base, extra",
          "p, role:too-few, applications, get, */*",
          "x, role:not-a-line, role:base",
          "g, my-org:team, role:admin",
          "g, bob@example.com, role:viewer",
          "# g, carol@example.com, role:commented",
          "g, ivan@example.com, proj:shop:deployer",
          "p, my-org:team, applications, get, */*, allow",
        ].join("\n"),
        "policy.team.csv": "g, dave@example.com, role:team",
        "policy.bak": "g, erin@example.com, role:elsewhere",
      },
    });
    expect(listRoles(policy).global).toEqual([
      "role:admin",
      "role:base",
      "role:deployer",
      "role:readonly",
      "role:subject-only",
      "role:team",
      "role:viewer",
    ]);
  });

  it("leaves out the connector's role and the default role", () => {
    const policy = parsePolicy({
      data: {
        "policy.csv": [
          "p, role:p0-connector, projects, get, *, allow",
          "g, p0-connector, role:p0-connector",
          "g, alice@example.com, role:viewer",
        ].join("\n"),
        "policy.default": "role:readonly",
      },
    });
    expect(listRoles(policy).global).toEqual(["role:admin", "role:viewer"]);
  });

  it("leaves out a role P0 wouldn't write", () => {
    const policy = parsePolicy({
      data: {
        "policy.csv": [
          'g, alice@example.com, "role:a, b"',
          'g, alice@example.com, "role:a #b"',
          'g, alice@example.com, "role:"',
          "g, alice@example.com, role:ok",
        ].join("\n"),
      },
    });
    expect(listRoles(policy).global).toEqual([
      "role:admin",
      "role:ok",
      "role:readonly",
    ]);
  });
});

describe("listRoles's project roles", () => {
  it("lists each AppProject's role names, in order", () => {
    const policy = parsePolicy({ data: {} }, [
      { name: "shop", roles: [{ name: "admin", groups: [] }] },
      {
        name: "web",
        roles: [
          { name: "viewer", groups: [] },
          { name: "deployer", groups: ["team"] },
        ],
      },
      { name: "empty", roles: [] },
    ]);
    expect(listRoles(policy).projects).toEqual([
      { name: "empty", roles: [] },
      { name: "shop", roles: ["admin"] },
      { name: "web", roles: ["deployer", "viewer"] },
    ]);
  });

  it("leaves out a project or role P0 wouldn't write", () => {
    const policy = parsePolicy({ data: {} }, [
      { name: "Bad Project", roles: [{ name: "deployer", groups: [] }] },
      {
        name: "shop",
        roles: [
          { name: "ok", groups: [] },
          { name: "has space", groups: [] },
          { name: "-dash", groups: [] },
        ],
      },
    ]);
    expect(listRoles(policy).projects).toEqual([
      { name: "shop", roles: ["ok"] },
    ]);
  });

  it("has no projects when none were read", () => {
    expect(listRoles(parsePolicy({ data: {} })).projects).toEqual([]);
  });
});

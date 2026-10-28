import { describe, expect, it } from "vitest";

import { displayRole, toPutRole } from "../roles.ts";

describe("toPutRole", () => {
  it.each([
    ["read", "pull"],
    ["Read", "pull"],
    ["write", "push"],
    ["WRITE", "push"],
    ["pull", "pull"],
    ["push", "push"],
    ["Triage", "triage"],
    ["triage_plus", "triage_plus"],
    ["Triage Plus", "triage_plus"],
    ["triage plus", "triage_plus"],
    ["TRIAGE_PLUS", "triage_plus"],
    ["triage-plus", "triage_plus"],
    ["Maintain", "maintain"],
    ["admin", "admin"],
  ])("maps the built-in %s to %s", (role, putRole) => {
    expect(toPutRole(role)).toBe(putRole);
  });

  it("keeps a custom role's name as GitHub gave it", () => {
    expect(toPutRole("Security Reviewer")).toBe("Security Reviewer");
  });
});

describe("displayRole", () => {
  it("shows the name GitHub shows", () => {
    expect(displayRole("push")).toBe("Write");
    expect(displayRole("read")).toBe("Read");
    expect(displayRole("triage plus")).toBe("Triage Plus");
    expect(displayRole("Labeler")).toBe("Labeler");
  });
});

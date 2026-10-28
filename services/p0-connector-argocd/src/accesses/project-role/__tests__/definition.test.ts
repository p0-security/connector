import { describe, expect, it } from "vitest";

import { INSTANCE } from "../../../__tests__/fixtures.ts";
import { projectName, projectRole, spec } from "../definition.ts";

describe("projectName", () => {
  it.each(["payments", "a", "team-a.payments", "0x"])("takes %s", (name) => {
    expect(projectName.parse(name)).toBe(name);
  });

  it.each([
    ["an upper-case letter", "Payments"],
    ["a colon", "pay:ments"],
    ["a slash", "pay/ments"],
    ["a leading hyphen", "-payments"],
    ["an empty name", ""],
    ["more than 253 characters", "a".repeat(254)],
  ])(
    "refuses a name with %s, saying only what a name must be",
    (_case, name) => {
      expect(
        projectName.safeParse(name).error?.issues.map(({ message }) => message)
      ).toEqual(["must be an Argo CD project name"]);
    }
  );
});

describe("projectRole", () => {
  it.each(["deployer", "Deploy_er-1", "x"])("takes %s", (role) => {
    expect(projectRole.parse(role)).toBe(role);
  });

  it.each([
    ["a colon", "dep:loyer"],
    ["the subject form", "proj:payments:deployer"],
    ["a space", "dep loyer"],
    ["a trailing hyphen", "deployer-"],
    ["an empty name", ""],
    ["more than 253 characters", "a".repeat(254)],
  ])(
    "refuses a role with %s, saying only what a role must be",
    (_case, role) => {
      expect(
        projectRole.safeParse(role).error?.issues.map(({ message }) => message)
      ).toEqual(["must be an Argo CD project role name"]);
    }
  );
});

describe("the project role access's schema", () => {
  const context = {
    ...INSTANCE,
    requestId: "req-1",
    project: "payments",
    role: "deployer",
  };

  it("fills the request context's namespace in", () => {
    expect(spec.requestContext(context)).toEqual({
      ...context,
      namespace: "argocd",
    });
  });

  it.each(["project", "role"] as const)(
    "requires the request context's %s",
    (field) => {
      const { [field]: _, ...without } = context;
      expect(() => spec.requestContext(without)).toThrow();
    }
  );

  it.each([
    { project: "payments", role: "deployer" },
    { project: "payments", role: null },
  ])("takes the policy %o", (policy) => {
    expect(spec.policy(policy)).toEqual(policy);
  });

  it.each([
    { role: "deployer" },
    { project: "payments" },
    { project: "Payments", role: null },
  ])("refuses the policy %o", (policy) => {
    expect(() => spec.policy(policy)).toThrow();
  });

  it.each([
    { type: "project", context: INSTANCE },
    { type: "project", context: INSTANCE, project: "payments" },
    { type: "role", context: INSTANCE, project: "payments" },
    { type: "role", context: INSTANCE, project: "payments", role: "deployer" },
    {
      type: "held",
      context: INSTANCE,
      email: "alice@example.com",
      project: "payments",
      role: "deployer",
    },
  ])("takes the lister query %o", (query) => {
    expect(spec.listerQuery(query)).toEqual({
      ...query,
      context: { ...INSTANCE, namespace: "argocd" },
    });
  });

  it.each([
    { type: "role", context: INSTANCE },
    { type: "held", context: INSTANCE, email: "a@example.com", role: "x" },
    { type: "project", context: INSTANCE, project: "pay/ments" },
  ])("refuses the lister query %o", (query) => {
    expect(() => spec.listerQuery(query)).toThrow();
  });
});

import { describe, expect, it } from "vitest";

import { INSTANCE } from "../../../__tests__/fixtures.ts";
import { globalRole, spec } from "../definition.ts";

describe("globalRole", () => {
  it.each(["role:readonly", "role:admin", "role:p0-connector", "role:a.b_c-d"])(
    "takes %s",
    (role) => {
      expect(globalRole.parse(role)).toBe(role);
    }
  );

  it.each([
    ["no role: prefix", "admin"],
    ["an empty name", "role:"],
    ["a space", "role:my role"],
    ["a comma", "role:a,b"],
    ["a #", "role:a#b"],
    ["a quote", 'role:a"b'],
    ["a newline", "role:a\nb"],
    ["more than 253 characters", `role:${"a".repeat(249)}`],
    ["a project role's subject", "proj:payments:deployer"],
  ])(
    "refuses a role with %s, saying only what a role must be",
    (_case, role) => {
      const result = globalRole.safeParse(role);
      expect(result.success).toBe(false);
      // One issue: an over-long role stops the parse before the pattern runs.
      expect(result.error?.issues.map(({ message }) => message)).toEqual([
        "must be an Argo CD role, as role:<name>",
      ]);
    }
  );
});

describe("the global role access's schema", () => {
  const context = { ...INSTANCE, requestId: "req-1", role: "role:dev" };

  it("fills the request context's namespace in", () => {
    expect(spec.requestContext(context)).toEqual({
      ...context,
      namespace: "argocd",
    });
  });

  it("requires the request context's role", () => {
    const { role: _, ...withoutRole } = context;
    expect(() => spec.requestContext(withoutRole)).toThrow();
  });

  it.each([{ role: "role:dev" }, { role: null }])(
    "takes the policy %o",
    (policy) => {
      expect(spec.policy(policy)).toEqual(policy);
    }
  );

  it.each([{}, { role: "dev" }, { role: undefined }])(
    "refuses the policy %o",
    (policy) => {
      expect(() => spec.policy(policy)).toThrow();
    }
  );

  it("takes the user body, and keeps the email as P0 sent it", () => {
    expect(
      spec.userBody({ instanceId: "p0-argocd", email: "Alice@Example.com" })
    ).toEqual({ instanceId: "p0-argocd", email: "Alice@Example.com" });
  });

  it.each([
    { instanceId: "", email: "alice@example.com" },
    { instanceId: "p0-argocd", email: "" },
    { instanceId: "p0-argocd" },
  ])("refuses the user body %o", (body) => {
    expect(() => spec.userBody(body)).toThrow();
  });

  it.each([
    { type: "role", context: INSTANCE },
    { type: "role", context: INSTANCE, role: "role:dev" },
    {
      type: "held",
      context: INSTANCE,
      email: "alice@example.com",
      role: "role:dev",
    },
  ])("takes the lister query %o", (query) => {
    expect(spec.listerQuery(query)).toEqual({
      ...query,
      context: { ...INSTANCE, namespace: "argocd" },
    });
  });

  it.each([
    { type: "project", context: INSTANCE },
    { type: "role", context: INSTANCE, role: "dev" },
    { type: "held", context: INSTANCE, role: "role:dev" },
    { type: "held", context: INSTANCE, email: "alice@example.com" },
    { type: "role" },
  ])("refuses the lister query %o", (query) => {
    expect(() => spec.listerQuery(query)).toThrow();
  });
});

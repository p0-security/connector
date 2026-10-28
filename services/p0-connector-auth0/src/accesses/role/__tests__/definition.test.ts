import { describe, expect, it } from "vitest";

import { CREDENTIALS, EMAIL } from "../../../__tests__/fixtures.ts";
import { schema } from "../definition.ts";

const CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  auth0UserId: "auth0|alice",
  roleId: "rol_admin",
};

describe("the role access's schema", () => {
  it("takes the requestor's email as the user", () => {
    expect(schema.userBody.parse(EMAIL)).toBe(EMAIL);
    expect(schema.userId.safeParse("auth0|alice").success).toBe(false);
  });

  it("takes a role to grant, or null to revoke", () => {
    expect(schema.policy.parse({ roleId: "rol_admin" })).toEqual({
      roleId: "rol_admin",
    });
    expect(schema.policy.parse(null)).toBeNull();
  });

  it.each(["", "../x", "rol admin", "rol/1", "a".repeat(65)])(
    "refuses %j as a role id",
    (roleId) => {
      expect(schema.policy.safeParse({ roleId }).success).toBe(false);
      expect(
        schema.requestContext.safeParse({ ...CONTEXT, roleId }).success
      ).toBe(false);
    }
  );

  it("takes a request context with the credentials, the Auth0 user and the role", () => {
    expect(schema.requestContext.parse(CONTEXT)).toEqual(CONTEXT);
  });

  it.each(["requestId", "auth0UserId", "roleId", "tenant", "clientSecret"])(
    "refuses a request context without %s",
    (field) => {
      const { [field as keyof typeof CONTEXT]: _dropped, ...rest } = CONTEXT;
      expect(schema.requestContext.safeParse(rest).success).toBe(false);
    }
  );

  it("refuses a request context for a custom domain", () => {
    expect(
      schema.requestContext.safeParse({ ...CONTEXT, tenant: "login.acme.com" })
        .success
    ).toBe(false);
  });
});

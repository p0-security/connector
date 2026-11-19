import {
  buildResourceRootSecurityPerimeter,
  createLogger,
} from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { LOGIN, context, target } from "../../__tests__/fixtures.ts";
import { t } from "../../router.ts";
import { spec } from "../role/definition.ts";
import { newRolePrimitives, router } from "../role/handler.ts";

const role = () => router(t).createCaller({ logger: createLogger() });

const approved = [{ type: "role" as const, rolename: "analyst" }];

const OTHER_LOGIN = `p0v_${"f".repeat(32)}`;

describe("request parsing", () => {
  it.each(["postgres", "p0v_", `${LOGIN}0`, `${LOGIN}"; DROP ROLE x; --`])(
    "refuses the login %j",
    async (login) => {
      await expect(
        role().provisionUser({ userBody: login, context })
      ).rejects.toThrow("Invalid string");
      await expect(
        role().deleteUser({ userId: login, userBody: LOGIN, context })
      ).rejects.toThrow("Invalid string");
    }
  );

  it.each([
    "",
    "has space",
    'analyst"; DROP ROLE x; --',
    "rôle",
    "a".repeat(64),
  ])("refuses the role name %j", async (rolename) => {
    await expect(
      role().setPoliciesForUser({
        userId: LOGIN,
        userBody: LOGIN,
        policies: [{ type: "role", rolename }],
        context,
      })
    ).rejects.toThrow("rolename");
  });

  it.each(["analyst", "Reporting.read-only", "x@example.com", "a".repeat(63)])(
    "accepts the role name %j",
    (rolename) => {
      const policy = { type: "role", rolename };

      expect(spec.policy(policy)).toEqual(policy);
    }
  );

  it("refuses a policy that is not a role", async () => {
    await expect(
      role().setPoliciesForUser({
        userId: LOGIN,
        userBody: LOGIN,
        // @ts-expect-error -- the only policy type is "role"
        policies: [{ type: "sql", rolename: "analyst" }],
        context,
      })
    ).rejects.toThrow("policies");
  });

  it("refuses a lister type other than role and database", async () => {
    await expect(
      // @ts-expect-error -- the only lister types are "role" and "database"
      role().list({ query: { type: "table", context: target } })
    ).rejects.toThrow("type");
  });
});

// The parsers already refuse a login outside the namespace, so the
// perimeter's own check is reached only without them.
describe("user namespace", () => {
  const perimeter = buildResourceRootSecurityPerimeter(newRolePrimitives());

  it("refuses to provision or identify a login outside the namespace", async () => {
    await expect(
      perimeter.provisionUser({ userBody: "postgres", context })
    ).rejects.toThrow('Username "postgres" is not namespaced');
    await expect(
      perimeter.identifyUser({ userBody: "postgres", context })
    ).rejects.toThrow('Username "postgres" is not namespaced');
  });

  it.each(["deleteUser", "setPoliciesForUser"] as const)(
    "%s refuses a login outside the namespace, by id and by body",
    async (method) => {
      await expect(
        perimeter[method]({
          userId: "postgres",
          userBody: LOGIN,
          policies: approved,
          context,
        })
      ).rejects.toThrow("Resource postgres is not namespaced");
      await expect(
        perimeter[method]({
          userId: LOGIN,
          userBody: "postgres",
          policies: approved,
          context,
        })
      ).rejects.toThrow('Username "postgres" is not namespaced');
    }
  );

  it("refuses a login whose grant secret is another login's", async () => {
    await expect(
      perimeter.provisionUser({ userBody: OTHER_LOGIN, context })
    ).rejects.toThrow(`Username "${OTHER_LOGIN}" is not namespaced`);
    await expect(
      perimeter.deleteUser({
        userId: OTHER_LOGIN,
        userBody: OTHER_LOGIN,
        context,
      })
    ).rejects.toThrow(`Resource ${OTHER_LOGIN} is not namespaced`);
  });

  it("lets a grant login through to the primitive", async () => {
    await expect(
      perimeter.provisionUser({ userBody: LOGIN, context })
    ).rejects.toThrow("pg-vaulted getUser is not implemented");
  });
});

describe("stubbed primitives", () => {
  const user = { userId: LOGIN, userBody: LOGIN, context };

  it.each([
    ["getUser", () => role().provisionUser({ userBody: LOGIN, context })],
    ["getUser", () => role().identifyUser({ userBody: LOGIN, context })],
    [
      "setPoliciesForUser",
      () => role().setPoliciesForUser({ ...user, policies: approved }),
    ],
    [
      "setPoliciesForUser",
      () => role().setPoliciesForUser({ ...user, policies: [] }),
    ],
    ["deleteUser", () => role().deleteUser(user)],
    ["list", () => role().list({ query: { type: "role", context: target } })],
  ])("rejects at %s", async (operation, call) => {
    await expect(call()).rejects.toThrow(
      `pg-vaulted ${operation} is not implemented`
    );
  });
});

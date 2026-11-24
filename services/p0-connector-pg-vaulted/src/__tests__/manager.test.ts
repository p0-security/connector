import { describe, expect, it } from "vitest";

import { isGrantSecretOfManagerTarget, managerSecretFor } from "../manager.ts";
import { MANAGER_SECRET_ARN, MANAGER_TARGET_ID, env } from "./fakes.ts";
import { context, target } from "./fixtures.ts";

describe("managerSecretFor", () => {
  it("returns the secret's ARN, its region and its target id", () => {
    expect(managerSecretFor(target.host, env)).toEqual({
      arn: MANAGER_SECRET_ARN,
      region: "us-east-1",
      targetId: MANAGER_TARGET_ID,
    });
  });
});

describe("isGrantSecretOfManagerTarget", () => {
  const secret = managerSecretFor(target.host, env);

  it("holds for a grant secret whose target id is the manager secret's", () => {
    expect(isGrantSecretOfManagerTarget(context.secretName, secret)).toBe(true);
  });

  it.each(["billing-prod", "Orders-prod", "orders-prod2", "orders"])(
    "does not hold for a grant secret of target %j",
    (targetId) => {
      const secretName = context.secretName.replace(
        "/orders-prod/",
        `/${targetId}/`
      );

      expect(isGrantSecretOfManagerTarget(secretName, secret)).toBe(false);
    }
  );
});

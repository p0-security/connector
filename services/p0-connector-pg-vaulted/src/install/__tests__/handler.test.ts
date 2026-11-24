import { createLogger } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { target } from "../../__tests__/fixtures.ts";
import { t } from "../../router.ts";
import { router } from "../handler.ts";

const validation = () => router(t).createCaller({ logger: createLogger() });

describe("install validation", () => {
  it("refuses an input with no target", async () => {
    // @ts-expect-error -- the input is { target }
    await expect(validation().get({})).rejects.toThrow("target");
  });

  it.each([0, 65536, 5432.5])("refuses the port %j", async (port) => {
    await expect(
      validation().get({ target: { ...target, port } })
    ).rejects.toThrow("port");
  });

  it("rejects as not implemented", async () => {
    await expect(validation().get({ target })).rejects.toThrow(
      "pg-vaulted install.validation.get is not implemented"
    );
  });

  it.each([
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
    "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:orders-manager-AbCdEf",
    "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:orders-manager-AbCdEf",
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
  ])("accepts the manager secret %s", async (managerSecretArn) => {
    await expect(
      validation().get({ target: { ...target, managerSecretArn } })
    ).rejects.toThrow("pg-vaulted install.validation.get is not implemented");
  });

  it.each([
    ["a name alone", "orders-manager"],
    [
      "an ARN with no account",
      "arn:aws:secretsmanager:us-east-1::secret:orders-manager-AbCdEf",
    ],
    [
      "an ARN of another service",
      "arn:aws:ssm:us-east-1:123456789012:parameter/orders-manager",
    ],
    [
      "an ARN in an unknown partition",
      "arn:aws-iso:secretsmanager:us-iso-east-1:123456789012:secret:orders-manager-AbCdEf",
    ],
  ])("refuses %s as the manager secret", async (_, managerSecretArn) => {
    await expect(
      validation().get({ target: { ...target, managerSecretArn } })
    ).rejects.toThrow("managerSecretArn");
  });

  it("refuses a grant secret as the manager secret", async () => {
    const managerSecretArn =
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:p0/postgres-ai/vpc-0abc1234/orders-prod/p0v_0123456789abcdef0123456789abcdef-AbCdEf";

    await expect(
      validation().get({ target: { ...target, managerSecretArn } })
    ).rejects.toThrow("managerSecretArn must not name a grant secret");
  });
});

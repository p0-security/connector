import { createLogger } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import { target } from "../../__tests__/fixtures.ts";
import { t } from "../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../clouds/aws-rds.ts", () => ({
  readManagerCredential: async () => {
    throw new Error("secret unreadable");
  },
}));

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

  it("fails at manager_secret when the secret can't be read", async () => {
    await expect(validation().get({ target })).rejects.toThrow(
      "could not read the manager secret"
    );
  });

  it.each([
    "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
    "p0/install/postgres/vpc-0a1b2c3d/O/p0manager",
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-zzzzzz",
  ])("accepts the manager secret %s", async (managerSecret) => {
    await expect(
      validation().get({ target: { ...target, managerSecret } })
    ).rejects.toThrow("could not read the manager secret");
  });

  it.each([
    ["a name P0 does not give", "orders-manager"],
    [
      "a name with another leaf",
      "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/manager",
    ],
    [
      "a name with no p0manager leaf",
      "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod",
    ],
    [
      "a name under another prefix",
      "p0/secrets/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
    ],
    ["a name with no vpc id", "p0/install/postgres/orders-prod/p0manager"],
    [
      "a name with an uppercase vpc id",
      "p0/install/postgres/vpc-0A1B2C3D/orders-prod/p0manager",
    ],
    [
      "a name with a target id P0 does not give",
      "p0/install/postgres/vpc-0a1b2c3d/-orders/p0manager",
    ],
    [
      "the ARN of a secret RDS does not manage",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:orders-manager-AbCdEf",
    ],
    [
      "the ARN of a secret P0 names",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager-AbCdEf",
    ],
    [
      "an RDS secret's name with no ARN",
      "rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with an uppercase uuid",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0A1B2C3D-4E5F-6789-ABCD-EF0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with no suffix",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    ],
    [
      "an RDS secret's ARN with a short suffix",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC12",
    ],
    [
      "an RDS secret's ARN with a uuid cut short",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef01234567-AbC123",
    ],
    [
      "an RDS secret's ARN of another kind",
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!proxy-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN with no account",
      "arn:aws:secretsmanager:us-east-1::secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an RDS secret's ARN in an unknown partition",
      "arn:aws-iso:secretsmanager:us-iso-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
    [
      "an ARN of another service",
      "arn:aws:ssm:us-east-1:123456789012:parameter/rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123",
    ],
  ])("refuses %s as the manager secret", async (_, managerSecret) => {
    await expect(
      validation().get({ target: { ...target, managerSecret } })
    ).rejects.toThrow("managerSecret must be a name");
  });
});

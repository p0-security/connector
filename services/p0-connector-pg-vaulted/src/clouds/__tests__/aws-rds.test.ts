import {
  DBInstanceNotFoundFault,
  DescribeDBInstancesCommand,
} from "@aws-sdk/client-rds";
import type * as Rds from "@aws-sdk/client-rds";
import { ConnectorError } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readManagerCredential } from "../aws-rds.ts";

const { send, getSecretValue } = vi.hoisted(() => ({
  send: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock("@aws-sdk/client-rds", async (importOriginal) => {
  const actual = await importOriginal<typeof Rds>();
  return {
    ...actual,
    RDSClient: vi.fn().mockImplementation(() => ({ send })),
  };
});

vi.mock("@p0security/connector-secret-manager-client", () => ({
  createSecretManagerClient: async () => ({ getSecretValue }),
}));

const INSTANCE_SECRET =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123";
const CLUSTER_SECRET =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!cluster-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123";
const INSTANCE_HOST = "orders-prod.abc123xyz.us-east-1.rds.amazonaws.com";
const CLUSTER_ID = "orders-cluster";

beforeEach(() => {
  send.mockReset();
  getSecretValue.mockReset();
  getSecretValue.mockResolvedValue({
    value: JSON.stringify({ username: "p0manager", password: "pw" }),
  });
});

describe("readManagerCredential for a secret RDS manages", () => {
  it("reads the secret once RDS says the host is the instance's endpoint", async () => {
    send.mockResolvedValue({
      DBInstances: [
        {
          MasterUserSecret: { SecretArn: INSTANCE_SECRET },
          Endpoint: { Address: INSTANCE_HOST.toUpperCase() },
        },
      ],
    });

    await expect(
      readManagerCredential(INSTANCE_SECRET, INSTANCE_HOST)
    ).resolves.toEqual({ username: "p0manager", password: "pw" });
    const [command] = send.mock.calls[0] ?? [];
    expect(command).toBeInstanceOf(DescribeDBInstancesCommand);
    expect(command.input).toEqual({ DBInstanceIdentifier: "orders-prod" });
  });

  it("refuses a cluster's reader endpoint without reading the secret", async () => {
    const readerHost = `${CLUSTER_ID}.cluster-ro-abc123xyz.us-east-1.rds.amazonaws.com`;
    send.mockResolvedValue({
      DBClusters: [
        {
          MasterUserSecret: { SecretArn: CLUSTER_SECRET },
          Endpoint: `${CLUSTER_ID}.cluster-abc123xyz.us-east-1.rds.amazonaws.com`,
          ReaderEndpoint: readerHost,
        },
      ],
    });

    await expect(
      readManagerCredential(CLUSTER_SECRET, readerHost)
    ).rejects.toThrow("could not confirm the manager secret is for this host");
    expect(getSecretValue).not.toHaveBeenCalled();
  });

  it("refuses a host that names no instance without reading the secret", async () => {
    send.mockRejectedValue(
      new DBInstanceNotFoundFault({ message: "not found", $metadata: {} })
    );

    await expect(
      readManagerCredential(INSTANCE_SECRET, INSTANCE_HOST)
    ).rejects.toThrow("could not confirm the manager secret is for this host");
    expect(getSecretValue).not.toHaveBeenCalled();
  });

  it("names the missing permissions when RDS denies the lookup", async () => {
    send.mockRejectedValue(
      Object.assign(new Error("denied"), { name: "AccessDenied" })
    );

    const error = await readManagerCredential(
      INSTANCE_SECRET,
      INSTANCE_HOST
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    const { data } = error as ConnectorError;
    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toContain(
      "rds:DescribeDBInstances and rds:DescribeDBClusters"
    );
    expect(data.payload).toEqual({ error: "AccessDenied" });
    expect(getSecretValue).not.toHaveBeenCalled();
  });
});

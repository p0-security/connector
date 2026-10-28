import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import type { SecretVersionRef } from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { t } from "../../../router.ts";
import * as facadeModule from "../../../salesforce/facade.ts";
import { router } from "../handler.ts";

vi.mock("../../../salesforce/facade.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof facadeModule>()),
  newFacadeClient: vi.fn(),
}));

const SECRET_REF = "projects/p/secrets/consumer-secret";
const USER_ID = "005000000000001AAA";

const store = new Map<string, string>();
const { secretManagerConfigs } = vi.hoisted(() => ({
  secretManagerConfigs: [] as unknown[],
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  return {
    ...actual,
    createSecretManagerClient: async (config: unknown) => {
      secretManagerConfigs.push(config);
      return {
        getSecretValue: async ({ ref }: { ref: string }) => {
          const value = store.get(ref);
          if (value === undefined)
            throw new actual.SecretVersionNotFoundError(
              ref as SecretVersionRef
            );
          return { value };
        },
      };
    },
  };
});

const facade = {
  findAgent: vi.fn(),
  upsertAgent: vi.fn(),
  setGrants: vi.fn(),
  retire: vi.fn(),
  listGrantable: vi.fn(),
};

const context = {
  requestId: "r-1",
  domain: "acme.my.salesforce.com",
  consumerKey: "key-1",
  secrets: {
    manager: "gcp" as const,
    consumerSecretSecretId: SECRET_REF,
    projectId: "p",
  },
};

const caller = () => router(t).createCaller({ logger: createLogger() });

beforeEach(() => {
  vi.resetAllMocks();
  store.clear();
  secretManagerConfigs.length = 0;
  store.set(SECRET_REF, "s3cret");
  vi.mocked(facadeModule.newFacadeClient).mockResolvedValue(facade);
});

describe("provisionUser", () => {
  it("uses an active agent as it is", async () => {
    facade.findAgent.mockResolvedValue({
      userId: USER_ID,
      username: "u",
      active: true,
    });

    await expect(
      caller().provisionUser({ userBody: "abc123", context })
    ).resolves.toBe(USER_ID);
    expect(facade.upsertAgent).not.toHaveBeenCalled();
    expect(facadeModule.newFacadeClient).toHaveBeenCalledWith({
      domain: "acme.my.salesforce.com",
      consumerKey: "key-1",
      consumerSecret: "s3cret",
    });
  });

  it("reactivates a retired agent", async () => {
    facade.findAgent.mockResolvedValue({
      userId: USER_ID,
      username: "u",
      active: false,
    });
    facade.upsertAgent.mockResolvedValue({
      userId: USER_ID,
      username: "u",
      active: true,
    });

    await expect(
      caller().provisionUser({ userBody: "abc123", context })
    ).resolves.toBe(USER_ID);
    expect(facade.upsertAgent).toHaveBeenCalledWith("abc123");
  });

  it("refuses an agent key that the facade cannot use", async () => {
    await expect(
      caller().provisionUser({ userBody: "Admin@acme", context })
    ).rejects.toThrow();
    expect(facadeModule.newFacadeClient).not.toHaveBeenCalled();
  });
});

describe("identifyUser", () => {
  it("treats a retired agent as gone", async () => {
    facade.findAgent.mockResolvedValue({
      userId: USER_ID,
      username: "u",
      active: false,
    });

    await expect(
      caller().identifyUser({ userBody: "abc123", context })
    ).resolves.toBeNull();
  });
});

describe("setPoliciesForUser", () => {
  it("sets the deduplicated permission sets", async () => {
    await caller().setPoliciesForUser({
      userId: USER_ID,
      userBody: "abc123",
      policies: ["B", "A", "B"],
      context,
    });

    expect(facade.setGrants).toHaveBeenCalledWith(USER_ID, ["A", "B"]);
  });

  it("fails when the consumer secret is empty", async () => {
    store.set(SECRET_REF, "");

    await expect(
      caller().setPoliciesForUser({
        userId: USER_ID,
        userBody: "abc123",
        policies: [],
        context,
      })
    ).rejects.toThrow("The Salesforce provisioner consumer secret is empty");
    expect(facadeModule.newFacadeClient).not.toHaveBeenCalled();
  });
});

describe("deleteUser", () => {
  it("retires the agent", async () => {
    await caller().deleteUser({ userId: USER_ID, userBody: "abc123", context });

    expect(facade.retire).toHaveBeenCalledWith(USER_ID);
  });
});

describe("list", () => {
  it("lists the grantable permission sets", async () => {
    facade.listGrantable.mockResolvedValue(["A"]);

    await expect(
      caller().list({ query: { type: "permission-set", context } })
    ).resolves.toEqual([{ key: "A", value: "A" }]);
  });
});

describe("secret manager", () => {
  it.each([
    [
      "AWS Secrets Manager",
      { manager: "aws" as const, region: "us-west-2" },
      { provider: "aws", region: "us-west-2" },
    ],
    [
      "Google Secret Manager",
      { manager: "gcp" as const, projectId: "p" },
      { provider: "gcp", projectId: "p" },
    ],
  ])("reads the consumer secret from %s", async (_, manager, config) => {
    facade.listGrantable.mockResolvedValue([]);

    await caller().list({
      query: {
        type: "permission-set",
        context: {
          ...context,
          secrets: { ...manager, consumerSecretSecretId: SECRET_REF },
        },
      },
    });

    expect(secretManagerConfigs).toEqual([config]);
    expect(facadeModule.newFacadeClient).toHaveBeenCalledWith(
      expect.objectContaining({ consumerSecret: "s3cret" })
    );
  });
});

describe("request context", () => {
  it.each(["evil.example.com", "acme.my.salesforce.com.evil.test"])(
    "refuses the domain %j",
    async (domain) => {
      await expect(
        caller().setPoliciesForUser({
          userId: USER_ID,
          userBody: "abc123",
          policies: ["A"],
          context: { ...context, domain },
        })
      ).rejects.toThrow();
      expect(facadeModule.newFacadeClient).not.toHaveBeenCalled();
    }
  );
});

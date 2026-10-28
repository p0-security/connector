import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../../../pagerduty/pagerduty-api.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../pagerduty/pagerduty-api.ts");

const CLIENT_SECRET_REF = "client-secret";
const GRANT_REF = "grant-secret";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
const secrets = new Set<string>();

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  return {
    ...actual,
    createSecretManagerClient: async () => ({
      getSecretValue: async ({ ref }: { ref: string }) => {
        const value = store.get(ref);
        if (value === undefined)
          throw new actual.SecretVersionNotFoundError(ref as SecretVersionRef);
        return { value };
      },
      createSecretVersion: async ({
        ref,
        value,
      }: {
        ref: string;
        value: Buffer;
      }) => {
        store.set(ref, value.toString("utf8"));
      },
      deleteSecret: async ({ ref }: { ref: string }) => {
        store.delete(ref);
      },
      // Like GCP: a ref is the full resource name, a name is its last part.
      createSecret: async ({ name }: { name: string }) => {
        secrets.add(name);
        return { ref: `projects/1/secrets/${name}`, name };
      },
      getSecret: async ({ ref }: { ref: string }) => {
        const name = ref.split("/").pop() ?? ref;
        if (!secrets.has(name))
          throw new actual.SecretNotFoundError(ref as SecretRef);
        return { ref: `projects/1/secrets/${name}`, name };
      },
    }),
  };
});

const context = {
  requestId: "r-2",
  region: "eu" as const,
  subdomain: "acme",
  clientId: "client-1",
  secrets: {
    manager: "gcp" as const,
    clientSecretSecretId: CLIENT_SECRET_REF,
    projectId: "p",
  },
};

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (scopes: string[]) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ scopes }],
    context,
  });

beforeEach(() => {
  vi.resetAllMocks();
  store.clear();
  secrets.clear();
  store.set(CLIENT_SECRET_REF, "s3cret");
  vi.mocked(api.requestAppToken).mockResolvedValue("new-token");
});

describe("setPoliciesForUser", () => {
  it("gets a token for the account's scopes and stores only the token", async () => {
    await setPolicies(["incidents.read"]);

    expect(api.requestAppToken).toHaveBeenCalledWith(
      { clientId: "client-1", clientSecret: "s3cret" },
      { region: "eu", subdomain: "acme", scopes: ["incidents.read"] }
    );
    expect(store.get(GRANT_REF)).toBe("new-token");
  });

  it("replaces the token when the scopes change", async () => {
    store.set(GRANT_REF, "old-token");

    await setPolicies(["incidents.read", "services.read"]);

    expect(store.get(GRANT_REF)).toBe("new-token");
  });

  it("gets no token when no scopes remain", async () => {
    store.set(GRANT_REF, "old-token");

    await setPolicies([]);

    expect(api.requestAppToken).not.toHaveBeenCalled();
    expect(store.get(GRANT_REF)).toBe("old-token");
  });

  it("keeps the old token when PagerDuty refuses the request", async () => {
    store.set(GRANT_REF, "old-token");
    vi.mocked(api.requestAppToken).mockRejectedValue(
      new Error("invalid_scope")
    );

    await expect(setPolicies(["incidents.write"])).rejects.toThrow();
    expect(store.get(GRANT_REF)).toBe("old-token");
  });

  it("fails when the client secret is empty", async () => {
    store.set(CLIENT_SECRET_REF, "");

    await expect(setPolicies(["incidents.read"])).rejects.toThrow(
      "The PagerDuty client secret is empty"
    );
    expect(api.requestAppToken).not.toHaveBeenCalled();
  });
});

describe("provisionUser", () => {
  it("gives the same user id for a new and an existing secret", async () => {
    const provision = () =>
      caller().provisionUser({ userBody: "p0_grant", context });

    const created = await provision();
    const found = await provision();

    expect(created).toBe("projects/1/secrets/p0_grant");
    expect(found).toBe(created);
  });
});

describe("deleteUser", () => {
  it("deletes the secret", async () => {
    store.set(GRANT_REF, "old-token");

    await caller().deleteUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      context,
    });

    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("list", () => {
  it("lists the region's supported scopes", async () => {
    vi.mocked(api.listSupportedScopes).mockResolvedValue(["incidents.read"]);

    await expect(
      caller().list({ query: { type: "scope", context } })
    ).resolves.toEqual([{ key: "incidents.read", value: "incidents.read" }]);
    expect(api.listSupportedScopes).toHaveBeenCalledWith("eu");
  });
});

describe("request context", () => {
  it.each(["acme incidents.write", "acme.eu", "Acme"])(
    "rejects the subdomain %j",
    async (subdomain) => {
      await expect(
        caller().setPoliciesForUser({
          userId: GRANT_REF,
          userBody: "p0_grant",
          policies: [{ scopes: ["incidents.read"] }],
          context: { ...context, subdomain },
        })
      ).rejects.toThrow();
      expect(api.requestAppToken).not.toHaveBeenCalled();
    }
  );
});

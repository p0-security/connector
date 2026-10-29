import { ConnectorError } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretVersionRef,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  deleteGrantSecret,
  fetchAdminKey,
  setGrantSecret,
} from "../secrets.ts";

const ADMIN_SECRET = "p0_install_looker_acme_admin-key";
const GRANT_SECRET = "p0_access-token_looker_acme_1a2b3c4d";

const KEY = { client_id: "grantid", client_secret: "grantsecret" };
const KEY_VALUE = "grantid:grantsecret";

const VERSION = {
  ref: `${GRANT_SECRET}/versions/1` as SecretVersionRef,
  secretRef: GRANT_SECRET as SecretRef,
  state: "enabled" as const,
  createTime: new Date(0),
};

const newSecretManager = () => ({
  createSecret: vi.fn<SecretManagerClient["createSecret"]>(),
  deleteSecret: vi.fn<SecretManagerClient["deleteSecret"]>(),
  getSecret: vi.fn<SecretManagerClient["getSecret"]>(),
  getAllSecrets: vi.fn<SecretManagerClient["getAllSecrets"]>(),
  getSecretVersions: vi.fn<SecretManagerClient["getSecretVersions"]>(),
  getSecretValue: vi.fn<SecretManagerClient["getSecretValue"]>(),
  createSecretVersion: vi.fn<SecretManagerClient["createSecretVersion"]>(),
  disableSecretVersion: vi.fn<SecretManagerClient["disableSecretVersion"]>(),
  deleteSecretVersion: vi.fn<SecretManagerClient["deleteSecretVersion"]>(),
});

let secrets: ReturnType<typeof newSecretManager>;

const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
    throw error;
  }
  throw new Error("expected the call to throw");
};

beforeEach(() => {
  secrets = newSecretManager();
  secrets.createSecret.mockResolvedValue({
    ref: GRANT_SECRET as SecretRef,
    name: GRANT_SECRET,
    createTime: new Date(0),
  });
  secrets.createSecretVersion.mockResolvedValue(VERSION);
  secrets.deleteSecret.mockResolvedValue();
});

describe("fetchAdminKey", () => {
  const read = () => fetchAdminKey(secrets, ADMIN_SECRET);
  const stored = (value: Buffer | string) =>
    secrets.getSecretValue.mockResolvedValue({ value, version: VERSION });

  it("reads the client ID and client secret from the secret", async () => {
    stored('{"client_id":"admin-id","client_secret":"admin-secret"}');

    await expect(read()).resolves.toEqual({
      client_id: "admin-id",
      client_secret: "admin-secret",
    });
    expect(secrets.getSecretValue).toHaveBeenCalledWith({ ref: ADMIN_SECRET });
  });

  it("decodes a binary secret as UTF-8", async () => {
    stored(
      Buffer.from('{"client_id":"admin-id","client_secret":"admin-secret"}')
    );

    await expect(read()).resolves.toEqual({
      client_id: "admin-id",
      client_secret: "admin-secret",
    });
  });

  it.each([
    ["is not JSON", "admin-id:admin-secret"],
    ["has no client secret", '{"client_id":"admin-id"}'],
    ["has an empty client ID", '{"client_id":"","client_secret":"s"}'],
    ["is Datadog's shape", '{"apiKey":"admin-id","appKey":"admin-secret"}'],
  ])("refuses a secret that %s, without its value", async (_, value) => {
    stored(value);

    const data = await connectorError(read);

    expect(data.type).toBe("validation_error");
    expect(data.message).toBe(
      'The Looker Admin API key secret must be JSON of the form {"client_id": "...", "client_secret": "..."}'
    );
    expect(JSON.stringify(data)).not.toMatch(/admin-id|admin-secret/);
  });

  it("reports a missing secret as object_not_found", async () => {
    secrets.getSecretValue.mockRejectedValue(
      new SecretNotFoundError(ADMIN_SECRET as SecretRef)
    );

    const data = await connectorError(read);

    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({ query: ADMIN_SECRET });
    expect(data.message).toBe(
      "The connector couldn't find the Looker Admin API key secret p0_install_looker_acme_admin-key. Check the Admin key secret in the P0 install, and that the secret has a version."
    );
  });

  it("reports a denied read as insufficient_privileges, naming what to grant", async () => {
    secrets.getSecretValue.mockRejectedValue(new UnauthorizedError("gcp"));

    const data = await connectorError(read);

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ secretId: ADMIN_SECRET });
    expect(data.message).toBe(
      "The connector isn't allowed to read the Looker Admin API key secret p0_install_looker_acme_admin-key. Grant the connector's GCP service account roles/secretmanager.secretAccessor and roles/secretmanager.viewer on that secret."
    );
  });

  it("lets anything else through as is", async () => {
    const error = new Error("vault exploded");
    secrets.getSecretValue.mockRejectedValue(error);

    await expect(read()).rejects.toBe(error);
  });
});

describe("setGrantSecret", () => {
  const write = () => setGrantSecret(secrets, GRANT_SECRET, KEY);
  const writtenValue = () => {
    const [params] = secrets.createSecretVersion.mock.calls[0];
    return params.type === "value" ? params.value.toString("utf8") : undefined;
  };

  it("creates the secret, then writes the key to it as <client_id>:<client_secret>", async () => {
    await write();

    expect(secrets.createSecret).toHaveBeenCalledWith({ name: GRANT_SECRET });
    expect(secrets.createSecretVersion).toHaveBeenCalledWith(
      expect.objectContaining({ ref: GRANT_SECRET, type: "value" })
    );
    expect(writtenValue()).toBe(KEY_VALUE);
    expect(secrets.createSecret.mock.invocationCallOrder[0]).toBeLessThan(
      secrets.createSecretVersion.mock.invocationCallOrder[0]
    );
  });

  it("writes the client ID and client secret only", async () => {
    await setGrantSecret(secrets, GRANT_SECRET, {
      ...KEY,
      ...{ id: "7", created_at: "2026-10-11T00:00:00Z" },
    });

    expect(writtenValue()).toBe(KEY_VALUE);
  });

  // An earlier attempt at the grant created the secret and failed later.
  it("writes to a secret that already exists", async () => {
    secrets.createSecret.mockRejectedValue(
      new SecretAlreadyExistsError(GRANT_SECRET)
    );

    await write();

    expect(writtenValue()).toBe(KEY_VALUE);
  });

  // The secret manager's error can carry the request that failed, and the
  // framework logs an error with its causes.
  it("does not pass on the secret manager's error, whose request holds the key", async () => {
    const payload = Buffer.from(KEY_VALUE).toString("base64");
    secrets.createSecretVersion.mockRejectedValue(
      Object.assign(new Error("Internal error encountered."), {
        config: { body: JSON.stringify({ payload: { data: payload } }) },
      })
    );

    const error = await write().catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data).toEqual({
      type: "upstream_unavailable",
      message:
        "The connector couldn't write the grant's secret p0_access-token_looker_acme_1a2b3c4d: Internal error encountered.",
      payload: { secretId: GRANT_SECRET },
    });
    expect((error as ConnectorError).cause).toBeUndefined();
    expect(inspect(error, { depth: Infinity })).not.toContain(payload);
    expect(inspect(error, { depth: Infinity })).not.toContain("grantsecret");
  });

  it.each([
    ["created", () => secrets.createSecret],
    ["written", () => secrets.createSecretVersion],
  ])(
    "reports a secret that may not be %s as insufficient_privileges",
    async (_, method) => {
      method().mockRejectedValue(new UnauthorizedError("gcp"));

      const data = await connectorError(write);

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ secretId: GRANT_SECRET });
      expect(data.message).toBe(
        "The connector isn't allowed to write the grant's secret p0_access-token_looker_acme_1a2b3c4d. Check that the connector's GCP service account can create secrets, and add versions to the secrets that P0 names."
      );
    }
  );

  // The MCP server spec splits the secret at the colon, and the Toolbox pastes
  // each field into its YAML config.
  it.each([
    ["a colon in the client ID", { ...KEY, client_id: "grant:id" }],
    ["a colon in the client secret", { ...KEY, client_secret: "grant:secret" }],
    ["an empty client ID", { ...KEY, client_id: "" }],
    ["an empty client secret", { ...KEY, client_secret: "" }],
    ["a hyphen", { ...KEY, client_id: "grant-id" }],
    ["a space", { ...KEY, client_secret: "grant secret" }],
    ["a quote", { ...KEY, client_secret: 'grant"secret' }],
    ["a letter outside ASCII", { ...KEY, client_id: "grànt" }],
    ["a line feed in the client secret", { ...KEY, client_secret: "grant\n" }],
    ["a NUL in the client ID", { ...KEY, client_id: "grant\u0000id" }],
    ["a DEL", { ...KEY, client_secret: "grant\u007fsecret" }],
    ["a C1 control character", { ...KEY, client_secret: "grant\u0085" }],
    ["a line separator", { ...KEY, client_id: "grant\u2028id" }],
    ["a paragraph separator", { ...KEY, client_secret: "\u2029grant" }],
  ])("refuses a key with %s, without quoting it", async (_, key) => {
    const data = await connectorError(() =>
      setGrantSecret(secrets, GRANT_SECRET, key)
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "Looker returned an API key whose client ID or client secret holds a character other than a letter or a digit, which the MCP server can't use. The connector didn't store it.",
      payload: { secretId: GRANT_SECRET },
    });
    expect(JSON.stringify(data)).not.toMatch(/grant/i);
    // Not even an empty secret.
    expect(secrets.createSecret).not.toHaveBeenCalled();
    expect(secrets.createSecretVersion).not.toHaveBeenCalled();
  });

  it("stores a key of letters and digits, which splits back at the colon", async () => {
    const key = { client_id: "Ab3XyZ09", client_secret: "q7RT2mmP0zLk" };

    await setGrantSecret(secrets, GRANT_SECRET, key);

    expect((writtenValue() ?? "").split(":")).toEqual([
      "Ab3XyZ09",
      "q7RT2mmP0zLk",
    ]);
  });

  it("writes nothing when the secret cannot be created", async () => {
    secrets.createSecret.mockRejectedValue(new Error("quota"));

    const data = await connectorError(write);

    expect(data.type).toBe("upstream_unavailable");
    expect(secrets.createSecretVersion).not.toHaveBeenCalled();
  });
});

describe("deleteGrantSecret", () => {
  const remove = () => deleteGrantSecret(secrets, GRANT_SECRET);

  it("deletes the secret", async () => {
    await remove();

    expect(secrets.deleteSecret).toHaveBeenCalledWith({ ref: GRANT_SECRET });
  });

  it("treats a secret that is already gone as deleted", async () => {
    secrets.deleteSecret.mockRejectedValue(
      new SecretNotFoundError(GRANT_SECRET as SecretRef)
    );

    await expect(remove()).resolves.toBeUndefined();
  });

  it("propagates any other failure", async () => {
    const error = new UnauthorizedError("gcp");
    secrets.deleteSecret.mockRejectedValue(error);

    await expect(remove()).rejects.toBe(error);
  });
});

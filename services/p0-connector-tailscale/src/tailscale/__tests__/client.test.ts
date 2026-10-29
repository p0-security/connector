import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CLIENT_SECRET,
  CREDENTIALS,
  FEDERATED_CREDENTIAL,
  TAILNET,
  fakeIdentityToken,
  identityTokenFor,
} from "../../__tests__/fixtures.ts";
import {
  holdSecret,
  newRecordingLogger,
  thrown,
} from "../../__tests__/helpers.ts";
import { newTestTailnet } from "../../__tests__/tailnet.ts";
import type { TailnetCredentials } from "../../credentials.ts";
import { TailscaleError } from "../api.ts";
import { newTailscaleClient, resetTokenCache } from "../client.ts";
import { TokenRejectedError } from "../errors.ts";
import { READ_SCOPES, REQUIRED_SCOPES, WRITE_SCOPES } from "../scopes.ts";
import { listUsers } from "../tailnet.ts";

const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof secretManagerClient>()),
    createSecretManagerClient: vault.createSecretManagerClient,
  })
);

const { log } = newRecordingLogger();

const clientFor = (
  credentials: TailnetCredentials = CREDENTIALS,
  identityToken = vi.fn(fakeIdentityToken)
) => newTailscaleClient({ credentials, log, identityToken });

beforeEach(() => {
  vi.clearAllMocks();
  resetTokenCache();
  holdSecret(vault, CLIENT_SECRET);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("an OAuth client credential", () => {
  it("exchanges for read-only scopes on a read", async () => {
    const tailnet = newTestTailnet();

    await clientFor().read(listUsers);

    const [exchange] = tailnet.exchanges();
    expect(exchange?.path).toBe("/api/v2/oauth/token");
    expect(exchange?.form).toEqual({
      grant_type: "client_credentials",
      client_id: CREDENTIALS.credential.clientId,
      client_secret: CLIENT_SECRET,
      scope: READ_SCOPES.join(" "),
    });
    expect(tailnet.scopesSent()).toEqual([[...READ_SCOPES]]);
  });

  it("exchanges for the attribute write scope on a write, and never policy_file", async () => {
    const tailnet = newTestTailnet();

    await clientFor()
      .write(listUsers)
      .catch(() => undefined);

    expect(tailnet.exchanges()[0]?.form?.scope).toBe(WRITE_SCOPES.join(" "));
    expect(WRITE_SCOPES).toEqual(["devices:posture_attributes"]);
  });

  it("keeps one token per scope set, and reuses it across clients", async () => {
    const tailnet = newTestTailnet();

    await clientFor().read(listUsers);
    await clientFor().read(listUsers);
    await clientFor().write(async () => undefined);
    await clientFor().write(async () => undefined);

    expect(tailnet.exchanges().map(({ form }) => form?.scope)).toEqual([
      READ_SCOPES.join(" "),
      WRITE_SCOPES.join(" "),
    ]);
  });

  it("shares one exchange between concurrent calls", async () => {
    const tailnet = newTestTailnet();
    const client = clientFor();

    await Promise.all([
      client.read(listUsers),
      client.read(listUsers),
      clientFor().read(listUsers),
    ]);

    expect(tailnet.exchanges()).toHaveLength(1);
  });

  it("drops a token five minutes before it expires", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const tailnet = newTestTailnet();

    await clientFor().read(listUsers);
    vi.setSystemTime(Date.now() + 54 * 60 * 1000);
    await clientFor().read(listUsers);
    expect(tailnet.exchanges()).toHaveLength(1);

    vi.setSystemTime(Date.now() + 2 * 60 * 1000);
    await clientFor().read(listUsers);
    expect(tailnet.exchanges()).toHaveLength(2);
  });

  it("exchanges again when the secret has a new version", async () => {
    const tailnet = newTestTailnet();

    await clientFor().read(listUsers);
    holdSecret(vault, CLIENT_SECRET, "v2");
    await clientFor().read(listUsers);

    expect(tailnet.exchanges()).toHaveLength(2);
  });

  it("reads the secret once per client", async () => {
    newTestTailnet();
    const client = clientFor();

    await client.read(listUsers);
    await client.write(async () => undefined);

    expect(vault.getSecretValue).toHaveBeenCalledTimes(1);
  });

  it("retries once with a new token after a 401 for a cached one", async () => {
    const tailnet = newTestTailnet();
    await clientFor().read(listUsers);
    tailnet.revokeTokens();

    await expect(clientFor().read(listUsers)).resolves.toHaveLength(2);
    expect(tailnet.exchanges()).toHaveLength(2);
  });

  it("doesn't retry a 401 for a token it just exchanged", async () => {
    const tailnet = newTestTailnet();
    tailnet.intercept((call) =>
      call.path.endsWith("/users")
        ? { status: 401, body: { message: "invalid token" } }
        : undefined
    );

    const error = await thrown(() => clientFor().read(listUsers));

    expect(error).toBeInstanceOf(TailscaleError);
    expect(tailnet.exchanges()).toHaveLength(1);
  });

  it("evicts a failed exchange, so the next call tries again", async () => {
    const tailnet = newTestTailnet();
    holdSecret(vault, "wrong-secret");

    const error = await thrown(() => clientFor().read(listUsers));
    expect(error).toBeInstanceOf(TokenRejectedError);

    holdSecret(vault, CLIENT_SECRET);
    await expect(clientFor().read(listUsers)).resolves.toHaveLength(2);
    expect(tailnet.exchanges()).toHaveLength(2);
  });

  it("refuses scopes the client doesn't hold at the exchange", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES.filter(
        (scope) => scope !== "devices:posture_attributes"
      ),
    });

    const error = await thrown(() => clientFor().write(async () => undefined));

    expect(error).toMatchObject({
      name: "TokenRejectedError",
      status: 403,
      reason: 'OAuth client cannot grant scopes "devices:posture_attributes"',
      scopes: WRITE_SCOPES,
    });
  });

  it("keeps no token it exchanged only to probe", async () => {
    const tailnet = newTestTailnet();
    const client = clientFor();

    await client.exchangeFor([]);
    await client.exchangeFor(READ_SCOPES);
    await client.read(listUsers);

    expect(tailnet.exchanges()).toHaveLength(3);
    expect(tailnet.scopesSent()).toEqual([[...READ_SCOPES]]);
  });

  it("notes the token's scopes on a failed call, from the exchange's answer", async () => {
    newTestTailnet();

    const error = await thrown(() =>
      clientFor().write((call) => listUsers(call))
    );

    expect(error).toMatchObject({
      name: "TailscaleError",
      status: 404,
      scope: "users:read",
      tokenScopes: ["devices:posture_attributes"],
    });
  });
});

describe("a federated credential", () => {
  const FEDERATED = { ...CREDENTIALS, credential: FEDERATED_CREDENTIAL };

  it("mints the cloud identity for Tailscale's default audience and exchanges it", async () => {
    const tailnet = newTestTailnet();
    const identityToken = vi.fn(fakeIdentityToken);

    await clientFor(FEDERATED, identityToken).read(listUsers);

    const audience = `api.tailscale.com/${FEDERATED_CREDENTIAL.clientId}`;
    expect(identityToken).toHaveBeenCalledWith(audience);
    const [exchange] = tailnet.exchanges();
    expect(exchange?.path).toBe("/api/v2/oauth/token-exchange");
    expect(exchange?.form).toEqual({
      client_id: FEDERATED_CREDENTIAL.clientId,
      jwt: identityTokenFor(audience),
    });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
  });

  // The exchange takes no scope, so the token carries the identity's own.
  it("uses one token for reads and writes", async () => {
    const tailnet = newTestTailnet();

    await clientFor(FEDERATED).read(listUsers);
    await clientFor(FEDERATED).write(listUsers);

    expect(tailnet.exchanges()).toHaveLength(1);
  });

  it("reports an identity Tailscale doesn't trust as a rejected credential", async () => {
    newTestTailnet();

    const error = await thrown(() =>
      clientFor(
        FEDERATED,
        vi.fn(async () => "eyJ.not.trusted")
      ).read(listUsers)
    );

    expect(error).toMatchObject({ name: "TokenRejectedError", status: 401 });
  });
});

describe("checkCredential", () => {
  it("reads an OAuth client's secret", async () => {
    newTestTailnet();
    await clientFor().checkCredential();
    expect(vault.getSecretValue).toHaveBeenCalledTimes(1);
  });

  it("mints a federated identity's cloud token, and calls nothing", async () => {
    const tailnet = newTestTailnet();
    const identityToken = vi.fn(fakeIdentityToken);

    await clientFor(
      { tailnet: TAILNET, credential: FEDERATED_CREDENTIAL },
      identityToken
    ).checkCredential();

    expect(identityToken).toHaveBeenCalledTimes(1);
    expect(tailnet.calls).toEqual([]);
  });
});

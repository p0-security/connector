import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  type SecretRef,
} from "@p0security/connector-secret-manager-client";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { describe, expect, it, vi } from "vitest";

import {
  generateGrantPassword,
  grantSecretRef,
  renderScramVerifier,
  writeGrantSecret,
} from "../grant-secret.ts";
import { GRANT_SECRET_PREFIX } from "./fixtures.ts";

type SaslSession = { clientNonce: string; response: string };

// The client half of SCRAM that `pg` itself signs in with.
const sasl = createRequire(import.meta.url)("pg/lib/crypto/sasl.js") as {
  startSession: (mechanisms: string[]) => SaslSession;
  continueSession: (
    session: SaslSession,
    password: string,
    serverData: string
  ) => Promise<void>;
  finalizeSession: (session: SaslSession, serverData: string) => void;
};

/**
 * Plays the server's half of a SCRAM-SHA-256 sign-in against `verifier`, as
 * PostgreSQL does against the verifier it stores. Throws if `password` does
 * not match.
 */
const signIn = async (verifier: string, password: string) => {
  const [, iterations, salt, storedKey, serverKey] =
    /^SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)$/.exec(verifier) ?? [];
  const session = sasl.startSession(["SCRAM-SHA-256"]);
  const clientFirstBare = session.response.replace(/^n,,/, "");
  const nonce = session.clientNonce + randomBytes(18).toString("base64");
  const serverFirst = `r=${nonce},s=${salt},i=${iterations}`;
  await sasl.continueSession(session, password, serverFirst);

  const [, clientFinalBare, proof] =
    /^(.*),p=([^,]+)$/.exec(session.response) ?? [];
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalBare}`;
  const clientSignature = createHmac(
    "sha256",
    Buffer.from(storedKey!, "base64")
  )
    .update(authMessage)
    .digest();
  const clientKey = Buffer.from(proof!, "base64").map(
    (byte, i) => byte ^ clientSignature[i]!
  );
  if (createHash("sha256").update(clientKey).digest("base64") !== storedKey) {
    throw new Error("password does not match the verifier");
  }
  const serverSignature = createHmac(
    "sha256",
    Buffer.from(serverKey!, "base64")
  )
    .update(authMessage)
    .digest("base64");
  sasl.finalizeSession(session, `v=${serverSignature}`);
};

const context = { grantSecretPrefix: GRANT_SECRET_PREFIX } as Parameters<
  typeof grantSecretRef
>[0];

describe("grant password", () => {
  it("signs in with the password against its verifier", async () => {
    const password = generateGrantPassword();
    await expect(
      signIn(renderScramVerifier(password), password)
    ).resolves.toBeUndefined();
  });

  it("refuses another password against the verifier", async () => {
    const verifier = renderScramVerifier(generateGrantPassword());
    await expect(signIn(verifier, generateGrantPassword())).rejects.toThrow();
  });

  it("salts each verifier", () => {
    const password = generateGrantPassword();
    expect(renderScramVerifier(password)).not.toBe(
      renderScramVerifier(password)
    );
  });
});

describe("grant secret name", () => {
  it("names the secret after the user, under the prefix", () => {
    expect(grantSecretRef(context, "p0_alice")).toBe(
      `${GRANT_SECRET_PREFIX}/p0_alice`
    );
  });

  it("refuses a user name that would leave the prefix", () => {
    expect(() => grantSecretRef(context, "../other/p0_alice")).toThrow(
      "Invalid Postgres identifier"
    );
  });
});

const pendingDeletion = () =>
  Object.assign(
    new Error(
      "You can't create this secret because a secret with this name is already scheduled for deletion."
    ),
    { name: "InvalidRequestException" }
  );

const newSecrets = (createSecret: () => Promise<unknown>) => {
  const secrets = {
    createSecret: vi.fn(createSecret),
    createSecretVersion: vi.fn(async () => ({})),
  };
  return secrets as typeof secrets & SecretManagerClient;
};

const REF = `${GRANT_SECRET_PREFIX}/p0_alice` as SecretRef;

describe("grant secret write", () => {
  it("reuses a secret that already exists", async () => {
    const secrets = newSecrets(async () => {
      throw new SecretAlreadyExistsError(REF);
    });
    await writeGrantSecret(secrets, REF, "password", []);
    expect(secrets.createSecretVersion).toHaveBeenCalledOnce();
  });

  it("waits out a secret by the same name that is still being deleted", async () => {
    const createSecret = vi
      .fn()
      .mockRejectedValueOnce(pendingDeletion())
      .mockResolvedValue({});
    const secrets = newSecrets(createSecret);
    await writeGrantSecret(secrets, REF, "password", [0]);
    expect(createSecret).toHaveBeenCalledTimes(2);
    expect(secrets.createSecretVersion).toHaveBeenCalledOnce();
  });

  it("gives up once the deletion outlasts every wait", async () => {
    const secrets = newSecrets(async () => {
      throw pendingDeletion();
    });
    await expect(
      writeGrantSecret(secrets, REF, "password", [0, 0])
    ).rejects.toThrow("scheduled for deletion");
    expect(secrets.createSecret).toHaveBeenCalledTimes(3);
  });

  it("does not retry any other failure", async () => {
    const secrets = newSecrets(async () => {
      throw new Error("access denied");
    });
    await expect(
      writeGrantSecret(secrets, REF, "password", [0])
    ).rejects.toThrow("access denied");
    expect(secrets.createSecret).toHaveBeenCalledOnce();
  });
});

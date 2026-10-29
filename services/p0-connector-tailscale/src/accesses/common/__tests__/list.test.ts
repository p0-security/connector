import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CLIENT_SECRET,
  CREDENTIALS,
  EMAIL,
  fakeIdentityToken,
} from "../../../__tests__/fixtures.ts";
import { holdSecret, newRecordingLogger } from "../../../__tests__/helpers.ts";
import { LAPTOP, newTestTailnet } from "../../../__tests__/tailnet.ts";
import { resetTokenCache } from "../../../tailscale/client.ts";
import { READ_SCOPES } from "../../../tailscale/scopes.ts";
import { list } from "../list.ts";

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

const { log, info } = newRecordingLogger();

const listing = (type: string, extra: Record<string, unknown> = {}) =>
  list(log, { identityToken: fakeIdentityToken }, {
    type,
    context: CREDENTIALS,
    ...extra,
  } as never);

beforeEach(() => {
  vi.clearAllMocks();
  resetTokenCache();
  holdSecret(vault, CLIENT_SECRET);
});

describe("list", () => {
  it("lists the requestor's own untagged devices", async () => {
    newTestTailnet();
    await expect(listing("own-devices", { email: EMAIL })).resolves.toEqual([
      { key: LAPTOP, value: "alice-laptop.tail1234.ts.net" },
    ]);
  });

  it("finds the requestor's devices when their P0 email differs in case from their login", async () => {
    const tailnet = newTestTailnet();
    await expect(
      listing("own-devices", { email: "Alice@Acme.com" })
    ).resolves.toEqual([
      { key: LAPTOP, value: "alice-laptop.tail1234.ts.net" },
    ]);
    const call = tailnet
      .apiCalls()
      .find(({ path }) => path.endsWith("/devices"));
    expect(call?.query).toEqual({});
  });

  it("lists P0 postures in both shapes, with the key each reads", async () => {
    newTestTailnet();
    await expect(listing("postures")).resolves.toEqual([
      {
        key: "posture:p0_db",
        value: "custom:p0_db == true",
        group: "custom:p0_db",
      },
      {
        key: "posture:p0_legacy",
        value: "custom:p0_legacy == true",
        group: "custom:p0_legacy",
      },
    ]);
  });

  it("finds sections spelled in PascalCase", async () => {
    newTestTailnet({
      policy: JSON.stringify({
        Postures: { "posture:p0_x": ["custom:p0_x == true"] },
      }),
    });
    await expect(listing("postures")).resolves.toEqual([
      {
        key: "posture:p0_x",
        value: "custom:p0_x == true",
        group: "custom:p0_x",
      },
    ]);
  });

  it("reads with the read-only token, and logs counts, not names", async () => {
    const tailnet = newTestTailnet();
    await listing("own-devices", { email: EMAIL });
    expect(tailnet.scopesSent()).toEqual([[...READ_SCOPES]]);
    expect(JSON.stringify(info.mock.calls)).not.toContain("alice");
  });
});

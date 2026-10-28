import {
  SecretNotFoundError,
  type SecretRef,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { failing } from "../../__tests__/fake-tailscale.ts";
import {
  CLIENT_SECRET,
  CREDENTIALS,
  FEDERATED_CREDENTIAL,
  TAILNET,
  fakeIdentityToken,
} from "../../__tests__/fixtures.ts";
import {
  connectorError,
  holdSecret,
  newRecordingLogger,
} from "../../__tests__/helpers.ts";
import {
  BOBS_LAPTOP,
  newTestTailnet,
  withoutFederatedScope,
  withoutOAuthScope,
} from "../../__tests__/tailnet.ts";
import { resetTokenCache } from "../../tailscale/client.ts";
import { REQUIRED_SCOPES } from "../../tailscale/scopes.ts";
import type { InstallValidationInput } from "../definition.ts";
import { POSTURE_CHECK_KEY, getInstallValidation } from "../handler.ts";

const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

const { log } = newRecordingLogger();

const NOW = Date.parse("2026-10-17T12:00:00Z");

const FEDERATED = { ...CREDENTIALS, credential: FEDERATED_CREDENTIAL };

const validate = (
  credentials: InstallValidationInput = CREDENTIALS,
  identityToken = fakeIdentityToken
) =>
  getInstallValidation(credentials, {
    logger: log,
    deps: { identityToken },
    now: () => NOW,
  });

const without = (scope: string) =>
  REQUIRED_SCOPES.filter((each) => each !== scope);

beforeEach(() => {
  vi.clearAllMocks();
  resetTokenCache();
  holdSecret(vault, CLIENT_SECRET);
});

describe("a working install", () => {
  it("passes, and reports what the tailnet offers", async () => {
    newTestTailnet();

    await expect(validate()).resolves.toEqual({
      tailnet: TAILNET,
      postureCheckDevice: BOBS_LAPTOP,
      dnsName: "tail1234.ts.net",
      discovery: { p0Postures: 2 },
    });
  });

  it("takes the DNS name from the first own device, not one shared in", async () => {
    const tailnet = newTestTailnet();
    tailnet.state.devices.push({
      isExternal: true,
      name: "theirs.other5678.ts.net",
      nodeId: "nAaShared1CNTRL",
    });

    await expect(validate()).resolves.toMatchObject({
      dnsName: "tail1234.ts.net",
    });
  });

  it("reports no DNS name when no own device has a MagicDNS name", async () => {
    const tailnet = newTestTailnet();
    tailnet.state.devices.splice(0, tailnet.state.devices.length, {
      hostname: "bare",
      nodeId: "nBare1CNTRL",
    });

    await expect(validate()).resolves.not.toHaveProperty("dnsName");
  });

  it("passes with a federated credential", async () => {
    const tailnet = newTestTailnet();

    await expect(validate(FEDERATED)).resolves.toMatchObject({
      tailnet: TAILNET,
    });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expect(tailnet.exchanges().map(({ path }) => path)).toEqual([
      "/api/v2/oauth/token-exchange",
    ]);
  });
});

describe("credential", () => {
  it("fails when the OAuth client's secret can't be read", async () => {
    newTestTailnet();
    vault.getSecretValue.mockRejectedValue(
      new SecretNotFoundError("tailscale-oauth-client" as SecretRef)
    );

    await expect(connectorError(() => validate())).resolves.toMatchObject({
      type: "object_not_found",
      payload: { step: "credential", tailnet: TAILNET },
    });
  });

  it("fails when the cloud identity can't be minted", async () => {
    newTestTailnet();
    const { ConnectorError } = await import("@p0security/connector");

    await expect(
      connectorError(() =>
        validate(FEDERATED, async () => {
          throw new ConnectorError({
            type: "insufficient_privileges",
            message: "no federation",
            payload: {},
          });
        })
      )
    ).resolves.toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "credential" },
    });
  });
});

describe("authenticate", () => {
  it("fails when Tailscale refuses the OAuth client", async () => {
    newTestTailnet();
    holdSecret(vault, "tskey-client-wrong");

    await expect(connectorError(() => validate())).resolves.toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "authenticate", status: 401 },
    });
  });

  it("fails when Tailscale doesn't trust the federated identity", async () => {
    newTestTailnet();

    await expect(
      connectorError(() => validate(FEDERATED, async () => "eyJ.untrusted.sig"))
    ).resolves.toMatchObject({ payload: { step: "authenticate" } });
  });
});

describe("scopes", () => {
  it.each(REQUIRED_SCOPES)(
    "names %s when the OAuth client lacks it",
    async (scope) => {
      newTestTailnet({ scopes: without(scope) });

      const error = await connectorError(() => validate());

      expect(error).toMatchObject({
        type: "insufficient_privileges",
        payload: { step: "scopes" },
      });
      expect(String(error.payload.missing)).toContain(
        scope.replace(/:read$/, "")
      );
    }
  );

  it("names the scope Tailscale won't put in a token for the OAuth client", async () => {
    const tailnet = newTestTailnet({ scopes: without("services:read") });
    // Tailscale's live answer, naming every scope asked for.
    tailnet.intercept(({ form }) => {
      const asked = (form?.scope ?? "").split(" ").sort();
      return asked.includes("services:read")
        ? failing(403, `OAuth client cannot grant scopes "${asked.join(" ")}"`)
        : undefined;
    });

    const error = await connectorError(() => validate());

    expect(error).toMatchObject({
      type: "insufficient_privileges",
      message:
        "The connector's Tailscale credential is missing a scope: services:read. It needs policy_file:read, users:read, devices:core:read, devices:posture_attributes, devices:routes:read, services:read. Add it, then validate again.",
      payload: { step: "scopes", missing: "services:read" },
    });
  });

  // If Tailscale issued a token without a scope the client lacks, rather
  // than refusing it, the endpoint's 404 to the token names it.
  it.each([
    ["users:read", "users:read"],
    ["services:read", "services:read"],
    ["devices:routes:read", "devices:routes:read"],
    ["devices:core:read", "devices:core:read"],
  ])(
    "names %s from the endpoint's 404 when the token is issued without it",
    async (scope, named) => {
      newTestTailnet({ scopes: without(scope), refuseUnheldScopes: false });

      const error = await connectorError(() => validate());

      expect(error.payload).toMatchObject({ step: "scopes" });
      expect(String(error.payload.missing).split(" ")).toContain(named);
    }
  );

  it("names a federated identity's missing read scope from the scopes its token carries", async () => {
    newTestTailnet({ scopes: without("services:read") });

    const error = await connectorError(() => validate(FEDERATED));

    expect(error.payload).toMatchObject({
      step: "scopes",
      missing: "services:read",
    });
  });

  it("names a federated identity's missing write scope, though nothing reads with it", async () => {
    const tailnet = newTestTailnet({
      scopes: [
        ...without("devices:posture_attributes"),
        "devices:posture_attributes:read",
      ],
    });

    const error = await connectorError(() => validate(FEDERATED));

    expect(error).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "scopes", missing: "devices:posture_attributes" },
    });
    expect(error.message).toContain(
      "missing a scope: devices:posture_attributes."
    );
    expect(tailnet.apiCalls()).toEqual([]);
  });

  it("passes a federated identity with every scope, its write scope covering its read", async () => {
    newTestTailnet();

    await expect(validate(FEDERATED)).resolves.toMatchObject({
      tailnet: TAILNET,
    });
  });

  it("takes all:read as every read scope, and still names the write scope", async () => {
    newTestTailnet({ scopes: ["all:read"] });

    const error = await connectorError(() => validate(FEDERATED));

    expect(error.payload).toMatchObject({
      step: "scopes",
      missing: "devices:posture_attributes",
    });
  });

  it("fails closed when Tailscale names no scope for a federated token, before any read", async () => {
    const tailnet = newTestTailnet({
      scopes: [...REQUIRED_SCOPES, "policy_file"],
    });
    withoutFederatedScope(tailnet);

    const error = await connectorError(() => validate(FEDERATED));

    expect(error).toMatchObject({
      type: "validation_error",
      message:
        "Tailscale didn't say which scopes the connector's federated credential carries, so P0 can't confirm it can't write the policy file. Check that the federated identity has only policy_file:read, users:read, devices:core:read, devices:posture_attributes, devices:routes:read, services:read, then validate again, or use an OAuth client instead.",
      payload: { step: "scopes", tailnet: TAILNET },
    });
    expect(tailnet.apiCalls()).toEqual([]);
  });

  it("refuses an OAuth client Tailscale gives a policy_file token, when it names no scope", async () => {
    const tailnet = newTestTailnet({
      scopes: [...REQUIRED_SCOPES, "policy_file"],
    });
    withoutOAuthScope(tailnet);

    const error = await connectorError(() => validate());

    expect(error).toMatchObject({
      type: "validation_error",
      payload: { step: "scopes", extra: "policy_file" },
    });
    expect(error.message).toBe(
      "The connector's Tailscale credential carries policy_file, more than P0 needs, and could write the policy file, which P0 never does. Use a credential with only policy_file:read, users:read, devices:core:read, devices:posture_attributes, devices:routes:read, services:read, then validate again."
    );
    expect(tailnet.apiCalls()).toEqual([]);
  });

  it("passes an OAuth client Tailscale won't give a policy_file token, when it names no scope", async () => {
    const tailnet = newTestTailnet();
    withoutOAuthScope(tailnet);

    await expect(validate()).resolves.toMatchObject({ tailnet: TAILNET });
    expect(tailnet.exchanges().map(({ form }) => form?.scope ?? "")).toContain(
      "policy_file"
    );
  });

  it("refuses an OAuth client that carries policy_file, and names it", async () => {
    const tailnet = newTestTailnet({
      scopes: [...REQUIRED_SCOPES, "policy_file"],
    });

    const error = await connectorError(() => validate());

    expect(error).toMatchObject({
      type: "validation_error",
      payload: { step: "scopes", extra: "policy_file" },
    });
    expect(error.message).toBe(
      "The connector's Tailscale credential carries policy_file, more than P0 needs, and could write the policy file, which P0 never does. Use a credential with only policy_file:read, users:read, devices:core:read, devices:posture_attributes, devices:routes:read, services:read, then validate again."
    );
    expect(tailnet.apiCalls()).toEqual([]);
  });

  it.each([
    ["policy_file", [...REQUIRED_SCOPES, "policy_file"]],
    ["all", ["all"]],
    ["policy_file and all", ["all", "policy_file"]],
  ])(
    "refuses a federated identity whose token carries %s",
    async (named, scopes) => {
      newTestTailnet({ scopes });

      const error = await connectorError(() => validate(FEDERATED));

      expect(error.payload).toMatchObject({ step: "scopes" });
      expect(error.message).toContain(
        `carries ${named}, more than P0 needs, and could write`
      );
    }
  );

  it("refuses an OAuth client with the all scope", async () => {
    newTestTailnet({ scopes: ["all"] });

    const error = await connectorError(() => validate());

    expect(error.payload).toMatchObject({ step: "scopes", extra: "all" });
  });

  it("passes a credential with only the listed scopes, the read of devices:posture_attributes included", async () => {
    newTestTailnet({
      scopes: [...REQUIRED_SCOPES, "devices:posture_attributes:read"],
    });

    await expect(validate(FEDERATED)).resolves.toMatchObject({
      tailnet: TAILNET,
    });
  });
});

describe("posture", () => {
  it("sets the check attribute on the first device for a minute, then removes it", async () => {
    const tailnet = newTestTailnet();

    await expect(validate()).resolves.toMatchObject({
      postureCheckDevice: "nBobLaptop1CNTRL",
    });

    expect(tailnet.writes()).toEqual([
      {
        method: "POST",
        path: `/api/v2/device/${BOBS_LAPTOP}/attributes/${encodeURIComponent(POSTURE_CHECK_KEY)}`,
        rawBody: JSON.stringify({
          value: true,
          expiry: "2026-10-17T12:01:00.000Z",
          comment: "P0 install check",
        }),
      },
      {
        method: "DELETE",
        path: `/api/v2/device/${BOBS_LAPTOP}/attributes/${encodeURIComponent(POSTURE_CHECK_KEY)}`,
        rawBody: undefined,
      },
    ]);
    const device = tailnet.state.devices.find(
      ({ nodeId }) => nodeId === BOBS_LAPTOP
    );
    expect(device?.attributes ?? {}).not.toHaveProperty(POSTURE_CHECK_KEY);
  });

  it("skips tagged and shared-in devices for the check attribute", async () => {
    const tailnet = newTestTailnet();
    tailnet.state.devices.push(
      { nodeId: "nAaShared1CNTRL", isExternal: true },
      { nodeId: "nAaTagged1CNTRL", tags: ["tag:db"] }
    );

    await expect(validate()).resolves.toMatchObject({
      postureCheckDevice: BOBS_LAPTOP,
    });
    expect(tailnet.writes().map(({ path }) => path)).not.toContainEqual(
      expect.stringContaining("nAa")
    );
  });

  it("fails on a tailnet with only tagged and shared-in devices", async () => {
    const tailnet = newTestTailnet();
    tailnet.state.devices.splice(
      0,
      tailnet.state.devices.length,
      { nodeId: "nAaShared1CNTRL", isExternal: true },
      { nodeId: "nAaTagged1CNTRL", tags: ["tag:db"] }
    );

    await expect(connectorError(() => validate())).resolves.toMatchObject({
      type: "validation_error",
      message: `Tailnet ${TAILNET} has no untagged device of its own, so P0 can't check that it may set device attributes. Add one, then validate again.`,
      payload: { step: "posture" },
    });
    expect(tailnet.writes()).toEqual([]);
  });

  it("writes with the posture write token, which has no policy_file", async () => {
    const tailnet = newTestTailnet();

    await validate();

    const writes = tailnet.calls.filter(
      ({ method, path }) => method !== "GET" && !path.includes("/oauth/")
    );
    for (const { headers } of writes) {
      expect(
        tailnet.scopesOf(headers.authorization?.replace(/^Bearer /, "") ?? "")
      ).toEqual(["devices:posture_attributes"]);
    }
  });

  it.each([402, 403, 400])(
    "refuses the install when Tailscale answers the attribute write with %i, naming the plans",
    async (status) => {
      const tailnet = newTestTailnet();
      tailnet.intercept((call) =>
        call.method === "POST" && call.path.includes("/attributes/")
          ? failing(status, "custom attributes need Premium")
          : undefined
      );

      await expect(connectorError(() => validate())).resolves.toMatchObject({
        type: "validation_error",
        message: `Tailnet ${TAILNET} refused a custom device attribute (${status}): custom attributes need Premium. P0 sets posture attributes, which need a Premium or Enterprise plan, and a credential with devices:posture_attributes.`,
        payload: { step: "posture", status },
      });
    }
  );

  it("writes nothing when asked to skip the write, even without devices", async () => {
    const tailnet = newTestTailnet();

    const validation = await validate({
      ...CREDENTIALS,
      skipPostureWrite: true,
    });

    expect(validation).toMatchObject({ tailnet: TAILNET });
    expect(validation).not.toHaveProperty("postureCheckDevice");
    expect(tailnet.writes()).toEqual([]);

    tailnet.state.devices.length = 0;
    await expect(
      validate({ ...CREDENTIALS, skipPostureWrite: true })
    ).resolves.toMatchObject({ tailnet: TAILNET });
  });

  it("fails on a tailnet without devices", async () => {
    const tailnet = newTestTailnet();
    tailnet.state.devices.length = 0;

    await expect(connectorError(() => validate())).resolves.toMatchObject({
      payload: { step: "posture" },
    });
  });
});

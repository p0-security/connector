import { createLogger } from "@p0security/connector";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { failing } from "../../../__tests__/fake-tailscale.ts";
import {
  CLIENT_SECRET,
  CREDENTIALS,
  EMAIL,
  FEDERATED_CREDENTIAL,
  fakeIdentityToken,
} from "../../../__tests__/fixtures.ts";
import {
  connectorError,
  holdSecret,
  thrown,
} from "../../../__tests__/helpers.ts";
import {
  BOBS_LAPTOP,
  DB_SERVER,
  LAPTOP,
  newTestTailnet,
  withoutFederatedScope,
} from "../../../__tests__/tailnet.ts";
import { newTailscaleRouter, t } from "../../../router.ts";
import { resetTokenCache } from "../../../tailscale/client.ts";
import { REQUIRED_SCOPES } from "../../../tailscale/scopes.ts";
import { attributeKeyFor } from "../definition.ts";

const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

const logger = createLogger();
logger.level = "silent";
const posture = t.createCallerFactory(
  newTailscaleRouter({ identityToken: fakeIdentityToken })
)({ logger }).tailscale.accesses.posture;

const EARLY = "2026-10-17T13:00:00.000Z";
const LATE = "2026-10-17T18:00:00.000Z";
// How Tailscale reads those ends back: to the second (spec check A49).
const EARLY_HELD = "2026-10-17T13:00:00Z";
const LATE_HELD = "2026-10-17T18:00:00Z";

const contextFor = (operation: "grant" | "revoke", overrides = {}) => ({
  ...CREDENTIALS,
  requestId: "Req1",
  operation,
  email: EMAIL,
  ...overrides,
});

const setPolicies = (
  operation: "grant" | "revoke",
  policies: { posture: string; expiresAt: string }[],
  deviceId = LAPTOP,
  overrides = {}
) =>
  posture.setPoliciesForUser({
    userId: deviceId,
    userBody: { email: EMAIL, deviceId },
    policies,
    context: contextFor(operation, overrides),
  });

const attributesOf = (
  tailnet: ReturnType<typeof newTestTailnet>,
  deviceId = LAPTOP
) => {
  const device = tailnet.state.devices.find(
    ({ nodeId }) => nodeId === deviceId
  );
  return {
    attributes: device?.attributes ?? {},
    expiries: device?.expiries ?? {},
  };
};

const postureTailnet = () => newTestTailnet({ scopes: REQUIRED_SCOPES });

// Before EARLY, so every end the tests send is still to come, unless a test
// moves the clock.
const NOW = "2026-10-17T12:00:00.000Z";

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"], now: new Date(NOW) });
  resetTokenCache();
  holdSecret(vault, CLIENT_SECRET);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("attributeKeyFor", () => {
  it("reads custom:p0_<name> for posture:p0_<name>", () => {
    expect(attributeKeyFor("posture:p0_prod_db")).toBe("custom:p0_prod_db");
  });
});

describe("the posture access", () => {
  it("sets the posture's attribute to true until the grant's end", async () => {
    const tailnet = postureTailnet();

    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);

    expect(attributesOf(tailnet)).toEqual({
      attributes: {
        "node:os": "macos",
        "custom:team": "eng",
        "custom:p0_db": true,
      },
      expiries: { "custom:p0_db": LATE_HELD },
    });
  });

  it("holds a key two requests carry until the later one ends", async () => {
    const tailnet = postureTailnet();

    await setPolicies("grant", [
      { posture: "posture:p0_db", expiresAt: LATE },
      { posture: "posture:p0_db", expiresAt: EARLY },
    ]);

    expect(attributesOf(tailnet).expiries).toEqual({
      "custom:p0_db": LATE_HELD,
    });
  });

  it("keeps the attribute when one of two requests is revoked", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [
      { posture: "posture:p0_db", expiresAt: LATE },
      { posture: "posture:p0_db", expiresAt: EARLY },
    ]);

    // The revoking request is left out of the union.
    await setPolicies("revoke", [
      { posture: "posture:p0_db", expiresAt: EARLY },
    ]);

    expect(attributesOf(tailnet)).toMatchObject({
      attributes: { "custom:p0_db": true },
      expiries: { "custom:p0_db": EARLY_HELD },
    });
  });

  it("deletes a key whose every request has ended, rather than set it with a past end", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [
      { posture: "posture:p0_db", expiresAt: LATE },
      { posture: "posture:p0_web", expiresAt: EARLY },
    ]);
    vi.setSystemTime(new Date("2026-10-17T14:00:00.000Z"));

    // A revoke of the db request, while the web request is still open past
    // its end.
    await setPolicies("revoke", [
      { posture: "posture:p0_web", expiresAt: EARLY },
    ]);

    expect(attributesOf(tailnet)).toEqual({
      attributes: { "node:os": "macos", "custom:team": "eng" },
      expiries: {},
    });
  });

  it("deletes the attribute when the last request is revoked, and only P0's", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [
      { posture: "posture:p0_db", expiresAt: LATE },
      { posture: "posture:p0_web", expiresAt: LATE },
    ]);

    await setPolicies("revoke", [
      { posture: "posture:p0_web", expiresAt: LATE },
    ]);
    await setPolicies("revoke", []);

    expect(attributesOf(tailnet)).toEqual({
      attributes: { "node:os": "macos", "custom:team": "eng" },
      expiries: {},
    });
  });

  it("never touches a customer key that only shares P0's prefix", async () => {
    const tailnet = postureTailnet();
    const laptop = tailnet.state.devices.find(
      ({ nodeId }) => nodeId === LAPTOP
    );
    if (laptop) {
      laptop.attributes = {
        ...laptop.attributes,
        "custom:p0_Prod": true,
        "custom:p0-db": "x",
      };
    }

    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);
    await setPolicies("revoke", []);

    expect(attributesOf(tailnet).attributes).toEqual({
      "node:os": "macos",
      "custom:team": "eng",
      "custom:p0_Prod": true,
      "custom:p0-db": "x",
    });
  });

  it("sets and deletes in one call, with the request in its comment", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);

    await setPolicies("grant", [
      { posture: "posture:p0_web", expiresAt: LATE },
    ]);

    const patches = tailnet.writes().filter(({ method }) => method === "PATCH");
    expect(patches).toHaveLength(2);
    expect(JSON.parse(patches[1]?.rawBody ?? "{}")).toEqual({
      nodes: {
        [LAPTOP]: {
          "custom:p0_web": { value: true, expiry: LATE },
          "custom:p0_db": null,
        },
      },
      comment: "P0 request Req1 (grant)",
    });
  });

  it("writes nothing the second time the lifecycle runs a step", async () => {
    const tailnet = postureTailnet();
    const policies = [{ posture: "posture:p0_db", expiresAt: LATE }];

    await setPolicies("grant", policies);
    await setPolicies("grant", policies);

    expect(tailnet.writes()).toHaveLength(1);
  });

  it("writes nothing the second time for an end with milliseconds, which Tailscale keeps to the second", async () => {
    const tailnet = postureTailnet();
    const policies = [
      { posture: "posture:p0_db", expiresAt: "2026-10-17T18:00:00.123Z" },
    ];

    await setPolicies("grant", policies);
    await setPolicies("grant", policies);

    expect(tailnet.writes()).toHaveLength(1);
  });

  it("refuses a device that isn't the requestor's", async () => {
    const tailnet = postureTailnet();

    await expect(
      connectorError(() =>
        setPolicies(
          "grant",
          [{ posture: "posture:p0_db", expiresAt: LATE }],
          BOBS_LAPTOP
        )
      )
    ).resolves.toMatchObject({ type: "validation_error" });
    expect(tailnet.writes()).toEqual([]);
  });

  it("takes the requestor's device when their email differs from its user only in case", async () => {
    const tailnet = postureTailnet();

    await setPolicies(
      "grant",
      [{ posture: "posture:p0_db", expiresAt: LATE }],
      LAPTOP,
      { email: EMAIL.toUpperCase() }
    );

    expect(attributesOf(tailnet).attributes).toMatchObject({
      "custom:p0_db": true,
    });
  });

  // A tagged device's user is whoever registered it: Alice registered it.
  it("refuses a tagged device the requestor registered", async () => {
    const tailnet = postureTailnet();

    await expect(
      connectorError(() =>
        setPolicies(
          "grant",
          [{ posture: "posture:p0_db", expiresAt: LATE }],
          DB_SERVER
        )
      )
    ).resolves.toMatchObject({
      type: "validation_error",
      message: expect.stringContaining("tagged"),
    });
    expect(tailnet.writes()).toEqual([]);
  });

  it("refuses a device shared in from another tailnet, though its user is the requestor's login", async () => {
    const tailnet = postureTailnet();
    const laptop = tailnet.state.devices.find(
      ({ nodeId }) => nodeId === LAPTOP
    );
    if (laptop) laptop.isExternal = true;

    await expect(
      connectorError(() =>
        setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
      )
    ).resolves.toMatchObject({
      type: "validation_error",
      message: `Device ${LAPTOP} is shared into tailnet ${CREDENTIALS.tailnet} from another tailnet. Choose one of your own devices on tailnet ${CREDENTIALS.tailnet}.`,
    });
    expect(tailnet.writes()).toEqual([]);
  });

  it("revokes from any device, without checking its owner", async () => {
    const tailnet = postureTailnet();
    const bob = tailnet.state.devices.find(
      ({ nodeId }) => nodeId === BOBS_LAPTOP
    );
    if (bob) bob.attributes = { "custom:p0_db": true };

    await setPolicies("revoke", [], BOBS_LAPTOP);

    expect(attributesOf(tailnet, BOBS_LAPTOP).attributes).toEqual({});
  });

  it("refuses a grant whose device left the tailnet as the requestor's to fix", async () => {
    const tailnet = postureTailnet();
    tailnet.state.devices.splice(0, 1);

    const error = await connectorError(() =>
      setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
    );

    expect(error).toMatchObject({
      type: "validation_error",
      message: `Device ${LAPTOP} isn't on tailnet ${CREDENTIALS.tailnet}. Choose one of your devices on the tailnet, then request again.`,
    });
    expect(tailnet.writes()).toEqual([]);
  });

  it("refuses a grant whose device's attributes are gone the same way", async () => {
    const tailnet = postureTailnet();
    tailnet.intercept((call) =>
      call.method === "GET" && call.path.endsWith("/attributes")
        ? failing(404, "not found")
        : undefined
    );

    await expect(
      connectorError(() =>
        setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
      )
    ).resolves.toMatchObject({
      type: "validation_error",
      message: expect.stringContaining("isn't on tailnet"),
    });
  });

  it("names a device another call can't find without pointing at the Tailnet ID", async () => {
    const tailnet = postureTailnet();
    tailnet.intercept((call) =>
      call.method === "PATCH" ? failing(404, "not found") : undefined
    );

    const error = await connectorError(() =>
      setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
    );

    expect(error.type).toBe("object_not_found");
    expect(error.message).not.toContain("Tailnet ID");
  });

  // Tailscale's live answer to an attribute write for a device that isn't
  // on the tailnet.
  const removeDeviceOnWrite = (tailnet: ReturnType<typeof newTestTailnet>) =>
    tailnet.intercept((call) => {
      if (call.method !== "PATCH") return undefined;
      tailnet.state.devices.splice(0, 1);
      return failing(403, "feature not available on current billing plan");
    });

  it("refuses a grant whose device left the tailnet before the attribute write as the requestor's to fix", async () => {
    const tailnet = postureTailnet();
    removeDeviceOnWrite(tailnet);

    const error = await connectorError(() =>
      setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
    );

    expect(error).toMatchObject({
      type: "validation_error",
      message: `Device ${LAPTOP} isn't on tailnet ${CREDENTIALS.tailnet}. Choose one of your devices on the tailnet, then request again.`,
    });
  });

  it("passes a revoke whose device left the tailnet before the attribute write", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);
    removeDeviceOnWrite(tailnet);

    await setPolicies("revoke", []);

    expect(tailnet.writes().at(-1)?.method).toBe("PATCH");
  });

  it.each([400, 402, 403])(
    "refuses an attribute write's %i for a device that's still there, naming the plans and the scope",
    async (status) => {
      const tailnet = postureTailnet();
      tailnet.intercept((call) =>
        call.method === "PATCH"
          ? failing(status, "feature not available on current billing plan")
          : undefined
      );

      const error = await connectorError(() =>
        setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }])
      );

      expect(error).toMatchObject({
        type: "insufficient_privileges",
        message: `Tailnet ${CREDENTIALS.tailnet} refused a custom device attribute (${status}): feature not available on current billing plan. P0 sets posture attributes, which need a Premium or Enterprise plan, and a credential with devices:posture_attributes.`,
        payload: { status, deviceId: LAPTOP },
      });
    }
  );

  it("doesn't take a 404 to a token without devices:core:read for a gone device on a revoke", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES.filter((scope) => scope !== "devices:core:read"),
    });

    const error = await connectorError(() =>
      posture.identifyUser({
        userBody: { email: EMAIL, deviceId: LAPTOP },
        context: contextFor("revoke", { credential: FEDERATED_CREDENTIAL }),
      })
    );

    expect(error).toMatchObject({
      type: "insufficient_privileges",
      message: `The connector's Tailscale credential for tailnet ${CREDENTIALS.tailnet} lacks devices:core:read, which P0 needs for device ${LAPTOP} (Tailscale answered "not found"). Add devices:core:read to the credential, then retry.`,
      payload: { missing: "devices:core:read" },
    });
  });

  it("says a grant's missing device may be a scope the token lacks, when Tailscale doesn't name the token's scopes", async () => {
    const tailnet = newTestTailnet({
      scopes: REQUIRED_SCOPES.filter((scope) => scope !== "devices:core:read"),
    });
    withoutFederatedScope(tailnet);

    const error = await connectorError(() =>
      posture.provisionUser({
        userBody: { email: EMAIL, deviceId: LAPTOP },
        context: contextFor("grant", { credential: FEDERATED_CREDENTIAL }),
      })
    );

    expect(error).toMatchObject({
      type: "validation_error",
      message: `Device ${LAPTOP} isn't on tailnet ${CREDENTIALS.tailnet}. Choose one of your devices on the tailnet, then request again. Tailscale also answers "not found" when the connector's Tailscale credential lacks the scope a call needs, so check that it holds devices:core:read.`,
    });
  });

  it("passes a revoke whose device is gone", async () => {
    const tailnet = postureTailnet();
    tailnet.state.devices.splice(0, 1);

    await setPolicies("revoke", []);

    expect(tailnet.writes()).toEqual([]);
  });

  // A 404 that may be a scope the token lacks, for a device the tailnet
  // still lists.
  const notFoundFor = (
    tailnet: ReturnType<typeof newTestTailnet>,
    path: string
  ) =>
    tailnet.intercept((call) =>
      call.method === "GET" && call.path === path
        ? failing(404, "not found")
        : undefined
    );

  it("fails a revoke whose attributes read is a 404 for a device the tailnet still lists, so it's retried", async () => {
    const tailnet = postureTailnet();
    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);
    notFoundFor(tailnet, `/api/v2/device/${LAPTOP}/attributes`);

    await expect(
      connectorError(() => setPolicies("revoke", []))
    ).resolves.toMatchObject({ type: "object_not_found" });
    expect(attributesOf(tailnet).attributes).toMatchObject({
      "custom:p0_db": true,
    });
  });

  it("fails a revoke whose device read is a 404 for a device the tailnet still lists", async () => {
    const tailnet = postureTailnet();
    notFoundFor(tailnet, `/api/v2/device/${LAPTOP}`);

    await expect(
      connectorError(() =>
        posture.identifyUser({
          userBody: { email: EMAIL, deviceId: LAPTOP },
          context: contextFor("revoke"),
        })
      )
    ).resolves.toMatchObject({ type: "object_not_found" });
  });

  it("refuses a request without an end", async () => {
    postureTailnet();
    const error = await thrown(() =>
      setPolicies("grant", [{ posture: "posture:p0_db" } as never])
    );
    expect(error).toMatchObject({ code: "BAD_REQUEST" });
  });

  it.each([
    "posture:p0-db",
    "posture:latest",
    "posture:p0_DB",
    "custom:p0_db",
    "posture:p0_install_check",
  ])("refuses %s as a P0 posture", async (name) => {
    postureTailnet();
    const error = await thrown(() =>
      setPolicies("grant", [{ posture: name, expiresAt: LATE }])
    );
    expect(error).toMatchObject({ code: "BAD_REQUEST" });
  });

  it("writes with devices:posture_attributes alone, and never the policy file", async () => {
    const tailnet = postureTailnet();

    await setPolicies("grant", [{ posture: "posture:p0_db", expiresAt: LATE }]);
    await setPolicies("revoke", []);

    const calls = tailnet.apiCalls();
    const scopes = tailnet.scopesSent();
    calls.forEach((call, i) => {
      expect(call.path).not.toMatch(/\/acl$/);
      if (call.method !== "GET" || call.path.endsWith("/attributes")) {
        expect(scopes[i]).toEqual(["devices:posture_attributes"]);
      }
    });
    expect(tailnet.exchanges().map(({ form }) => form?.scope)).not.toContain(
      expect.stringContaining("policy_file ")
    );
  });
});

describe("the posture user", () => {
  it("is the device, when it's on the tailnet", async () => {
    postureTailnet();
    await expect(
      posture.provisionUser({
        userBody: { email: EMAIL, deviceId: LAPTOP },
        context: contextFor("grant"),
      })
    ).resolves.toBe(LAPTOP);
  });

  it("is refused at grant when the device isn't on the tailnet", async () => {
    postureTailnet();
    await expect(
      connectorError(() =>
        posture.provisionUser({
          userBody: { email: EMAIL, deviceId: "nGone1CNTRL" },
          context: contextFor("grant"),
        })
      )
    ).resolves.toMatchObject({ type: "validation_error" });
  });

  it("is null on a revoke when the device is gone, so the revoke has nothing to do", async () => {
    postureTailnet();
    await expect(
      posture.identifyUser({
        userBody: { email: EMAIL, deviceId: "nGone1CNTRL" },
        context: contextFor("revoke"),
      })
    ).resolves.toBeNull();
  });
});

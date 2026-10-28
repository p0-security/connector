import { ConnectorError, createLogger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  failing,
  fakeEndpoint,
  isCall,
  newSeededCloud,
} from "../../__tests__/fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  KEY_ID,
  KEY_SECRET,
  KEY_UUID,
  ORGANIZATION_ID,
  OTHER_SERVICE_ID,
  SERVICE_ID,
} from "../../__tests__/fixtures.ts";
import { connectorError } from "../../__tests__/helpers.ts";
import {
  RATE_LIMIT_BUDGET,
  forgetKeyUuids,
  setPacing,
} from "../../cloud/client.ts";
import { REQUIRED_PERMISSIONS } from "../../cloud/permissions.ts";
import { connectorRouter, t } from "../../router.ts";

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ readApiKey }));

const requireAllowedDomains = vi.hoisted(() => vi.fn());
vi.mock("../../allowed-domains.ts", () => ({ requireAllowedDomains }));

const logger = createLogger();
logger.level = "silent";
const connector = t.createCallerFactory(connectorRouter)({ logger });
const validate = (input: unknown = CREDENTIALS) =>
  connector.clickhouse.install.validation.get(input as typeof CREDENTIALS);

const THIRD_SERVICE_ID = "7b2a1f0e-9d8c-4b76-8c54-3b2a1f0e9d8c";
const BYOC_SERVICE_ID = "8c3b2a1f-0e9d-4c87-9d65-4c3b2a1f0e9d";

let cloud: FakeCloud;

const step = async (stepName: string) => {
  const data = await connectorError(() => validate());
  expect(data.payload.step).toBe(stepName);
  expect(data.payload.organizationId).toBe(ORGANIZATION_ID);
  return data;
};

beforeEach(() => {
  cloud = newSeededCloud();
  vi.stubGlobal("fetch", cloud.fetch);
  forgetKeyUuids();
  readApiKey.mockReset();
  readApiKey.mockResolvedValue({
    keyId: KEY_ID,
    keySecret: KEY_SECRET,
    version: "1",
  });
  requireAllowedDomains.mockReset();
  requireAllowedDomains.mockReturnValue({
    pattern: ALLOWED_PATTERN,
    allows: () => true,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("install validation", () => {
  it("passes every step and reports the organization, without setting up or running any endpoint", async () => {
    await expect(validate()).resolves.toEqual({
      organizationName: "Acme",
      apiKeyId: KEY_ID,
      apiKeyUuid: KEY_UUID,
      allowedDomains: ALLOWED_PATTERN,
      services: [{ id: SERVICE_ID, name: "prod", status: "ready" }],
    });
    expect(cloud.endpointsOf(SERVICE_ID)).toEqual([]);
    expect(cloud.writes()).toEqual([]);
    expect(cloud.runs()).toEqual([]);
  });

  it("refuses an organization ID that isn't a UUID, and calls nothing", async () => {
    const error = await validate({
      ...CREDENTIALS,
      organizationId: "acme",
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(Error);
    expect(readApiKey).not.toHaveBeenCalled();
    expect(cloud.calls).toEqual([]);
  });

  describe("the secret step", () => {
    it("fails naming the step when the key can't be read, and asks ClickHouse Cloud nothing", async () => {
      readApiKey.mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "can't read it",
          payload: { manager: "aws" },
        })
      );

      await expect(connectorError(() => validate())).resolves.toEqual({
        type: "insufficient_privileges",
        message: "can't read it",
        payload: {
          manager: "aws",
          step: "secret",
          organizationId: ORGANIZATION_ID,
        },
      });
      expect(cloud.calls).toEqual([]);
    });
  });

  describe("the authenticate step", () => {
    it("words a 401 as the key rejected", async () => {
      readApiKey.mockResolvedValue({
        keyId: KEY_ID,
        keySecret: "wrong",
        version: "1",
      });

      await expect(step("authenticate")).resolves.toEqual({
        type: "insufficient_privileges",
        message: `The ClickHouse Cloud organization ${ORGANIZATION_ID} rejected P0's API key (401): the key ID or secret is wrong, or the key is disabled or expired. Check the key in its secret.`,
        payload: {
          status: 401,
          step: "authenticate",
          organizationId: ORGANIZATION_ID,
        },
      });
    });

    it.each([400, 403, 404])(
      "words a %s as another organization's key, or one without organization:view",
      async (status) => {
        cloud.intercept((call) =>
          isCall("GET", `/v1/organizations/${ORGANIZATION_ID}`)(call)
            ? failing(status)
            : undefined
        );

        const data = await step("authenticate");

        expect(data.type).toBe("insufficient_privileges");
        expect(data.message).toBe(
          `The ClickHouse Cloud organization ${ORGANIZATION_ID} didn't answer to P0's API key (${status}): the key belongs to another organization, or its p0-connector role lacks control-plane:organization:view. Check the key's role and the organization ID. If the ID is wrong, remove the organization in P0 and add it again.`
        );
        expect(data.payload.status).toBe(status);
      }
    );

    it("maps anything else as it is, naming the step", async () => {
      cloud.intercept(() => failing(503));

      const data = await step("authenticate");

      expect(data.type).toBe("upstream_unavailable");
    });
  });

  describe("the permissions step", () => {
    it.each(
      REQUIRED_PERMISSIONS.filter(
        (p) => p !== "control-plane:service:manage-query-api-endpoints"
      )
    )("names %s when the key lacks it", async (permission) => {
      cloud.state.permissions.delete(permission);
      // The authenticate step reads the organization with organization:view.
      if (permission === "control-plane:organization:view") {
        cloud.intercept((call) =>
          isCall("GET", `/v1/organizations/${ORGANIZATION_ID}`)(call)
            ? {
                status: 200,
                body: { result: { id: ORGANIZATION_ID, name: "Acme" } },
              }
            : undefined
        );
      }

      const data = await step("permissions");

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload.missing).toBe(permission);
      expect(data.message).toContain(`is missing a permission: ${permission}.`);
    });

    it("names every permission that's missing, in the order it checks them", async () => {
      cloud.state.permissions = new Set(["control-plane:organization:view"]);

      const data = await step("permissions");

      expect(data.payload.missing).toBe(
        "control-plane:organization:manage control-plane:service:view control-plane:service:view-query-api-endpoints control-plane:organization:view-api-keys"
      );
      expect(data.message).toBe(
        `P0's API key for the ClickHouse Cloud organization ${ORGANIZATION_ID} is missing permissions: control-plane:organization:manage, control-plane:service:view, control-plane:service:view-query-api-endpoints, control-plane:organization:view-api-keys. Add them to the key's p0-connector role, which needs ${REQUIRED_PERMISSIONS.join(", ")}, then try again.`
      );
    });

    it("probes a service that isn't BYOC", async () => {
      cloud.services.unshift({
        id: OTHER_SERVICE_ID,
        name: "byoc",
        state: "running",
        byocId: "byoc-1",
      });

      await validate();

      expect(
        cloud.calls.filter(
          isCall("GET", new RegExp(`services/${OTHER_SERVICE_ID}`))
        )
      ).toEqual([]);
    });

    it("skips the service probes when there are no services, and leaves it to the services step", async () => {
      cloud.services.length = 0;
      cloud.state.permissions.delete("control-plane:service:view");

      const data = await step("services");

      expect(data).toEqual({
        type: "dependency_violation",
        message:
          "The ClickHouse Cloud organization Acme has no services. Create one, then try again.",
        payload: { step: "services", organizationId: ORGANIZATION_ID },
      });
    });

    it("fails the step as it is on a probe that fails another way", async () => {
      cloud.intercept((call) =>
        isCall("GET", /\/roles$/)(call) ? failing(500) : undefined
      );

      const data = await step("permissions");

      expect(data.type).toBe("upstream_unavailable");
    });
  });

  describe("the services step", () => {
    const report = async () => {
      const validation = await validate();
      return validation.services;
    };

    const addReadyService = () =>
      cloud.services.push({
        id: THIRD_SERVICE_ID,
        name: "ready",
        state: "running",
        clickhouseVersion: "26.8.2.1",
      });

    /** `count` more running services on 26.8, after the seeded one. */
    const addServices = (count: number) =>
      Array.from({ length: count }, (_, i) => {
        const id = `${String(i + 1).padStart(8, "0")}-0000-4000-8000-000000000000`;
        cloud.services.push({
          id,
          name: `s${i + 1}`,
          state: "running",
          clickhouseVersion: "26.8.2.1",
        });
        return id;
      });

    it.each([1, 20])(
      "makes 7 ClickHouse Cloud calls with %s services, none about one service but the probes'",
      async (count) => {
        addServices(count - 1);

        const services = await report();

        expect(services).toHaveLength(count);
        expect(services.every(({ status }) => status === "ready")).toBe(true);
        expect(cloud.calls).toHaveLength(7);
        // Only the permission probes read a service, and only one.
        const about = new Set(
          cloud.calls.flatMap(
            ({ path }) => /\/services\/([^/]+)/.exec(path)?.slice(1) ?? []
          )
        );
        expect(about).toEqual(new Set([SERVICE_ID]));
        expect(cloud.writes()).toEqual([]);
        expect(cloud.runs()).toEqual([]);
      }
    );

    it("answers with the key's UUID, which it finds from its secret's suffix too", async () => {
      const [own] = cloud.keys;
      if (own) own.keySuffix = KEY_SECRET.slice(-4);

      await expect(validate()).resolves.toMatchObject({
        apiKeyUuid: KEY_UUID,
      });
    });

    it.each([
      ["no key matches", () => (cloud.keys.length = 0)],
      [
        "two keys match",
        () =>
          cloud.keys.push({
            id: OTHER_SERVICE_ID,
            name: "copy",
            keySuffix: KEY_SECRET.slice(-4),
          }),
      ],
    ])("fails the step, writing nothing, when %s", async (_case, change) => {
      change();

      const data = await step("services");

      expect(data.type).toBe("dependency_violation");
      expect(data.message).toContain(
        "P0 couldn't tell which of the ClickHouse Cloud organization's API keys is its own"
      );
      expect(cloud.writes()).toEqual([]);
    });

    it("reports a BYOC service as not ready", async () => {
      Object.assign(cloud.services[0] ?? {}, { byocId: "byoc-1" });
      addReadyService();

      await expect(report()).resolves.toContainEqual({
        id: SERVICE_ID,
        name: "prod",
        status: "not-ready",
        reason: "BYOC isn't supported",
      });
      expect(cloud.endpointsOf(SERVICE_ID)).toEqual([]);
    });

    it.each(["25.8.1.1", "26.3.9.9", "24.12"])(
      "reports ClickHouse %s as console-only",
      async (version) => {
        Object.assign(cloud.services[0] ?? {}, { clickhouseVersion: version });
        addReadyService();

        await expect(report()).resolves.toContainEqual({
          id: SERVICE_ID,
          name: "prod",
          status: "console-only",
          reason: `ClickHouse ${version} is older than 26.4, so only console access can be requested`,
        });
        expect(cloud.endpointsOf(SERVICE_ID)).toEqual([]);
      }
    );

    it.each(["26.4", "26.4.0.1", "26.10.1.1", "27.1.1.1"])(
      "takes ClickHouse %s",
      async (version) => {
        Object.assign(cloud.services[0] ?? {}, { clickhouseVersion: version });

        await expect(report()).resolves.toEqual([
          { id: SERVICE_ID, name: "prod", status: "ready" },
        ]);
      }
    );

    it.each([undefined, "", "latest"])(
      "reports a service whose version reads %j as console-only",
      async (version) => {
        Object.assign(cloud.services[0] ?? {}, { clickhouseVersion: version });
        addReadyService();

        await expect(report()).resolves.toContainEqual({
          id: SERVICE_ID,
          name: "prod",
          status: "console-only",
          reason:
            "ClickHouse Cloud didn't report the service's ClickHouse version, so only console access can be requested",
        });
      }
    );

    it.each(["idle", "stopped", "starting", "awaking"])(
      "reports a service that's %s as ready, without waking it",
      async (state) => {
        Object.assign(cloud.services[0] ?? {}, { state });

        await expect(report()).resolves.toEqual([
          { id: SERVICE_ID, name: "prod", status: "ready" },
        ]);
        expect(cloud.runs()).toEqual([]);
      }
    );

    // A service's endpoints are a lookup's to set up.
    it("reads no service's endpoints but the probe's", async () => {
      cloud.endpointsOf(SERVICE_ID).push(fakeEndpoint({ name: "p0_objects" }));
      addReadyService();

      await expect(report()).resolves.toEqual([
        { id: SERVICE_ID, name: "prod", status: "ready" },
        { id: THIRD_SERVICE_ID, name: "ready", status: "ready" },
      ]);
      expect(
        cloud.calls.filter(isCall("GET", /query-api-endpoints/))
      ).toHaveLength(1);
    });

    // A lookup needs it, and names it when it's missing.
    it("passes without the manage permission, which it can't probe", async () => {
      cloud.state.permissions.delete(
        "control-plane:service:manage-query-api-endpoints"
      );

      await expect(report()).resolves.toEqual([
        { id: SERVICE_ID, name: "prod", status: "ready" },
      ]);
    });

    const OLD_SERVICE = {
      id: OTHER_SERVICE_ID,
      name: "old",
      state: "running",
      clickhouseVersion: "25.8.1.1",
    };

    it("fails only when every service is not ready, listing each and their IDs", async () => {
      Object.assign(cloud.services[0] ?? {}, { byocId: "byoc-1" });
      cloud.services.push({ ...OLD_SERVICE, byocId: "byoc-2" });

      const data = await step("services");

      expect(data).toEqual({
        type: "dependency_violation",
        message:
          "No service in the ClickHouse Cloud organization Acme can take requests from P0. prod: BYOC isn't supported. old: BYOC isn't supported.",
        payload: {
          step: "services",
          organizationId: ORGANIZATION_ID,
          notReady: `${SERVICE_ID},${OTHER_SERVICE_ID}`,
        },
      });
    });

    // Console roles work on any version.
    it("passes with only a console-only service besides ones that aren't ready", async () => {
      Object.assign(cloud.services[0] ?? {}, { byocId: "byoc-1" });
      cloud.services.push(OLD_SERVICE);

      await expect(report()).resolves.toEqual([
        {
          id: SERVICE_ID,
          name: "prod",
          status: "not-ready",
          reason: "BYOC isn't supported",
        },
        {
          id: OTHER_SERVICE_ID,
          name: "old",
          status: "console-only",
          reason:
            "ClickHouse 25.8.1.1 is older than 26.4, so only console access can be requested",
        },
      ]);
    });

    it("passes with one ready service among others, reporting every one", async () => {
      Object.assign(cloud.services[0] ?? {}, { byocId: "byoc-1" });
      addReadyService();

      await expect(report()).resolves.toEqual([
        {
          id: SERVICE_ID,
          name: "prod",
          status: "not-ready",
          reason: "BYOC isn't supported",
        },
        { id: THIRD_SERVICE_ID, name: "ready", status: "ready" },
      ]);
    });

    it("reports the services in their order, BYOC and console-only ones included", async () => {
      const [second] = addServices(1);
      cloud.services.push({
        id: BYOC_SERVICE_ID,
        name: "byoc",
        state: "running",
        clickhouseVersion: "26.8.2.1",
        byocId: "byoc-1",
      });
      cloud.services.push(OLD_SERVICE);

      await expect(report()).resolves.toEqual([
        { id: SERVICE_ID, name: "prod", status: "ready" },
        { id: second, name: "s1", status: "ready" },
        {
          id: BYOC_SERVICE_ID,
          name: "byoc",
          status: "not-ready",
          reason: "BYOC isn't supported",
        },
        {
          id: OTHER_SERVICE_ID,
          name: "old",
          status: "console-only",
          reason:
            "ClickHouse 25.8.1.1 is older than 26.4, so only console access can be requested",
        },
      ]);
    });

    describe("against the key's rate limit", () => {
      beforeEach(() => {
        vi.useFakeTimers();
        setPacing(true);
      });

      afterEach(() => {
        setPacing(false);
        vi.useRealTimers();
      });

      it("lists the keys once, for both the permission probe and the key's UUID", async () => {
        const validation = validate();
        await vi.advanceTimersByTimeAsync(RATE_LIMIT_BUDGET);
        await validation;

        expect(cloud.calls.filter(isCall("GET", /\/keys$/))).toHaveLength(1);
      });

      it("fails the step as rate_limited once the 429s outlast the budget", async () => {
        cloud.intercept((call) =>
          isCall("GET", /\/keys$/)(call)
            ? failing(429, "Too Many Requests", { "retry-after": "60" })
            : undefined
        );

        const data = step("permissions");
        await vi.advanceTimersByTimeAsync(RATE_LIMIT_BUDGET);

        await expect(data).resolves.toMatchObject({
          type: "rate_limited",
          payload: { step: "permissions", retryAfter: "60", status: 429 },
        });
      });

      it("takes under 11 seconds with 20 services, paced", async () => {
        addServices(19);
        const validation = validate();
        await vi.advanceTimersByTimeAsync(10_999);

        await expect(validation).resolves.toMatchObject({
          services: expect.arrayContaining([
            expect.objectContaining({ status: "ready" }),
          ]),
        });
      });
    });
  });

  describe("the domains step", () => {
    it("fails naming the step when the pattern is unusable", async () => {
      requireAllowedDomains.mockImplementation(() => {
        throw new Error("DOMAIN_ALLOW_PATTERN isn't set, or is blank.");
      });

      await expect(step("domains")).resolves.toEqual({
        type: "validation_error",
        message: "DOMAIN_ALLOW_PATTERN isn't set, or is blank.",
        payload: { step: "domains", organizationId: ORGANIZATION_ID },
      });
    });
  });
});

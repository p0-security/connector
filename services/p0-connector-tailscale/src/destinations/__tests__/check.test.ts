import { createLogger } from "@p0security/connector";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { failing } from "../../__tests__/fake-tailscale.ts";
import {
  CLIENT_SECRET,
  CREDENTIALS,
  fakeIdentityToken,
} from "../../__tests__/fixtures.ts";
import { connectorError, holdSecret, thrown } from "../../__tests__/helpers.ts";
import { BASE_POLICY, newTestTailnet } from "../../__tests__/tailnet.ts";
import type { TailnetCredentials } from "../../credentials.ts";
import { newTailscaleRouter, t } from "../../router.ts";
import { resetTokenCache } from "../../tailscale/client.ts";
import { REQUIRED_SCOPES } from "../../tailscale/scopes.ts";

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
const caller = t.createCallerFactory(
  newTailscaleRouter({ identityToken: fakeIdentityToken })
)({ logger });

const check = (
  destination: Record<string, unknown>,
  context: TailnetCredentials = CREDENTIALS
) =>
  caller.tailscale.install.destination.check({ context, destination } as never);

beforeEach(() => {
  vi.clearAllMocks();
  resetTokenCache();
  holdSecret(vault, CLIENT_SECRET);
});

describe("install.destination.check", () => {
  it("answers a read Tailscale can't find without the Tailnet ID hint", async () => {
    const tailnet = newTestTailnet();
    tailnet.intercept((call) =>
      call.method === "GET" ? failing(404, "not found") : undefined
    );
    const error = await connectorError(() =>
      check({ type: "posture", target: "posture:p0_db" })
    );
    expect(error).toMatchObject({
      type: "object_not_found",
      message: `Tailscale tailnet ${CREDENTIALS.tailnet} couldn't find the requested posture posture:p0_db.`,
    });
  });

  it("answers a posture destination with the key it reads", async () => {
    newTestTailnet({ scopes: REQUIRED_SCOPES });
    await expect(
      check({ type: "posture", target: "posture:p0_legacy" })
    ).resolves.toEqual({
      kind: "posture",
      posture: "posture:p0_legacy",
      attribute: "custom:p0_legacy",
      assertions: ["custom:p0_legacy == true"],
      unlocks: { grants: [], ssh: [] },
    });
    await expect(
      connectorError(() =>
        check({ type: "posture", target: "posture:p0_gone" })
      )
    ).resolves.toMatchObject({ type: "object_not_found" });
  });

  it("answers the grants and legacy ACLs a posture unlocks, and no other", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        grants: [
          ...BASE_POLICY.grants,
          {
            src: ["autogroup:member"],
            dst: ["tag:db"],
            ip: ["tcp:5432"],
            srcPosture: ["posture:latest", "posture:p0_db"],
          },
          {
            Src: ["group:eng"],
            Dst: ["tag:k8s-operator"],
            App: {
              "tailscale.com/cap/kubernetes": [
                { impersonate: { groups: ["system:masters"] } },
              ],
            },
            SrcPosture: ["posture:p0_db"],
          },
          {
            src: ["autogroup:member"],
            dst: ["autogroup:internet"],
            ip: ["*"],
            via: ["tag:exit"],
            srcPosture: ["posture:p0_legacy"],
          },
        ],
        acls: [
          {
            action: "accept",
            src: ["alice@acme.com"],
            proto: "tcp",
            dst: [
              "tag:db:5432,5433",
              "100.64.0.6:5432,5433",
              "fd7a:115c:a1e0::6:22",
            ],
            srcPosture: ["posture:p0_db"],
          },
          {
            action: "accept",
            src: ["*"],
            dst: ["*:*"],
          },
        ],
      }),
    });
    await expect(
      check({ type: "posture", target: "posture:p0_db" })
    ).resolves.toMatchObject({
      kind: "posture",
      unlocks: {
        grants: [
          { src: ["autogroup:member"], dst: ["tag:db"], ip: ["tcp:5432"] },
          {
            src: ["group:eng"],
            dst: ["tag:k8s-operator"],
            app: {
              "tailscale.com/cap/kubernetes": [
                { impersonate: { groups: ["system:masters"] } },
              ],
            },
          },
          {
            src: ["alice@acme.com"],
            dst: ["tag:db", "100.64.0.6"],
            ip: ["tcp:5432", "tcp:5433"],
          },
          {
            src: ["alice@acme.com"],
            dst: ["fd7a:115c:a1e0::6"],
            ip: ["tcp:22"],
          },
        ],
        ssh: [],
      },
    });
    await expect(
      check({ type: "posture", target: "posture:p0_legacy" })
    ).resolves.toMatchObject({
      unlocks: {
        grants: [
          {
            src: ["autogroup:member"],
            dst: ["autogroup:internet"],
            ip: ["*"],
            via: ["tag:exit"],
          },
        ],
        ssh: [],
      },
    });
  });

  it("answers the SSH rules a posture unlocks, with their users", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        ssh: [
          {
            action: "accept",
            src: ["group:eng"],
            dst: ["tag:prod"],
            users: ["root"],
            srcPosture: ["posture:p0_db"],
          },
          {
            Action: "check",
            Src: ["autogroup:member"],
            Dst: ["autogroup:self"],
            Users: ["autogroup:nonroot"],
            SrcPosture: ["posture:p0_db"],
          },
          {
            action: "accept",
            src: ["group:eng"],
            dst: ["tag:db"],
            users: ["postgres"],
            srcPosture: ["posture:p0_legacy"],
          },
        ],
      }),
    });
    await expect(
      check({ type: "posture", target: "posture:p0_db" })
    ).resolves.toMatchObject({
      unlocks: {
        grants: [],
        ssh: [
          {
            src: ["group:eng"],
            dst: ["tag:prod"],
            users: ["root"],
            action: "accept",
          },
          {
            src: ["autogroup:member"],
            dst: ["autogroup:self"],
            users: ["autogroup:nonroot"],
            action: "check",
          },
        ],
      },
    });
  });

  // Tailscale reads a `null` or empty `srcPosture` as none, so the default applies.
  it("answers the entries without their own posture when the file's default names it", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        defaultSrcPosture: ["posture:p0_db"],
        grants: [
          { src: ["group:eng"], dst: ["tag:db"], ip: ["*"] },
          {
            src: ["autogroup:member"],
            dst: ["tag:prod"],
            ip: ["*"],
            srcPosture: null,
          },
          {
            src: ["group:eng"],
            dst: ["tag:exit"],
            ip: ["*"],
            srcPosture: ["posture:p0_legacy"],
          },
          {
            src: ["group:eng"],
            dst: ["tag:router"],
            ip: ["tcp:22"],
            srcPosture: ["posture:p0_db"],
          },
        ],
        acls: [{ action: "accept", src: ["*"], dst: ["tag:db:5432"] }],
        ssh: [
          {
            action: "accept",
            src: ["group:eng"],
            dst: ["tag:prod"],
            users: ["root"],
          },
          {
            action: "accept",
            src: ["group:eng"],
            dst: ["tag:db"],
            users: ["root"],
            srcPosture: [],
          },
        ],
      }),
    });
    await expect(
      check({ type: "posture", target: "posture:p0_db" })
    ).resolves.toMatchObject({
      unlocks: {
        grants: [
          {
            src: ["group:eng"],
            dst: ["tag:db"],
            ip: ["*"],
            fromDefault: true,
          },
          {
            src: ["autogroup:member"],
            dst: ["tag:prod"],
            ip: ["*"],
            fromDefault: true,
          },
          { src: ["group:eng"], dst: ["tag:router"], ip: ["tcp:22"] },
          {
            src: ["*"],
            dst: ["tag:db"],
            ip: ["5432"],
            fromDefault: true,
          },
        ],
        ssh: [
          {
            src: ["group:eng"],
            dst: ["tag:prod"],
            users: ["root"],
            fromDefault: true,
          },
          {
            src: ["group:eng"],
            dst: ["tag:db"],
            users: ["root"],
            fromDefault: true,
          },
        ],
      },
    });
    const legacy = await check({
      type: "posture",
      target: "posture:p0_legacy",
    });
    expect(legacy.kind === "posture" && legacy.unlocks).toEqual({
      grants: [
        {
          src: ["group:eng"],
          dst: ["tag:exit"],
          ip: ["*"],
          posture: "posture:p0_legacy",
        },
      ],
      ssh: [],
    });
  });

  it("answers the entries other postures reading the attribute gate, with the posture that gates each", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        postures: {
          ...BASE_POLICY.postures,
          "posture:breakglass": ["custom:p0_db == true", "node:os == 'linux'"],
          "posture:db2": ["custom:p0_db2 == true"],
          "posture:oncall": { Assertions: ["custom:p0_db == true"] },
        },
        defaultSrcPosture: ["posture:breakglass"],
        grants: [
          {
            src: ["group:eng"],
            dst: ["tag:db"],
            ip: ["tcp:5432"],
            srcPosture: ["posture:p0_db"],
          },
          { src: ["group:ops"], dst: ["tag:router"], ip: ["*"] },
          {
            src: ["group:eng"],
            dst: ["tag:exit"],
            ip: ["*"],
            srcPosture: ["posture:db2"],
          },
          {
            src: ["group:eng"],
            dst: ["tag:web"],
            ip: ["tcp:443"],
            srcPosture: ["posture:breakglass", "posture:p0_db"],
          },
        ],
        ssh: [
          {
            action: "accept",
            src: ["autogroup:member"],
            dst: ["tag:prod"],
            users: ["root"],
            srcPosture: ["posture:breakglass"],
          },
          {
            action: "accept",
            src: ["autogroup:member"],
            dst: ["tag:db"],
            users: ["postgres"],
            srcPosture: ["posture:oncall"],
          },
        ],
      }),
    });
    const answer = await check({ type: "posture", target: "posture:p0_db" });
    expect(answer.kind === "posture" && answer.unlocks).toEqual({
      grants: [
        {
          src: ["group:eng"],
          dst: ["tag:db"],
          ip: ["tcp:5432"],
          posture: "posture:p0_db",
        },
        {
          src: ["group:ops"],
          dst: ["tag:router"],
          ip: ["*"],
          posture: "posture:breakglass",
          fromDefault: true,
        },
        {
          src: ["group:eng"],
          dst: ["tag:web"],
          ip: ["tcp:443"],
          posture: "posture:p0_db",
        },
      ],
      ssh: [
        {
          src: ["autogroup:member"],
          dst: ["tag:prod"],
          users: ["root"],
          action: "accept",
          posture: "posture:breakglass",
        },
        {
          src: ["autogroup:member"],
          dst: ["tag:db"],
          users: ["postgres"],
          action: "accept",
          posture: "posture:oncall",
        },
      ],
    });
  });

  // `users` and `ports` are the legacy names of `src` and `dst` in `acls`.
  it("answers a legacy ACL written with users and ports", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        acls: [
          {
            action: "accept",
            users: ["autogroup:member"],
            ports: ["*:*"],
            srcPosture: ["posture:p0_db"],
          },
          {
            Action: "accept",
            Users: ["group:eng"],
            Ports: ["tag:db:5432"],
            SrcPosture: ["posture:p0_db"],
          },
        ],
      }),
    });
    const answer = await check({ type: "posture", target: "posture:p0_db" });
    expect(answer.kind === "posture" && answer.unlocks).toEqual({
      grants: [
        {
          src: ["autogroup:member"],
          dst: ["*"],
          ip: ["*"],
          posture: "posture:p0_db",
        },
        {
          src: ["group:eng"],
          dst: ["tag:db"],
          ip: ["5432"],
          posture: "posture:p0_db",
        },
      ],
      ssh: [],
    });
  });

  // A device passing any one posture of the list reaches the entry.
  it("marks an entry another posture in its list opens without P0", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        postures: {
          ...BASE_POLICY.postures,
          "posture:linux": ["node:os == 'linux'"],
        },
        defaultSrcPosture: ["posture:p0_db", "posture:latest"],
        grants: [
          {
            src: ["group:eng"],
            dst: ["tag:db"],
            ip: ["tcp:5432"],
            srcPosture: ["posture:p0_db", "posture:linux"],
          },
          { src: ["group:ops"], dst: ["tag:router"], ip: ["*"] },
        ],
        ssh: [
          {
            action: "accept",
            src: ["group:eng"],
            dst: ["tag:prod"],
            users: ["root"],
            srcPosture: ["posture:linux", "posture:p0_db", "posture:latest"],
          },
        ],
      }),
    });
    const answer = await check({ type: "posture", target: "posture:p0_db" });
    expect(answer.kind === "posture" && answer.unlocks).toEqual({
      grants: [
        {
          src: ["group:eng"],
          dst: ["tag:db"],
          ip: ["tcp:5432"],
          posture: "posture:p0_db",
          alsoOpenedBy: ["posture:linux"],
        },
        {
          src: ["group:ops"],
          dst: ["tag:router"],
          ip: ["*"],
          posture: "posture:p0_db",
          fromDefault: true,
          alsoOpenedBy: ["posture:latest"],
        },
      ],
      ssh: [
        {
          src: ["group:eng"],
          dst: ["tag:prod"],
          users: ["root"],
          action: "accept",
          posture: "posture:p0_db",
          alsoOpenedBy: ["posture:linux", "posture:latest"],
        },
      ],
    });
  });

  it("refuses a posture that doesn't check P0's attribute is true", async () => {
    newTestTailnet({
      scopes: REQUIRED_SCOPES,
      policy: JSON.stringify({
        ...BASE_POLICY,
        postures: {
          "posture:p0_db": ["node:os == 'linux'"],
          "posture:p0_web": ["custom:p0_web == true || node:os == 'linux'"],
          "posture:p0_api": {
            assertions: ["node:os == 'linux'", "custom:p0_api==true"],
          },
        },
      }),
    });
    await expect(
      connectorError(() => check({ type: "posture", target: "posture:p0_db" }))
    ).resolves.toMatchObject({
      type: "validation_error",
      message:
        "Posture posture:p0_db doesn't check custom:p0_db == true, so a device can pass it without P0. Add the assertion custom:p0_db == true to posture:p0_db in tailnet T1234CNTRL's policy file.",
    });
    await expect(
      connectorError(() => check({ type: "posture", target: "posture:p0_web" }))
    ).resolves.toMatchObject({ type: "validation_error" });
    await expect(
      check({ type: "posture", target: "posture:p0_api" })
    ).resolves.toMatchObject({ kind: "posture", attribute: "custom:p0_api" });
  });

  it("refuses a destination that doesn't parse", async () => {
    newTestTailnet();
    expect(
      await thrown(() => check({ type: "posture", target: "posture:db" }))
    ).toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(
      await thrown(() => check({ type: "tag", target: "tag:db" }))
    ).toMatchObject({ code: "BAD_REQUEST" });
  });

  it("refuses posture:p0_install_check, which install validation sets", async () => {
    const tailnet = newTestTailnet();
    const error = await thrown(() =>
      check({ type: "posture", target: "posture:p0_install_check" })
    );
    expect(error).toMatchObject({
      code: "BAD_REQUEST",
      message: expect.stringContaining(
        "must not be posture:p0_install_check, which P0's install check sets"
      ),
    });
    expect(tailnet.apiCalls()).toEqual([]);
  });

  it("writes nothing", async () => {
    const tailnet = newTestTailnet();
    await check({ type: "posture", target: "posture:p0_db" });
    expect(tailnet.writes()).toEqual([]);
  });
});

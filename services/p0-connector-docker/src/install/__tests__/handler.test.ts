import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeDockerHub,
  type HubReply,
  failing,
  isCall,
  newFakeDockerHub,
} from "../../__tests__/fake-docker-hub.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  TOKEN,
} from "../../__tests__/fixtures.ts";
import { newRecordingLogger } from "../../__tests__/helpers.ts";
import { DockerHubError } from "../../dockerhub/api.ts";
import { newDockerHubClient } from "../../dockerhub/client.ts";
import { getInstallValidation } from "../handler.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const getOrgAccessToken = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ getOrgAccessToken }));

// Read when the pattern is first asked for, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

const MEMBERS = "/v2/orgs/acme/members";
const BULK_INVITE = "/v2/invites/bulk";
const TOKEN_EXCHANGE = "/v2/auth/token";

const PASSING = {
  tokenAccepted: true,
  canReadMembers: true,
  canInvite: true,
  allowedDomains: ALLOWED_PATTERN,
};

let hub: FakeDockerHub;
let versions = 0;

const validate = () =>
  getInstallValidation(
    newDockerHubClient({ ...CREDENTIALS, log: newRecordingLogger().log })
  );

/** Docker Hub answering one endpoint some other way. */
const answering = (method: string, path: string, reply: HubReply) =>
  hub.intercept((call) => (isCall(method, path)(call) ? reply : undefined));

beforeEach(() => {
  hub = newFakeDockerHub({ org: "acme", token: TOKEN });
  vi.stubGlobal("fetch", hub.fetch);
  getOrgAccessToken.mockReset();
  getOrgAccessToken.mockResolvedValue({
    token: TOKEN,
    version: `version-${++versions}`,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getInstallValidation", () => {
  it("passes a token that can read members and invite, and reports the pattern", async () => {
    await expect(validate()).resolves.toEqual(PASSING);
    expect(
      hub.apiCalls().map(({ method, path }) => `${method} ${path}`)
    ).toEqual([`GET ${MEMBERS}`, `POST ${BULK_INVITE}`]);
  });

  it("changes nothing in the org, however often it runs", async () => {
    await validate();
    await expect(validate()).resolves.toEqual(PASSING);

    expect(hub.members).toEqual([]);
    expect(hub.invites).toEqual([]);
  });

  describe("the token", () => {
    it.each([400, 401, 403])(
      "fails every check when Docker Hub refuses the exchange with a %s, without asking further",
      async (status) => {
        answering("POST", TOKEN_EXCHANGE, failing(status, "no"));

        await expect(validate()).resolves.toEqual({
          tokenAccepted: false,
          canReadMembers: false,
          canInvite: false,
          allowedDomains: ALLOWED_PATTERN,
        });
        expect(hub.apiCalls()).toEqual([]);
      }
    );

    // Says nothing about the token, so P0 tries again.
    it.each([429, 500])(
      "fails the call when the exchange answers %s",
      async (status) => {
        answering("POST", TOKEN_EXCHANGE, failing(status));

        const error = await validate().catch((e: unknown) => e);

        expect(error).toBeInstanceOf(DockerHubError);
        expect(error).toMatchObject({ status });
      }
    );

    it("fails the call when the secret can't be read", async () => {
      const error = new ConnectorError({
        type: "object_not_found",
        message: "no such secret",
        payload: { query: "docker-oat" },
      });
      getOrgAccessToken.mockRejectedValue(error);

      await expect(validate()).rejects.toBe(error);
      expect(hub.calls).toEqual([]);
    });
  });

  // Each check fails on its own, and only on a 401 or a 403: what a token
  // without the scope looks like.
  describe.each([
    ["reading members", "GET", MEMBERS, "canReadMembers"],
    ["inviting", "POST", BULK_INVITE, "canInvite"],
  ] as const)("%s", (_check, method, path, check) => {
    it.each([401, 403])(
      "fails alone on a %s, and the other check still runs",
      async (status) => {
        answering(method, path, failing(status, "permission denied"));

        await expect(validate()).resolves.toEqual({
          ...PASSING,
          [check]: false,
        });
        expect(hub.apiCalls().map((call) => call.path)).toEqual(
          expect.arrayContaining([MEMBERS, BULK_INVITE])
        );
      }
    );

    // Not about the token's scopes, so not a check that failed.
    it.each([400, 404, 409, 429, 500])(
      "fails the call on a %s",
      async (status) => {
        answering(method, path, failing(status, "no"));

        await expect(validate()).rejects.toMatchObject({ status });
      }
    );

    it("fails the call when Docker Hub can't be reached", async () => {
      answering(method, path, { throws: new TypeError("fetch failed") });

      await expect(validate()).rejects.toMatchObject({ status: undefined });
    });
  });

  it("reports both checks failing, each on its own", async () => {
    hub.intercept((call) =>
      call.path === TOKEN_EXCHANGE ? undefined : failing(403, "no")
    );

    await expect(validate()).resolves.toEqual({
      ...PASSING,
      canReadMembers: false,
      canInvite: false,
    });
  });

  it("asks for one member", async () => {
    await validate();

    expect(hub.apiCalls()[0]?.query).toEqual({ page: "1", page_size: "1" });
  });

  describe("the invite", () => {
    // An address no one holds, and one the allowed domains don't have to
    // match: there's no person here for the pattern to gate.
    it("is a dry run to an address outside the allowed domains, with the least role", async () => {
      await validate();

      expect(hub.writes()).toEqual([
        {
          method: "POST",
          path: BULK_INVITE,
          body: {
            org: "acme",
            role: "member",
            invitees: ["p0-install-check@example.com"],
            dry_run: true,
          },
        },
      ]);
      // Nothing was sent, and no seat was used.
      expect(hub.invites).toEqual([]);
    });

    // The invitee's status is about the address or the org's seats, not the
    // token.
    it.each([
      ["a 200 with no body", { status: 200 }],
      [
        "a refused invitee",
        {
          status: 202,
          body: {
            invitees: [{ status: "invalid_email_or_docker_id" }],
          },
        },
      ],
    ])("passes on %s", async (_case, reply) => {
      answering("POST", BULK_INVITE, reply);

      await expect(validate()).resolves.toEqual(PASSING);
    });
  });
});

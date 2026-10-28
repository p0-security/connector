import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  HARBOR_HOST,
  ID_TOKEN,
  connectorError,
  propertySeed,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import { type HarborCall, HarborError, type HarborFailure } from "../api.ts";
import { HARBOR_CALLS } from "../client.ts";
import {
  callHarbor,
  notHarborAdmin,
  toConnectorError,
  tokenRejected,
} from "../errors.ts";

const LIST_MEMBERS = HARBOR_CALLS.listMembers;

const mapped = (failure: HarborFailure, call: HarborCall = LIST_MEMBERS) =>
  connectorError(() =>
    callHarbor(async () => {
      throw new HarborError(call, failure);
    }, HARBOR_HOST)
  );

const TOKEN_REJECTED = `Harbor at ${HARBOR_HOST} didn't accept the ID token the connector minted for its admin account. Check that the admin credential's clientId is Harbor's OIDC client ID, that the admin account has signed in to Harbor once, and that Harbor signs users in with OIDC.`;

const NOT_ADMIN = `The admin account the connector signs in to Harbor at ${HARBOR_HOST} with isn't a Harbor system administrator. Make it one on Harbor's Users page.`;

const NOT_HARBOR = (status?: number) =>
  `${HARBOR_HOST} didn't answer GET /api/v2.0/projects/{project_name}/members the way Harbor does${status === undefined ? "" : `: it answered ${status}`}. Check that the instance's URL points at Harbor.`;

describe("toConnectorError", () => {
  it.each<[string, HarborFailure, HarborCall, ConnectorError["data"]]>([
    [
      "a 401 is the token-rejected refusal, whatever the call",
      { kind: "status", status: 401 },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: TOKEN_REJECTED,
        payload: {
          host: HARBOR_HOST,
          status: 401,
          reason: "admin_token_rejected",
        },
      },
    ],
    [
      "a 403 is the not-an-administrator refusal, whatever the call",
      { kind: "status", status: 403 },
      HARBOR_CALLS.listUsers,
      {
        type: "validation_error",
        message: NOT_ADMIN,
        payload: {
          host: HARBOR_HOST,
          status: 403,
          reason: "admin_not_harbor_admin",
        },
      },
    ],
    [
      "a project that doesn't exist is named, with a reason a revoke can recognise",
      { kind: "project_gone", project: "team" },
      HARBOR_CALLS.removeMember,
      {
        type: "validation_error",
        message: `Project team no longer exists on ${HARBOR_HOST}.`,
        payload: {
          host: HARBOR_HOST,
          project: "team",
          reason: "project_gone",
        },
      },
    ],
    [
      "a 409 is something there already",
      { kind: "status", status: 409 },
      HARBOR_CALLS.addMember,
      {
        type: "already_exists",
        message: `Harbor at ${HARBOR_HOST} answered POST /api/v2.0/projects/{project_name}/members with 409: what the call would add is there already.`,
        payload: { host: HARBOR_HOST, status: 409 },
      },
    ],
    [
      "a 429 is a limit",
      { kind: "status", status: 429 },
      LIST_MEMBERS,
      {
        type: "rate_limited",
        message: `${HARBOR_HOST} is limiting the connector's calls: it answered GET /api/v2.0/projects/{project_name}/members with 429. Try again later.`,
        payload: { host: HARBOR_HOST, status: 429 },
      },
    ],
    [
      "a 5xx is Harbor not answering",
      { kind: "status", status: 502 },
      LIST_MEMBERS,
      {
        type: "upstream_unavailable",
        message: `${HARBOR_HOST} answered GET /api/v2.0/projects/{project_name}/members with 502. Check that Harbor is running, and try again.`,
        payload: { host: HARBOR_HOST, status: 502 },
      },
    ],
    [
      "a 400 is Harbor refusing the call",
      { kind: "status", status: 400 },
      HARBOR_CALLS.addMember,
      {
        type: "validation_error",
        message: `Harbor at ${HARBOR_HOST} refused POST /api/v2.0/projects/{project_name}/members with 400.`,
        payload: { host: HARBOR_HOST, status: 400 },
      },
    ],
    [
      "a 404 is something other than Harbor",
      { kind: "status", status: 404 },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: NOT_HARBOR(404),
        payload: { host: HARBOR_HOST, status: 404 },
      },
    ],
    [
      "a redirect is something other than Harbor",
      { kind: "status", status: 302 },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: NOT_HARBOR(302),
        payload: { host: HARBOR_HOST, status: 302 },
      },
    ],
    [
      "a status Harbor never sends is something other than Harbor",
      { kind: "status", status: 418 },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: NOT_HARBOR(418),
        payload: { host: HARBOR_HOST, status: 418 },
      },
    ],
    [
      "an answer Harbor wouldn't give is something other than Harbor",
      { kind: "unexpected", reason: "wrong_shape" },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: NOT_HARBOR(),
        payload: { host: HARBOR_HOST },
      },
    ],
    [
      "a host that doesn't resolve is the customer's to fix",
      { kind: "unreachable", timedOut: false, code: "ENOTFOUND" },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: `${HARBOR_HOST} doesn't resolve from the connector. Check the instance's URL, and that the connector's network can resolve its host.`,
        payload: { host: HARBOR_HOST, code: "ENOTFOUND" },
      },
    ],
    [
      "a certificate Node doesn't trust is the customer's to fix",
      { kind: "unreachable", timedOut: false, code: "CERT_HAS_EXPIRED" },
      LIST_MEMBERS,
      {
        type: "validation_error",
        message: `The connector doesn't trust the certificate ${HARBOR_HOST} presents (CERT_HAS_EXPIRED). The certificate has to be valid for that host and chain to a public CA.`,
        payload: { host: HARBOR_HOST, code: "CERT_HAS_EXPIRED" },
      },
    ],
    [
      "no answer in time is worth trying again",
      { kind: "unreachable", timedOut: true, name: "TimeoutError" },
      LIST_MEMBERS,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Harbor at ${HARBOR_HOST}: no answer within 10 seconds. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: HARBOR_HOST },
      },
    ],
    [
      "a refused connection is worth trying again",
      { kind: "unreachable", timedOut: false, code: "ECONNREFUSED" },
      LIST_MEMBERS,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Harbor at ${HARBOR_HOST}: ECONNREFUSED. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: HARBOR_HOST },
      },
    ],
    [
      "a failure that says nothing about itself is worth trying again",
      { kind: "unreachable", timedOut: false },
      LIST_MEMBERS,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Harbor at ${HARBOR_HOST}: the request failed. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: HARBOR_HOST },
      },
    ],
  ])("%s", async (_case, failure, call, data) => {
    const error = await mapped(failure, call);

    expect(error.data).toEqual(data);
  });

  // How Node says it doesn't trust the certificate a host presented.
  it.each([
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "SELF_SIGNED_CERT_IN_CHAIN",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "CERT_HAS_EXPIRED",
    "ERR_TLS_CERT_ALTNAME_INVALID",
  ])("says the certificate isn't trusted on %s", async (code) => {
    const error = await mapped({ kind: "unreachable", timedOut: false, code });

    expect(error.data).toEqual({
      type: "validation_error",
      message: `The connector doesn't trust the certificate ${HARBOR_HOST} presents (${code}). The certificate has to be valid for that host and chain to a public CA.`,
      payload: { host: HARBOR_HOST, code },
    });
  });

  it("passes a ConnectorError as it is", () => {
    const error = new ConnectorError({
      type: "object_not_found",
      message: "no secret",
      payload: {},
    });

    expect(toConnectorError(error, HARBOR_HOST)).toBe(error);
  });

  // A bug stays a bug.
  it("passes any other error as it is", () => {
    const error = new TypeError("x is undefined");

    expect(toConnectorError(error, HARBOR_HOST)).toBe(error);
  });

  it("returns what the calls return when they succeed", async () => {
    await expect(callHarbor(async () => 7, HARBOR_HOST)).resolves.toBe(7);
  });

  // Any failure maps to a typed error whose payload P0 can carry, and whose
  // message says nothing a requestor shouldn't read.
  const seed = propertySeed();
  it(
    `maps any failure to a ConnectorError P0 can carry (PROPERTY_SEED=${seed})`,
    // Thousands of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const pick = <T>(values: readonly T[]): T =>
        values[Math.floor(random() * values.length)] as T;
      const calls: HarborCall[] = Object.values(HARBOR_CALLS);
      const failures: (() => HarborFailure)[] = [
        () => ({ kind: "status", status: 100 + Math.floor(random() * 500) }),
        () => ({
          kind: "unreachable",
          timedOut: random() < 0.3,
          ...(random() < 0.7
            ? {
                code: pick([
                  "ENOTFOUND",
                  "ECONNRESET",
                  "CERT_HAS_EXPIRED",
                  "UND_ERR_SOCKET",
                  23,
                ]),
              }
            : {}),
          ...(random() < 0.5
            ? { name: pick(["TimeoutError", "AbortError"]) }
            : {}),
        }),
        () => ({
          kind: "project_gone",
          project: pick(["team", "007", "a.b"]),
        }),
        () => ({
          kind: "unexpected",
          reason: pick([
            "endless",
            "not_json",
            "too_large",
            "too_many_rows",
            "wrong_shape",
          ] as const),
        }),
      ];

      for (let i = 0; i < 2000; i++) {
        const call = pick(calls);
        const failure = pick(failures)();

        const error = await mapped(failure, call);

        expect(error.data.message).toContain(HARBOR_HOST);
        expect(error.data.message).not.toContain(ID_TOKEN);
        expect(error.data.payload.host).toBe(HARBOR_HOST);
        for (const value of Object.values(error.data.payload)) {
          expect(["string", "number", "boolean"]).toContain(typeof value);
        }
        expect(
          Object.keys(error.data.payload).every((key) =>
            ["host", "status", "code", "project", "reason"].includes(key)
          )
        ).toBe(true);
        if (failure.kind === "status" && failure.status === 401) {
          expect(error.data.message).toBe(TOKEN_REJECTED);
          expect(error.data.payload.reason).toBe("admin_token_rejected");
        }
        if (failure.kind === "status" && failure.status === 403) {
          expect(error.data.message).toBe(NOT_ADMIN);
          expect(error.data.payload.reason).toBe("admin_not_harbor_admin");
        }
        if (failure.kind === "status" && failure.status >= 500) {
          expect(error.data.type).toBe("upstream_unavailable");
        }
        expect(error.cause).toBeUndefined();
      }
    }
  );
});

describe("the admin refusals install validation raises without a status", () => {
  it.each([
    ["tokenRejected", tokenRejected, "admin_token_rejected"],
    ["notHarborAdmin", notHarborAdmin, "admin_not_harbor_admin"],
  ] as const)("%s carries no status", (_, refuse, reason) => {
    expect(refuse(HARBOR_HOST).data.payload).toStrictEqual({
      reason,
      host: HARBOR_HOST,
    });
  });
});

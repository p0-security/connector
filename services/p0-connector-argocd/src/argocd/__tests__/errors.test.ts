// copy of services/p0-connector-harbor/src/harbor/__tests__/errors.test.ts,
// for Argo CD's statuses and failures
import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  ARGOCD_HOST,
  TOKEN,
  connectorError,
  propertySeed,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import { type ArgoCdCall, ArgoCdError, type ArgoCdFailure } from "../api.ts";
import { ARGOCD_CALLS } from "../client.ts";
import { callArgoCd, toConnectorError } from "../errors.ts";

const GET_APP = ARGOCD_CALLS.getApplication;

const mapped = (failure: ArgoCdFailure, call: ArgoCdCall = GET_APP) =>
  connectorError(() =>
    callArgoCd(async () => {
      throw new ArgoCdError(call, failure);
    }, ARGOCD_HOST)
  );

const TOKEN_REJECTED = `Argo CD at ${ARGOCD_HOST} didn't accept the connector's API token. Check that the secret holds a current API token of the p0-connector account, and that the account is enabled and has the apiKey capability.`;

const NOT_ARGOCD = (status?: number) =>
  `${ARGOCD_HOST} didn't answer GET /api/v1/applications/{name} the way Argo CD does${status === undefined ? "" : `: it answered ${status}`}. Check that the instance's URL points at Argo CD.`;

describe("toConnectorError", () => {
  it.each<[string, ArgoCdFailure, ArgoCdCall, ConnectorError["data"]]>([
    [
      "a 401 is the one token message",
      { kind: "status", status: 401 },
      GET_APP,
      {
        type: "insufficient_privileges",
        message: TOKEN_REJECTED,
        payload: { host: ARGOCD_HOST, status: 401 },
      },
    ],
    [
      "an anonymous answer is the one token message",
      { kind: "anonymous" },
      ARGOCD_CALLS.userInfo,
      {
        type: "insufficient_privileges",
        message: TOKEN_REJECTED,
        payload: { host: ARGOCD_HOST },
      },
    ],
    [
      "a 403 on an Application's route doesn't take it for a missing permission",
      { kind: "status", status: 403 },
      GET_APP,
      {
        type: "insufficient_privileges",
        message: `Argo CD at ${ARGOCD_HOST} refused the connector's call to GET /api/v1/applications/{name}. Either the p0-connector account doesn't have "applications, get" on the managing Application, or that Application doesn't exist: Argo CD answers both the same way. Check the managing Application on the Argo CD instance in P0, and the account's policy lines in argocd-rbac-cm.`,
        payload: {
          host: ARGOCD_HOST,
          status: 403,
          permission: "applications, get",
        },
      },
    ],
    [
      "a 403 on the patch names the fine-grained update",
      { kind: "status", status: 403 },
      ARGOCD_CALLS.patchResource,
      {
        type: "insufficient_privileges",
        message: `Argo CD at ${ARGOCD_HOST} refused the connector's call to POST /api/v1/applications/{name}/resource. Either the p0-connector account doesn't have "applications, update//ConfigMap/<namespace>/argocd-rbac-cm" on the managing Application, or that Application doesn't exist: Argo CD answers both the same way. Check the managing Application on the Argo CD instance in P0, and the account's policy lines in argocd-rbac-cm.`,
        payload: {
          host: ARGOCD_HOST,
          status: 403,
          permission:
            "applications, update//ConfigMap/<namespace>/argocd-rbac-cm",
        },
      },
    ],
    [
      "a 403 elsewhere names the permission",
      { kind: "status", status: 403 },
      ARGOCD_CALLS.listProjects,
      {
        type: "insufficient_privileges",
        message: `Argo CD at ${ARGOCD_HOST} refused the connector's call to GET /api/v1/projects. The p0-connector account needs "projects, get" in argocd-rbac-cm.`,
        payload: {
          host: ARGOCD_HOST,
          status: 403,
          permission: "projects, get",
        },
      },
    ],
    [
      "a 403 on a call that needs no permission names the call",
      { kind: "status", status: 403 },
      ARGOCD_CALLS.canI,
      {
        type: "insufficient_privileges",
        message: `Argo CD at ${ARGOCD_HOST} refused the connector's call to GET /api/v1/account/can-i/{resource}/{action}/{subresource}.`,
        payload: { host: ARGOCD_HOST, status: 403 },
      },
    ],
    [
      "an Application that doesn't manage argocd-rbac-cm is named",
      { kind: "not_managed", app: "argocd", namespace: "gitops" },
      ARGOCD_CALLS.getResource,
      {
        type: "validation_error",
        message: `Application argocd on ${ARGOCD_HOST} doesn't manage ConfigMap gitops/argocd-rbac-cm. Check the managing Application and the namespace on the Argo CD instance in P0: the Application has to be the one that deploys argocd-rbac-cm.`,
        payload: { host: ARGOCD_HOST, app: "argocd", namespace: "gitops" },
      },
    ],
    [
      "a 404 is a wrong URL or a wrong name",
      { kind: "status", status: 404 },
      GET_APP,
      {
        type: "validation_error",
        message: `${ARGOCD_HOST} answered GET /api/v1/applications/{name} with 404. Check that the instance's URL points at Argo CD, served at its root, and the managing Application's name on the instance in P0.`,
        payload: { host: ARGOCD_HOST, status: 404 },
      },
    ],
    [
      "a 429 is a limit",
      { kind: "status", status: 429 },
      GET_APP,
      {
        type: "rate_limited",
        message: `${ARGOCD_HOST} is limiting the connector's calls: it answered GET /api/v1/applications/{name} with 429. Try again later.`,
        payload: { host: ARGOCD_HOST, status: 429 },
      },
    ],
    [
      "a 5xx is Argo CD not answering",
      { kind: "status", status: 502 },
      GET_APP,
      {
        type: "upstream_unavailable",
        message: `${ARGOCD_HOST} answered GET /api/v1/applications/{name} with 502. Check that Argo CD is running, and try again.`,
        payload: { host: ARGOCD_HOST, status: 502 },
      },
    ],
    [
      "a 500 is Argo CD not answering",
      { kind: "status", status: 500 },
      GET_APP,
      {
        type: "upstream_unavailable",
        message: `${ARGOCD_HOST} answered GET /api/v1/applications/{name} with 500. Check that Argo CD is running, and try again.`,
        payload: { host: ARGOCD_HOST, status: 500 },
      },
    ],
    [
      "a 400 is Argo CD refusing the call",
      { kind: "status", status: 400 },
      ARGOCD_CALLS.patchResource,
      {
        type: "validation_error",
        message: `Argo CD at ${ARGOCD_HOST} refused POST /api/v1/applications/{name}/resource with 400.`,
        payload: { host: ARGOCD_HOST, status: 400 },
      },
    ],
    [
      "a 409 is Argo CD refusing the call",
      { kind: "status", status: 409 },
      ARGOCD_CALLS.patchResource,
      {
        type: "validation_error",
        message: `Argo CD at ${ARGOCD_HOST} refused POST /api/v1/applications/{name}/resource with 409.`,
        payload: { host: ARGOCD_HOST, status: 409 },
      },
    ],
    [
      "a redirect is something other than Argo CD",
      { kind: "status", status: 302 },
      GET_APP,
      {
        type: "validation_error",
        message: NOT_ARGOCD(302),
        payload: { host: ARGOCD_HOST, status: 302 },
      },
    ],
    [
      "a status Argo CD never sends is something other than Argo CD",
      { kind: "status", status: 418 },
      GET_APP,
      {
        type: "validation_error",
        message: NOT_ARGOCD(418),
        payload: { host: ARGOCD_HOST, status: 418 },
      },
    ],
    [
      "an answer Argo CD wouldn't give is something other than Argo CD",
      { kind: "unexpected", reason: "wrong_shape" },
      GET_APP,
      {
        type: "validation_error",
        message: NOT_ARGOCD(),
        payload: { host: ARGOCD_HOST },
      },
    ],
    [
      "a host that doesn't resolve is the customer's to fix",
      { kind: "unreachable", timedOut: false, code: "ENOTFOUND" },
      GET_APP,
      {
        type: "validation_error",
        message: `${ARGOCD_HOST} doesn't resolve from the connector. Check the instance's URL, and that the connector's network can resolve its host.`,
        payload: { host: ARGOCD_HOST, code: "ENOTFOUND" },
      },
    ],
    [
      "no answer in time is worth trying again",
      { kind: "unreachable", timedOut: true, name: "TimeoutError" },
      GET_APP,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Argo CD at ${ARGOCD_HOST}: no answer within 10 seconds. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: ARGOCD_HOST },
      },
    ],
    [
      "a refused connection is worth trying again",
      { kind: "unreachable", timedOut: false, code: "ECONNREFUSED" },
      GET_APP,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Argo CD at ${ARGOCD_HOST}: ECONNREFUSED. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: ARGOCD_HOST },
      },
    ],
    [
      "a failure that says nothing about itself is worth trying again",
      { kind: "unreachable", timedOut: false },
      GET_APP,
      {
        type: "upstream_unavailable",
        message: `The connector couldn't reach Argo CD at ${ARGOCD_HOST}: the request failed. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { host: ARGOCD_HOST },
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
      message: `The connector doesn't trust the certificate ${ARGOCD_HOST} presents (${code}). The certificate has to be valid for that host and chain to a public CA.`,
      payload: { host: ARGOCD_HOST, code },
    });
  });

  // A payload P0 carries holds no undefined value.
  it("leaves the permission out of a 403's payload when the call has none", async () => {
    const error = await mapped(
      { kind: "status", status: 403 },
      ARGOCD_CALLS.canI
    );

    expect(Object.keys(error.data.payload)).toEqual(["host", "status"]);
  });

  it("passes a ConnectorError as it is", () => {
    const error = new ConnectorError({
      type: "object_not_found",
      message: "no secret",
      payload: {},
    });

    expect(toConnectorError(error, ARGOCD_HOST)).toBe(error);
  });

  // A bug stays a bug.
  it("passes any other error as it is", () => {
    const error = new TypeError("x is undefined");

    expect(toConnectorError(error, ARGOCD_HOST)).toBe(error);
  });

  it("returns what the calls return when they succeed", async () => {
    await expect(callArgoCd(async () => 7, ARGOCD_HOST)).resolves.toBe(7);
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
      const calls: ArgoCdCall[] = Object.values(ARGOCD_CALLS);
      const failures: (() => ArgoCdFailure)[] = [
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
        () => ({ kind: "anonymous" }),
        () => ({
          kind: "not_managed",
          app: pick(["argocd", "a.b"]),
          namespace: pick(["argocd", "gitops"]),
        }),
        () => ({
          kind: "unexpected",
          reason: pick(["not_json", "too_large", "wrong_shape"] as const),
        }),
      ];

      for (let i = 0; i < 2000; i++) {
        const call = pick(calls);
        const failure = pick(failures)();

        const error = await mapped(failure, call);

        expect(error.data.message).toContain(ARGOCD_HOST);
        expect(error.data.message).not.toContain(TOKEN);
        expect(error.data.payload.host).toBe(ARGOCD_HOST);
        for (const value of Object.values(error.data.payload)) {
          expect(["string", "number", "boolean"]).toContain(typeof value);
        }
        expect(
          Object.keys(error.data.payload).every((key) =>
            [
              "host",
              "status",
              "permission",
              "code",
              "app",
              "namespace",
            ].includes(key)
          )
        ).toBe(true);
        if (
          failure.kind === "anonymous" ||
          (failure.kind === "status" && failure.status === 401)
        ) {
          expect(error.data.message).toBe(TOKEN_REJECTED);
        }
        if (failure.kind === "status" && failure.status === 403) {
          expect(error.data.type).toBe("insufficient_privileges");
          expect(error.data.payload.permission).toBe(call.permission);
        }
        if (failure.kind === "status" && failure.status >= 500) {
          expect(error.data.type).toBe("upstream_unavailable");
        }
        expect(error.cause).toBeUndefined();
      }
    }
  );
});

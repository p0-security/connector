/** What the accesses' tests share. */
import type { Logger } from "@p0security/connector";
import { expect, vi } from "vitest";

import { INSTANCE, TOKEN } from "../../__tests__/fixtures.ts";
import {
  type FakeArgoCd,
  sentPatch,
} from "../../argocd/__tests__/fake-argocd.ts";
import { type ConnectArgoCd, argoCdClientFor } from "../../argocd/client.ts";
import { instance } from "../../instance.ts";

/** The allowlist the tests run with. */
export const PATTERN = "example\\.com";

/** {@link INSTANCE} as the router hands it on: the namespace filled in. */
export const PARSED_INSTANCE = instance.parse(INSTANCE);

/** The user body P0 sends alongside the email that names the user. */
export const userBodyOf = (email: string) => ({
  instanceId: "p0-argocd",
  email,
});

/** Connects with `token`, without the secret manager. */
export const connectWith = (token = TOKEN) =>
  vi.fn<ConnectArgoCd>(async ({ url }, log: Logger) =>
    argoCdClientFor({ url, token, logger: log })
  );

/** Each call the fake took, as its method and path, without the query. */
export const routes = (argocd: FakeArgoCd) =>
  argocd.fetch.mock.calls.map(
    ([url, init]) => `${init?.method ?? "GET"} ${new URL(url).pathname}`
  );

/** Each patch the fake took, as the object the patch string holds. */
export const patches = (argocd: FakeArgoCd) =>
  argocd.fetch.mock.calls
    .filter(([, init]) => init?.method === "POST")
    .map(([, init]) => sentPatch(init));

/** Each POST's raw HTTP body. */
export const postBodies = (argocd: FakeArgoCd) =>
  argocd.fetch.mock.calls
    .filter(([, init]) => init?.method === "POST")
    .map(([, init]) => (typeof init?.body === "string" ? init.body : ""));

/**
 * Makes the fake answer every patch with success without applying it, as an
 * Argo CD whose write didn't land would.
 */
export const dropPatches = (argocd: FakeArgoCd) => {
  const answer = argocd.fetch.getMockImplementation();
  if (!answer) throw new Error("the fake has no implementation");
  argocd.fetch.mockImplementation(async (url, init) =>
    init?.method === "POST"
      ? new Response(JSON.stringify({ manifest: "{}" }), { status: 200 })
      : await answer(url, init)
  );
};

/**
 * Checks the fake's calls phase by phase: the calls in a phase are made
 * together, so their order within it isn't fixed, but the phases' order is,
 * and nothing comes after the last.
 */
export const expectPhases = (argocd: FakeArgoCd, phases: string[][]) => {
  const all = routes(argocd);
  const taken: string[][] = [];
  let at = 0;
  for (const phase of phases) {
    taken.push(all.slice(at, at + phase.length).sort());
    at += phase.length;
  }
  if (at < all.length) taken.push(all.slice(at));
  expect(taken).toEqual(phases.map((phase) => [...phase].sort()));
};

export const USER_INFO = "GET /api/v1/session/userinfo";

/** The privilege self-check's calls. */
export const CAN_I = [
  "GET /api/v1/account/can-i/applications/sync/*/*",
  "GET /api/v1/account/can-i/applications/delete/*/*",
  "GET /api/v1/account/can-i/projects/update/*",
  "GET /api/v1/account/can-i/accounts/update/*",
  "GET /api/v1/account/can-i/clusters/update/*",
];

export const READ_RBAC = "GET /api/v1/applications/argocd/resource";
export const PATCH_RBAC = "POST /api/v1/applications/argocd/resource";
export const LIST_PROJECTS = "GET /api/v1/projects";

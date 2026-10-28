import { vi } from "vitest";

import { REQUIRED_SCOPES } from "../tailscale/scopes.ts";
import { type FakeTailscale, newFakeTailscale } from "./fake-tailscale.ts";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  EMAIL,
  FEDERATED_CLIENT_ID,
  TAILNET,
} from "./fixtures.ts";

/** The requestor's laptop: untagged, so its user is its owner. */
export const LAPTOP = "nLaptop1CNTRL";

/** Bob's laptop. */
export const BOBS_LAPTOP = "nBobLaptop1CNTRL";

/** A server tagged `tag:db`, registered by Alice. */
export const DB_SERVER = "nDb1CNTRL";

/** The policy file every test tailnet starts with, as JSON. */
export const BASE_POLICY = {
  groups: { "group:eng": ["bob@acme.com"] },
  tagOwners: {
    "tag:router": ["group:eng"],
    "tag:db": ["group:eng"],
  },
  grants: [{ src: ["group:eng"], dst: ["tag:db"], ip: ["*"] }],
  postures: {
    "posture:p0_db": { assertions: ["custom:p0_db == true"] },
    "posture:p0_legacy": ["custom:p0_legacy == true"],
    "posture:latest": ["node:tsVersion >= '1.60'"],
  },
};

/**
 * A tailnet with the requestor and Bob as members, their laptops, a tagged
 * server and a service, behind a stubbed `fetch`. Both credentials hold
 * `scopes`.
 */
export const newTestTailnet = ({
  scopes = REQUIRED_SCOPES,
  policy = JSON.stringify(BASE_POLICY, null, 2),
  refuseUnheldScopes,
}: {
  scopes?: readonly string[];
  policy?: string;
  refuseUnheldScopes?: boolean;
} = {}): FakeTailscale => {
  const fake = newFakeTailscale({
    tailnet: TAILNET,
    refuseUnheldScopes,
    clients: { [CLIENT_ID]: { secret: CLIENT_SECRET, scopes: [...scopes] } },
    identities: { [FEDERATED_CLIENT_ID]: { scopes: [...scopes] } },
  });
  fake.state.users.push(
    { id: "u1", loginName: EMAIL, role: "member" },
    { id: "u2", loginName: "bob@acme.com", role: "admin" }
  );
  fake.state.devices.push(
    {
      nodeId: LAPTOP,
      id: "1001",
      name: "alice-laptop.tail1234.ts.net",
      hostname: "alice-laptop",
      user: EMAIL,
      attributes: { "node:os": "macos", "custom:team": "eng" },
    },
    {
      nodeId: BOBS_LAPTOP,
      name: "bob-laptop.tail1234.ts.net",
      hostname: "bob-laptop",
      user: "bob@acme.com",
    },
    {
      nodeId: DB_SERVER,
      name: "db.tail1234.ts.net",
      hostname: "db",
      user: EMAIL,
      tags: ["tag:db"],
    }
  );
  fake.state.services.push({ name: "svc:postgres" });
  fake.state.policy = policy;
  vi.stubGlobal("fetch", fake.fetch);
  return fake;
};

/** Makes the token endpoint at `path` answer without its `scope`. */
const withoutScope = (tailnet: FakeTailscale, path: string) => {
  const answer = tailnet.fetch.getMockImplementation();
  if (answer === undefined) throw new Error("the fake has no fetch");
  tailnet.fetch.mockImplementation(async (resource, init) => {
    const response = await answer(resource, init);
    const url =
      resource instanceof Request ? resource.url : resource.toString();
    if (!url.endsWith(path)) return response;
    const { scope: _scope, ...body } = (await response.json()) as Record<
      string,
      unknown
    >;
    return new Response(JSON.stringify(body), { status: response.status });
  });
};

/** Makes the federated exchange answer without its `scope`, so the token's scopes aren't known. */
export const withoutFederatedScope = (tailnet: FakeTailscale) =>
  withoutScope(tailnet, "/oauth/token-exchange");

/** Makes the OAuth client's exchange answer without its `scope`. */
export const withoutOAuthScope = (tailnet: FakeTailscale) =>
  withoutScope(tailnet, "/oauth/token");

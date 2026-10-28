import { afterEach, beforeEach, vi } from "vitest";

import { resetOwnServicePrincipalCache } from "../databricks/client.ts";
import type { DatabricksAccountContext } from "../databricks/context.ts";
import {
  AWS_TOKEN_LIFETIME_SECONDS,
  resetTokenCache,
} from "../databricks/federation.ts";
import { resetWorkspaceBindingCache } from "../databricks/workspaces.ts";
import { AWS_JWT, stsSend } from "./sts.ts";

/** A minimal `Response`-like object matching what `databricksRequest` reads. */
export const jsonResponse = (
  data: unknown,
  init: { status?: number; statusText?: string } = {}
) => {
  const status = init.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: init.statusText ?? "OK",
    text: async () => (data === undefined ? "" : JSON.stringify(data)),
  };
};

export const ACCOUNTS_URL = "https://accounts.cloud.databricks.com";
export const WORKSPACE_URL = "https://dbc-1234abcd-5678.cloud.databricks.com";
/** The workspace `WORKSPACE_URL` serves. */
export const WORKSPACE_ID = "1234567890123456";
/** The Unity Catalog metastore `WORKSPACE_ID` is on. */
export const METASTORE_ID = "11111111-aaaa-4bbb-8ccc-222222222222";
export const ACCOUNT_ID = "0d26daa6-5e44-4c97-a497-ef015f91254a";
export const APPLICATION_ID = "8f3e1b2c-4d5a-4e6f-9a0b-1c2d3e4f5a6b";
export const SP_SCIM_ID = "7234567890123456";

/** The workspace API every workspace call binds through first. */
export const METASTORE_ASSIGNMENT =
  "/api/2.1/unity-catalog/current-metastore-assignment";

/** Whether `url` is the binding call to `WORKSPACE_URL`. */
export const isBinding = (url: string) =>
  url === `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`;

/**
 * Databricks' answer to the binding call: the workspace `WORKSPACE_URL`
 * serves (`WORKSPACE_ID` unless given) and its metastore.
 */
export const bindingResponse = (workspaceId: string = WORKSPACE_ID) =>
  jsonResponse({
    workspace_id: Number(workspaceId),
    metastore_id: METASTORE_ID,
    default_catalog_name: "main",
  });

export const accountContext = (
  overrides: Partial<DatabricksAccountContext> = {}
): DatabricksAccountContext => ({
  requestId: "req-123",
  accountsUrl: ACCOUNTS_URL,
  accountId: ACCOUNT_ID,
  applicationId: APPLICATION_ID,
  ...overrides,
});

/**
 * The token endpoint's success body. The Databricks token inherits the AWS
 * token's lifetime, so by default it lives as long as the connector asks STS
 * for.
 */
export const tokenResponse = (
  accessToken: string,
  expiresIn = AWS_TOKEN_LIFETIME_SECONDS
) =>
  jsonResponse({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    scope: "all-apis",
  });

export type FetchCall = {
  url: string;
  init: { method?: string; headers: Record<string, string>; body?: string };
};

export const isTokenExchange = ({ url }: FetchCall) =>
  url.includes("/oidc/accounts/");

/** Stubs the global `fetch`, answering the token endpoint with a fresh token per call and everything else from `handler`. */
export const stubFetch = (
  handler: (url: string, init: RequestInit) => unknown = () => jsonResponse({})
) => {
  let issued = 0;
  const mock = vi.fn(async (url: string, init: RequestInit) =>
    url.includes("/oidc/accounts/")
      ? tokenResponse(`dbx-token-${++issued}`)
      : handler(url, init)
  );
  vi.stubGlobal("fetch", mock);
  return mock;
};

export type FetchMock = ReturnType<typeof stubFetch>;

/** The calls a stubbed `fetch` received. `databricksRequest` always sends plain-object headers and a string body. */
export const fetchCalls = (mock: FetchMock): FetchCall[] =>
  mock.mock.calls.map(([url, init]) => ({
    url,
    init: init as FetchCall["init"],
  }));

/**
 * Registers the resets every suite that calls the connector needs: no cached
 * tokens, principals or workspace bindings, STS answering with
 * {@link AWS_JWT}, and no stubbed globals, environment or timers left over.
 */
export const resetBetweenTests = () => {
  beforeEach(() => {
    resetTokenCache();
    resetOwnServicePrincipalCache();
    resetWorkspaceBindingCache();
    stsSend.mockReset();
    stsSend.mockResolvedValue({ WebIdentityToken: AWS_JWT });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
};

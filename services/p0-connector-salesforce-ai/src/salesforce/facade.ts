import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector-core";
import { setTimeout as sleep } from "node:timers/promises";

const logger = createLogger();

const API_TIMEOUT = 10_000;

const FACADE_PATH = "/services/apexrest/p0/agents";

/** Waits before each new login try, in milliseconds. */
const LOGIN_RETRY_DELAYS = [1_000, 2_000, 4_000];

/** The facade puts the key in the agent's username. */
export const AGENT_KEY_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;

export type ProvisionerCredentials = {
  /** The org's My Domain host, e.g. `acme.my.salesforce.com` */
  domain: string;
  consumerKey: string;
  consumerSecret: string;
};

export type Agent = { userId: string; username: string; active: boolean };

type TokenResponse = { access_token: string };

type ErrorBody = { error?: string; error_description?: string };

const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((data) => {
      const body = (Array.isArray(data) ? data[0] : data) as ErrorBody & {
        message?: string;
      };
      return body?.error_description ?? body?.error ?? body?.message;
    })
    .catch(() => undefined);

/**
 * Runs a Salesforce call, converting any failure into a {@link ConnectorError}
 * so the framework renders it to the user. Only the HTTP status and
 * Salesforce's own message are surfaced. The request, whose body can hold the
 * consumer secret, is never logged or attached to the error.
 */
const salesforceRequest = async (
  label: string,
  url: string,
  init: RequestInit
): Promise<Response> => {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ label, error }, "Salesforce request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `Salesforce ${label} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }
  return response;
};

const failFor = async (label: string, response: Response) => {
  const { status } = response;
  const message = await errorMessage(response);
  logger.error(
    { label, status, message },
    "Salesforce request returned a non-2xx response"
  );
  return new ConnectorError({
    type: connectorErrorTypeForHttpStatus(status),
    message: `Salesforce ${label} failed (${status}): ${
      message ?? response.statusText
    }`,
    payload: { status },
  });
};

/** Sends one client credentials login. A network failure throws an
 * `upstream_unavailable` {@link ConnectorError}. */
const sendLogin = (credentials: ProvisionerCredentials) =>
  salesforceRequest(
    "provisioner login",
    `https://${credentials.domain}/services/oauth2/token`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: credentials.consumerKey,
        client_secret: credentials.consumerSecret,
      }),
    }
  );

type LoginResult =
  | { type: "failed"; error: ConnectorError }
  | { type: "token"; token: string }
  | { type: "transient"; error: ConnectorError };

const tryLogin = async (
  credentials: ProvisionerCredentials
): Promise<LoginResult> => {
  let response: Response;
  try {
    response = await sendLogin(credentials);
  } catch (error) {
    if (error instanceof ConnectorError) return { type: "transient", error };
    throw error;
  }
  if (response.ok) {
    return {
      type: "token",
      token: ((await response.json()) as TokenResponse).access_token,
    };
  }
  const { status } = response;
  const message = await errorMessage(response);
  if (status === 400 || status === 401) {
    logger.error(
      { status, message },
      "Salesforce refused the provisioner login"
    );
    // Salesforce answers 400 for an unknown consumer key or a wrong secret.
    return {
      type: "failed",
      error: new ConnectorError({
        type: "insufficient_privileges",
        message: `Salesforce refused the P0 Provisioner app's login (${
          message ?? status
        }). Check the provisioner consumer key and the consumer secret in your secret manager. A new external client app can take up to 10 minutes to work`,
        payload: { status },
      }),
    };
  }
  logger.error(
    { label: "provisioner login", status, message },
    "Salesforce request returned a non-2xx response"
  );
  // For a short time, Salesforce can answer 404 with no error body before it
  // reads the login.
  const transient = status >= 500 || (status === 404 && message === undefined);
  const error = new ConnectorError({
    type: transient
      ? "upstream_unavailable"
      : connectorErrorTypeForHttpStatus(status),
    message: `Salesforce provisioner login failed (${status}): ${
      message ?? response.statusText
    }`,
    payload: { status },
  });
  return { type: transient ? "transient" : "failed", error };
};

/** Logs in as the provisioner with the client credentials grant. Tries again
 * after a network failure, a 5xx, or a 404 with no error body. */
const login = async (credentials: ProvisionerCredentials) => {
  let result = await tryLogin(credentials);
  for (const delay of LOGIN_RETRY_DELAYS) {
    if (result.type !== "transient") break;
    logger.warn({ delay }, "Salesforce provisioner login failed; trying again");
    await sleep(delay);
    result = await tryLogin(credentials);
  }
  if (result.type === "token") return result.token;
  throw result.error;
};

/** Calls the P0 package's agent facade as the provisioner. The facade only
 * touches users in the package's agent role and profile, and only grants
 * permission sets on its grantable list. */
export const newFacadeClient = async (credentials: ProvisionerCredentials) => {
  const token = await login(credentials);

  const call = async <T>(
    label: string,
    method: "GET" | "POST" | "PUT",
    path: string[],
    options: { body?: unknown; query?: Record<string, string> } = {}
  ): Promise<{ status: number; data?: T }> => {
    const url = new URL(
      [FACADE_PATH, ...path.map(encodeURIComponent)].join("/"),
      `https://${credentials.domain}`
    );
    for (const [key, value] of Object.entries(options.query ?? {}))
      url.searchParams.set(key, value);
    const response = await salesforceRequest(label, url.toString(), {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
    });
    if (response.status === 404 && method === "GET" && path.length === 0)
      return { status: 404 };
    if (!response.ok) throw await failFor(label, response);
    return { status: response.status, data: (await response.json()) as T };
  };

  return {
    /** @returns the agent with this key, active or not, or null */
    findAgent: async (agentKey: string): Promise<Agent | null> =>
      (await call<Agent>("agent lookup", "GET", [], { query: { agentKey } }))
        .data ?? null,
    /** Creates the agent's user, or reactivates it with no grants. */
    upsertAgent: async (agentKey: string): Promise<Agent> => {
      const { data } = await call<Omit<Agent, "active">>(
        "agent upsert",
        "POST",
        [],
        { body: { agentKey } }
      );
      return { ...data!, active: true };
    },
    /** Makes the agent hold exactly these grantable permission sets. */
    setGrants: async (userId: string, permissionSets: string[]) => {
      await call("grant update", "PUT", [userId, "grants"], {
        body: { permissionSets },
      });
    },
    /** Removes every grant, then deactivates the user, which ends its sessions. */
    retire: async (userId: string) => {
      await call("agent retire", "POST", [userId, "retire"]);
    },
    listGrantable: async (): Promise<string[]> => {
      const { data } = await call<{ permissionSets: string[] }>(
        "permission set list",
        "GET",
        ["permission-sets"]
      );
      return data!.permissionSets;
    },
  };
};

export type FacadeClient = Awaited<ReturnType<typeof newFacadeClient>>;

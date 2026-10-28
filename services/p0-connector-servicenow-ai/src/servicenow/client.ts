import {
  ConnectorError,
  connectorErrorTypeForHttpStatus,
  createLogger,
} from "@p0security/connector";
import { createPrivateKey, randomUUID, sign } from "node:crypto";

const logger = createLogger();

const API_TIMEOUT = 10_000;

/** The lifetime of the JWT that the connector exchanges, in seconds. */
const ASSERTION_LIFETIME = 300;

const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** P0 creates agent users with this `user_name` prefix only. */
export const AGENT_USER_PREFIX = "p0-agent-";

/** ServiceNow keeps at most 40 characters of `user_name`. */
export const AGENT_KEY_PATTERN = /^[a-z0-9]{1,31}$/;

export const agentUserName = (agentKey: string) =>
  `${AGENT_USER_PREFIX}${agentKey}`;

export type ProvisionerCredentials = {
  /** The instance host, e.g. `acme.service-now.com` */
  domain: string;
  clientId: string;
  clientSecret: string;
};

export type JwtBearerCredentials = {
  domain: string;
  clientId: string;
  clientSecret: string;
  /** PEM-encoded RSA private key; ServiceNow has its certificate */
  signingKey: string;
  /** The `kid` of the certificate in the JWT bearer integration's verifier map */
  keyId: string;
};

export type AgentUser = { sysId: string; userName: string };

export type UserRole = {
  /** The `sys_user_has_role` row */
  rowId: string;
  /** Empty when ServiceNow kept the row but refused the role */
  roleName: string;
};

type ErrorBody = {
  error?: string | { message?: string; detail?: string };
  error_description?: string;
};

const errorMessage = async (response: Response) =>
  await response
    .json()
    .then((json: unknown) => {
      const data = json as ErrorBody | undefined;
      return typeof data?.error === "object"
        ? (data.error.detail ?? data.error.message)
        : (data?.error_description ?? data?.error);
    })
    .catch(() => undefined);

/**
 * Sends one ServiceNow request. A network failure throws an
 * `upstream_unavailable` {@link ConnectorError}. The request is not logged,
 * because its body can hold a client secret.
 */
const serviceNowRequest = async (
  label: string,
  url: string,
  init: RequestInit
): Promise<Response> => {
  try {
    return await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
  } catch (error) {
    logger.error({ label, error }, "ServiceNow request failed");
    throw new ConnectorError({
      type: "upstream_unavailable",
      message: `ServiceNow ${label} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      payload: {},
    });
  }
};

const failFor = async (label: string, response: Response) => {
  const { status } = response;
  const message = await errorMessage(response);
  logger.error(
    { label, status, message },
    "ServiceNow request returned a non-2xx response"
  );
  return new ConnectorError({
    type: connectorErrorTypeForHttpStatus(status),
    message: `ServiceNow ${label} failed (${status}): ${
      message ?? response.statusText
    }`,
    payload: { status },
  });
};

const requestToken = async (
  label: string,
  domain: string,
  params: Record<string, string>
): Promise<string> => {
  const response = await serviceNowRequest(
    label,
    `https://${domain}/oauth_token.do`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params),
    }
  );
  if (!response.ok) throw await failFor(label, response);
  const { access_token } = (await response.json()) as {
    access_token?: string;
  };
  if (!access_token) {
    throw new ConnectorError({
      type: "unknown",
      message: `ServiceNow ${label} returned no access token`,
      payload: {},
    });
  }
  return access_token;
};

const base64Url = (value: string) => Buffer.from(value).toString("base64url");

/** Signs the RS256 JWT for ServiceNow's JWT bearer grant. ServiceNow refuses
 * an `iss` that is not the integration's client ID. */
export const signAssertion = (
  credentials: Pick<JwtBearerCredentials, "clientId" | "keyId" | "signingKey">,
  userName: string,
  now = Math.floor(Date.now() / 1000)
): string => {
  const header = { alg: "RS256", typ: "JWT", kid: credentials.keyId };
  const claims = {
    iss: credentials.clientId,
    aud: credentials.clientId,
    sub: userName,
    iat: now,
    exp: now + ASSERTION_LIFETIME,
    jti: randomUUID(),
  };
  const input = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(claims))}`;
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(input),
    createPrivateKey(credentials.signingKey)
  );
  return `${input}.${signature.toString("base64url")}`;
};

/** Gets an access token for the user `userName` with the JWT bearer grant. */
export const mintUserToken = async (
  credentials: JwtBearerCredentials,
  userName: string
): Promise<string> =>
  await requestToken("agent token exchange", credentials.domain, {
    grant_type: JWT_BEARER_GRANT_TYPE,
    assertion: signAssertion(credentials, userName),
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
  });

type TableRow = Record<string, unknown>;

/** Calls the Table API as the provisioner, which needs only `user_admin`. */
export const newProvisionerClient = async (
  credentials: ProvisionerCredentials
) => {
  const token = await requestToken("provisioner login", credentials.domain, {
    grant_type: "client_credentials",
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
  });

  const table = async (
    label: string,
    method: "DELETE" | "GET" | "POST",
    path: string,
    body?: TableRow
  ): Promise<TableRow | TableRow[] | undefined> => {
    const response = await serviceNowRequest(
      label,
      `https://${credentials.domain}/api/now/table/${path}`,
      {
        method,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      }
    );
    if (method === "DELETE" && response.status === 404) return undefined;
    if (!response.ok) throw await failFor(label, response);
    if (response.status === 204) return undefined;
    return ((await response.json()) as { result: TableRow | TableRow[] })
      .result;
  };

  const rows = async (label: string, path: string) =>
    ((await table(label, "GET", path)) ?? []) as TableRow[];

  const query = (params: Record<string, string>) =>
    new URLSearchParams(params).toString();

  return {
    findUser: async (userName: string): Promise<AgentUser | null> => {
      const [row] = await rows(
        "user lookup",
        `sys_user?${query({
          sysparm_query: `user_name=${userName}`,
          sysparm_fields: "sys_id,user_name",
        })}`
      );
      return row
        ? { sysId: String(row.sys_id), userName: String(row.user_name) }
        : null;
    },

    getUser: async (sysId: string): Promise<AgentUser | null> => {
      const [row] = await rows(
        "user lookup",
        `sys_user?${query({
          sysparm_query: `sys_id=${sysId}`,
          sysparm_fields: "sys_id,user_name",
        })}`
      );
      return row
        ? { sysId: String(row.sys_id), userName: String(row.user_name) }
        : null;
    },

    createUser: async (userName: string): Promise<string> => {
      const row = (await table(
        "user creation",
        "POST",
        "sys_user?sysparm_fields=sys_id",
        {
          user_name: userName,
          first_name: "P0",
          last_name: "Agent",
          identity_type: "machine",
          web_service_access_only: true,
          active: true,
        }
      )) as TableRow;
      return String(row.sys_id);
    },

    deleteUser: async (sysId: string): Promise<void> => {
      await table("user deletion", "DELETE", `sys_user/${sysId}`);
    },

    /** The roles assigned to the user directly, not the inherited ones */
    userRoles: async (sysId: string): Promise<UserRole[]> =>
      (
        await rows(
          "role lookup",
          `sys_user_has_role?${query({
            sysparm_query: `user=${sysId}^inherited=false`,
            sysparm_fields: "sys_id,role.name",
          })}`
        )
      ).map((row) => ({
        rowId: String(row.sys_id),
        roleName: String(row["role.name"] ?? ""),
      })),

    addRole: async (sysId: string, roleName: string): Promise<void> => {
      const [role] = await rows(
        "role lookup",
        `sys_user_role?${query({
          sysparm_query: `name=${roleName}`,
          sysparm_fields: "sys_id",
        })}`
      );
      if (!role) {
        throw new ConnectorError({
          type: "validation_error",
          message: `ServiceNow has no role "${roleName}"`,
          payload: { roleName },
        });
      }
      await table(
        "role grant",
        "POST",
        "sys_user_has_role?sysparm_fields=sys_id",
        { user: sysId, role: String(role.sys_id) }
      );
    },

    removeRole: async (rowId: string): Promise<void> => {
      await table("role removal", "DELETE", `sys_user_has_role/${rowId}`);
    },

    /** Roles that are not elevated privilege roles */
    listRoles: async (): Promise<string[]> =>
      (
        await rows(
          "role listing",
          `sys_user_role?${query({
            sysparm_query: "elevated_privilege=false^ORDERBYname",
            sysparm_fields: "name",
          })}`
        )
      ).map((row) => String(row.name)),
  };
};

export type ProvisionerClient = Awaited<
  ReturnType<typeof newProvisionerClient>
>;

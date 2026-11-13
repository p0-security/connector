import type { Logger } from "@p0security/connector-core";
import { randomUUID, sign } from "node:crypto";
import { z } from "zod";

import type { App } from "../account.ts";
import { failureFacts } from "../failure.ts";
import { readPrivateKey } from "../secrets.ts";

/** How long Okta has to answer a call, its body included. */
export const OKTA_TIMEOUT_MS = 10_000;

/** How many times to send a call again after a 429 or 5xx answer. */
const OKTA_RETRIES = 2;

/** The longest wait before a retry. Keep retries inside the app's user lock. */
const OKTA_MAX_RETRY_WAIT_MS = 5_000;

/** The scopes the service app must be granted. The connector asks for all of them on every token. */
export const OKTA_SCOPES = [
  "okta.apps.manage",
  "okta.schemas.manage",
  "okta.users.read",
] as const;

type Method = "DELETE" | "GET" | "POST" | "PUT";

/** A call, by the path as Okta's API reference writes it, so it carries no id. */
export type OktaCall = { method: Method; route: `/${string}` };

export const OKTA_ROUTES = {
  token: { method: "POST", route: "/oauth2/v1/token" },
  getApp: { method: "GET", route: "/api/v1/apps/{appId}" },
  replaceApp: { method: "PUT", route: "/api/v1/apps/{appId}" },
  getSamlMetadata: {
    method: "GET",
    route: "/api/v1/apps/{appId}/sso/saml/metadata",
  },
  updateAppUserSchema: {
    method: "POST",
    route: "/api/v1/meta/schemas/apps/{appId}/default",
  },
  searchUsers: { method: "GET", route: "/api/v1/users" },
  getAppUser: { method: "GET", route: "/api/v1/apps/{appId}/users/{userId}" },
  assignAppUser: { method: "POST", route: "/api/v1/apps/{appId}/users" },
  updateAppUser: {
    method: "POST",
    route: "/api/v1/apps/{appId}/users/{userId}",
  },
  unassignAppUser: {
    method: "DELETE",
    route: "/api/v1/apps/{appId}/users/{userId}",
  },
} as const satisfies Record<string, OktaCall>;

export type OktaFailure =
  /** An answer outside 2xx. `code` is Okta's `errorCode`, or the OAuth `error`. */
  | { kind: "status"; status: number; code?: string }
  /** A 2xx with a body Okta wouldn't send. */
  | { kind: "unexpected" }
  /** No answer. */
  | { kind: "unreachable"; timedOut: boolean; code?: number | string };

/**
 * An Okta call that failed. It holds nothing of the request: not the URL,
 * and not the headers, which carry the access token.
 */
export class OktaError extends Error {
  constructor(
    readonly call: OktaCall,
    readonly failure: OktaFailure
  ) {
    super(`Okta ${call.method} ${call.route}: ${failure.kind}`);
    this.name = "OktaError";
  }
}

const oktaErrorBody = z.object({
  errorCode: z.string().optional().catch(undefined),
  error: z.string().optional().catch(undefined),
});

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

const isRetryable = (status: number) => status === 429 || status >= 500;

/** Gets the wait before retry `attempt` (0 for the first retry). Okta gives
 * the end of a rate limit window in `X-Rate-Limit-Reset`, in epoch seconds. */
const retryWaitMs = (response: Response, attempt: number) => {
  const reset = Number(response.headers.get("x-rate-limit-reset"));
  const wait = reset > 0 ? reset * 1000 - Date.now() : 500 * 2 ** attempt;
  return Math.min(Math.max(wait, 0), OKTA_MAX_RETRY_WAIT_MS);
};

const fetchOnce = async (
  call: OktaCall,
  url: string,
  toInit: () => RequestInit
) => {
  try {
    const response = await fetch(url, {
      ...toInit(),
      method: call.method,
      redirect: "manual",
      signal: AbortSignal.timeout(OKTA_TIMEOUT_MS),
    });
    return { response, text: await response.text() };
  } catch (error: unknown) {
    const { code, name } = failureFacts(error);
    throw new OktaError(call, {
      kind: "unreachable",
      timedOut: name === "TimeoutError",
      ...(code === undefined ? {} : { code }),
    });
  }
};

/** Sends one call, and returns the body of a 2xx answer as text. Sends it
 * again after a 429 or 5xx answer, up to {@link OKTA_RETRIES} times.
 *
 * @param toInit makes the request for each attempt
 */
const send = async (
  call: OktaCall,
  url: string,
  toInit: () => RequestInit
): Promise<string> => {
  let { response, text } = await fetchOnce(call, url, toInit);
  for (
    let attempt = 0;
    attempt < OKTA_RETRIES && isRetryable(response.status);
    attempt++
  ) {
    await new Promise((resolve) =>
      setTimeout(resolve, retryWaitMs(response, attempt))
    );
    ({ response, text } = await fetchOnce(call, url, toInit));
  }
  if (response.status < 200 || response.status >= 300) {
    const body = oktaErrorBody.safeParse(parseJson(text));
    const code = body.success
      ? (body.data.errorCode ?? body.data.error)
      : undefined;
    throw new OktaError(call, {
      kind: "status",
      status: response.status,
      ...(code === undefined ? {} : { code }),
    });
  }
  return text;
};

/** Parses a 2xx JSON answer with `schema`. */
const parseAnswer = <T>(call: OktaCall, text: string, schema: z.ZodType<T>) => {
  const parsed = schema.safeParse(parseJson(text));
  if (!parsed.success) throw new OktaError(call, { kind: "unexpected" });
  return parsed.data;
};

const tokenAnswer = z.object({
  access_token: z.string().min(1),
  token_type: z.literal("Bearer"),
});

/**
 * Gets an access token for the service app with a private key JWT client
 * assertion (client credentials grant).
 */
const getAccessToken = async (
  { domain, clientId, privateKey }: App,
  logger: Logger
): Promise<string> => {
  const { key, kid } = await readPrivateKey(privateKey, logger);
  const call = OKTA_ROUTES.token;
  const audience = `https://${domain}${call.route}`;
  const encode = (part: object) =>
    Buffer.from(JSON.stringify(part)).toString("base64url");
  // Okta refuses a client assertion that it saw before, so sign a new one for each attempt.
  const toAssertion = () => {
    const now = Math.floor(Date.now() / 1000);
    const signingInput = `${encode({ alg: "RS256", typ: "JWT", ...(kid === undefined ? {} : { kid }) })}.${encode(
      {
        aud: audience,
        exp: now + 300,
        iat: now,
        iss: clientId,
        jti: randomUUID(),
        sub: clientId,
      }
    )}`;
    const signature = sign("RSA-SHA256", Buffer.from(signingInput), key);
    return `${signingInput}.${signature.toString("base64url")}`;
  };
  const text = await send(call, audience, () => ({
    body: new URLSearchParams({
      client_assertion: toAssertion(),
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      grant_type: "client_credentials",
      scope: OKTA_SCOPES.join(" "),
    }),
    headers: { Accept: "application/json" },
  }));
  return parseAnswer(call, text, tokenAnswer).access_token;
};

/**
 * The AWS Account Federation app as Okta returns it. `settings.app` is kept
 * whole, because a replace sends the app back.
 */
const oktaApp = z.looseObject({
  id: z.string(),
  name: z.string(),
  label: z.string(),
  status: z.string(),
  signOnMode: z.string(),
  settings: z.looseObject({
    app: z.looseObject({ joinAllRoles: z.boolean().optional() }).optional(),
  }),
});

export type OktaApp = z.infer<typeof oktaApp>;

const oktaUser = z.object({
  id: z.string().min(1),
  status: z.string(),
  profile: z.object({ login: z.string().min(1) }),
});

export type OktaUser = z.infer<typeof oktaUser>;

/** An app user's profile, as much of it as the connector writes. */
export type AppUserProfile = { samlRoles: string[]; managedByP0?: boolean };

const appUser = z.object({
  profile: z
    .object({
      // Okta returns no `samlRoles`, or `null`, for a user without roles.
      samlRoles: z.array(z.string()).nullish().catch(undefined),
      managedByP0: z.boolean().nullish().catch(undefined),
    })
    .catch({}),
});

/** Quotes `value` for an Okta search expression. */
const searchString = (value: string) =>
  `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/** Okta, on one app, as the app's service app. The access token is got now. */
export const connectOkta = async (app: App, logger: Logger) => {
  const token = await getAccessToken(app, logger);
  const base = `https://${app.domain}`;
  const appPath = `/api/v1/apps/${app.appId}`;
  const call = (
    route: OktaCall,
    path: string,
    {
      accept = "application/json",
      body,
    }: { accept?: string; body?: unknown } = {}
  ) =>
    send(route, `${base}${path}`, () => ({
      headers: {
        Accept: accept,
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }));

  return {
    getApp: async () =>
      parseAnswer(
        OKTA_ROUTES.getApp,
        await call(OKTA_ROUTES.getApp, appPath),
        oktaApp
      ),

    replaceApp: async (replacement: OktaApp) => {
      await call(OKTA_ROUTES.replaceApp, appPath, { body: replacement });
    },

    getSamlMetadata: () =>
      call(OKTA_ROUTES.getSamlMetadata, `${appPath}/sso/saml/metadata`, {
        accept: "application/xml",
      }),

    /** Adds custom properties to the app user schema. Other properties stay. */
    addAppUserProperties: async (properties: Record<string, unknown>) => {
      await call(
        OKTA_ROUTES.updateAppUserSchema,
        `/api/v1/meta/schemas/apps/${app.appId}/default`,
        {
          body: {
            definitions: {
              custom: { id: "#custom", properties, type: "object" },
            },
          },
        }
      );
    },

    /** The users whose primary email is `email`. */
    findUsersByEmail: async (email: string) => {
      const search = new URLSearchParams({
        search: `profile.email eq ${searchString(email)}`,
      });
      return parseAnswer(
        OKTA_ROUTES.searchUsers,
        await call(
          OKTA_ROUTES.searchUsers,
          `/api/v1/users?${search.toString()}`
        ),
        z.array(oktaUser)
      );
    },

    /** The user's assignment to the app, or `null` if the user isn't assigned. */
    getAppUser: async (userId: string): Promise<AppUserProfile | null> => {
      const route = OKTA_ROUTES.getAppUser;
      const text = await call(route, `${appPath}/users/${userId}`).catch(
        (error: unknown) => {
          if (
            error instanceof OktaError &&
            error.failure.kind === "status" &&
            error.failure.status === 404
          ) {
            return null;
          }
          throw error;
        }
      );
      if (text === null) return null;
      const { profile } = parseAnswer(route, text, appUser);
      return {
        samlRoles: profile.samlRoles ?? [],
        ...(profile.managedByP0 ? { managedByP0: true } : {}),
      };
    },

    assignAppUser: async (user: OktaUser, profile: AppUserProfile) => {
      await call(OKTA_ROUTES.assignAppUser, `${appPath}/users`, {
        body: {
          credentials: { userName: user.profile.login },
          id: user.id,
          profile,
          scope: "USER",
        },
      });
    },

    updateAppUser: async (userId: string, profile: AppUserProfile) => {
      await call(OKTA_ROUTES.updateAppUser, `${appPath}/users/${userId}`, {
        body: { profile },
      });
    },

    unassignAppUser: async (userId: string) => {
      await call(OKTA_ROUTES.unassignAppUser, `${appPath}/users/${userId}`);
    },
  };
};

export type OktaClient = Awaited<ReturnType<typeof connectOkta>>;

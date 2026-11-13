import type { Logger } from "@p0security/connector-core";
import { z } from "zod";

import { type App, REGION_TLDS } from "../account.ts";
import { failureFacts } from "../failure.ts";
import { readClientSecret } from "../secrets.ts";

/** How long PingOne has to answer a call, its body included. */
export const PINGONE_TIMEOUT_MS = 10_000;

type Method = "GET" | "POST";

/** A call, by the path as PingOne's API reference writes it, so it carries no id. */
export type PingOneCall = { method: Method; route: `/${string}` };

export const PINGONE_ROUTES = {
  token: { method: "POST", route: "/{envID}/as/token" },
  getSamlMetadata: {
    method: "GET",
    route: "/{envID}/saml20/metadata/{appID}",
  },
  getApp: {
    method: "GET",
    route: "/environments/{envID}/applications/{appID}",
  },
  listAttributeMappings: {
    method: "GET",
    route: "/environments/{envID}/applications/{appID}/attributes",
  },
  listSchemas: { method: "GET", route: "/environments/{envID}/schemas" },
  listSchemaAttributes: {
    method: "GET",
    route: "/environments/{envID}/schemas/{schemaID}/attributes",
  },
} as const satisfies Record<string, PingOneCall>;

export type PingOneFailure =
  /** An answer outside 2xx. `code` is PingOne's `code`, or the OAuth `error`. */
  | { kind: "status"; status: number; code?: string }
  /** A 2xx with a body PingOne wouldn't send. */
  | { kind: "unexpected" }
  /** No answer. */
  | { kind: "unreachable"; timedOut: boolean; code?: number | string };

/**
 * A PingOne call that failed. It holds nothing of the request: not the URL,
 * and not the headers, which carry the client secret or the access token.
 */
export class PingOneError extends Error {
  constructor(
    readonly call: PingOneCall,
    readonly failure: PingOneFailure
  ) {
    super(`PingOne ${call.method} ${call.route}: ${failure.kind}`);
    this.name = "PingOneError";
  }
}

const pingOneErrorBody = z.object({
  code: z.string().optional().catch(undefined),
  error: z.string().optional().catch(undefined),
});

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** Sends one call, and returns the body of a 2xx answer as text. */
const send = async (
  call: PingOneCall,
  url: string,
  init: RequestInit
): Promise<string> => {
  let response: Response;
  let text: string;
  try {
    response = await fetch(url, {
      ...init,
      method: call.method,
      redirect: "manual",
      signal: AbortSignal.timeout(PINGONE_TIMEOUT_MS),
    });
    text = await response.text();
  } catch (error: unknown) {
    const { code, name } = failureFacts(error);
    throw new PingOneError(call, {
      kind: "unreachable",
      timedOut: name === "TimeoutError",
      ...(code === undefined ? {} : { code }),
    });
  }
  if (response.status < 200 || response.status >= 300) {
    const body = pingOneErrorBody.safeParse(parseJson(text));
    const code = body.success ? (body.data.code ?? body.data.error) : undefined;
    throw new PingOneError(call, {
      kind: "status",
      status: response.status,
      ...(code === undefined ? {} : { code }),
    });
  }
  return text;
};

/** Parses a 2xx JSON answer with `schema`. */
const parseAnswer = <T>(
  call: PingOneCall,
  text: string,
  schema: z.ZodType<T>
) => {
  const parsed = schema.safeParse(parseJson(text));
  if (!parsed.success) throw new PingOneError(call, { kind: "unexpected" });
  return parsed.data;
};

const tokenAnswer = z.object({
  access_token: z.string().min(1),
  token_type: z.literal("Bearer"),
});

const embedded = <K extends string, T extends z.ZodType>(key: K, item: T) =>
  z.object({
    _embedded: z.object({ [key]: z.array(item) } as Record<K, z.ZodArray<T>>),
  });

const pingOneApp = z.looseObject({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  protocol: z.string(),
  nameIdFormat: z.string().optional(),
});

export type PingOneApp = z.infer<typeof pingOneApp>;

const attributeMapping = z.looseObject({
  name: z.string(),
  value: z.string(),
  nameFormat: z.string().optional(),
});

export type AttributeMapping = z.infer<typeof attributeMapping>;

const schema = z.looseObject({ id: z.string(), name: z.string() });

const schemaAttribute = z.looseObject({
  name: z.string(),
  type: z.string(),
  multiValued: z.boolean().optional(),
  enumeratedValues: z.array(z.unknown()).nullish(),
  regexValidation: z.unknown().optional(),
});

export type SchemaAttribute = z.infer<typeof schemaAttribute>;

/**
 * Gets an access token for the worker app with its client secret (client
 * credentials grant, `client_secret_basic`).
 */
const getAccessToken = async (
  { region, environmentId, clientId, clientSecret }: App,
  logger: Logger
): Promise<string> => {
  const secret = await readClientSecret(clientSecret, logger);
  const call = PINGONE_ROUTES.token;
  const text = await send(
    call,
    `https://auth.pingone.${REGION_TLDS[region]}/${environmentId}/as/token`,
    {
      body: new URLSearchParams({ grant_type: "client_credentials" }),
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`,
      },
    }
  );
  return parseAnswer(call, text, tokenAnswer).access_token;
};

/** PingOne, on one environment, as the worker app. The access token is got now. */
export const connectPingOne = async (app: App, logger: Logger) => {
  const token = await getAccessToken(app, logger);
  const tld = REGION_TLDS[app.region];
  const base = `https://api.pingone.${tld}/v1/environments/${app.environmentId}`;
  const appPath = `/applications/${app.appId}`;
  const get = async <T>(
    route: PingOneCall,
    path: string,
    schema: z.ZodType<T>
  ) =>
    parseAnswer(
      route,
      await send(route, `${base}${path}`, {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
        },
      }),
      schema
    );

  return {
    getApp: () => get(PINGONE_ROUTES.getApp, appPath, pingOneApp),

    listAttributeMappings: async () =>
      (
        await get(
          PINGONE_ROUTES.listAttributeMappings,
          `${appPath}/attributes`,
          embedded("attributes", attributeMapping)
        )
      )._embedded.attributes,

    /** The attributes of the user schema. */
    listUserAttributes: async () => {
      const { schemas } = (
        await get(
          PINGONE_ROUTES.listSchemas,
          "/schemas",
          embedded("schemas", schema)
        )
      )._embedded;
      const user = schemas.find(({ name }) => name === "User");
      if (user === undefined) {
        throw new PingOneError(PINGONE_ROUTES.listSchemas, {
          kind: "unexpected",
        });
      }
      return (
        await get(
          PINGONE_ROUTES.listSchemaAttributes,
          `/schemas/${user.id}/attributes`,
          embedded("attributes", schemaAttribute)
        )
      )._embedded.attributes;
    },

    /** The app's public SAML metadata, as XML. It needs no token. */
    getSamlMetadata: () =>
      send(
        PINGONE_ROUTES.getSamlMetadata,
        `https://auth.pingone.${tld}/${app.environmentId}/saml20/metadata/${app.appId}`,
        { headers: { Accept: "application/xml" } }
      ),
  };
};

export type PingOneClient = Awaited<ReturnType<typeof connectPingOne>>;

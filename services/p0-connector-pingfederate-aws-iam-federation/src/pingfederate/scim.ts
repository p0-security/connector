import { z } from "zod";

import type { App } from "../account.ts";
import { type Call, callPingFederate } from "./http.ts";

/** The namespace of the custom attributes on PingFederate's SCIM connection. */
export const SCIM_EXTENSION = "urn:scim:schemas:extension:custom:2.0";

const SCIM_JSON = "application/scim+json";

/** PingFederate's SCIM endpoint answered with a status other than 2xx. */
export class ScimStatusError extends Error {
  constructor(
    readonly status: number,
    /** The `detail` of PingFederate's SCIM error, if it gave one. */
    readonly detail: string | undefined
  ) {
    super(`PingFederate's SCIM endpoint answered with ${status}`);
  }
}

/** PingFederate answered with a 2xx reply that isn't the SCIM reply asked for. */
export class ScimReplyError extends Error {
  constructor() {
    super("PingFederate's SCIM endpoint answered with an unexpected reply");
  }
}

const parseReply = <T>(shape: z.ZodType<T>, json: unknown): T => {
  const parsed = shape.safeParse(json);
  if (!parsed.success) throw new ScimReplyError();
  return parsed.data;
};

const scimError = z.object({ detail: z.string() });

const schemaAttribute = z.object({
  name: z.string(),
  multiValued: z.boolean(),
  mutability: z.string(),
});

export type SchemaAttribute = z.infer<typeof schemaAttribute>;

const schema = z.object({ attributes: z.array(schemaAttribute) });

const userList = z.object({
  Resources: z.array(z.object({ id: z.string().nullish() })),
});

const parseJson = (body: string): unknown => {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
};

export type Scim = {
  /** The attributes of the custom SCIM schema, or `undefined` when PingFederate has none. */
  getExtensionAttributes(): Promise<SchemaAttribute[] | undefined>;
  /** The SCIM IDs of the users whose work email is `email`, `null` for a user PingFederate gave no ID. */
  findUsers(email: string): Promise<(string | null)[]>;
  /** Adds one value to a custom attribute. Does nothing if the user has it. */
  addValue(id: string, attribute: string, value: string): Promise<void>;
  /** Removes one value from a custom attribute. Does nothing if the user doesn't have it. */
  removeValue(id: string, attribute: string, value: string): Promise<void>;
};

const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/**
 * A client for PingFederate's SCIM 2.0 inbound provisioning endpoint. The
 * credentials select PingFederate's IdP connection.
 */
export const scimClient = (
  target: Pick<App, "caCertificate" | "pingFederateUrl" | "scimUsername">,
  password: string
): Scim => {
  const authorization = `Basic ${Buffer.from(`${target.scimUsername}:${password}`).toString("base64")}`;

  const send = async (call: Call): Promise<unknown> => {
    const { status, body } = await callPingFederate(target, {
      ...call,
      path: `/pf-scim/v2${call.path}`,
      headers: {
        accept: SCIM_JSON,
        authorization,
        ...(call.body === undefined ? {} : { "content-type": SCIM_JSON }),
      },
    });
    const json = parseJson(body);
    if (status < 200 || status >= 300) {
      throw new ScimStatusError(status, scimError.safeParse(json).data?.detail);
    }
    return json;
  };

  // PingFederate reads the user, changes the list, and writes all of it back:
  // two PATCHes for one user at the same time can lose one of them.
  const patch = async (id: string, operation: object) => {
    await send({
      method: "PATCH",
      path: `/Users/${encodeURIComponent(id)}`,
      body: JSON.stringify({ schemas: [PATCH_OP], Operations: [operation] }),
    });
  };

  return {
    getExtensionAttributes: async () => {
      try {
        const found = await send({
          method: "GET",
          path: `/Schemas/${SCIM_EXTENSION}`,
        });
        return parseReply(schema, found).attributes;
      } catch (error) {
        if (error instanceof ScimStatusError && error.status === 404) {
          return undefined;
        }
        throw error;
      }
    },
    findUsers: async (email) => {
      // A SCIM filter writes a string as JSON does.
      const filter = `emails.work.value eq ${JSON.stringify(email)}`;
      const found = await send({
        method: "GET",
        path: `/Users?filter=${encodeURIComponent(filter)}&attributes=id`,
      });
      return parseReply(userList, found).Resources.map(({ id }) => id ?? null);
    },
    addValue: (id, attribute, value) =>
      patch(id, {
        op: "add",
        path: `${SCIM_EXTENSION}:${attribute}`,
        value: [value],
      }),
    removeValue: (id, attribute, value) =>
      patch(id, {
        op: "remove",
        path: `${SCIM_EXTENSION}:${attribute}[value eq ${JSON.stringify(value)}]`,
      }),
  };
};

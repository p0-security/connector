import {
  ConnectorError,
  type Logger,
  throwAssertNever,
} from "@p0security/connector";
import { z } from "zod";

import { type CloudClient, newCloudClient } from "../../cloud/client.ts";
import { callCloud, isNotFound } from "../../cloud/errors.ts";
import { MAX_OBJECTS, MAX_OBJECT_BYTES } from "../../query/endpoints.ts";
import { newEndpointRunner } from "../../query/lookup.ts";
import {
  type ListerQuery,
  type ListerResponse,
  OBJECT_KINDS,
  listerQuery,
} from "./definition.ts";
import { findMember, requireAllowedEmail } from "./member.ts";

// `p0_objects`'s row: a database's `name` is "".
const objectRow = z.object({
  database: z.string(),
  name: z.string(),
  kind: z.enum(OBJECT_KINDS),
});

/** Rows from one of P0's endpoints, or `unknown` when they aren't in its shape. */
const parseRows = <T>(
  log: Logger,
  endpoint: string,
  schema: z.ZodType<T>,
  rows: unknown[]
): T[] => {
  const parsed = z.array(schema).safeParse(rows);
  if (parsed.success) return parsed.data;
  // Where and which issue, never a value: a row is the customer's data.
  log.warn(
    {
      endpoint,
      issues: parsed.error.issues.map(({ path, code }) => ({
        path: path.join("."),
        code,
      })),
    },
    "an endpoint returned rows the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: `ClickHouse Cloud returned rows from P0's Query API endpoint ${endpoint} in a shape P0 doesn't recognize.`,
    payload: { endpoint },
  });
};

/**
 * The refusal for a service with more objects than `objects` answers with.
 * The requestor picked the service, so "this service" names it.
 */
const tooManyObjects = (serviceId: string, why: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `This ClickHouse Cloud service has ${why}, so P0 can't list them. Request the whole service as '*' instead: that doesn't need the list.`,
    payload: { serviceId },
  });

/** The member with the email, ignoring case, if there's one. */
const memberItems = async (
  cloud: CloudClient,
  log: Logger,
  { organizationId, email }: { organizationId: string; email: string }
): Promise<ListerResponse> => {
  requireAllowedEmail(email, log);
  const member = await callCloud(
    () => findMember(cloud, { organizationId, email }),
    { organizationId }
  );
  return member === undefined
    ? []
    : [{ key: member.userId, value: member.email ?? email }];
};

/** The service's fields, one item each, or `[]` when it isn't there. */
const describeService = async (
  cloud: CloudClient,
  { organizationId, serviceId }: { organizationId: string; serviceId: string }
): Promise<ListerResponse> =>
  callCloud(
    async () => {
      const service = await cloud
        .getService(serviceId)
        .catch((error: unknown) => {
          if (isNotFound(error)) return undefined;
          throw error;
        });
      if (service === undefined) return [];
      return [
        { key: "id", value: service.id },
        { key: "name", value: service.name },
        { key: "version", value: service.clickhouseVersion ?? "" },
        { key: "byoc", value: String(Boolean(service.byocId)) },
      ];
    },
    { organizationId, subject: `service ${serviceId}` }
  );

/**
 * Answers a {@link ListerQuery}, for every access: `list` is one of each
 * access's primitives, and they share the queries.
 *
 * Reads inside a service run P0's own Query API endpoints there, setting
 * them up first when they aren't, with the query's values as typed
 * variables, never in SQL.
 */
export const list = async (
  logger: Logger,
  input: ListerQuery
): Promise<ListerResponse> => {
  // The framework never runs `validation` before `list`, and the router's
  // parser is the access's own, so each query is checked again here.
  const query = listerQuery.parse(input);
  const { context } = query;
  const { organizationId } = context;
  const log = logger.child({ organizationId, type: query.type });
  const cloud = newCloudClient({ ...context, log });

  switch (query.type) {
    case "member":
      return memberItems(cloud, log, { organizationId, email: query.email });
    case "services":
      return (
        await callCloud(() => cloud.listServices(), { organizationId })
      ).map(({ id, name }) => ({ key: id, value: name }));
    case "service":
      return describeService(cloud, {
        organizationId,
        serviceId: query.serviceId,
      });
    case "objects": {
      const { serviceId } = query;
      const runner = newEndpointRunner({ cloud, serviceId, log });
      const rows = parseRows(
        log,
        "p0_objects",
        objectRow,
        await callCloud(() => runner.run("p0_objects"), {
          organizationId,
          subject: `service ${serviceId}`,
        })
      );
      if (rows.length > MAX_OBJECTS) {
        throw tooManyObjects(
          serviceId,
          `more than ${MAX_OBJECTS.toLocaleString("en-US")} databases, tables, views and dictionaries`
        );
      }
      const items = rows.map(({ database, name, kind }) => {
        const key = kind === "database" ? database : `${database}.${name}`;
        return { key, value: key, group: kind };
      });
      // Each item as it's serialized, plus the comma before the next.
      const bytes = items.reduce(
        (sum, item) => sum + Buffer.byteLength(JSON.stringify(item)) + 1,
        0
      );
      if (bytes > MAX_OBJECT_BYTES) {
        throw tooManyObjects(
          serviceId,
          `too many databases, tables, views and dictionaries to fit in ${MAX_OBJECT_BYTES / 1024 / 1024} MB`
        );
      }
      return items;
    }
    default:
      throw throwAssertNever(query);
  }
};

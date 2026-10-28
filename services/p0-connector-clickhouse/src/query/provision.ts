import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { CloudClient, Endpoint, ListedEndpoint } from "../cloud/client.ts";
import { isForbidden, isNotFound } from "../cloud/errors.ts";
import { isP0Name } from "../namespace.ts";
import {
  type P0EndpointName,
  P0_ENDPOINTS,
  endpointRequest,
  isCurrent,
  matchesListed,
} from "./endpoints.ts";

/** A P0 endpoint as set up: what running it needs. */
export type ProvisionedEndpoint = { id: string; name: string; url: string };

const provisioned = ({ id, name, url }: ProvisionedEndpoint) => ({
  id,
  name,
  url,
});

/** A create or update the key's role doesn't allow: only the manage permission is missing. */
const manageRefused = (serviceId: string) =>
  new ConnectorError({
    type: "insufficient_privileges",
    message: `P0's API key can't set up P0's Query API endpoints on ClickHouse Cloud service ${serviceId}: its p0-connector role lacks control-plane:service:manage-query-api-endpoints. Add the permission to the role, then try again.`,
    payload: { serviceId },
  });

/**
 * An endpoint ClickHouse Cloud stored other than as P0 sent it, such as with
 * its SQL changed, which P0 doesn't run.
 */
const notAsSent = (serviceId: string, name: string) =>
  new ConnectorError({
    type: "unknown",
    message: `ClickHouse Cloud stored P0's Query API endpoint ${name} on service ${serviceId} other than as P0 sent it, so P0 won't run it.`,
    payload: { serviceId, endpoint: name },
  });

/**
 * Sets up one of P0's endpoints on one service for the key
 * ({@link P0_ENDPOINTS}), and returns it, exactly its definition. It lists
 * the service's endpoints once, and reads only that one whole.
 *
 * - The endpoint is created when it's missing by name.
 * - One P0 created whose database, roles, CORS origins or key differ in the
 *   listing is updated (`PUT`). After a key rotation, this is what moves the
 *   endpoint to the new key.
 * - Otherwise it's read whole, since the listing leaves out the SQL and the
 *   parameters, and updated when either differs: an endpoint whose SQL
 *   changed behind P0's back is never run as it is.
 * - What a create or update answers with is checked against the definition,
 *   at no extra call. One that isn't fails as `unknown` and isn't run.
 * - Another one P0 created with the same name, from a race, is deleted. A
 *   failed delete is logged and left to the next time P0 sets up the
 *   service's endpoints.
 *
 * An endpoint whose name doesn't start with `p0_` is never read, changed or
 * deleted. A create or update the key isn't allowed fails as
 * `insufficient_privileges`, naming the permission. Any other failed list,
 * read, create or update is thrown as it is.
 */
export const provisionEndpoint = async ({
  cloud,
  serviceId,
  apiKeyUuid,
  name,
  log,
}: {
  cloud: CloudClient;
  serviceId: string;
  apiKeyUuid: string;
  name: P0EndpointName;
  log: Logger;
}): Promise<ProvisionedEndpoint> => {
  const listed = (await cloud.listEndpoints(serviceId)).filter(({ name }) =>
    isP0Name(name)
  );

  const remove = async (stale: ListedEndpoint, why: string) => {
    try {
      await cloud.deleteEndpoint(serviceId, stale);
      log.info({ serviceId, endpoint: stale.name }, why);
    } catch (error) {
      // The next time P0 sets up this service's endpoints, it tries again.
      log.warn(
        {
          serviceId,
          endpoint: stale.name,
          error: error instanceof Error ? error.message : String(error),
        },
        "couldn't delete a stale P0 endpoint"
      );
    }
  };

  const definition = P0_ENDPOINTS[name];
  const request = endpointRequest(definition, apiKeyUuid);

  const write = async (
    change: () => Promise<Endpoint>
  ): Promise<ProvisionedEndpoint> => {
    let written: Endpoint;
    try {
      written = await change();
    } catch (error) {
      if (isForbidden(error)) throw manageRefused(serviceId);
      throw error;
    }
    // What ClickHouse Cloud answers with is what it stored, at no extra call.
    if (!isCurrent(written, definition, apiKeyUuid)) {
      log.warn(
        { serviceId, endpoint: name },
        "ClickHouse Cloud stored a P0 endpoint other than its definition"
      );
      throw notAsSent(serviceId, name);
    }
    return provisioned(written);
  };

  const create = async () => {
    const created = await write(() => cloud.createEndpoint(serviceId, request));
    log.info({ serviceId, endpoint: name }, "created a P0 endpoint");
    return created;
  };

  const update = async (existing: ListedEndpoint) => {
    const updated = await write(() =>
      cloud.updateEndpoint(serviceId, existing, request)
    );
    log.info({ serviceId, endpoint: name }, "updated a P0 endpoint");
    return updated;
  };

  /** The endpoint read whole, or `undefined` when it isn't at its ID any more. */
  const readWhole = (existing: ListedEndpoint) =>
    cloud.getEndpoint(serviceId, existing).catch((error: unknown) => {
      if (isNotFound(error)) return undefined;
      throw error;
    });

  const [existing, ...duplicates] = listed.filter(
    (endpoint) => endpoint.name === name
  );
  for (const duplicate of duplicates) {
    await remove(duplicate, "deleted a duplicate P0 endpoint");
  }
  if (existing === undefined) return create();
  if (!matchesListed(existing, apiKeyUuid)) return update(existing);
  const whole = await readWhole(existing);
  if (whole === undefined) return create();
  if (isCurrent(whole, definition, apiKeyUuid)) return provisioned(whole);
  log.warn(
    { serviceId, endpoint: name },
    "a P0 endpoint isn't its definition any more; putting it back"
  );
  return update(existing);
};

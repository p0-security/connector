import type { Logger } from "@p0security/connector";

import type { CloudClient } from "../cloud/client.ts";
import { isNotFound } from "../cloud/errors.ts";
import type { P0EndpointName } from "./endpoints.ts";
import { type ProvisionedEndpoint, provisionEndpoint } from "./provision.ts";

/**
 * Running P0's endpoints on a service.
 *
 * Nothing about an endpoint is kept between connector calls: anyone who can
 * manage a service's endpoints can change one behind P0's back, keeping its
 * ID. So a runner sets up the endpoint it needs the first time it runs it
 * ({@link provisionEndpoint}): one listing of the service's endpoints, and
 * that one endpoint read whole and put back to its definition when it
 * isn't. The first lookup on a service creates the endpoint there.
 */

/**
 * Runs P0's endpoints on one service, as the organization's key. Failures
 * are thrown as they are, for the caller to map with `callCloud`.
 */
export const newEndpointRunner = ({
  cloud,
  serviceId,
  log,
}: {
  cloud: CloudClient;
  serviceId: string;
  log: Logger;
}) => {
  // The endpoints this runner set up and read whole, by name.
  const ready = new Map<P0EndpointName, ProvisionedEndpoint>();

  const runnable = async (
    name: P0EndpointName
  ): Promise<ProvisionedEndpoint> => {
    const known = ready.get(name);
    if (known !== undefined) return known;
    const endpoint = await provisionEndpoint({
      cloud,
      serviceId,
      apiKeyUuid: await cloud.keyUuid(),
      name,
      log,
    });
    ready.set(name, endpoint);
    return endpoint;
  };

  return {
    /**
     * Runs one of P0's fixed endpoints, and returns its rows. A run that
     * gets a 404, the endpoint gone since it was read, sets it up again and
     * runs once more.
     */
    run: async (name: P0EndpointName): Promise<unknown[]> => {
      const endpoint = await runnable(name);
      try {
        return await cloud.runEndpoint(endpoint);
      } catch (error) {
        if (!(isNotFound(error) && error.api === "query")) throw error;
      }
      log.info(
        { serviceId, endpoint: name },
        "a P0 endpoint wasn't at its URL; setting it up again"
      );
      ready.delete(name);
      return cloud.runEndpoint(await runnable(name));
    },
  };
};

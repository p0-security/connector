import { type Logger, throwAssertNever } from "@p0security/connector-core";

import type { ConnectorDeps } from "../../deps.ts";
import { newTailscaleClient } from "../../tailscale/client.ts";
import { callTailscale } from "../../tailscale/errors.ts";
import { posturesOf } from "../../tailscale/inventory.ts";
import {
  type TailscaleDevice,
  getPolicyJson,
  listDevices,
} from "../../tailscale/tailnet.ts";
import { attributeKeyFor, postureName } from "../posture/definition.ts";
import {
  type ListerQuery,
  type ListerResponse,
  listerQuery,
} from "./definition.ts";

const nameOf = (device: TailscaleDevice) =>
  device.name ?? device.hostname ?? device.nodeId;

/**
 * The posture access's `list`, with a read-only token. It logs counts,
 * never a name, email or hostname.
 */
export const list = async (
  logger: Logger,
  deps: ConnectorDeps,
  input: ListerQuery
): Promise<ListerResponse> => {
  const query = listerQuery.parse(input);
  const { context } = query;
  const log = logger.child({ tailnet: context.tailnet, type: query.type });
  const client = newTailscaleClient({
    credentials: context,
    log,
    identityToken: deps.identityToken,
  });

  const answer = async (): Promise<ListerResponse> => {
    switch (query.type) {
      case "own-devices": {
        // Tailscale's `user` filter matches the exact login, so the devices
        // are filtered here instead, whatever the login's case. A shared-in
        // device belongs to another tailnet, so a grant refuses it.
        const wanted = query.email.toLowerCase();
        const devices = await client.read((call) => listDevices(call));
        return devices
          .filter(
            (device) =>
              (device.user ?? "").toLowerCase() === wanted &&
              (device.tags ?? []).length === 0 &&
              device.isExternal !== true
          )
          .map((device) => ({ key: device.nodeId, value: nameOf(device) }));
      }
      case "postures":
        return (
          posturesOf(await client.read(getPolicyJson))
            // Only names a request can carry, which leaves out install_check.
            .filter(({ name }) => postureName.safeParse(name).success)
            .map(({ name, assertions }) => ({
              key: name,
              value: assertions.join(" && "),
              group: attributeKeyFor(name),
            }))
        );
      default:
        throw throwAssertNever(query);
    }
  };

  return callTailscale(
    async () => {
      const items = await answer();
      log.info({ count: items.length }, "listed the tailnet");
      return items;
    },
    { tailnet: context.tailnet, subject: `the tailnet's ${query.type}` }
  );
};

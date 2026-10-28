import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { attributeKeyFor } from "../accesses/posture/definition.ts";
import type { ConnectorDeps } from "../deps.ts";
import { newTailscaleClient } from "../tailscale/client.ts";
import { callTailscale } from "../tailscale/errors.ts";
import { posturesOf } from "../tailscale/inventory.ts";
import { getPolicyJson } from "../tailscale/tailnet.ts";
import {
  type DestinationCheck,
  type DestinationCheckInput,
  destinationCheckInput,
} from "./definition.ts";
import { unlocksOf } from "./unlocks.ts";

/** Whether `assertion` is exactly `<attribute> == true`, however it's spaced. */
const isCheckOf = (assertion: string, attribute: string) =>
  assertion.replace(/\s+/g, "") === `${attribute}==true`;

/**
 * Confirms the posture is in the tailnet's policy file and checks the
 * attribute P0 sets, and answers what it unlocks. Read-only.
 */
export const checkDestination = async (
  { context, destination }: DestinationCheckInput,
  { logger, deps }: { logger: Logger; deps: ConnectorDeps }
): Promise<DestinationCheck> => {
  const { tailnet } = context;
  const { target } = destination;
  const log = logger.child({ tailnet, type: destination.type });
  const client = newTailscaleClient({
    credentials: context,
    log,
    identityToken: deps.identityToken,
  });

  return callTailscale(
    async () => {
      const policy = await client.read(getPolicyJson);
      const found = posturesOf(policy).find(({ name }) => name === target);
      if (!found) {
        throw new ConnectorError({
          type: "object_not_found",
          message: `Tailnet ${tailnet} has no posture ${target} in its policy file.`,
          payload: { tailnet, query: target },
        });
      }
      const attribute = attributeKeyFor(found.name);
      const wanted = `${attribute} == true`;
      // Any other assertion only narrows it: a device must pass them all.
      if (!found.assertions.some((each) => isCheckOf(each, attribute))) {
        throw new ConnectorError({
          type: "validation_error",
          message: `Posture ${found.name} doesn't check ${wanted}, so a device can pass it without P0. Add the assertion ${wanted} to ${found.name} in tailnet ${tailnet}'s policy file.`,
          payload: { tailnet },
        });
      }
      log.info("checked the posture");
      return {
        kind: "posture",
        posture: found.name,
        attribute,
        assertions: found.assertions,
        unlocks: unlocksOf(policy, found.name),
      };
    },
    {
      tailnet,
      subject: `the requested posture ${target}`,
      // The app says what the requestor does next, so no admin hint here.
      missingMeansTailnet: false,
    }
  );
};

/**
 * `install.destination.check`. The app calls it when a posture request is
 * made.
 */
export const router = (t: AnyConnectorTRPCInstance, deps: ConnectorDeps) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);
  return router({
    check: procedure
      .input(destinationCheckInput.parse)
      .query(({ input, ctx }) =>
        checkDestination(input, { logger: ctx.logger, deps })
      ),
  });
};

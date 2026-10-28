import {
  type AnyConnectorTRPCInstance,
  withRouteLogging,
} from "@p0security/connector-core";

import { createPrincipal, principalByName } from "../agent/agent.ts";
import { parse } from "../databricks/api.ts";
import { newDatabricksClient } from "../databricks/client.ts";
import { type Stage, stageInput, stageOutput } from "./definition.ts";

// Every later call parses the agent's application ID as a GUID, so one that
// isn't fails here, before P0 records it for the grant and the gateway.
const toStage = (applicationId: string, requestId: string): Stage =>
  parse({
    schema: stageOutput,
    data: { applicationId },
    what: "account SCIM ServicePrincipals",
    requestId,
  });

/**
 * `stage` gets or creates the bare service principal for one grant, by its
 * exact display name in account SCIM, and returns its application ID. It
 * creates nothing else: the grant sets the principal up later. Two matches
 * fail, and so does P0's own principal.
 *
 * It runs once, when P0 stages the request, which then records the
 * application ID for the grant and the gateway.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    stage: procedure
      .input(stageInput.parse)
      .mutation(async ({ input, ctx }): Promise<Stage> => {
        const { requestId, accountId, principalName } = input;
        const logger = ctx.logger.child({
          requestId,
          accountId,
          principalName,
        });
        const client = newDatabricksClient(input);

        const existing = await principalByName(client, principalName);
        if (existing) {
          logger.info(
            { principalId: existing.id },
            "found the agent principal already staged"
          );
          return toStage(existing.applicationId, requestId);
        }
        const created = await createPrincipal(client, principalName);
        logger.info({ principalId: created.id }, "created the agent principal");
        return toStage(created.applicationId, requestId);
      }),
  });
};

import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import { orgCredentials } from "../accesses/role/definition.ts";
import { requireAllowedDomains } from "../allowed-domains.ts";
import type { NewInvite } from "../dockerhub/api.ts";
import {
  type DockerHubClient,
  newDockerHubClient,
} from "../dockerhub/client.ts";
import { callDockerHub, isMissingScope } from "../dockerhub/errors.ts";
import type { InstallValidation } from "./definition.ts";

/**
 * Who the dry-run invite is for: an address no one can hold. `example.com` is
 * reserved for documentation and takes no mail, so no Docker account can have
 * confirmed it.
 *
 * It doesn't go through the allowed-domain check. That gates acting for a
 * person, and there's no person here.
 */
const DRY_RUN_INVITE: NewInvite = {
  email: "p0-install-check@example.com",
  role: "member",
};

/**
 * Whether the token may do what `check` does. Only a 401 or a 403 says it
 * may not: that's what a missing scope looks like. Anything else Docker Hub
 * answers with fails the call.
 */
const passes = async (check: () => Promise<unknown>): Promise<boolean> => {
  try {
    await check();
    return true;
  } catch (error) {
    if (isMissingScope(error)) return false;
    throw error;
  }
};

/**
 * The install checks, each reported separately so P0 can say what to fix. A
 * token Docker Hub won't exchange fails the other two without asking.
 */
export const getInstallValidation = async (
  docker: Pick<
    DockerHubClient,
    "dryRunInvite" | "isTokenAccepted" | "readOneMember"
  >
): Promise<InstallValidation> => {
  const allowedDomains = requireAllowedDomains().pattern;
  if (!(await docker.isTokenAccepted())) {
    return {
      tokenAccepted: false,
      canReadMembers: false,
      canInvite: false,
      allowedDomains,
    };
  }
  const canReadMembers = await passes(() => docker.readOneMember());
  // Any 2xx passes: the status Docker Hub gives the invitee is about the
  // address or the org's seats, not the token.
  const canInvite = await passes(() => docker.dryRunInvite(DRY_RUN_INVITE));
  return { tokenAccepted: true, canReadMembers, canInvite, allowedDomains };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure.input(orgCredentials.parse).query(async ({ input, ctx }) => {
      const { org } = input;
      const logger = ctx.logger.child({ org });
      const validation = await callDockerHub(
        () =>
          getInstallValidation(newDockerHubClient({ ...input, log: logger })),
        { org }
      );
      logger.info(validation, "validated the Docker Hub organization");
      return validation;
    }),
  });
};

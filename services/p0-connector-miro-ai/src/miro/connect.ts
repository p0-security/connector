import { ConnectorError, type Logger } from "@p0security/connector-core";

import { readToken } from "../secrets.ts";
import type { Team } from "../team.ts";
import {
  type MiroClient,
  type Pause,
  newMiroApi,
  newMiroClient,
} from "./client.ts";
import { toConnectorError } from "./errors.ts";

/** A client for the team's Miro, with the token its secret holds. */
export const connectMiro = async (
  { secret }: Pick<Team, "secret">,
  logger: Logger,
  pause?: Pause
): Promise<MiroClient> =>
  newMiroClient(
    newMiroApi({
      logger,
      token: await readToken(secret, logger),
      ...(pause === undefined ? {} : { pause }),
    })
  );

/**
 * Runs `run`, and maps a failed Miro call onto the error P0 shows. A
 * `ConnectorError` passes as it is.
 */
export const callMiro = async <T>(run: () => Promise<T>): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    const mapped = toConnectorError(error);
    if (mapped instanceof ConnectorError) throw mapped;
    throw error;
  }
};

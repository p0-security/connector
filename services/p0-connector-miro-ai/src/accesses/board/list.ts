import { type Logger, throwAssertNever } from "@p0security/connector-core";

import type { MiroClient } from "../../miro/client.ts";
import { callMiro, connectMiro } from "../../miro/connect.ts";
import type { Team } from "../../team.ts";
import {
  type ListerQuery,
  type ListerResponse,
  listerQuery,
} from "./definition.ts";
import { checkTeam, findTeamMember } from "./members.ts";

/**
 * Runs `read` with a client for the team, once the token is checked to be
 * the team's, and maps Miro's failures onto the errors P0 shows.
 */
const queryMiro = async (
  team: Team,
  logger: Logger,
  read: (miro: MiroClient, teamName: string) => Promise<ListerResponse>
): Promise<ListerResponse> => {
  const miro = await connectMiro(team, logger);
  return callMiro(async () => {
    const { teamName } = await checkTeam(
      miro,
      { operation: "grant", teamId: team.teamId },
      logger
    );
    return read(miro, teamName);
  });
};

/**
 * Answers a {@link ListerQuery}. Each answer is described on
 * {@link listerQuery}.
 */
export const list = async (
  logger: Logger,
  input: ListerQuery
): Promise<ListerResponse> => {
  // The framework runs no `validation` before `list`, so the query is
  // checked again here: each id in it becomes a path segment.
  const query = listerQuery.parse(input);
  const log = logger.child({ access: "board", type: query.type });
  switch (query.type) {
    case "member": {
      const { context, email } = query;
      return queryMiro(context, log, async (miro, teamName) => {
        const user = await findTeamMember(
          miro,
          { email, teamId: context.teamId, teamName },
          log
        );
        return [{ key: user.id, value: user.email ?? email }];
      });
    }
    case "member-state": {
      const { context, boardId, memberId } = query;
      return queryMiro(context, log, async (miro) => {
        const members = await miro.listBoardMembers(boardId);
        const role = members.find(({ id }) => id === memberId)?.role ?? "none";
        return [{ key: "role", value: role }];
      });
    }
    case "boards":
      return queryMiro(query.context, log, async (miro) =>
        (await miro.listShareableBoards(query.context.teamId)).map(
          ({ id, name }) => ({ key: id, value: name })
        )
      );
    default:
      throw throwAssertNever(query);
  }
};

import {
  DescribeSessionsCommand,
  SSMClient,
  type Session,
  TerminateSessionCommand,
} from "@aws-sdk/client-ssm";
import {
  type AnyConnectorTRPCInstance,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { nameOf, toConnectorError } from "../ssm/errors.ts";
import {
  type EndSessionsInput,
  type EndSessionsResult,
  endSessionsInput,
} from "./definition.ts";

export type SessionsDependencies = {
  client?: Pick<SSMClient, "send">;
};

/** How many sessions it ends at once, as P0's SSH integration does. */
const MAX_CONCURRENCY = 5;

type OwnedSession = Session & { SessionId: string };

const isRejected = (
  result: PromiseSettledResult<unknown>
): result is PromiseRejectedResult => result.status === "rejected";

/**
 * Ends the SSM sessions a gateway session still has open on one instance,
 * so that a revoke also closes what is already connected.
 *
 * The gateway assumes the agent's role with the gateway session's id as the
 * role session name, so that id is the last part of each session's owner:
 * `arn:aws:sts::<account>:assumed-role/<role>/<session id>`. SSM can't
 * filter on part of an owner, so this lists the instance's sessions and
 * matches the owner here.
 *
 * A session SSM refuses to end doesn't stop the others. The result counts
 * it, and the caller decides what a failure means.
 */
export const endSessions = async (
  input: EndSessionsInput,
  logger: Logger,
  dependencies: SessionsDependencies = {}
): Promise<EndSessionsResult> => {
  const { instance, sessionId, requestId } = input;
  const { client = new SSMClient({ region: instance.region }) } = dependencies;
  const ownerSuffix = `/${sessionId}`;
  /** An open session on the instance that the gateway session owns. */
  const isOwned = (session: Session): session is OwnedSession =>
    Boolean(session.SessionId) &&
    session.Target === instance.id &&
    session.Owner?.endsWith(ownerSuffix) === true;

  const open: string[] = [];
  let nextToken: string | undefined;
  do {
    const page = await client
      .send(
        new DescribeSessionsCommand({
          State: "Active",
          Filters: [{ key: "Target", value: instance.id }],
          NextToken: nextToken,
        })
      )
      .catch((error: unknown) => {
        throw toConnectorError(error);
      });
    const sessions = page.Sessions ?? [];
    open.push(...sessions.filter(isOwned).map(({ SessionId }) => SessionId));
    nextToken = page.NextToken;
  } while (nextToken);

  const failures: string[] = [];
  for (let start = 0; start < open.length; start += MAX_CONCURRENCY) {
    const results = await Promise.allSettled(
      open
        .slice(start, start + MAX_CONCURRENCY)
        .map((SessionId) =>
          client.send(new TerminateSessionCommand({ SessionId }))
        )
    );
    failures.push(
      ...results
        .filter(isRejected)
        .map(({ reason }) => nameOf(reason) ?? "unknown")
    );
  }

  const result = { matched: open.length, failed: failures.length };
  // The instance and the request, so the log shows which revoke ended which
  // sessions.
  const where = {
    instanceId: instance.id,
    ...(requestId ? { requestId } : {}),
  };
  if (failures.length > 0) {
    logger.warn(
      { ...result, ...where, awsErrors: [...new Set(failures)] },
      "could not end every open session"
    );
  } else {
    logger.info({ ...result, ...where }, "ended the open sessions");
  }
  return result;
};

/** `sessions.end`, the route that ends a gateway session's SSM sessions. */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: SessionsDependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);
  return t.router({
    end: procedure
      .input(endSessionsInput.parse)
      .mutation(({ input, ctx }): Promise<EndSessionsResult> =>
        endSessions(input, ctx.logger, dependencies)
      ),
  });
};

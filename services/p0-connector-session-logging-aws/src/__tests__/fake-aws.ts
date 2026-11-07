import type { AwsDependencies } from "../aws.ts";

type Command = { constructor: { name: string }; input: unknown };

export type StartedQuery = {
  id: string;
  logGroupName: string;
  queryString: string;
  /** Epoch seconds, as StartQuery takes them. */
  startTime: number;
  endTime: number;
  polls: number;
};

type Row = Record<string, string>;

/** An Insights answer: rows once complete, or "running" while it isn't. */
export type InsightsAnswer = (query: StartedQuery) => Row[] | "running";

export const NOW = Date.parse("2026-11-01T14:00:00Z");

/**
 * AWS for tests: each command is answered by the handler registered under
 * its class name, and Logs Insights queries by `insights`. Waiting advances
 * the clock instead of sleeping.
 */
export const fakeAws = (insights: InsightsAnswer = () => []) => {
  let clock = NOW;
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const queries: StartedQuery[] = [];
  const handlers: Record<string, (input: Record<string, unknown>) => unknown> =
    {
      DescribeLogGroupsCommand: (input) => ({
        logGroups: [
          {
            logGroupName: input.logGroupNamePrefix,
            arn: `arn:aws:logs:us-west-2:123456789012:log-group:${String(input.logGroupNamePrefix)}:*`,
            retentionInDays: 365,
          },
        ],
      }),
      StartQueryCommand: (input) => {
        const query: StartedQuery = {
          id: `query-${queries.length + 1}`,
          logGroupName: input.logGroupName as string,
          queryString: input.queryString as string,
          startTime: input.startTime as number,
          endTime: input.endTime as number,
          polls: 0,
        };
        queries.push(query);
        return { queryId: query.id };
      },
      GetQueryResultsCommand: (input) => {
        const query = queries.find((q) => q.id === input.queryId);
        if (!query) {
          throw Object.assign(new Error("no such query"), {
            name: "ResourceNotFoundException",
          });
        }
        query.polls++;
        const answer = insights(query);
        if (answer === "running") return { status: "Running", results: [] };
        return {
          status: "Complete",
          results: answer.map((row) =>
            Object.entries(row).map(([field, value]) => ({ field, value }))
          ),
        };
      },
    };
  const send = async (command: Command) => {
    const name = command.constructor.name;
    const input = command.input as Record<string, unknown>;
    calls.push({ command: name, input });
    const handler = handlers[name];
    if (!handler) throw new Error(`unexpected AWS call ${name}`);
    return handler(input);
  };
  const dependencies: AwsDependencies = {
    logs: { send },
    cloudtrail: { send },
    now: () => clock,
    wait: async (ms) => {
      clock += ms;
    },
  };
  return {
    dependencies,
    calls,
    queries,
    on: (
      command: string,
      handler: (input: Record<string, unknown>) => unknown
    ) => {
      handlers[command] = handler;
    },
    setNow: (ms: number) => {
      clock = ms;
    },
  };
};

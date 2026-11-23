import {
  DescribeSessionsCommand,
  TerminateSessionCommand,
} from "@aws-sdk/client-ssm";
import { describe, expect, it } from "vitest";

import {
  type Command,
  dataOf,
  recordingLogger,
  sdkError,
} from "../../__tests__/fakes.ts";
import { t } from "../../router.ts";
import { endSessionsInput } from "../definition.ts";
import { endSessions, router } from "../handler.ts";

const INSTANCE = { id: "i-0123456789abcdef0", region: "us-west-2" };
const SESSION_ID = "0b0e1c1a-6f0e-4f43-9d1e-2f6b1f0a9c11";
const input = { instance: INSTANCE, sessionId: SESSION_ID };
const ROLE = "arn:aws:sts::123456789012:assumed-role/p0-agent-role";

type Session = { SessionId: string; Target?: string; Owner: string };

/** An SSM session the gateway session owns on the instance. */
const ours = (id: string): Session => ({
  SessionId: id,
  Target: INSTANCE.id,
  Owner: `${ROLE}/${SESSION_ID}`,
});

/**
 * SSM with the given pages of sessions. `refuses` names the sessions it
 * won't end. It keeps every call, and the most ends it saw in flight.
 */
const fakeSsm = (pages: Session[][], refuses: string[] = []) => {
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const ended: string[] = [];
  const flight = { now: 0, most: 0 };
  const send = async (command: Command) => {
    calls.push({ command: command.constructor.name, input: command.input });
    if (command instanceof DescribeSessionsCommand) {
      const index = Number(command.input.NextToken ?? 0);
      return {
        Sessions: pages[index] ?? [],
        NextToken: index + 1 < pages.length ? String(index + 1) : undefined,
      };
    }
    if (command instanceof TerminateSessionCommand) {
      const id = command.input.SessionId ?? "";
      flight.now++;
      flight.most = Math.max(flight.most, flight.now);
      await new Promise((resolve) => setImmediate(resolve));
      flight.now--;
      if (refuses.includes(id)) throw sdkError("InternalServerError");
      ended.push(id);
      return { SessionId: id };
    }
    throw new Error(`unexpected AWS call ${command.constructor.name}`);
  };
  return { client: { send }, calls, ended, flight };
};

const end = (ssm: ReturnType<typeof fakeSsm>, log = recordingLogger()) =>
  endSessions(input, log.logger, { client: ssm.client });

describe("endSessions", () => {
  it("ends nothing when the instance has no open session", async () => {
    const ssm = fakeSsm([[]]);
    await expect(end(ssm)).resolves.toEqual({ matched: 0, failed: 0 });
    expect(ssm.calls).toEqual([
      {
        command: "DescribeSessionsCommand",
        input: {
          State: "Active",
          Filters: [{ key: "Target", value: INSTANCE.id }],
          NextToken: undefined,
        },
      },
    ]);
  });

  it("ends each open session the gateway session owns", async () => {
    const ssm = fakeSsm([[ours("s-1"), ours("s-2")]]);
    await expect(end(ssm)).resolves.toEqual({ matched: 2, failed: 0 });
    expect(ssm.ended.sort()).toEqual(["s-1", "s-2"]);
  });

  it("logs the instance and the counts, and the request when it is given one", async () => {
    const log = recordingLogger();
    await end(fakeSsm([[ours("s-1"), ours("s-2")]]), log);
    await endSessions({ ...input, requestId: "r1" }, log.logger, {
      client: fakeSsm([[ours("s-1")]]).client,
    });
    expect(log.lines).toEqual([
      [
        { matched: 2, failed: 0, instanceId: INSTANCE.id },
        "ended the open sessions",
      ],
      [
        { matched: 1, failed: 0, instanceId: INSTANCE.id, requestId: "r1" },
        "ended the open sessions",
      ],
    ]);
  });

  it("leaves a session that someone else owns", async () => {
    const ssm = fakeSsm([
      [
        ours("s-1"),
        { ...ours("s-2"), Owner: `${ROLE}/another-gateway-session` },
        { ...ours("s-3"), Owner: `${ROLE}/x${SESSION_ID}` },
        { ...ours("s-4"), Owner: `${ROLE}/${SESSION_ID}/more` },
        { ...ours("s-5"), Owner: "arn:aws:iam::123456789012:user/alice" },
        { ...ours("s-6"), Target: "i-0fedcba9876543210" },
      ],
    ]);
    await expect(end(ssm)).resolves.toEqual({ matched: 1, failed: 0 });
    expect(ssm.ended).toEqual(["s-1"]);
  });

  it("reads every page, through one with no session of ours", async () => {
    const ssm = fakeSsm([
      [ours("s-1")],
      [{ ...ours("s-2"), Owner: `${ROLE}/another-gateway-session` }],
      [ours("s-3")],
    ]);
    await expect(end(ssm)).resolves.toEqual({ matched: 2, failed: 0 });
    expect(ssm.ended.sort()).toEqual(["s-1", "s-3"]);
    expect(
      ssm.calls
        .filter(({ command }) => command === "DescribeSessionsCommand")
        .map(({ input }) => input.NextToken)
    ).toEqual([undefined, "1", "2"]);
  });

  it("ends the others when one session can't be ended, and reports it", async () => {
    const ssm = fakeSsm([[ours("s-1"), ours("s-2"), ours("s-3")]], ["s-2"]);
    const log = recordingLogger();
    await expect(end(ssm, log)).resolves.toEqual({ matched: 3, failed: 1 });
    expect(ssm.ended.sort()).toEqual(["s-1", "s-3"]);
    expect(log.lines).toContainEqual([
      {
        matched: 3,
        failed: 1,
        instanceId: INSTANCE.id,
        awsErrors: ["InternalServerError"],
      },
      "could not end every open session",
    ]);
  });

  it("ends at most five sessions at once", async () => {
    const sessions = Array.from({ length: 12 }, (_, i) => ours(`s-${i}`));
    const ssm = fakeSsm([sessions]);
    await expect(end(ssm)).resolves.toEqual({ matched: 12, failed: 0 });
    expect(ssm.flight.most).toBe(5);
    expect(ssm.ended).toHaveLength(12);
  });

  it("fails when SSM won't list the sessions", async () => {
    const client = {
      send: async () => {
        throw sdkError(
          "AccessDeniedException",
          "not authorized to perform: ssm:DescribeSessions"
        );
      },
    };
    const data = await dataOf(
      endSessions(input, recordingLogger().logger, { client })
    );
    expect(data.type).toBe("insufficient_privileges");
  });
});

describe("the sessions route", () => {
  it("serves end, and returns what it did", async () => {
    const ssm = fakeSsm([[ours("s-1")]]);
    const caller = router(t, { client: ssm.client }).createCaller({
      logger: recordingLogger().logger,
    });
    await expect(caller.end(input)).resolves.toEqual({ matched: 1, failed: 0 });
  });

  it.each([
    "",
    "a",
    "a/b",
    `role/${SESSION_ID}`,
    "a b",
    "a*",
    "a:b",
    "x".repeat(65),
  ])("refuses the session id %j", (sessionId) => {
    expect(endSessionsInput.safeParse({ ...input, sessionId }).success).toBe(
      false
    );
  });

  it.each([SESSION_ID, "test-session-sid-1", "ab", "x".repeat(64)])(
    "accepts the session id %j",
    (sessionId) => {
      expect(endSessionsInput.safeParse({ ...input, sessionId }).success).toBe(
        true
      );
    }
  );

  it("refuses an instance id that isn't one", () => {
    expect(
      endSessionsInput.safeParse({
        ...input,
        instance: { ...INSTANCE, id: "mi-0123456789abcdef0" },
      }).success
    ).toBe(false);
  });

  it("takes a request id, and does without one", () => {
    expect(endSessionsInput.parse({ ...input, requestId: "r1" })).toEqual({
      ...input,
      requestId: "r1",
    });
    expect(endSessionsInput.parse(input)).toEqual(input);
    expect(
      endSessionsInput.safeParse({ ...input, requestId: "" }).success
    ).toBe(false);
  });
});

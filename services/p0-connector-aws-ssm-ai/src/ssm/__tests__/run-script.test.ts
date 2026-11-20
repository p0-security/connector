import { ConnectorError, type Logger } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  type Command,
  dataOf,
  recordingLogger,
  sdkError,
} from "../../__tests__/fakes.ts";
import type { Instance } from "../../context.ts";
import { RUN_SCRIPT_FAILURES } from "../../failures.ts";
import {
  CommandFailedError,
  type CommandTag,
  type RunScriptDependencies,
  commentOf,
  runScript,
} from "../run-script.ts";

const INSTANCE: Instance = { id: "i-0123456789abcdef0", region: "us-west-2" };
const COMMAND_ID = "11111111-2222-3333-4444-555555555555";
const SCRIPT = "#!/bin/bash\nset -- 'ensure-key' 'argument-in-the-script'\n";

type FakeSsmOptions = {
  sendCommand?: () => unknown;
  /** `ListCommands` pages, in the order the calls get them. */
  listed?: unknown[];
};

/**
 * An SSM client that accepts one command. Each `GetCommandInvocation` takes
 * the next answer, and repeats the last one once they run out. It throws an
 * answer that is an `Error`. `ListCommands` does the same with `listed`, and
 * lists nothing without it.
 */
const fakeSsm = (invocations: unknown[], options: FakeSsmOptions = {}) => {
  const { sendCommand, listed = [{ Commands: [] }] } = options;
  const pages = [...listed];
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  // What each call passed after the command. It is `unknown` because the
  // SDK's `send` also takes a callback there.
  const sent: unknown[] = [];
  const answers = [...invocations];
  const send = async (command: Command, sendOptions?: unknown) => {
    const name = command.constructor.name;
    calls.push({ command: name, input: command.input });
    sent.push(sendOptions);
    switch (name) {
      case "SendCommandCommand":
        return sendCommand
          ? sendCommand()
          : { Command: { CommandId: COMMAND_ID } };
      case "GetCommandInvocationCommand": {
        const answer = answers.length > 1 ? answers.shift() : answers[0];
        if (answer instanceof Error) throw answer;
        return answer;
      }
      case "ListCommandsCommand": {
        const page = pages.length > 1 ? pages.shift() : pages[0];
        if (page instanceof Error) throw page;
        return page;
      }
      default:
        return {};
    }
  };
  return { client: { send }, send, calls, sent };
};

const TAG: CommandTag = {
  group: "p0-ssh-ai:m1",
  action: "set-sudo-on",
  reusable: true,
};

const run = (
  dependencies: RunScriptDependencies,
  logger?: Logger,
  requestId?: string,
  tag: CommandTag = TAG
) =>
  runScript(
    { instance: INSTANCE, script: SCRIPT, requestId, tag },
    logger ?? recordingLogger().logger,
    { wait: async () => {}, ...dependencies }
  );

/**
 * A clock that moves only when the code waits, so a run reaches the deadline
 * at once.
 */
const fakeClock = () => {
  const waits: number[] = [];
  const clock = { time: 0, waits };
  const dependencies = {
    wait: async (ms: number) => {
      waits.push(ms);
      clock.time += ms;
    },
    now: () => clock.time,
  } satisfies RunScriptDependencies;
  return { clock, dependencies };
};

const SUCCESS = {
  Status: "Success",
  StatusDetails: "Success",
  ResponseCode: 0,
  StandardOutputContent: "host-key-in-the-output\n",
  StandardErrorContent: "",
};

/** The names of the calls a fake took, in order. */
const namesOf = (ssm: ReturnType<typeof fakeSsm>) =>
  ssm.calls.map(({ command }) => command);

/** A command `ListCommands` lists. */
const listedCommand = (
  id: string,
  comment: string,
  status = "InProgress",
  at = 1
) => ({
  CommandId: id,
  Comment: comment,
  Status: status,
  RequestedDateTime: new Date(at),
});

describe("runScript", () => {
  it("sends the script to the one instance and returns its exit code and output", async () => {
    const ssm = fakeSsm([SUCCESS]);
    await expect(run({ client: ssm.client })).resolves.toEqual({
      exitCode: 0,
      stdout: "host-key-in-the-output\n",
      stderr: "",
    });
    expect(ssm.calls).toEqual([
      {
        command: "ListCommandsCommand",
        input: {
          InstanceId: INSTANCE.id,
          Filters: [
            { key: "DocumentName", value: "AWS-RunShellScript" },
            { key: "InvokedAfter", value: expect.any(String) },
          ],
          NextToken: undefined,
        },
      },
      {
        command: "SendCommandCommand",
        input: {
          DocumentName: "AWS-RunShellScript",
          InstanceIds: [INSTANCE.id],
          Comment: "p0-ssh-ai:m1:set-sudo-on",
          Parameters: { commands: [SCRIPT], executionTimeout: ["30"] },
          TimeoutSeconds: 30,
        },
      },
      {
        command: "GetCommandInvocationCommand",
        input: { CommandId: COMMAND_ID, InstanceId: INSTANCE.id },
      },
    ]);
  });

  it("polls until the command ends, through an invocation SSM doesn't list yet", async () => {
    const ssm = fakeSsm([
      sdkError("InvocationDoesNotExist"),
      { Status: "Pending" },
      { Status: "InProgress" },
      { Status: "Delayed" },
      SUCCESS,
    ]);
    const { clock, dependencies } = fakeClock();
    await run({ client: ssm.client, ...dependencies });
    expect(clock.waits).toEqual([500, 500, 1000, 2000, 2000]);
  });

  it("polls again after a throttled poll", async () => {
    const ssm = fakeSsm([
      sdkError("ThrottlingException", "Rate exceeded"),
      { Status: "InProgress" },
      sdkError("ThrottlingException", "Rate exceeded"),
      SUCCESS,
    ]);
    await expect(run({ client: ssm.client })).resolves.toMatchObject({
      exitCode: 0,
    });
  });

  it("never logs the script or its output", async () => {
    const { logger, lines } = recordingLogger();
    await run({ client: fakeSsm([SUCCESS]).client }, logger);
    await run(
      {
        client: fakeSsm([
          { Status: "Failed", ResponseCode: 1, StandardOutputContent: "o" },
        ]).client,
      },
      logger
    ).catch(() => undefined);
    const logged = JSON.stringify(lines);
    expect(lines.length).toBeGreaterThan(0);
    expect(logged).toContain(COMMAND_ID);
    expect(logged).not.toContain("argument-in-the-script");
    expect(logged).not.toContain("host-key-in-the-output");
  });

  it("throws a failed command with its exit code and the end of its stderr", async () => {
    const ssm = fakeSsm([
      {
        Status: "Failed",
        StatusDetails: "Failed",
        ResponseCode: 2,
        StandardOutputContent: "stdout-of-the-failure",
        StandardErrorContent: `${"x".repeat(600)}\nvisudo refused the file\n`,
      },
    ]);
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("unknown");
    expect(data.payload).toEqual({
      reason: "command_failed",
      instanceId: INSTANCE.id,
      commandId: COMMAND_ID,
      exitCode: 2,
      status: "Failed",
    });
    expect(data.message).toMatch(
      /^P0's script on i-0123456789abcdef0 exited with code 2: x+\nvisudo refused the file$/
    );
    expect(data.message.length).toBeLessThan(600);
    expect(JSON.stringify(data)).not.toContain("stdout-of-the-failure");
  });

  it("keeps a failed command's output for the caller, and out of the error's data", async () => {
    const failed = {
      Status: "Failed",
      ResponseCode: 69,
      StandardOutputContent: "stdout-of-the-failure\n",
      StandardErrorContent: "stderr-of-the-failure\n",
    };
    const error = await run(
      { client: fakeSsm([failed]).client },
      undefined,
      "r1"
    ).catch((e: unknown) => e);
    if (!(error instanceof CommandFailedError)) {
      throw new Error(`expected a CommandFailedError, got ${String(error)}`);
    }
    expect(error.output).toEqual({
      exitCode: 69,
      stdout: "stdout-of-the-failure\n",
      stderr: "stderr-of-the-failure\n",
    });
    expect(error.data.payload).toMatchObject({ requestId: "r1" });
    expect(JSON.stringify(error)).not.toContain("stdout-of-the-failure");
  });

  it("puts the caller's request id on every error, and only then", async () => {
    const failed = { Status: "Failed", ResponseCode: 1 };
    const refused = () => {
      throw sdkError("AccessDeniedException", "not authorized");
    };
    const withId = [
      await dataOf(run({ client: fakeSsm([failed]).client }, undefined, "r1")),
      await dataOf(
        run(
          { client: fakeSsm([], { sendCommand: refused }).client },
          undefined,
          "r1"
        )
      ),
    ];
    for (const { payload } of withId) {
      expect(payload).toMatchObject({
        requestId: "r1",
        instanceId: INSTANCE.id,
      });
    }
    const without = await dataOf(run({ client: fakeSsm([failed]).client }));
    expect(without.payload).not.toHaveProperty("requestId");
  });

  describe("at the deadline", () => {
    it("throws a timeout when the script started and didn't finish", async () => {
      const ssm = fakeSsm([{ Status: "Pending" }, { Status: "InProgress" }]);
      const { clock, dependencies } = fakeClock();
      const data = await dataOf(run({ client: ssm.client, ...dependencies }));
      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({
        reason: "timeout",
        instanceId: INSTANCE.id,
        commandId: COMMAND_ID,
      });
      expect(data.message).toBe(
        "P0's script on i-0123456789abcdef0 didn't finish in 20 seconds. Try the request again."
      );
      expect(clock.time).toBe(20_000);
    });

    it.each([
      ["stayed pending", [{ Status: "Pending" }]],
      ["was delayed", [{ Status: "Pending" }, { Status: "Delayed" }]],
      ["was never listed", [sdkError("InvocationDoesNotExist")]],
    ])(
      "throws an unreachable instance when the command %s",
      async (_name, invocations) => {
        const ssm = fakeSsm(invocations);
        const { clock, dependencies } = fakeClock();
        const data = await dataOf(run({ client: ssm.client, ...dependencies }));
        expect(data.type).toBe("object_not_found");
        expect(data.payload).toEqual({
          reason: "instance_unreachable",
          instanceId: INSTANCE.id,
          commandId: COMMAND_ID,
        });
        expect(clock.time).toBe(20_000);
      }
    );

    it("never waits past it", async () => {
      const ssm = fakeSsm([{ Status: "InProgress" }]);
      const { clock, dependencies } = fakeClock();
      const waited: { start: number; ms: number }[] = [];
      const slow: RunScriptDependencies = {
        // Each call to SSM takes 700 ms.
        client: {
          send: async (command: Command) => {
            clock.time += 700;
            return ssm.send(command);
          },
        },
        now: dependencies.now,
        wait: async (ms) => {
          waited.push({ start: clock.time, ms });
          await dependencies.wait(ms);
        },
      };
      await dataOf(run(slow));
      expect(waited.length).toBeGreaterThan(3);
      for (const { start, ms } of waited) {
        expect(start + ms).toBeLessThanOrEqual(20_000);
      }
      // runScript cut the last wait short to end on the deadline.
      expect(waited.at(-1)?.ms).toBeLessThan(2000);
    });

    it("reports a throttle when no poll was ever answered", async () => {
      const ssm = fakeSsm([sdkError("ThrottlingException", "Rate exceeded")]);
      const { dependencies } = fakeClock();
      const data = await dataOf(run({ client: ssm.client, ...dependencies }));
      expect(data.type).toBe("rate_limited");
      expect(data.message).toBe(
        "SSM throttled the connector. Try again in a moment."
      );
    });
  });

  it("throws a timeout when SSM reports the script ran too long, and doesn't name the deadline", async () => {
    const ssm = fakeSsm([
      { Status: "TimedOut", StatusDetails: "ExecutionTimedOut" },
    ]);
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.payload).toMatchObject({ reason: "timeout" });
    expect(data.message).toBe(
      "SSM stopped P0's script on i-0123456789abcdef0 at its 30-second execution timeout. Try the request again."
    );
  });

  it("throws an unreachable instance when SSM refuses the instance id", async () => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw sdkError("InvalidInstanceId");
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({
      reason: "instance_unreachable",
      instanceId: INSTANCE.id,
    });
    expect(namesOf(ssm)).not.toContain("GetCommandInvocationCommand");
  });

  it("throws a validation error, which the requester reads, for a Windows or macOS instance", async () => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw sdkError("UnsupportedPlatformType");
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      awsError: "UnsupportedPlatformType",
      instanceId: INSTANCE.id,
    });
    expect(data.message).toBe(
      "SSH (AI) works only on Linux instances, and i-0123456789abcdef0 is not one. Request access to a Linux instance instead."
    );
    expect(namesOf(ssm)).not.toContain("GetCommandInvocationCommand");
  });

  it.each([
    ["TimedOut", "DeliveryTimedOut"],
    ["TimedOut", "Delivery Timed Out"],
    ["Failed", "Undeliverable"],
  ])(
    "throws an unreachable instance when a command ends %s with %s",
    async (Status, StatusDetails) => {
      const ssm = fakeSsm([{ Status, StatusDetails, ResponseCode: -1 }]);
      const data = await dataOf(run({ client: ssm.client }));
      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        reason: "instance_unreachable",
        instanceId: INSTANCE.id,
        commandId: COMMAND_ID,
      });
    }
  );

  it("names every failure it throws in the closed set", () => {
    expect(RUN_SCRIPT_FAILURES).toEqual([
      "timeout",
      "command_failed",
      "instance_unreachable",
      "busy",
    ]);
  });

  it("maps a refused call, and keeps AWS's account of it", async () => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw sdkError(
          "AccessDeniedException",
          "User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: ssm:SendCommand"
        );
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({
      awsError: "AccessDeniedException",
      instanceId: INSTANCE.id,
    });
    expect(data.message).toBe(
      "SSM refused the connector's role: User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: ssm:SendCommand. Check the role's SSM permissions."
    );
  });

  it("keeps the script out of an error whose AWS message quotes the request", async () => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw sdkError(
          "ValidationException",
          `Value '[${SCRIPT}]' at 'parameters' failed to satisfy constraint`
        );
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("upstream_unavailable");
    expect(data.message).toBe(
      "SSM failed the call (ValidationException). Try again, and contact P0 support if it keeps failing."
    );
    expect(JSON.stringify(data)).not.toContain("argument-in-the-script");
  });

  it.each([
    ["a timeout", sdkError("TimeoutError"), { awsError: "TimeoutError" }],
    [
      "a reset socket",
      Object.assign(new Error("read ECONNRESET"), { code: "ECONNRESET" }),
      { awsError: "Error" },
    ],
  ])("counts %s as SSM being unavailable", async (_name, thrown, payload) => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw thrown;
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({ ...payload, instanceId: INSTANCE.id });
  });

  it("fails a poll that SSM refuses", async () => {
    const ssm = fakeSsm([sdkError("AccessDeniedException", "not authorized")]);
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("insufficient_privileges");
  });

  it("never cancels a command, so no kill frees the instance's lock early", async () => {
    const outcomes = [
      [{ Status: "InProgress" }],
      [{ Status: "InProgress" }, sdkError("ECONNRESET")],
      [{ Status: "InProgress" }, sdkError("AbortError")],
      [{ Status: "Pending" }],
    ];
    for (const invocations of outcomes) {
      const ssm = fakeSsm(invocations);
      const { dependencies } = fakeClock();
      await dataOf(run({ client: ssm.client, ...dependencies }));
      expect(namesOf(ssm)).not.toContain("CancelCommandCommand");
    }
  });

  it("gives every call to SSM a signal that stops it", async () => {
    const ssm = fakeSsm([{ Status: "InProgress" }]);
    const { dependencies } = fakeClock();
    await dataOf(run({ client: ssm.client, ...dependencies }));
    for (const options of ssm.sent) {
      expect(options).toEqual({ abortSignal: expect.any(AbortSignal) });
    }
  });

  it("throws a timeout when sending the command runs into the deadline", async () => {
    const ssm = fakeSsm([], {
      sendCommand: () => {
        throw sdkError("AbortError");
      },
    });
    const data = await dataOf(run({ client: ssm.client }));
    expect(data.type).toBe("upstream_unavailable");
    expect(data.payload).toEqual({
      reason: "timeout",
      instanceId: INSTANCE.id,
    });
  });

  it("throws a timeout when a poll runs into the deadline", async () => {
    const ssm = fakeSsm([{ Status: "InProgress" }, sdkError("AbortError")]);
    const { dependencies } = fakeClock();
    const data = await dataOf(run({ client: ssm.client, ...dependencies }));
    expect(data.payload).toMatchObject({ reason: "timeout" });
  });

  describe("a command an earlier try sent", () => {
    it("is taken over when it is the same action, with nothing sent", async () => {
      const ssm = fakeSsm([SUCCESS], {
        listed: [
          {
            Commands: [listedCommand("earlier", "p0-ssh-ai:m1:set-sudo-on")],
          },
        ],
      });
      const { logger, lines } = recordingLogger();
      await expect(run({ client: ssm.client }, logger)).resolves.toMatchObject({
        exitCode: 0,
      });
      expect(namesOf(ssm)).toEqual([
        "ListCommandsCommand",
        "GetCommandInvocationCommand",
      ]);
      expect(ssm.calls[1]?.input).toEqual({
        CommandId: "earlier",
        InstanceId: INSTANCE.id,
      });
      expect(lines).toContainEqual([
        { instanceId: INSTANCE.id, commandId: "earlier" },
        "took over the SSM command an earlier try sent",
      ]);
    });

    it("is waited for when it is another action of the group, then this one is sent", async () => {
      const other = listedCommand("earlier", "p0-ssh-ai:m1:set-sudo-off");
      const ssm = fakeSsm([SUCCESS], {
        listed: [
          { Commands: [other] },
          { Commands: [other] },
          { Commands: [] },
        ],
      });
      const { clock, dependencies } = fakeClock();
      await run({ client: ssm.client, ...dependencies });
      expect(namesOf(ssm)).toEqual([
        "ListCommandsCommand",
        "ListCommandsCommand",
        "ListCommandsCommand",
        "SendCommandCommand",
        "GetCommandInvocationCommand",
      ]);
      expect(clock.waits.slice(0, 2)).toEqual([500, 500]);
    });

    it("is waited for, never taken over, when its action isn't reusable", async () => {
      const tag = { ...TAG, action: "ensure-key", reusable: false };
      const same = listedCommand("earlier", "p0-ssh-ai:m1:ensure-key");
      const ssm = fakeSsm([SUCCESS], {
        listed: [{ Commands: [same] }, { Commands: [] }],
      });
      await run({ client: ssm.client }, undefined, undefined, tag);
      expect(namesOf(ssm)).toEqual([
        "ListCommandsCommand",
        "ListCommandsCommand",
        "SendCommandCommand",
        "GetCommandInvocationCommand",
      ]);
    });

    it("takes over the newest of the same action once the others end", async () => {
      const ssm = fakeSsm([SUCCESS], {
        listed: [
          {
            Commands: [
              listedCommand("newer", "p0-ssh-ai:m1:set-sudo-on", "Pending", 5),
              listedCommand(
                "older",
                "p0-ssh-ai:m1:set-sudo-on",
                "InProgress",
                2
              ),
            ],
          },
        ],
      });
      await run({ client: ssm.client });
      expect(ssm.calls.at(-1)?.input).toMatchObject({ CommandId: "newer" });
    });

    it("throws busy, with nothing sent, while another action still runs at the deadline", async () => {
      const ssm = fakeSsm([], {
        listed: [
          { Commands: [listedCommand("earlier", "p0-ssh-ai:m1:remove-key")] },
        ],
      });
      const { clock, dependencies } = fakeClock();
      const data = await dataOf(run({ client: ssm.client, ...dependencies }));
      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toEqual({
        reason: "busy",
        instanceId: INSTANCE.id,
        earlierCommandIds: "earlier",
      });
      expect(clock.time).toBe(20_000);
      expect(namesOf(ssm)).not.toContain("SendCommandCommand");
    });

    it("doesn't count commands that ended, or that belong to another group", async () => {
      const ssm = fakeSsm([SUCCESS], {
        listed: [
          {
            Commands: [
              listedCommand("done", "p0-ssh-ai:m1:remove-key", "Success"),
              listedCommand(
                "cancelled",
                "p0-ssh-ai:m1:remove-key",
                "Cancelled"
              ),
              listedCommand("other-group", "p0-ssh-ai:m10:remove-key"),
              { CommandId: "no-comment", Status: "InProgress" },
            ],
          },
        ],
      });
      await run({ client: ssm.client });
      expect(namesOf(ssm)).toEqual([
        "ListCommandsCommand",
        "SendCommandCommand",
        "GetCommandInvocationCommand",
      ]);
    });

    it("is found on any page of the listing", async () => {
      const other = listedCommand("earlier", "p0-ssh-ai:m1:remove-key");
      const ssm = fakeSsm([SUCCESS], {
        listed: [
          { Commands: [], NextToken: "page-2" },
          { Commands: [other] },
          { Commands: [] },
        ],
      });
      await run({ client: ssm.client });
      expect(ssm.calls[1]?.input).toMatchObject({ NextToken: "page-2" });
      expect(namesOf(ssm)).toEqual([
        "ListCommandsCommand",
        "ListCommandsCommand",
        "ListCommandsCommand",
        "SendCommandCommand",
        "GetCommandInvocationCommand",
      ]);
    });

    it("throws a timeout, with nothing sent, when the listing runs into the deadline", async () => {
      const ssm = fakeSsm([], { listed: [sdkError("AbortError")] });
      const data = await dataOf(run({ client: ssm.client }));
      expect(data.payload).toEqual({
        reason: "timeout",
        instanceId: INSTANCE.id,
      });
      expect(namesOf(ssm)).not.toContain("SendCommandCommand");
    });

    it("fails the run when SSM refuses to list commands", async () => {
      const ssm = fakeSsm([], {
        listed: [sdkError("AccessDeniedException", "not authorized")],
      });
      const data = await dataOf(run({ client: ssm.client }));
      expect(data.type).toBe("insufficient_privileges");
      expect(namesOf(ssm)).not.toContain("SendCommandCommand");
    });
  });

  it("refuses a comment longer than SSM keeps", () => {
    expect(() =>
      commentOf({
        group: "g".repeat(90),
        action: "set-sudo-on",
        reusable: true,
      })
    ).toThrow(ConnectorError);
    expect(commentOf(TAG)).toBe("p0-ssh-ai:m1:set-sudo-on");
  });
});

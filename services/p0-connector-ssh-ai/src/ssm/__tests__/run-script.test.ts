import type { Logger } from "@p0security/connector-core";
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
  type RunScriptDependencies,
  runScript,
} from "../run-script.ts";

const INSTANCE: Instance = { id: "i-0123456789abcdef0", region: "us-west-2" };
const COMMAND_ID = "11111111-2222-3333-4444-555555555555";
const SCRIPT = "#!/bin/bash\nset -- 'ensure-key' 'argument-in-the-script'\n";

type FakeSsmOptions = { sendCommand?: () => unknown; refuseCancel?: boolean };

/**
 * An SSM client that accepts one command. Each `GetCommandInvocation` takes
 * the next answer, and repeats the last one once they run out. It throws an
 * answer that is an `Error`. `refuseCancel` makes `CancelCommand` fail.
 */
const fakeSsm = (invocations: unknown[], options: FakeSsmOptions = {}) => {
  const { sendCommand, refuseCancel = false } = options;
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const answers = [...invocations];
  const send = async (command: Command) => {
    const name = command.constructor.name;
    calls.push({ command: name, input: command.input });
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
      case "CancelCommandCommand":
        if (refuseCancel) throw sdkError("AccessDeniedException");
        return {};
      default:
        return {};
    }
  };
  return { client: { send }, send, calls };
};

const run = (
  dependencies: RunScriptDependencies,
  logger?: Logger,
  requestId?: string
) =>
  runScript(
    { instance: INSTANCE, script: SCRIPT, requestId },
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

const CANCEL = {
  command: "CancelCommandCommand",
  input: { CommandId: COMMAND_ID, InstanceIds: [INSTANCE.id] },
};

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
        command: "SendCommandCommand",
        input: {
          DocumentName: "AWS-RunShellScript",
          InstanceIds: [INSTANCE.id],
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
      expect(ssm.calls.at(-1)).toEqual(CANCEL);
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
        // So the instance doesn't run it when its agent comes back.
        expect(ssm.calls.at(-1)).toEqual(CANCEL);
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
      expect(ssm.calls.at(-1)).toEqual(CANCEL);
    });

    it("warns when the command can't be cancelled, without the script", async () => {
      const ssm = fakeSsm([{ Status: "InProgress" }], { refuseCancel: true });
      const { logger, lines } = recordingLogger();
      const { dependencies } = fakeClock();
      const data = await dataOf(
        run({ client: ssm.client, ...dependencies }, logger)
      );
      expect(data.payload).toMatchObject({ reason: "timeout" });
      expect(lines).toContainEqual([
        {
          instanceId: INSTANCE.id,
          commandId: COMMAND_ID,
          awsError: "AccessDeniedException",
        },
        "could not cancel the SSM command",
      ]);
      expect(JSON.stringify(lines)).not.toContain("argument-in-the-script");
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
    expect(ssm.calls).toHaveLength(1);
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
    expect(ssm.calls).toHaveLength(1);
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
});

import {
  CancelCommandCommand,
  GetCommandInvocationCommand,
  type GetCommandInvocationCommandOutput,
  SSMClient,
  SendCommandCommand,
} from "@aws-sdk/client-ssm";
import {
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  throwAssertNever,
} from "@p0security/connector-core";

import type { Instance } from "../context.ts";
import type { RunScriptFailure } from "../failures.ts";
import { isNamed, nameOf, toConnectorError } from "./errors.ts";

/** AWS's own document, which runs a shell script on a Linux instance. */
const RUN_SHELL_SCRIPT_DOCUMENT = "AWS-RunShellScript";

// P0 holds a 60-second lock around a whole grant, and a grant makes more
// than one call. Each call gets 20 seconds, which leaves room for the rest.
export const COMMAND_DEADLINE_MS = 20_000;

// SSM's minimum. A command the instance hasn't picked up by then never runs,
// so a command that timed out here can't start minutes later.
const DELIVERY_TIMEOUT_SECONDS = 30;

// SSM stops a script that runs longer than this on the instance. A hung
// script holds the instance's P0 lock, which P0's SSH integration takes
// too, and the document's own default is an hour. It is past the deadline,
// so SSM never stops a run this client still waits for.
export const EXECUTION_TIMEOUT_SECONDS = 30;

const POLL_INTERVALS_MS = [500, 500, 1000];

/** The wait between polls once the intervals above run out. */
const LAST_POLL_INTERVAL_MS = 2000;

/** How much of a failed script's stderr its error keeps. */
const STDERR_TAIL_CHARS = 500;

/** The end of a script's stderr, as much as a failed script's error keeps. */
export const stderrTailOf = (stderr: string) =>
  stderr.trim().slice(-STDERR_TAIL_CHARS);

export type ScriptRun = {
  instance: Instance;
  script: string;
  /** The request the run belongs to. Every error then carries it. */
  requestId?: string;
};

export type ScriptResult = {
  exitCode: number;
  /** SSM returns the first 24,000 characters of stdout. */
  stdout: string;
  /** SSM returns the first 8,000 characters of stderr. */
  stderr: string;
};

/**
 * A script that exited non-zero. Only the caller knows what its script
 * writes, so the error keeps the run's output for it. The field is private
 * because connector-core logs the error and sends its data to P0, and the
 * output must reach neither.
 */
export class CommandFailedError extends ConnectorError {
  readonly #output: ScriptResult;

  constructor(options: ConnectorErrorOptions, output: ScriptResult) {
    super(options);
    this.#output = output;
  }

  get output(): ScriptResult {
    return this.#output;
  }
}

export type RunScriptDependencies = {
  client?: Pick<SSMClient, "send">;
  wait?: (ms: number) => Promise<void>;
  now?: () => number;
};

/** The command a failure is about. */
type CommandRef = { instanceId: string; commandId?: string };

type RunFailureOptions = {
  reason: RunScriptFailure;
  type: ConnectorErrorOptions["type"];
  message: string;
  command: CommandRef;
  /** More fields for the error's payload. */
  extra?: Record<string, number | string>;
};

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

const toFailureOptions = (
  options: RunFailureOptions
): ConnectorErrorOptions => {
  const { reason, type, message, command, extra = {} } = options;
  const { instanceId, commandId } = command;
  return {
    type,
    message,
    payload: {
      reason,
      instanceId,
      ...(commandId ? { commandId } : {}),
      ...extra,
    },
  };
};

const newRunFailure = (options: RunFailureOptions) =>
  new ConnectorError(toFailureOptions(options));

const newTimeoutError = (command: CommandRef) =>
  newRunFailure({
    reason: "timeout",
    type: "upstream_unavailable",
    message: `P0's script on ${command.instanceId} didn't finish in ${COMMAND_DEADLINE_MS / 1000} seconds. Try the request again.`,
    command,
  });

const newExecutionTimeoutError = (command: CommandRef) =>
  newRunFailure({
    reason: "timeout",
    type: "upstream_unavailable",
    message: `SSM stopped P0's script on ${command.instanceId} at its ${EXECUTION_TIMEOUT_SECONDS}-second execution timeout. Try the request again.`,
    command,
  });

const newUnreachableError = (command: CommandRef) =>
  newRunFailure({
    reason: "instance_unreachable",
    type: "object_not_found",
    message: `SSM can't reach ${command.instanceId}. Check that the instance is running, that SSM manages it in this region, and that its SSM Agent is online.`,
    command,
  });

/**
 * SSM's answer for a Windows or macOS instance. The requester named it, so
 * P0 shows them the message.
 */
const newUnsupportedPlatformError = (instanceId: string) =>
  new ConnectorError({
    type: "validation_error",
    message: `SSH (AI) works only on Linux instances, and ${instanceId} is not one. Request access to a Linux instance instead.`,
    payload: { awsError: "UnsupportedPlatformType", instanceId },
  });

/** A run's exit code and output, with `missingExitCode` when SSM gives none. */
const outputOf = (
  invocation: GetCommandInvocationCommandOutput,
  missingExitCode: number
): ScriptResult => ({
  exitCode: invocation.ResponseCode ?? missingExitCode,
  stdout: invocation.StandardOutputContent ?? "",
  stderr: invocation.StandardErrorContent ?? "",
});

/**
 * A script's stderr is its own account of why it failed, so the message
 * ends with its last 500 characters. A script sent through here must not
 * echo its arguments. Whatever runs on the instance with that stderr open
 * can write into it too. So the message suits an `unknown` error, which P0
 * never shows. A caller that gives the error a type P0 shows builds its own
 * message.
 */
const newCommandFailedError = (
  command: CommandRef,
  invocation: GetCommandInvocationCommandOutput
) => {
  const output = outputOf(invocation, -1);
  const { exitCode } = output;
  const tail = stderrTailOf(output.stderr);
  const options = toFailureOptions({
    reason: "command_failed",
    type: "unknown",
    message: `P0's script on ${command.instanceId} exited with code ${exitCode}${tail ? `: ${tail}` : ""}`,
    command,
    extra: { exitCode, status: invocation.Status ?? "unknown" },
  });
  return new CommandFailedError(options, output);
};

/** SSM accepted the command and then couldn't hand it to the instance. */
const UNDELIVERED_DETAILS = ["DeliveryTimedOut", "Undeliverable"];

/**
 * The result of an invocation that succeeded, or `undefined` while it is
 * still pending or running. It throws for one that ended `Failed`,
 * `Cancelled` or `TimedOut`.
 */
const toScriptResult = (
  command: CommandRef,
  invocation: GetCommandInvocationCommandOutput
): ScriptResult | undefined => {
  switch (invocation.Status) {
    case "Success":
      return outputOf(invocation, 0);
    case "Failed":
    case "Cancelled":
    case "TimedOut": {
      // SSM documents these with spaces and returns them without.
      const details = (invocation.StatusDetails ?? "").replace(/\s/g, "");
      if (UNDELIVERED_DETAILS.includes(details)) {
        throw newUnreachableError(command);
      }
      if (invocation.Status === "TimedOut") {
        throw newExecutionTimeoutError(command);
      }
      throw newCommandFailedError(command, invocation);
    }
    default:
      // Pending, InProgress, Delayed, Cancelling or a status SSM adds later:
      // keep polling.
      return undefined;
  }
};

/** The statuses of a command the instance has picked up. */
const STARTED_STATUSES = ["InProgress", "Cancelling"];

/**
 * What the polls have shown of a command that hasn't ended. `nothing` means
 * SSM answered no poll at all.
 */
type Seen = "nothing" | "started" | "waiting";

const run = async (
  { instance, script }: ScriptRun,
  logger: Logger,
  dependencies: RunScriptDependencies
): Promise<ScriptResult> => {
  const { wait = sleep, now = Date.now } = dependencies;
  const client =
    dependencies.client ?? new SSMClient({ region: instance.region });
  const instanceId = instance.id;
  const deadline = now() + COMMAND_DEADLINE_MS;

  const { Command } = await client
    .send(
      new SendCommandCommand({
        DocumentName: RUN_SHELL_SCRIPT_DOCUMENT,
        InstanceIds: [instanceId],
        Parameters: {
          commands: [script],
          executionTimeout: [`${EXECUTION_TIMEOUT_SECONDS}`],
        },
        TimeoutSeconds: DELIVERY_TIMEOUT_SECONDS,
      })
    )
    .catch((error: unknown) => {
      // SSM answers this for an instance it doesn't manage, a stopped one,
      // and one whose agent is offline.
      if (isNamed(error, "InvalidInstanceId")) {
        throw newUnreachableError({ instanceId });
      }
      if (isNamed(error, "UnsupportedPlatformType")) {
        throw newUnsupportedPlatformError(instanceId);
      }
      throw toConnectorError(error);
    });
  const commandId = Command?.CommandId;
  if (!commandId) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "SSM accepted P0's script but returned no command id. Try the request again.",
      payload: { instanceId },
    });
  }
  const command = { instanceId, commandId };
  logger.debug(command, "sent the SSM command");

  let seen: Seen = "nothing";
  let throttled: unknown;
  for (let poll = 0; ; poll++) {
    const left = deadline - now();
    if (left <= 0) break;
    // Never past the deadline: the last wait lasts only what is left.
    await wait(
      Math.min(POLL_INTERVALS_MS[poll] ?? LAST_POLL_INTERVAL_MS, left)
    );
    const invocation = await client
      .send(
        new GetCommandInvocationCommand({
          CommandId: commandId,
          InstanceId: instanceId,
        })
      )
      .catch((error: unknown) => {
        // SSM takes a moment to list a new command's invocation.
        if (isNamed(error, "InvocationDoesNotExist")) return "waiting";
        // A throttled poll says nothing about the command. The next one
        // may.
        if (isNamed(error, "ThrottlingException")) {
          throttled = error;
          return "throttled";
        }
        throw toConnectorError(error);
      });
    if (invocation === "throttled") continue;
    if (invocation !== "waiting") {
      const result = toScriptResult(command, invocation);
      if (result) {
        logger.debug(
          { ...command, exitCode: result.exitCode },
          "the SSM command succeeded"
        );
        return result;
      }
    }
    if (
      invocation !== "waiting" &&
      STARTED_STATUSES.includes(invocation.Status ?? "")
    ) {
      seen = "started";
    } else if (seen === "nothing") {
      seen = "waiting";
    }
  }

  // Best effort. The execution timeout still stops a script that started,
  // and the delivery timeout one the instance never picked up.
  await client
    .send(
      new CancelCommandCommand({
        CommandId: commandId,
        InstanceIds: [instanceId],
      })
    )
    .catch((error: unknown) => {
      logger.warn(
        { ...command, awsError: nameOf(error) ?? "unknown" },
        "could not cancel the SSM command"
      );
    });
  switch (seen) {
    case "started":
      throw newTimeoutError(command);
    case "waiting":
      // SSM took the command and the instance never picked it up: its agent
      // is not connected. SSM would say so itself, but only when its
      // delivery timeout passes, which is after the deadline.
      throw newUnreachableError(command);
    case "nothing":
      // SSM answered no poll. Report the last throttle if there was one,
      // and the deadline otherwise.
      throw throttled === undefined
        ? newTimeoutError(command)
        : toConnectorError(throttled);
    default:
      throw throwAssertNever(seen);
  }
};

/**
 * Runs a script on one instance with Run Command, and returns its exit code
 * and output. It throws when the script exits non-zero, when it doesn't
 * finish by the deadline, and when SSM can't reach the instance. Each error
 * carries its {@link RunScriptFailure} in `payload.reason`, the instance id,
 * and the request id when the caller gave one. A non-zero exit throws a
 * {@link CommandFailedError}, which keeps the output.
 *
 * `logger` is the caller's, already bound to its request. Nothing here logs
 * the script or its output, because a script's arguments are part of its
 * text.
 */
export const runScript = async (
  scriptRun: ScriptRun,
  logger: Logger,
  dependencies: RunScriptDependencies = {}
): Promise<ScriptResult> => {
  try {
    return await run(scriptRun, logger, dependencies);
  } catch (error) {
    const failure = toConnectorError(error);
    const { data } = failure;
    const { requestId, instance } = scriptRun;
    const options = {
      ...data,
      payload: {
        ...data.payload,
        instanceId: instance.id,
        ...(requestId ? { requestId } : {}),
      },
    };
    throw failure instanceof CommandFailedError
      ? new CommandFailedError(options, failure.output)
      : new ConnectorError(options);
  }
};

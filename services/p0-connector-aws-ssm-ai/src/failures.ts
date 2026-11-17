// The closed sets P0 reads off a failed call. This module imports nothing,
// so the control plane can load it without the AWS SDK.

/**
 * The failures of a script run that P0 tells apart, by the name the error
 * carries in `payload.reason`.
 *
 * - `timeout`: the script started and didn't finish by the deadline.
 * - `command_failed`: the script ran and exited non-zero.
 * - `instance_unreachable`: SSM doesn't manage the instance, or the
 *   instance never picked the command up.
 * - `busy`: an earlier command for the same access was still running at
 *   the deadline, so this run sent nothing.
 */
export const RUN_SCRIPT_FAILURES = [
  "timeout",
  "command_failed",
  "instance_unreachable",
  "busy",
] as const;

export type RunScriptFailure = (typeof RUN_SCRIPT_FAILURES)[number];

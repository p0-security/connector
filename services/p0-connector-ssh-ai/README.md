# p0-connector-ssh-ai

SSH (AI) connector. It prepares an EC2 instance for an agent in a P0 agentic session. It reaches
the instance only through SSM Run Command, with the AWS-owned `AWS-RunShellScript` document.

It ships as an AWS Lambda container image, `p0-connector-ssh-ai`, once `docker.yaml` builds it.

This is the skeleton. It serves install validation and holds the SSM command client. It has no
grant or revoke routes yet.

## Install validation

`ssh-ai.install.validation.get` takes `{ region }`. It checks that the execution role can
describe the SSM managed instances in that region (`ssm:DescribeInstanceInformation`). It never
writes. A failure reports `managed_instances` in `payload.step`.

## Running a script

`runScript` in `src/ssm/run-script.ts` runs one script on one instance and returns its exit code
and output. It sends the script with `ssm:SendCommand`, then polls `ssm:GetCommandInvocation`
for up to 20 seconds. P0 holds a 60-second lock around a whole grant, and a grant makes more
than one call.

When a run fails, `runScript` throws an error with one of these in `payload.reason`:

| `payload.reason`       | Error type             | When                                                                                  |
| ---------------------- | ---------------------- | ------------------------------------------------------------------------------------- |
| `timeout`              | `upstream_unavailable` | The script started and didn't finish in 20 seconds.                                   |
| `command_failed`       | `unknown`              | The script exited non-zero. The error holds the exit code and the end of stderr.      |
| `instance_unreachable` | `object_not_found`     | SSM doesn't manage the instance, or the instance never picked the command up in time. |

Every other failed call to SSM carries the AWS error's name in `payload.awsError`, and no
reason. A refusal is `insufficient_privileges`, and a throttle is `rate_limited`.
`UnsupportedPlatformType`, SSM's answer for a Windows or macOS instance, is `validation_error`.
The rest, a network timeout among them, are `upstream_unavailable`.

SSM still accepts a command for an instance whose SSM Agent is offline. It reports that only
after its 30-second delivery timeout, which is past the deadline. So the client watches whether
the command ever starts: at the deadline it reports `instance_unreachable` when it never did,
and `timeout` when it did. Either way it then cancels the command, and logs a warning when it
can't. The document's `executionTimeout`, which the client sets to 30 seconds, stops a script
that still runs on the instance. That kill and a cancel reach only the script's process group.
A command the script runs under `timeout` gets a group of its own, so it can run on until its
own limit.

The client retries a poll that SSM throttles. Every error carries the instance id, and the
request id when the caller gave one.

The connector's own code logs no script and none of its output, because a script's arguments
are part of its text. A failed script's error, which connector-core logs, ends with up to 500
characters of its stderr (`STDERR_TAIL_CHARS`). Whatever runs on the instance with that stderr
open can write into it too, so that message suits an `unknown` error, which P0 never shows. The
error is a `CommandFailedError`, which keeps the run's output out of its data. A caller that
gives the error a type P0 shows builds its own message from that output.

## Permissions

The execution role needs `ssm:DescribeInstanceInformation`, `ssm:SendCommand` on the
`AWS-RunShellScript` document and on the instances, `ssm:GetCommandInvocation`, and
`ssm:CancelCommand`. Without `ssm:CancelCommand`, a script that times out keeps running on the
instance until its execution timeout.

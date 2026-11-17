# p0-connector-aws-ssm-ai

`aws-ssm-ai` is the SSH (AI) integration's connector for EC2 instances that SSM manages. It
prepares an instance for an agent in a P0 agentic session. It reaches the instance only through
SSM Run Command, with the AWS-owned `AWS-RunShellScript` document.

It ships only as the AWS Lambda container image `p0security/p0-connector-aws-ssm-ai-aws`, once
`docker.yaml` builds it.

This is the skeleton. It serves install validation, and holds the SSM command client and the
provisioning script. It has no grant or revoke routes yet.

## Install validation

`aws-ssm-ai.install.validation.get` takes `{ region }`. It checks that the execution role can
describe the SSM managed instances in that region (`ssm:DescribeInstanceInformation`). It never
writes. A failure reports `managed_instances` in `payload.step`.

## Running a script

`runScript` in `src/ssm/run-script.ts` runs one script on one instance and returns its exit code
and output. It sends the script with `ssm:SendCommand`, then polls `ssm:GetCommandInvocation`
for up to 20 seconds. P0 holds a 60-second lock around a whole grant, and a grant makes more
than one call. Every call to SSM, its retries included, stops at that deadline.

### A try P0 makes again

P0 tries a failed step twice more, half a second apart, while it still holds its lock. The
script may still be running from the try before. So each command carries a comment,
`p0-ssh-ai:<marker>:<action>`, where the action is `ensure-key`, `set-sudo-on`,
`set-sudo-off` or `remove-key`. Before it sends anything, a run lists the instance's recent
`AWS-RunShellScript` commands (`ssm:ListCommands`, every page) and looks at the ones of its
marker that haven't ended:

- It waits for every one with another action, so a grant's and a revoke's changes land in the
  order P0 made them. A late `set-sudo on` can't land after a revoke.
- One with the same action it takes over instead of sending another, and polls it as its own.
  It takes over the newest. `ensure-key` is never taken over: each try sends a new key, and the
  key a try stores must be the one it installed. That run waits for the earlier one and then
  sends its own, which replaces the earlier key.

When a command of another action is still running at the deadline, the run sends nothing and
fails with `busy`, and P0's next try waits again. The run never cancels a command: a cancel
would stop the script and free the instance's lock while a command it started still runs. A
command that outlives its run ends by its own timeouts, and the next run waits for it.

When a run fails, `runScript` throws an error with one of these in `payload.reason`:

| `payload.reason`       | Error type             | When                                                                                  |
| ---------------------- | ---------------------- | ------------------------------------------------------------------------------------- |
| `timeout`              | `upstream_unavailable` | The script started and didn't finish in 20 seconds.                                   |
| `command_failed`       | `unknown`              | The script exited non-zero. The error holds the exit code and the end of stderr.      |
| `instance_unreachable` | `object_not_found`     | SSM doesn't manage the instance, or the instance never picked the command up in time. |
| `busy`                 | `upstream_unavailable` | A command of another action for the same marker was still running at the deadline.    |

Every other failed call to SSM carries the AWS error's name in `payload.awsError`, and no
reason. A refusal is `insufficient_privileges`, and a throttle is `rate_limited`.
`UnsupportedPlatformType`, SSM's answer for a Windows or macOS instance, is `validation_error`.
The rest, a network timeout among them, are `upstream_unavailable`.

SSM still accepts a command for an instance whose SSM Agent is offline. It reports that only
after its 30-second delivery timeout, which is past the deadline. So the client watches whether
the command ever starts: at the deadline it reports `instance_unreachable` when it never did,
and `timeout` when it did. The document's `executionTimeout`, which the client sets to 30
seconds, stops a script that still runs on the instance. That kill reaches only the script's
process group. A command the script runs under `timeout` gets a group of its own, so the script
gives each one a limit that ends before that kill.

The client retries a poll that SSM throttles. Every error carries the instance id, and the
request id when the caller gave one.

The connector's own code logs no script and none of its output, because a script's arguments
are part of its text. A failed script's error, which connector-core logs, ends with up to 500
characters of its stderr (`STDERR_TAIL_CHARS`). Whatever runs on the instance with that stderr
open can write into it too, so that message suits an `unknown` error, which P0 never shows. The
error is a `CommandFailedError`, which keeps the run's output out of its data. A caller that
gives the error a type P0 shows builds its own message from that output.

## The provisioning script

`src/script/provision.ts` holds one bash script, as a string, because the Lambda image ships
only the bundle. The script runs as root. It takes everything as arguments and calls no cloud
API, so another transport can run the same script later. `buildProvisionScript` checks and
quotes one action's arguments and returns the text to pass to `runScript`.

| Action                                    | What it does                                                                                                               |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `ensure-key <user> <marker> <public key>` | Creates the Linux user when it is missing, puts the key in its `authorized_keys`, and prints the instance's SSH host keys. |
| `set-sudo <user> <marker> on\|off`        | Adds or removes the marker's entry in `/etc/sudoers-p0`. `visudo -cf` checks the file before an addition replaces it.      |
| `remove-key <user> <marker>`              | Removes the marker's key line and sudoers entry. It keeps the user and everything else.                                    |

A marker names one holder group. An action only touches what carries its own marker, so two
groups can share one Linux user. Running an action again changes nothing.

- The user name must match `^[a-z][a-z0-9_-]*-ai$` and have at most 32 characters. The marker is
  1 to 64 letters, digits, `_` or `-`. The public key is one ed25519 key with no options and no
  comment. The script checks all three itself, before it changes anything.
- A key line in `authorized_keys` ends with `p0-ssh-ai:<marker>`, as the key's comment. A
  marker's new key replaces its old one.
- The script edits `authorized_keys` as the agent's user, with `setpriv`. The agent owns its
  home directory, so a link it plants there could point a write by root at any file.
- That child shell gets the script's stderr and none of its other open files, and its stdout
  goes nowhere. The agent can open the files of its own processes through `/proc`, so a child
  that kept the lock's file or the script's stdout would let it hold the lock, which stops every
  P0 change on the instance, or add a host key line or a reason. The kernel refuses it the files
  of the script itself, which runs as root.
- Through the child, the agent can write anything to the script's stderr, even after the
  script's last line. So the child's own reason for a failure goes only to stderr, and a failed
  edit gets the script's own reason instead: "could not edit authorized_keys in the home
  directory of the agent's Linux user".
- The agent can also stop that child while the script holds the lock. So the edit gets at most 5
  seconds, and then `timeout` ends it with TERM and, a second later, KILL.
- Each command the script waits for gets at most what is left of a 28-second budget, and the
  lock wait gets at most 10 seconds. `timeout` runs a command in a process group of its own,
  which SSM's kill doesn't reach, and that kill frees the lock. So its TERM comes by 28 seconds
  after the script starts and its KILL by 29, inside SSM's 30-second execution timeout. A
  command that changes accounts can wait seconds for SSSD's cache flush, so it gets all that is
  left.
- The agent can take its own access to `~/.ssh` away to keep a key line in place. So the edit
  first gives the owner access back, and fails when it still can't read the directory. It never
  reports a key line it could not see as gone.
- The script doesn't check a removal with `visudo`. Taking the script's own two lines out can't
  break the file, and a revoke must not fail on a line someone else got wrong. It checks an
  addition.
- `remove-key` for a user with no home directory removes the sudoers entry and stops there.
- `ensure-key` uses a user that already exists, whoever made it, only when its user id is from
  65536 to 90000, P0's id range. A user outside that range is someone else's account: the agent
  would get its groups and files, and a sudo grant would give root to everyone else who can log
  in as it. So `ensure-key` refuses it with exit 69, before it changes any account, sudoers file
  or home. `set-sudo` and `remove-key` don't check the id, so a revoke works on any user. A
  holder group's later grants run only `set-sudo`, and a sudoers entry names the user, so sudo
  goes to whichever account has that name when someone runs sudo.
- When no user has the agent's name but a Linux group does, `ensure-key` deletes that group and
  makes it again for the agent's user only when its group id is in P0's range. Such a group
  counts as what is left of a user P0 made. A group outside the range is someone else's:
  deleting it and making it again for the agent would move every rule that names it, such as a
  `%group` line in sudoers, from its members to the agent. So `ensure-key` refuses it with exit
  69, before it changes any account, sudoers file or home.
- A `useradd` that something stopped after it wrote `/etc/passwd` leaves a user with no home.
  So `ensure-key` makes the home of a user in P0's id range when the home that `getent passwd`
  gives for it doesn't exist, as `useradd -m` does: mode 0700, the contents of `/etc/skel`, owned
  by the user and its group. It does so only in a directory that root alone can write in. For
  any other user in that range with no home, `ensure-key` fails.
- The script prints each host key as `p0-ssh-ai-host-key: <type> <key>`.
- The last line of output is `p0-ssh-ai-result: ok` or `p0-ssh-ai-result: failed`, for a caller
  that can't read the exit code. A failure's reason never holds an argument. It goes to stderr,
  and to stdout as `p0-ssh-ai-reason: <reason>`, just before the result line. A command the
  script runs, or the agent through the edit's stderr, can add any text to stderr. So a caller
  that shows a reason to a person reads it from stdout.
- The exit code tells the caller what kind of failure it was:
  - 69 (`INSTANCE_STATE_EXIT_CODE`): the instance's own state stops the action, such as a
    missing tool, a user or group with the agent's name whose id is outside P0's range, no free
    user id, an unusable home or `.ssh`, no SSH host keys, a sudoers file that visudo refuses or
    the script can't write or replace, or a lock the script can't take.
  - 75 (`TRY_AGAIN_EXIT_CODE`): a retry can work. Another P0 change held the lock for the whole
    wait, or a command ran out of time.
  - 1 (`P0_BUG_EXIT_CODE`): P0 called the script wrong, with an argument it refuses, an unknown
    action, or a run that isn't root.

  TERM ends the script with code 143, and the result line then says failed. A command that
  fails where the script expects no failure ends it with that command's own code.

### What it shares with the SSH integration

P0's SSH integration (the SSM document `P0ProvisionUserAccess`) can manage the same instance, so
the script uses that integration's sudoers file, entry format, lock and way of creating a new
user. Unlike that integration, it refuses a user with the agent's name whose id is outside P0's
range. When no user has that name, it also refuses a group with it whose id is outside the range.

- A sudoers entry is two lines in `/etc/sudoers-p0`, with the marker where the SSH integration
  writes a request id:

  ```
  # RequestID: p0-ssh-ai:<marker> | GrantedAt: <unix time>
  <user> ALL=(ALL) NOPASSWD: ALL
  ```

  The SSH integration's `cleanup` deletes every line of that file that is not part of such a
  pair, so no other shape survives there.

- The script writes no `RevokedAt` line. The SSH integration refuses to grant an id that has
  one, and P0 grants a marker again and again. Removing an entry removes its two lines and
  leaves every other line as it was.
- `set-sudo on` creates `/etc/sudoers-p0` when it is missing, with mode 0440, and adds
  `#include sudoers-p0` to `/etc/sudoers` when that line is missing. Only the whole line counts,
  so a commented-out include doesn't. The script adds a line break first when the last line of
  `/etc/sudoers` has none, and renames its draft over the file only after `visudo -cf` accepts
  it with every file it includes. It never deletes `/etc/sudoers-p0`, because `/etc/sudoers`
  includes it by name. That file stays, empty, when its last entry goes.
- `flock` on `/run/p0/p0-operations.lock` lets one action of either script run at a time. An
  action of this script waits up to 10 seconds for it.
- A new user gets the next free id from 65536 to 90000, and a group with the same name and id.

### Instance requirements

- `bash`, `getent` and `awk`.
- `flock` and `setpriv` from util-linux.
- `timeout` from coreutils. The script uses its `-k` to send KILL after TERM.
- `useradd`, `groupadd` and `groupdel`, which `ensure-key` checks for before it creates a user.
- `sudo`, for `set-sudo on`.
- The SSH host keys in `/etc/ssh`, for `ensure-key`.

### Tests

`src/script/__tests__/provision.run.test.ts` runs the script with bash: a syntax check, the
argument checks, the exit codes and reason lines, the result line after TERM, the time budget,
the checks on a user or group that already has the agent's name, and the sudoers, key, lock and
timeout functions against a temp directory. It needs no root. The parts that need root, a real
`sshd`, or P0's SSH integration on the same instance have no automated test, because this repo
has no container tests.

## Permissions

The execution role needs `ssm:DescribeInstanceInformation`, `ssm:SendCommand` on the
`AWS-RunShellScript` document and on the instances, `ssm:GetCommandInvocation`, and
`ssm:ListCommands`. It never cancels a command, so it doesn't need `ssm:CancelCommand`.

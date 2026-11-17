# p0-connector-aws-ssm-ai

`aws-ssm-ai` is the SSH (AI) integration's connector for EC2 instances that SSM manages. It
prepares an instance for an agent in a P0 agentic session. It reaches the instance only through
SSM Run Command, with the AWS-owned `AWS-RunShellScript` document.

It ships only as the AWS Lambda container image `p0security/p0-connector-aws-ssm-ai-aws`, once
`docker.yaml` builds it.

## The session access

`aws-ssm-ai.accesses.session` is a resource-root access. It gives a holder group a key to one
instance. A holder group is the set of grants that share one secret, and so one key and one
Linux user. The "user" of the access is that secret, as it is for `p0-connector-github-ai`.

Every call carries the request context `{ requestId, secrets: { manager: "aws", region },
instance: { id, region } }` and the user body `{ user, secretName }`. `user` is the agent's
Linux user and must match `^[a-z][a-z0-9_-]*-ai$` with at most 32 characters. `secretName` is
the secret's name. P0 chooses both. The user id is the secret's ARN.

- `provisionUser` returns the ARN when the secret exists and holds a value. Otherwise it
  creates the secret when it is missing, with no value, mints an ed25519 key pair, runs
  `ensure-key` on the instance, and writes the secret's value. The secret comes first, so the
  instance is untouched when Secrets Manager refuses it. A grant that stopped halfway finishes
  on the next call: the new key replaces the old one on the instance.
- `setPoliciesForUser` takes the group's full set of policies, each `{ sudo: boolean }`. It
  runs `set-sudo on` when any policy has `sudo: true`, and `set-sudo off` otherwise.
- `deleteUser` runs `remove-key`, and deletes the secret only after that succeeds. The Linux
  user stays. It refuses an ARN that doesn't name `secretName` in the request's region.
- `list` is not there yet.

A revoke fails when it can't remove access from the instance. `setPoliciesForUser` fails when
`set-sudo off` fails, and `deleteUser` fails when `remove-key` fails, so a stopped instance or
an agent that breaks its own key removal fails the revoke. `deleteUser` then keeps the secret.
P0 marks the request errored, and a person cleans up by hand, in this order:

1. On the instance, remove the key line that ends with `p0-ssh-ai:<marker>` from the user's
   `~/.ssh/authorized_keys`, and the marker's two lines from `/etc/sudoers-p0`.
2. Delete the secret.

P0 finds the group by its secret, so a secret deleted first hides what is left on the instance.
A terminated instance takes its key line and sudoers entry with it, and leaves only step 2.

When the script fails on the instance, its exit code sets the error's type, and so what the
requester reads:

| Exit code | Error type             | The requester reads                                                      |
| --------- | ---------------------- | ------------------------------------------------------------------------ |
| 69        | `dependency_violation` | The message word for word. It holds the script's reason and no stderr.   |
| 75        | `upstream_unavailable` | That SSH (AI) is unavailable for now, and to try again in a few minutes. |
| any other | `unknown`              | An error id, and P0 records the failure as its own bug.                  |

69 is the instance's own state, such as a missing tool or a sudoers file that visudo refuses,
which a person with access to the instance can fix. 75 is a run that a retry can fix: another
P0 change held the instance's lock, or a command ran out of time. Host keys that P0 can't read
are `dependency_violation` too. P0 retries every failed call the same way, whatever its type.

The agent can write to the script's stderr, so a 69's message holds nothing from it. The
message is `P0's script couldn't change <instance>: <reason>.`, with the reason the script
printed on stdout, and then names the SSM command whose output has the details. With no reason
line, it names only the command. The connector logs the end of stderr in a warning instead. A
75 or an `unknown` keeps the message `runScript` built, which ends with that stderr, because P0
never shows either one's message.

Sudo belongs to the Linux user, not to a holder group. When two groups share one Linux user and
one of them has sudo, sessions of both can use it on the instance. The marker only records which
group asked for the entry, so that each can take its own away.

Secrets Manager deletes a secret in the background, and describes it with a `DeletedDate` until
the deletion finishes. `provisionUser` counts that secret as gone and goes on to create a new
one, which Secrets Manager refuses while the name is still taken. The grant then fails with
`upstream_unavailable` and a message that says to try again, before it touches the instance.

The secret's value is this JSON, written as the secret's binary value:

```json
{
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "user": "alice-ai",
  "hostKeys": ["ssh-ed25519 AAAA...", "ecdsa-sha2-nistp256 AAAA..."]
}
```

`privateKey` is in OpenSSH's own format, which `ssh -i` reads. The connector doesn't use Node's
PKCS8, because OpenSSH reads it only from 9.9 on. The private key exists in the connector's
memory and in the secret. The connector never reads a secret's value, and never puts a key in a
log line or an error. A Secrets Manager failure reports its name, the step in `payload.step` and
the request id, not its message. The one exception is a refusal, which keeps AWS's message: it
names the action and the secret, never a value. A refusal is `insufficient_privileges`, a
throttle is `rate_limited`, and every other failure is `upstream_unavailable`.

The marker the script gets is the first 32 hex digits of the SHA-256 of `secretName`.

The control plane imports the contract from `@p0security/p0-connector-aws-ssm-ai/connector`:
the spec, the router's type, the schemas, and the closed sets `AWS_SSM_AI_RUN_SCRIPT_FAILURES`
(`payload.reason`), `AWS_SSM_AI_SECRET_STEPS` and `AWS_SSM_AI_INSTALL_STEPS` (`payload.step`).
That entry loads no Lambda handler, no router, and neither the SSM client nor the secret manager
client.

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

The session access then gives a `command_failed` error the type of the script's exit code, as
[The session access](#the-session-access) says.

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

The connector's own code logs no script, since a script's arguments are part of its text. It
logs none of a script's stdout either. A failed script's error, which connector-core logs, ends
with up to 500 characters of its stderr (`STDERR_TAIL_CHARS`). Whatever runs on the instance
with that stderr open can write into it too, so that message suits an `unknown` error, which P0
never shows. The error is a `CommandFailedError`, which keeps the run's output out of its data.
A caller that gives the error a type P0 shows builds its own message from that output. The
session access does so for exit code 69, and logs the 500 characters in a warning instead.

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

On the secrets P0 names, in the vault's region, it needs `secretsmanager:CreateSecret`,
`secretsmanager:DescribeSecret`, `secretsmanager:PutSecretValue` and
`secretsmanager:DeleteSecret`. It does not need `secretsmanager:GetSecretValue`.

### A known trade-off: `AWS-RunShellScript`

`ssm:SendCommand` with `AWS-RunShellScript` lets this role run any command as root on every
instance in its scope. Nothing in AWS holds it to the provisioning script. Only this service's
code does: it sends one script, with one of three actions, and arguments it has checked.
Whoever can change the Lambda's code or use its role has root on those instances.

P0 chose `AWS-RunShellScript` on 2026-11-16 so that a customer creates no SSM document of their
own. A document that fixes the script and takes only the action and its arguments as parameters
would move that limit into AWS.

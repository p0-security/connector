import { ConnectorError, throwAssertNever } from "@p0security/connector-core";

// The script checks its arguments with these same patterns, in bash's
// `[[ =~ ]]`. Each one uses only what bash's extended regular expressions
// and JavaScript's agree on: literal characters, ASCII ranges in brackets
// (the script sets LC_ALL=C), counted repeats, and `^` and `$` once each.
// Neither side lets `$` match before a trailing line break: JavaScript
// because the patterns carry no `m` flag, and bash because it compiles
// them without REG_NEWLINE. A test runs the script with such an argument.

/**
 * The agent's Linux user: `^[a-z][a-z0-9_-]*-ai$`, and at most 32
 * characters, which is Linux's limit. The script acts on no user outside
 * this namespace.
 */
const USER_SOURCE = "^[a-z][a-z0-9_-]{0,28}-ai$";

/**
 * A marker names one holder group. Two groups can share one Linux user, and
 * the marker on a line says which group the line belongs to.
 */
const MARKER_SOURCE = "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";

/**
 * One ed25519 public key with no options and no comment. The key's first
 * 25 characters encode its type and length, so they never change.
 */
const PUBLIC_KEY_SOURCE =
  "^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$";

export const USER_PATTERN = new RegExp(USER_SOURCE);
export const MARKER_PATTERN = new RegExp(MARKER_SOURCE);
export const PUBLIC_KEY_PATTERN = new RegExp(PUBLIC_KEY_SOURCE);

/** The script prints each of the instance's SSH host public keys after this. */
export const HOST_KEY_PREFIX = "p0-ssh-ai-host-key: ";

/** A host key as the script prints it: its type, then its base64. */
const HOST_KEY_PATTERN = /^[a-z0-9@.-]+ [A-Za-z0-9+/]+={0,2}$/;

/**
 * The instance's SSH host public keys, each as `<type> <key>`, from what
 * `ensure-key` printed. Its error names the request the run belongs to.
 */
export const hostKeysOf = (stdout: string, requestId: string) => {
  const keys = stdout
    .split("\n")
    .filter((line) => line.startsWith(HOST_KEY_PREFIX))
    .map((line) => line.slice(HOST_KEY_PREFIX.length));
  if (keys.length === 0 || !keys.every((key) => HOST_KEY_PATTERN.test(key))) {
    throw new ConnectorError({
      // The host key files are the instance's, not P0's, so the requester
      // reads this message as it is, and P0 records no bug of its own.
      type: "dependency_violation",
      message:
        "The instance returned no SSH host keys P0 can read. Check the host keys in /etc/ssh/ssh_host_*_key.pub on the instance.",
      payload: { nHostKeys: keys.length, requestId },
    });
  }
  return keys;
};

/**
 * The script prints its reason for a failure after this, on stdout, just
 * before the failed result line. Only root can write to the script's
 * stdout, and the agent can write anything to its stderr. So a reason that
 * P0 shows the requester comes from this line, never from stderr.
 */
export const REASON_PREFIX = "p0-ssh-ai-reason: ";

/**
 * The reason a failed run gave on its reason line, or `undefined` when it
 * gave none. The last such line counts, because the script prints its
 * reason just before the result line.
 */
export const reasonOf = (stdout: string) => {
  const reason = stdout
    .split("\n")
    .filter((line) => line.startsWith(REASON_PREFIX))
    .at(-1)
    ?.slice(REASON_PREFIX.length)
    .trim();
  return reason || undefined;
};

/**
 * The last line the script prints, whatever happens. A caller that can't
 * read an exit code reads this.
 */
export const RESULT_LINES = {
  ok: "p0-ssh-ai-result: ok",
  failed: "p0-ssh-ai-result: failed",
} as const;

/**
 * The script's exit code when P0 called it wrong: an argument it refuses, an
 * unknown action, or a run that isn't root. That is P0's own bug.
 */
export const P0_BUG_EXIT_CODE = 1;

/**
 * The script's exit code when the instance's own state stops the action: a
 * missing tool, no free user id, an unusable home or `.ssh`, no SSH host
 * keys, a sudoers file that visudo refuses or it can't write or replace, or
 * a lock it can't take. It is sysexits' EX_UNAVAILABLE. A person with access
 * to the instance can fix it.
 */
export const INSTANCE_STATE_EXIT_CODE = 69;

/**
 * The script's exit code when a retry can work: another P0 change held the
 * instance's lock for the whole wait, or a command ran out of time. It is
 * sysexits' EX_TEMPFAIL.
 */
export const TRY_AGAIN_EXIT_CODE = 75;

const SHEBANG = "#!/bin/bash";

// `String.raw` keeps every backslash for bash. JavaScript still reads `${`,
// so the script uses no bash expansion of that form.
const BODY = String.raw`# P0 SSH (AI): prepares a Linux user for an agent. It takes everything as
# arguments and calls no cloud API, so any transport that runs bash as root
# can run it.
#
#   ensure-key <user> <marker> <public key>
#   set-sudo <user> <marker> on|off
#   remove-key <user> <marker>
#
# A marker names one holder group. An action only touches what carries its
# own marker, and running it again changes nothing.
#
# The sudoers file, its entry format, the lock and the way the script
# creates a user are those of P0's SSH integration (the SSM document
# P0ProvisionUserAccess), which can manage the same instance.
set -euo pipefail
# [a-z] must mean ASCII, whatever the instance's locale is.
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

TAG_PREFIX='p0-ssh-ai:'
SUDOERS_FILE='/etc/sudoers-p0'
SUDOERS_MAIN='/etc/sudoers'
SUDOERS_INCLUDE='#include sudoers-p0'
LOCK_DIR='/run/p0'
LOCK_FILE='/run/p0/p0-operations.lock'
MIN_ID=65536
MAX_ID=90000
# SSM's execution timeout kills the script at 30 seconds, but only the
# script's own process group. timeout runs each command in a group of its
# own, so every command gets at most what is left of this budget, and
# timeout's KILL, a second after its TERM, still comes before SSM's.
RUN_BUDGET_SECONDS=28
LOCK_WAIT_SECONDS=10
# The key edit runs as the agent's user, so the agent can stop it while
# this script holds the lock. On a healthy instance it takes a moment.
KEY_EDIT_SECONDS=5
# The sudoers draft while one exists, so the exit trap can remove it.
sudoers_draft=''

# Each kind of failure has its own exit code, so the connector can tell
# P0's own bug from the instance's state and from a run a retry can fix. A
# reason never holds an argument, because reasons end up in logs and in
# what P0 shows the requester. The reason goes to stderr, for the run's
# output, and to the script's own stdout, which the agent can't write to.
fail_with() {
  echo "p0-ssh-ai: $2" >&2
  echo '${REASON_PREFIX}'"$2" >&3
  exit "$1"
}

fail() {
  fail_with ${P0_BUG_EXIT_CODE} "$1"
}

fail_instance() {
  fail_with ${INSTANCE_STATE_EXIT_CODE} "$1"
}

fail_try_again() {
  fail_with ${TRY_AGAIN_EXIT_CODE} "$1"
}

# A failure's reason and the result line go to the script's own stdout,
# even when the script stops inside a command whose output the script
# redirects. Only root's processes hold fd 3, and the key edit, which runs
# as the agent's user, doesn't get it.
exec 3>&1
report() {
  local code="$?"
  # A run that stops partway leaves no draft in /etc.
  if [ -n "$sudoers_draft" ]; then
    rm -f "$sudoers_draft"
  fi
  if [ "$code" -eq 0 ]; then
    echo '${RESULT_LINES.ok}' >&3
  else
    echo '${RESULT_LINES.failed}' >&3
  fi
}
trap report EXIT
# On TERM, bash runs the exit trap with the last command's status, which can
# be 0. So the script exits with TERM's own code, and the result line says
# failed.
trap 'exit 143' TERM

check() {
  [[ "$3" =~ $2 ]] || fail "invalid $1"
}

# The seconds a wait may take: the number asked for, or what is left of the
# run's budget when that is less. SECONDS counts whole seconds since the
# script started and can be up to one behind, so one more counts as spent.
seconds_for() {
  local left=$((RUN_BUDGET_SECONDS - 1 - SECONDS))
  if [ "$1" -lt "$left" ]; then
    echo "$1"
  else
    echo "$left"
  fi
}

# Runs a command under a time limit, so nothing the script waits for can
# keep the lock until SSM stops the script, or run on after it. The agent
# can stop its own processes, and only KILL is sure to end a stopped one,
# so KILL follows TERM a second later. The command gets the script's stderr
# and none of its other open files.
run_with_timeout() {
  local seconds what="$2" code=0
  seconds="$(seconds_for "$1")"
  shift 2
  [ "$seconds" -gt 0 ] || fail_try_again "no time was left for $what"
  timeout -k 1 "$seconds" "$@" </dev/null >/dev/null 3>&- 9>&- || code="$?"
  # timeout exits 124 when TERM ended the command, and 137 when KILL did.
  if [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; then
    fail_try_again "$what took longer than $seconds seconds"
  fi
  return "$code"
}

# A user or group command can wait seconds for SSSD's cache flush, and the
# agent can't stop it, so it gets all that is left of the budget.
run_account_command() {
  run_with_timeout "$RUN_BUDGET_SECONDS" 'a user or group command' "$@"
}

# The next id that is free as a user id and as a group id, because the
# user's own group gets the same id.
next_free_id() {
  local id="$MIN_ID"
  while getent passwd "$id" >/dev/null 2>&1 || getent group "$id" >/dev/null 2>&1; do
    id=$((id + 1))
    [ "$id" -le "$MAX_ID" ] || fail_instance "no user id from $MIN_ID to $MAX_ID is free"
  done
  echo "$id"
}

ensure_group() {
  local name="$1" id="$2" existing
  existing="$(getent group "$name" | cut -d: -f3 || true)"
  if [ "$existing" = "$id" ]; then
    return 0
  fi
  if [ -n "$existing" ]; then
    # A group has the user's name and another id. Deleting it fails while
    # an account still uses it.
    run_account_command groupdel "$name" ||
      fail_instance "could not delete the existing group named after the agent's Linux user"
  fi
  run_account_command groupadd -g "$id" "$name" ||
    fail_instance "could not create the group for the agent's Linux user"
}

create_user() {
  local name="$1" id="$2"
  run_account_command useradd -m -u "$id" -g "$id" -s /bin/bash "$name" ||
    fail_instance "could not create the agent's Linux user"
}

ensure_user() {
  local new_id tool
  if id -u "$1" >/dev/null 2>&1; then
    return 0
  fi
  # Before any change, so a missing tool can't leave a group with no user.
  for tool in groupadd groupdel useradd; do
    command -v "$tool" >/dev/null 2>&1 || fail_instance "$tool is not installed"
  done
  new_id="$(next_free_id)"
  ensure_group "$1" "$new_id"
  create_user "$1" "$new_id"
}

# The user's home directory, or nothing when the user has none.
home_of() {
  local home
  home="$(getent passwd "$1" | cut -d: -f6 || true)"
  if [ -d "$home" ]; then
    echo "$home"
  fi
}

# useradd writes /etc/passwd before it makes the home, so a useradd that
# stops in between leaves a user with no home, which every later grant
# would fail on. This makes that home as useradd -m does. It acts only on
# a user in P0's id range, and only in a directory that root alone can
# write in, so nothing can swap the new home for a link while root fills
# it.
add_missing_home() {
  local uid gid home parent owner mode
  IFS=: read -r _ _ uid gid _ home _ <<<"$(getent passwd "$1")"
  [ "$uid" -ge "$MIN_ID" ] && [ "$uid" -le "$MAX_ID" ] || return 0
  case "$home" in
    /?*) ;;
    *) return 0 ;;
  esac
  if [ -e "$home" ] || [ -L "$home" ]; then
    return 0
  fi
  parent="$(dirname "$home")"
  if [ ! -d "$parent" ] || [ -L "$parent" ]; then
    return 0
  fi
  read -r owner mode <<<"$(stat -c '%u %a' "$parent")"
  if [ "$owner" != 0 ] || [ "$((8#$mode & 8#22))" -ne 0 ]; then
    return 0
  fi
  mkdir -m 0700 "$home" ||
    fail_instance "could not make the home directory of the agent's Linux user"
  if [ -d /etc/skel ]; then
    cp -a /etc/skel/. "$home" ||
      fail_instance "could not make the home directory of the agent's Linux user"
  fi
  # The copy gives the home the mode of /etc/skel, so the mode comes last.
  chown -R "$uid:$gid" "$home" && chmod 0700 "$home" ||
    fail_instance "could not make the home directory of the agent's Linux user"
}

# Runs one function of this script as the agent's user, not as root. The
# agent owns its home directory, so a link it plants there could point a
# write by root at any file on the instance.
#
# The child gets this script's stderr and none of its other open files. The
# agent can open the child's files through /proc, as it can those of any of
# its own processes, but not this script's, which runs as root. So it can't
# reopen the lock and hold it, which would stop every P0 change on the
# instance, or write to this script's stdout, which the connector reads the
# host keys and the reason from. It can write to stderr, and go on writing
# after this script's last line. So the child's own reason goes only to
# stderr, and a failed child gets a reason from this script.
as_user() {
  local user="$1" fn="$2"
  shift 2
  run_with_timeout "$KEY_EDIT_SECONDS" 'the edit of authorized_keys' \
    setpriv --reuid="$(id -u "$user")" --regid="$(id -g "$user")" --clear-groups \
    "$BASH" --noprofile --norc -c "$(declare -f fail_edit "$fn"); $fn \"\$@\"" p0-ssh-ai "$@" ||
    fail_instance "could not edit authorized_keys in the home directory of the agent's Linux user"
}

# A failure in the child, which has no stdout to give a reason on. as_user
# gives the script's own.
fail_edit() {
  echo "p0-ssh-ai: $1" >&2
  exit 1
}

# Runs as the agent's user. Puts the line in authorized_keys in place of
# the marker's old line, or only removes the old line when the line is
# empty.
edit_keys() {
  set -euo pipefail
  umask 077
  local home="$1" tag=" $2" line="$3" dir file
  dir="$home/.ssh"
  file="$dir/authorized_keys"
  # The agent owns these, and can take its own access away to keep a key
  # line in place. An owner can always give itself access back. On anything
  # the agent doesn't own the chmod fails, and the checks then refuse it:
  # "cannot look" must never read as "not there".
  chmod u+rwx "$home" 2>/dev/null || true
  [ -x "$home" ] || fail_edit 'cannot enter the home directory of the user'
  if [ -e "$dir" ] || [ -L "$dir" ]; then
    chmod u+rwx "$dir" 2>/dev/null || true
    if [ ! -d "$dir" ] || [ ! -r "$dir" ] || [ ! -w "$dir" ] || [ ! -x "$dir" ]; then
      fail_edit 'cannot use the .ssh directory'
    fi
  fi
  if [ -e "$file" ] || [ -L "$file" ]; then
    chmod u+rw "$file" 2>/dev/null || true
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
      fail_edit 'cannot read authorized_keys'
    fi
    if [ -n "$line" ] && grep -qxF -- "$line" "$file"; then
      return 0
    fi
  elif [ -z "$line" ]; then
    return 0
  fi
  mkdir -p "$dir"
  # Not local, so the trap can still read it when this shell exits.
  draft="$(mktemp "$dir/authorized_keys.XXXXXX")"
  trap 'rm -f "$draft"' EXIT
  if [ -f "$file" ]; then
    awk -v tag="$tag" '{
      n = length($0) - length(tag)
      if (n < 0 || substr($0, n + 1) != tag) print
    }' "$file" >"$draft"
  fi
  if [ -n "$line" ]; then
    printf '%s\n' "$line" >>"$draft"
  fi
  mv -f "$draft" "$file"
}

# An entry in the sudoers file is two lines, in the SSH integration's
# format, with the marker where that integration writes a request id:
#
#   # RequestID: p0-ssh-ai:<marker> | GrantedAt: <unix time>
#   <user> ALL=(ALL) NOPASSWD: ALL
#
# That integration's cleanup deletes every line of the file that is not
# part of such a pair. This script writes no RevokedAt line, because P0
# grants a marker again and again and that line would refuse the next
# grant.
sudoers_head() {
  echo "# RequestID: $TAG_PREFIX$1 | GrantedAt: "
}

# awk: whether a line is the first line of the entry that starts with head.
IS_HEAD='function is_head(s) {
  return index(s, head) == 1 && substr(s, length(head) + 1) ~ /^[0-9]+$/
}'

sudoers_has_head() {
  awk -v head="$1" "$IS_HEAD"'
    is_head($0) { found = 1 }
    END { exit !found }
  ' "$SUDOERS_FILE"
}

# Whether the entry is in the file with this second line.
sudoers_has_entry() {
  awk -v head="$1" -v line="$2" "$IS_HEAD"'
    after && $0 == line { found = 1 }
    { after = is_head($0) }
    END { exit !found }
  ' "$SUDOERS_FILE"
}

# The file without the entry. The line after the first one goes too, unless
# it is a comment, which would be another entry's first line.
sudoers_without() {
  awk -v head="$1" "$IS_HEAD"'
    skip { skip = 0; if (substr($0, 1, 1) != "#") next }
    is_head($0) { skip = 1; next }
    { print }
  ' "$SUDOERS_FILE"
}

# The include line counts only as a whole line of the main sudoers file, so
# a commented-out one doesn't. Added to a file with no line break at its
# end, it would join the last line and break sudo for everyone. The main
# file includes others, so visudo checks the draft with all of them before
# the rename. The draft sits next to the main file, so the include line's
# relative name finds the same sudoers-p0.
ensure_sudoers_include() {
  if grep -qxF -- "$SUDOERS_INCLUDE" "$SUDOERS_MAIN"; then
    return 0
  fi
  sudoers_draft="$SUDOERS_MAIN.p0-ssh-ai.tmp"
  cat "$SUDOERS_MAIN" >"$sudoers_draft" ||
    fail_instance "could not copy $SUDOERS_MAIN to a draft next to it"
  { [ -z "$(tail -c 1 "$sudoers_draft")" ] || echo >>"$sudoers_draft"; } &&
    echo "$SUDOERS_INCLUDE" >>"$sudoers_draft" &&
    chmod 0440 "$sudoers_draft" ||
    fail_instance "could not write a draft of $SUDOERS_MAIN next to it"
  if ! visudo -cf "$sudoers_draft" >/dev/null; then
    fail_instance "visudo refused $SUDOERS_MAIN with P0's include line added, so the script left it as it was. Fix the line visudo names."
  fi
  mv -f "$sudoers_draft" "$SUDOERS_MAIN" ||
    fail_instance "could not replace $SUDOERS_MAIN with its draft"
  sudoers_draft=''
}

# Puts the marker's entry in the sudoers file for the user, or takes the
# marker's entry out.
edit_sudoers() {
  local change="$1" head line
  head="$(sudoers_head "$2")"
  if [ "$change" = add ]; then
    line="$3 ALL=(ALL) NOPASSWD: ALL"
    command -v visudo >/dev/null 2>&1 || fail_instance 'sudo is not installed'
    if [ -f "$SUDOERS_FILE" ] && sudoers_has_entry "$head" "$line"; then
      ensure_sudoers_include
      return 0
    fi
  else
    [ -f "$SUDOERS_FILE" ] || return 0
    sudoers_has_head "$head" || return 0
  fi
  # sudo reads the draft only after the rename.
  sudoers_draft="$SUDOERS_FILE.p0-ssh-ai.tmp"
  : >"$sudoers_draft" &&
    { [ ! -f "$SUDOERS_FILE" ] || sudoers_without "$head" >"$sudoers_draft"; } &&
    { [ "$change" != add ] ||
      printf '%s%s\n%s\n' "$head" "$(date +%s)" "$line" >>"$sudoers_draft"; } &&
    chmod 0440 "$sudoers_draft" ||
    fail_instance "could not write a draft of $SUDOERS_FILE next to it"
  # The script checks only an addition. Taking this script's own two lines
  # out can't break the file, and a revoke must not fail on a line someone
  # else got wrong. visudo names the line it refuses on stderr, and that
  # line is never one of this script's.
  if [ "$change" = add ] && ! visudo -cf "$sudoers_draft" >/dev/null; then
    fail_instance "visudo refused $SUDOERS_FILE with the agent's sudo entry added, so the script left it as it was. Fix the line visudo names."
  fi
  # The file stays even when it is empty: /etc/sudoers includes it by name.
  mv -f "$sudoers_draft" "$SUDOERS_FILE" ||
    fail_instance "could not replace $SUDOERS_FILE with its draft"
  sudoers_draft=''
  if [ "$change" = add ]; then
    ensure_sudoers_include
  fi
}

host_keys() {
  local file found=0
  for file in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$file" ] || continue
    awk '{ print "${HOST_KEY_PREFIX}" $1 " " $2 }' "$file"
    found=1
  done
  [ "$found" -eq 1 ] || fail_instance 'no SSH host keys in /etc/ssh'
}

ensure_key() {
  local user="$1" tag="$TAG_PREFIX$2" key="$3" keys home
  # Read before any change: a grant is no use without the host keys.
  keys="$(host_keys)"
  ensure_user "$user"
  home="$(home_of "$user")"
  if [ -z "$home" ]; then
    add_missing_home "$user"
    home="$(home_of "$user")"
  fi
  [ -n "$home" ] || fail_instance "the agent's Linux user has no home directory"
  as_user "$user" edit_keys "$home" "$tag" "$key $tag"
  printf '%s\n' "$keys"
}

set_sudo() {
  local user="$1" marker="$2"
  if [ "$3" = on ]; then
    id -u "$user" >/dev/null 2>&1 || fail_instance "the agent's Linux user does not exist"
    edit_sudoers add "$marker" "$user"
  else
    edit_sudoers remove "$marker"
  fi
}

remove_key() {
  local user="$1" marker="$2" home
  # sudo goes first, so a failure in the user's home can't keep it.
  edit_sudoers remove "$marker"
  # No user, or a user with no home directory, has no key line to remove.
  home="$(home_of "$user")"
  if [ -n "$home" ]; then
    as_user "$user" edit_keys "$home" "$TAG_PREFIX$marker" ''
  fi
}

# The SSH integration's lock, so the two scripts never rewrite the sudoers
# file at once.
take_lock() {
  local seconds code=0
  seconds="$(seconds_for "$LOCK_WAIT_SECONDS")"
  [ "$seconds" -gt 0 ] || fail_try_again 'no time was left to wait for the lock'
  exec 9>"$LOCK_FILE" || fail_instance "could not open $LOCK_FILE"
  chmod 600 "$LOCK_FILE" || fail_instance "could not set the mode of $LOCK_FILE"
  flock -x -w "$seconds" 9 || code="$?"
  # flock exits 1 when the wait runs out, and a retry can work then. Any
  # other code means flock can't run.
  if [ "$code" -eq 1 ]; then
    fail_try_again "another P0 change held the instance for $seconds seconds. Try again."
  fi
  [ "$code" -eq 0 ] || fail_instance "could not lock $LOCK_FILE with flock"
}

main() {
  [ "$#" -ge 3 ] || fail 'expected an action, a user and a marker'
  local action="$1" user="$2" marker="$3"
  check 'user name' '${USER_SOURCE}' "$user"
  check 'marker' '${MARKER_SOURCE}' "$marker"
  case "$action" in
    ensure-key)
      [ "$#" -eq 4 ] || fail 'ensure-key takes a user, a marker and a public key'
      check 'public key' '${PUBLIC_KEY_SOURCE}' "$4"
      ;;
    set-sudo)
      [ "$#" -eq 4 ] || fail 'set-sudo takes a user, a marker and on or off'
      [ "$4" = on ] || [ "$4" = off ] || fail 'set-sudo takes on or off'
      ;;
    remove-key)
      [ "$#" -eq 3 ] || fail 'remove-key takes a user and a marker'
      ;;
    *)
      fail 'unknown action'
      ;;
  esac
  [ "$(id -u)" -eq 0 ] || fail 'must run as root'

  # One change at a time on the instance.
  mkdir -p "$LOCK_DIR" && chown root:root "$LOCK_DIR" && chmod 700 "$LOCK_DIR" ||
    fail_instance "could not set up $LOCK_DIR for the lock"
  take_lock

  case "$action" in
    ensure-key) ensure_key "$user" "$marker" "$4" ;;
    set-sudo) set_sudo "$user" "$marker" "$4" ;;
    remove-key) remove_key "$user" "$marker" ;;
  esac
}

main "$@"
`;

/**
 * The provisioning script as a program that reads its arguments. It is one
 * string because the Lambda image ships only the bundle.
 */
export const PROVISION_SCRIPT = `${SHEBANG}\n${BODY}`;

export type ProvisionAction =
  | { action: "ensure-key"; user: string; marker: string; publicKey: string }
  | { action: "remove-key"; user: string; marker: string }
  | { action: "set-sudo"; user: string; marker: string; sudo: boolean };

const invalid = (what: string) =>
  new ConnectorError({
    // Not `validation_error`, which P0 shows the user as their own mistake.
    // P0 builds every argument, so a bad one is P0's bug. Like the script,
    // the error never holds the value.
    type: "unknown",
    message: `P0 built an invalid ${what} for the provisioning script. Contact P0 support.`,
    payload: { argument: what },
  });

const validateArgument = (what: string, pattern: RegExp, value: string) => {
  if (!pattern.test(value)) throw invalid(what);
  return value;
};

const toArguments = (input: ProvisionAction): string[] => {
  const common = [
    input.action,
    validateArgument("user name", USER_PATTERN, input.user),
    validateArgument("holder group id", MARKER_PATTERN, input.marker),
  ];
  switch (input.action) {
    case "ensure-key":
      return [
        ...common,
        validateArgument("public key", PUBLIC_KEY_PATTERN, input.publicKey),
      ];
    case "set-sudo":
      return [...common, input.sudo ? "on" : "off"];
    case "remove-key":
      return common;
    default:
      throw throwAssertNever(input);
  }
};

/**
 * Quotes one word for bash. Inside single quotes bash reads every character
 * as itself, so only a single quote needs care: it closes the string, adds
 * an escaped quote, and opens the string again.
 */
export const quoteShellWord = (value: string) =>
  `'${value.replace(/'/g, `'\\''`)}'`;

/**
 * The script with one action's arguments set, as the text to send in the
 * `commands` parameter of `AWS-RunShellScript`. This checks the arguments,
 * and the script checks them again. The check alone makes them safe to
 * place, and the quoting keeps them safe if someone ever widens a pattern.
 */
export const buildProvisionScript = (input: ProvisionAction): string =>
  [
    SHEBANG,
    `set -- ${toArguments(input).map(quoteShellWord).join(" ")}`,
    BODY,
  ].join("\n");

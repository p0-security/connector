import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { EXECUTION_TIMEOUT_SECONDS, commentOf } from "../../ssm/run-script.ts";
import {
  HOST_KEY_PREFIX,
  MARKER_PATTERN,
  PROVISION_SCRIPT,
  PUBLIC_KEY_PATTERN,
  type ProvisionAction,
  REASON_PREFIX,
  RESULT_LINES,
  USER_PATTERN,
  buildProvisionScript,
  commandTagFor,
  quoteShellWord,
} from "../provision.ts";

// A real ed25519 public key, made for this test. Its private half was
// thrown away.
const PUBLIC_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNfTRvCl8zew9m3iUw0qNRiI6Qm/TBT59IyFnrYVPLQ";

const ensureKey: ProvisionAction = {
  action: "ensure-key",
  user: "alice-ai",
  marker: "group-1",
  publicKey: PUBLIC_KEY,
};

const linesOf = (script: string) => script.split("\n");

const errorOf = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    if (error instanceof ConnectorError) return error.data;
  }
  throw new Error("expected a ConnectorError");
};

describe("quoteShellWord", () => {
  it.each([
    ["alice-ai", "'alice-ai'"],
    ["", "''"],
    ["two words", "'two words'"],
    ["$(id) `id` $HOME", "'$(id) `id` $HOME'"],
    ['a"b\\c', `'a"b\\c'`],
    ["a;b|c&d>e", "'a;b|c&d>e'"],
    ["line\nbreak", "'line\nbreak'"],
    ["it's", `'it'\\''s'`],
    ["'; rm -rf / #", `''\\''; rm -rf / #'`],
    ["''", `''\\'''\\'''`],
  ])("quotes %j as %s", (value, quoted) => {
    expect(quoteShellWord(value)).toBe(quoted);
  });
});

describe("buildProvisionScript", () => {
  it("sets the arguments on the line after the shebang, each quoted", () => {
    const [shebang, set] = linesOf(buildProvisionScript(ensureKey));
    expect(shebang).toBe("#!/bin/bash");
    expect(set).toBe(
      `set -- 'ensure-key' 'alice-ai' 'group-1' '${PUBLIC_KEY}'`
    );
  });

  it.each<[ProvisionAction, string]>([
    [
      { action: "set-sudo", user: "alice-ai", marker: "g1", sudo: true },
      "set -- 'set-sudo' 'alice-ai' 'g1' 'on'",
    ],
    [
      { action: "set-sudo", user: "alice-ai", marker: "g1", sudo: false },
      "set -- 'set-sudo' 'alice-ai' 'g1' 'off'",
    ],
    [
      { action: "remove-key", user: "alice-ai", marker: "g1" },
      "set -- 'remove-key' 'alice-ai' 'g1'",
    ],
  ])("renders %j", (action, set) => {
    expect(linesOf(buildProvisionScript(action))[1]).toBe(set);
  });

  it("sends the same script for every action, apart from the arguments", () => {
    const rendered = linesOf(buildProvisionScript(ensureKey));
    const standalone = linesOf(PROVISION_SCRIPT);
    expect([rendered[0], ...rendered.slice(2)]).toEqual(standalone);
  });

  it.each([
    ["a user without the -ai suffix", { user: "alice" }],
    ["a user with an upper-case letter", { user: "Alice-ai" }],
    ["a user that starts with a digit", { user: "1alice-ai" }],
    ["a user of 33 characters", { user: `${"a".repeat(30)}-ai` }],
    ["a user with a quote", { user: "a'; id; '-ai" }],
    ["a user with a line break", { user: "alice-ai\nbob-ai" }],
    ["root", { user: "root" }],
    ["an empty marker", { marker: "" }],
    ["a marker with a space", { marker: "group 1" }],
    ["a marker with a quote", { marker: "g'$(id)'" }],
    ["a marker with a line break", { marker: "g1\nALL ALL=(ALL) ALL" }],
    ["a marker of 65 characters", { marker: "m".repeat(65) }],
    ["an RSA key", { publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7" }],
    ["a key with a comment", { publicKey: `${PUBLIC_KEY} alice@laptop` }],
    ["a key with options", { publicKey: `no-pty ${PUBLIC_KEY}` }],
    ["two keys", { publicKey: `${PUBLIC_KEY}\n${PUBLIC_KEY}` }],
    ["a key that is too short", { publicKey: PUBLIC_KEY.slice(0, -1) }],
  ])(
    "refuses %s as P0's own bug, and keeps it out of the error",
    (_name, change) => {
      const data = errorOf(() =>
        buildProvisionScript({ ...ensureKey, ...change })
      );
      expect(data.type).toBe("unknown");
      expect(data.message).toMatch(
        /^P0 built an invalid (user name|holder group id|public key) for the provisioning script\. Contact P0 support\.$/
      );
      const [value] = Object.values(change);
      expect(JSON.stringify(data)).not.toContain(JSON.stringify(value));
    }
  );

  it("names the marker as the holder group id", () => {
    const data = errorOf(() =>
      buildProvisionScript({ ...ensureKey, marker: "" })
    );
    expect(data.message).toBe(
      "P0 built an invalid holder group id for the provisioning script. Contact P0 support."
    );
    expect(data.payload).toEqual({ argument: "holder group id" });
  });

  it("accepts a user of 32 characters and a marker of 64", () => {
    const user = `${"a".repeat(29)}-ai`;
    const marker = "m".repeat(64);
    expect(
      linesOf(buildProvisionScript({ action: "remove-key", user, marker }))[1]
    ).toBe(`set -- 'remove-key' '${user}' '${marker}'`);
  });
});

describe("commandTagFor", () => {
  // The longest marker the script takes.
  const MARKER = "0123456789abcdef".repeat(4);
  const common = { user: "bot-ai", marker: MARKER };

  it.each([
    [{ ...common, action: "ensure-key", publicKey: "k" }, "ensure-key", false],
    [{ ...common, action: "set-sudo", sudo: true }, "set-sudo-on", true],
    [{ ...common, action: "set-sudo", sudo: false }, "set-sudo-off", true],
    [{ ...common, action: "remove-key" }, "remove-key", true],
  ] as const)(
    "tags %o as %s, taken over by a retry: %s",
    (input, action, reusable) => {
      const tag = commandTagFor(input);
      expect(tag).toEqual({ group: `p0-ssh-ai:${MARKER}`, action, reusable });
      expect(commentOf(tag).length).toBeLessThanOrEqual(100);
    }
  );

  it("refuses a marker the script would refuse", () => {
    expect(() =>
      commandTagFor({ ...common, marker: "a b", action: "remove-key" })
    ).toThrow(ConnectorError);
  });
});

describe("the argument patterns", () => {
  it("match the user name rule", () => {
    const rule = /^[a-z][a-z0-9_-]*-ai$/;
    const longest = `${"x".repeat(29)}-ai`;
    for (const user of ["a-ai", "alice-ai", "a_b-c9-ai", longest]) {
      expect(rule.test(user)).toBe(true);
      expect(USER_PATTERN.test(user)).toBe(true);
    }
    for (const user of ["-ai", "ai", "alice", "alice-AI", "9a-ai", "a.b-ai"]) {
      expect(rule.test(user)).toBe(false);
      expect(USER_PATTERN.test(user)).toBe(false);
    }
    // One character past Linux's limit, which the rule's pattern allows.
    expect(USER_PATTERN.test(`x${longest}`)).toBe(false);
  });

  it.each([
    ["user name", USER_PATTERN],
    ["marker", MARKER_PATTERN],
    ["public key", PUBLIC_KEY_PATTERN],
  ])("are the ones the script checks the %s with", (what, pattern) => {
    const checked = new RegExp(`check '${what}' '([^']+)' "\\$`).exec(
      PROVISION_SCRIPT
    )?.[1];
    if (checked === undefined) {
      throw new Error(`the script doesn't check the ${what}`);
    }
    expect(new RegExp(checked).source).toBe(pattern.source);
  });

  it("accept a real ed25519 key", () => {
    expect(PUBLIC_KEY_PATTERN.test(PUBLIC_KEY)).toBe(true);
  });
});

describe("PROVISION_SCRIPT", () => {
  /** The script without its comment lines. */
  const code = linesOf(PROVISION_SCRIPT)
    .filter((line) => !line.trim().startsWith("#"))
    .join("\n");

  it("is a bash program that reads its arguments", () => {
    const lines = linesOf(PROVISION_SCRIPT);
    expect(lines[0]).toBe("#!/bin/bash");
    expect(lines).toContain("set -euo pipefail");
    expect(lines.at(-2)).toBe('main "$@"');
    expect(lines.at(-1)).toBe("");
  });

  // JavaScript reads `${` in the template, and an escaped one reaches bash
  // with its backslash, so the text can hold neither.
  it("holds no ${ and no value JavaScript failed to place", () => {
    expect(PROVISION_SCRIPT).not.toContain("${");
    expect(PROVISION_SCRIPT).not.toContain("undefined");
    expect(PROVISION_SCRIPT).not.toContain("[object");
  });

  it("keeps the backslashes bash needs", () => {
    expect(PROVISION_SCRIPT).toContain(String.raw`$fn \"\$@\""`);
    expect(PROVISION_SCRIPT).toContain(String.raw`printf '%s\n' "$line"`);
  });

  it("prints the result line and the prefixes the caller reads", () => {
    expect(PROVISION_SCRIPT).toContain(`echo '${RESULT_LINES.ok}' >&3`);
    expect(PROVISION_SCRIPT).toContain(`echo '${RESULT_LINES.failed}' >&3`);
    expect(PROVISION_SCRIPT).toContain("trap report EXIT");
    expect(PROVISION_SCRIPT).toContain(`print "${HOST_KEY_PREFIX}" $1 " " $2`);
    expect(PROVISION_SCRIPT).toContain(`echo '${REASON_PREFIX}'"$2" >&3`);
  });

  it("shares the SSH integration's sudoers file, and its include line", () => {
    expect(code).toContain("SUDOERS_FILE='/etc/sudoers-p0'");
    expect(code).toContain("SUDOERS_MAIN='/etc/sudoers'");
    expect(code).toContain("SUDOERS_INCLUDE='#include sudoers-p0'");
    expect(code).toContain(
      'if grep -qxF -- "$SUDOERS_INCLUDE" "$SUDOERS_MAIN"; then'
    );
    expect(PROVISION_SCRIPT).not.toContain("/etc/sudoers.d");
  });

  it("checks a draft with visudo before an addition replaces the sudoers file", () => {
    const mode = code.indexOf('chmod 0440 "$sudoers_draft"');
    const check = code.indexOf(
      'if [ "$change" = add ] && ! visudo -cf "$sudoers_draft" >/dev/null; then'
    );
    const rename = code.indexOf('mv -f "$sudoers_draft" "$SUDOERS_FILE"');
    expect(mode).toBeGreaterThan(-1);
    expect(check).toBeGreaterThan(mode);
    expect(rename).toBeGreaterThan(check);
  });

  it("checks the main sudoers file with visudo, in a draft next to it, before the include line goes in", () => {
    const draft = code.indexOf('sudoers_draft="$SUDOERS_MAIN.p0-ssh-ai.tmp"');
    const include = code.indexOf('echo "$SUDOERS_INCLUDE" >>"$sudoers_draft"');
    const check = code.indexOf(
      'if ! visudo -cf "$sudoers_draft" >/dev/null; then',
      include
    );
    const rename = code.indexOf('mv -f "$sudoers_draft" "$SUDOERS_MAIN"');
    expect(draft).toBeGreaterThan(-1);
    expect(include).toBeGreaterThan(draft);
    expect(check).toBeGreaterThan(include);
    expect(rename).toBeGreaterThan(check);
  });

  it("gives each command it waits for none of its open files, and a time limit", () => {
    expect(code).toContain(
      'timeout -k 1 "$seconds" "$@" </dev/null >/dev/null 3>&- 9>&-'
    );
    expect(code).toContain('chmod 600 "$LOCK_FILE"');
    expect(code).toContain(
      `run_with_timeout "$KEY_EDIT_SECONDS" 'the edit of authorized_keys'`
    );
  });

  it("ends every command it waits for inside SSM's execution timeout", () => {
    const seconds = (name: string) => {
      const line = linesOf(code).find((each) => each.startsWith(`${name}=`));
      return Number(line?.slice(name.length + 1));
    };
    const budget = seconds("RUN_BUDGET_SECONDS");
    // Each wait gets at most what is left of the budget.
    expect(code).toContain("local left=$((RUN_BUDGET_SECONDS - 1 - SECONDS))");
    expect(code).toContain('seconds="$(seconds_for "$1")"');
    expect(code).toContain('seconds="$(seconds_for "$LOCK_WAIT_SECONDS")"');
    expect(seconds("LOCK_WAIT_SECONDS")).toBeLessThan(budget);
    expect(seconds("KEY_EDIT_SECONDS")).toBeLessThan(budget);
    // timeout sends KILL one second after TERM.
    expect(code).toContain('timeout -k 1 "$seconds" "$@"');
    expect(budget + 1).toBeLessThan(EXECUTION_TIMEOUT_SECONDS);
  });

  it("writes a sudoers entry the SSH integration's script reads as a pair", () => {
    expect(code).toContain("TAG_PREFIX='p0-ssh-ai:'");
    expect(code).toContain('echo "# RequestID: $TAG_PREFIX$1 | GrantedAt: "');
    expect(code).toContain('line="$3 ALL=(ALL) NOPASSWD: ALL"');
    expect(code).toContain(
      String.raw`printf '%s%s\n%s\n' "$head" "$(date +%s)" "$line"`
    );
    // The first line of an entry, as the script writes it for the longest
    // marker, against the pattern in the integration's UpdateFile.
    const marker = "m".repeat(64);
    const head = `# RequestID: p0-ssh-ai:${marker} | GrantedAt: 1794935763`;
    const reference =
      /^#\sRequestID:\s(.+)\s\|\s(GrantedAt|RevokedAt):\s([0-9]+)/;
    expect(reference.exec(head)?.slice(1)).toEqual([
      `p0-ssh-ai:${marker}`,
      "GrantedAt",
      "1794935763",
    ]);
  });

  it("writes no RevokedAt line, and never deletes the sudoers file", () => {
    expect(code).not.toContain("RevokedAt");
    expect(code).not.toMatch(/rm -f[^\n]*\$SUDOERS_FILE"/);
  });

  it("creates a user as the SSH integration does, with its tools only", () => {
    expect(code).toContain("MIN_ID=65536");
    expect(code).toContain("MAX_ID=90000");
    expect(code).toContain(
      'run_account_command useradd -m -u "$id" -g "$id" -s /bin/bash "$name"'
    );
    expect(code).toContain('run_account_command groupadd -g "$id" "$name"');
    expect(code).toContain("for tool in groupadd groupdel useradd; do");
    expect(code).not.toMatch(/\b(adduser|addgroup|delgroup)\b/);
  });

  // The take_lock call, not the function: its body comes earlier in the
  // file than main.
  const takeLock = code.indexOf("\n  take_lock\n");

  it("takes the SSH integration's lock before it changes anything", () => {
    expect(code).toContain("LOCK_DIR='/run/p0'");
    expect(code).toContain("LOCK_FILE='/run/p0/p0-operations.lock'");
    expect(code).toContain('chmod 700 "$LOCK_DIR"');
    expect(code).toContain('flock -x -w "$seconds" 9');
    const firstAction = code.indexOf('ensure-key) ensure_key "$user"');
    expect(takeLock).toBeGreaterThan(-1);
    expect(firstAction).toBeGreaterThan(takeLock);
  });

  it("fails with a retry's code when another change holds the lock", () => {
    expect(code).toContain(
      'fail_try_again "another P0 change held the instance for $seconds seconds. Try again."'
    );
  });

  it("checks every argument before it takes the lock", () => {
    const lock = PROVISION_SCRIPT.indexOf("\n  take_lock\n");
    expect(lock).toBeGreaterThan(-1);
    for (const what of ["user name", "marker", "public key"]) {
      const check = PROVISION_SCRIPT.indexOf(`check '${what}'`);
      expect(check).toBeGreaterThan(-1);
      expect(check).toBeLessThan(lock);
    }
  });

  it("edits the agent's files as the agent's user, not as root", () => {
    expect(PROVISION_SCRIPT).toContain('as_user "$user" edit_keys "$home"');
    expect(PROVISION_SCRIPT).toContain('setpriv --reuid="$(id -u "$user")"');
    // The child shell gets no function that writes a reason to stdout.
    expect(PROVISION_SCRIPT).toContain('"$(declare -f fail_edit "$fn"); $fn');
  });

  it("calls no cloud API", () => {
    expect(PROVISION_SCRIPT).not.toMatch(/\b(aws|gcloud|az|curl|wget)\b/);
  });
});

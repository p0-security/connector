import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  INSTANCE_STATE_EXIT_CODE,
  P0_BUG_EXIT_CODE,
  PROVISION_SCRIPT,
  REASON_PREFIX,
  RESULT_LINES,
  TRY_AGAIN_EXIT_CODE,
  buildProvisionScript,
  quoteShellWord,
} from "../provision.ts";

// These tests run the script with bash. The other test file only reads its
// text, which would not catch a syntax error in a script that runs as root.
// Nothing here needs root: the tests run the whole script only with
// arguments it refuses before it changes anything, and run its functions
// against a temp directory.

const version = spawnSync("bash", ["-c", 'printf %s "$BASH_VERSION"'], {
  encoding: "utf8",
});
const BASH_VERSION = version.status === 0 ? version.stdout : undefined;

// The script's own PATH, so the tests find the same tools an instance does.
const SCRIPT_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const hasTool = (tool: string) =>
  spawnSync("bash", ["-c", `PATH=${SCRIPT_PATH} command -v ${tool}`]).status ===
  0;
const hasVisudo = hasTool("visudo");

/**
 * Whether visudo checks a file that includes another in a temp directory.
 * Newer sudo refuses an include in a directory root doesn't own, as on
 * GitHub's Ubuntu runners, so the tests whose main file includes
 * `sudoers-p0` run only where it doesn't, or as root.
 */
const visudoFollowsTempIncludes = (() => {
  if (!hasVisudo) return false;
  const probe = mkdtempSync(join(tmpdir(), "p0-ssh-ai-visudo-"));
  try {
    writeFileSync(join(probe, "sudoers"), "#include included\n");
    writeFileSync(join(probe, "included"), "");
    return (
      spawnSync("bash", [
        "-c",
        `PATH=${SCRIPT_PATH} visudo -cf "$1"`,
        "bash",
        join(probe, "sudoers"),
      ]).status === 0
    );
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();
// coreutils' timeout and util-linux's flock, which macOS lacks.
const hasTimeout = hasTool("timeout");
const hasFlock = hasTool("flock");
const isRoot = process.getuid?.() === 0;

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNfTRvCl8zew9m3iUw0qNRiI6Qm/TBT59IyFnrYVPLQ";
const OTHER_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrInlG8MGQVPGDUEs0M1VlSZIBMD9w9yaNkIicdN2WV";

/** The script's functions and settings, without the call that runs them. */
const FUNCTIONS = PROVISION_SCRIPT.replace(/\nmain "\$@"\n$/, "\n");

let dir = "";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "p0-ssh-ai-"));
});

afterEach(() => {
  // A test can leave a directory it may not enter.
  spawnSync("chmod", ["-R", "u+rwx", dir]);
  rmSync(dir, { recursive: true, force: true });
});

const result = ({ status, stdout, stderr }: SpawnSyncReturns<string>) => ({
  status,
  stdout,
  stderr,
  lastLine: stdout.trimEnd().split("\n").at(-1),
});

/** Runs the whole script with these arguments, as the user running the tests. */
const runScript = (...args: string[]) =>
  result(
    spawnSync("bash", ["-c", PROVISION_SCRIPT, "p0-ssh-ai", ...args], {
      encoding: "utf8",
    })
  );

/**
 * Runs bash lines after loading the script's functions, with its two
 * sudoers paths and its lock file pointed into the temp directory.
 */
const runFunctions = (lines: string) =>
  result(
    spawnSync(
      "bash",
      [
        "-c",
        [
          FUNCTIONS,
          `SUDOERS_FILE=${quoteShellWord(join(dir, "sudoers-p0"))}`,
          `SUDOERS_MAIN=${quoteShellWord(join(dir, "sudoers"))}`,
          `LOCK_FILE=${quoteShellWord(join(dir, "lock"))}`,
          lines,
        ].join("\n"),
      ],
      { encoding: "utf8" }
    )
  );

const read = (name: string) => readFileSync(join(dir, name), "utf8");
const modeOf = (name: string) => statSync(join(dir, name)).mode & 0o777;

/** What a failed run prints on stdout: its reason, then the result line. */
const failedWith = (reason: string) =>
  `${REASON_PREFIX}${reason}\n${RESULT_LINES.failed}\n`;

describe.skipIf(!BASH_VERSION)(
  `the script, run by bash ${BASH_VERSION}`,
  () => {
    it("keeps its last line, so the functions can be loaded without it", () => {
      expect(FUNCTIONS).not.toBe(PROVISION_SCRIPT);
      expect(FUNCTIONS).not.toContain('main "$@"');
    });

    describe("syntax", () => {
      it.each([
        ["as it ships", () => PROVISION_SCRIPT],
        [
          "with the arguments of an action set",
          () =>
            buildProvisionScript({
              action: "ensure-key",
              user: "alice-ai",
              marker: "m1",
              publicKey: KEY,
            }),
        ],
      ])("parses %s", (_name, script) => {
        const file = join(dir, "script.sh");
        writeFileSync(file, script());
        const parsed = spawnSync("bash", ["-n", file], { encoding: "utf8" });
        expect(parsed.stderr).toBe("");
        expect(parsed.status).toBe(0);
      });
    });

    it("says it failed on its last line when TERM stops it", () => {
      const run = runFunctions(
        [
          // Another process sends TERM while the script waits.
          "( kill -TERM $$ ) &",
          "wait",
          "echo 'p0-ssh-ai: still running' >&2",
        ].join("\n")
      );
      expect(run.stderr).toBe("");
      expect(run.status).toBe(143);
      expect(run.stdout).toBe(`${RESULT_LINES.failed}\n`);
    });

    it.each([
      ["P0's own bug", "fail", P0_BUG_EXIT_CODE],
      ["the instance's state", "fail_instance", INSTANCE_STATE_EXIT_CODE],
      ["a run a retry can fix", "fail_try_again", TRY_AGAIN_EXIT_CODE],
    ])(
      "exits with the code of %s, and gives the reason on stderr and stdout",
      (_name, fn, code) => {
        const run = runFunctions(`${fn} 'the reason'`);
        expect(run.status).toBe(code);
        expect(run.stderr).toBe("p0-ssh-ai: the reason\n");
        expect(run.stdout).toBe(failedWith("the reason"));
      }
    );

    it("gives the reason on stdout when it fails inside a command substitution", () => {
      const run = runFunctions(
        "keys=\"$(echo 'not a reason'; fail_instance 'the reason')\""
      );
      expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
      expect(run.stdout).toBe(failedWith("the reason"));
    });

    describe("the time budget", () => {
      // Stand-ins that print the limit they get, so no test waits for one.
      // SECONDS can tick between its assignment and a wait, so a limit
      // that depends on it can be a second short.
      const STUBS = [
        'timeout() { echo "limit $3" >&2; }',
        'flock() { echo "wait $3" >&2; }',
      ].join("\n");

      it("gives each wait what it asks for while the budget lasts", () => {
        const run = runFunctions(
          [
            STUBS,
            "SECONDS=0",
            "run_with_timeout 5 'the test command' true",
            "run_with_timeout \"$RUN_BUDGET_SECONDS\" 'the test command' true",
            "take_lock",
          ].join("\n")
        );
        // The whole budget is a second short, the one SECONDS can be behind.
        expect(run.stderr).toMatch(/^limit 5\nlimit 2[67]\nwait 10\n$/);
        expect(run.status).toBe(0);
      });

      it("cuts a wait down to what is left of the budget", () => {
        const run = runFunctions(
          [
            STUBS,
            "SECONDS=24",
            "run_with_timeout 5 'the test command' true",
            "SECONDS=22",
            "take_lock",
          ].join("\n")
        );
        expect(run.stderr).toMatch(/^limit [23]\nwait [45]\n$/);
        expect(run.status).toBe(0);
      });

      it.each([
        [
          "a command",
          "run_with_timeout 5 'the test command' true",
          "no time was left for the test command",
        ],
        ["the lock", "take_lock", "no time was left to wait for the lock"],
      ])(
        "fails %s with a retry's code once no time is left",
        (_name, call, message) => {
          const run = runFunctions([STUBS, "SECONDS=27", call].join("\n"));
          expect(run.status).toBe(TRY_AGAIN_EXIT_CODE);
          expect(run.stderr).toBe(`p0-ssh-ai: ${message}\n`);
          expect(run.lastLine).toBe(RESULT_LINES.failed);
        }
      );
    });

    describe("arguments", () => {
      it.each<[string, string[], string]>([
        ["no arguments", [], "expected an action, a user and a marker"],
        [
          "a user without -ai",
          ["ensure-key", "alice", "m1", KEY],
          "invalid user name",
        ],
        [
          "a user of 33 characters",
          ["ensure-key", `${"a".repeat(30)}-ai`, "m1", KEY],
          "invalid user name",
        ],
        [
          "a user with a command in it",
          ["ensure-key", "a$(id)-ai", "m1", KEY],
          "invalid user name",
        ],
        [
          "a user with a second line",
          ["ensure-key", "alice-ai\nroot-ai", "m1", KEY],
          "invalid user name",
        ],
        [
          "a user that ends in a line break",
          ["ensure-key", "alice-ai\n", "m1", KEY],
          "invalid user name",
        ],
        ["an empty marker", ["remove-key", "alice-ai", ""], "invalid marker"],
        [
          "a marker with the entry format's bar",
          ["set-sudo", "alice-ai", "m | GrantedAt: 1", "on"],
          "invalid marker",
        ],
        [
          "a marker that ends in a line break",
          ["remove-key", "alice-ai", "m1\n"],
          "invalid marker",
        ],
        [
          "an RSA key",
          ["ensure-key", "alice-ai", "m1", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB"],
          "invalid public key",
        ],
        [
          "a key with a comment",
          ["ensure-key", "alice-ai", "m1", `${KEY} alice@laptop`],
          "invalid public key",
        ],
        [
          "a key that ends in a line break",
          ["ensure-key", "alice-ai", "m1", `${KEY}\n`],
          "invalid public key",
        ],
        [
          "a missing public key",
          ["ensure-key", "alice-ai", "m1"],
          "ensure-key takes a user, a marker and a public key",
        ],
        [
          "a sudo state that is neither on nor off",
          ["set-sudo", "alice-ai", "m1", "maybe"],
          "set-sudo takes on or off",
        ],
        [
          "an extra argument",
          ["remove-key", "alice-ai", "m1", "extra"],
          "remove-key takes a user and a marker",
        ],
        ["an unknown action", ["cleanup", "alice-ai", "m1"], "unknown action"],
      ])("refuses %s, and says so on the last line", (_name, args, message) => {
        const run = runScript(...args);
        expect(run.status).toBe(P0_BUG_EXIT_CODE);
        expect(run.stderr).toBe(`p0-ssh-ai: ${message}\n`);
        expect(run.stdout).toBe(failedWith(message));
      });

      // Never as root: with arguments it accepts, the script would go on to
      // change this machine.
      it.skipIf(isRoot)(
        "accepts good arguments, then stops because it is not root",
        () => {
          for (const args of [
            ["ensure-key", "alice-ai", "m1", KEY],
            ["set-sudo", "alice-ai", "m1", "on"],
            ["remove-key", `${"a".repeat(29)}-ai`, "m".repeat(64)],
          ]) {
            const run = runScript(...args);
            expect(run.stderr).toBe("p0-ssh-ai: must run as root\n");
            expect(run.status).toBe(P0_BUG_EXIT_CODE);
            expect(run.lastLine).toBe(RESULT_LINES.failed);
          }
        }
      );
    });

    describe("the sudoers entry", () => {
      const MAIN = "root ALL=(ALL:ALL) ALL\n";
      const ENTRY =
        /^# RequestID: p0-ssh-ai:m1 \| GrantedAt: \d+\nalice-ai ALL=\(ALL\) NOPASSWD: ALL\n$/;
      // What P0's SSH integration leaves in the same file.
      const REFERENCE_BEFORE = [
        "# RequestID: refreqAAAA1111 | GrantedAt: 1794935763",
        "human1 ALL=(ALL) NOPASSWD: ALL",
        "# RequestID: refreqBBBB2222 | RevokedAt: 1794935764",
        "",
      ].join("\n");
      const REFERENCE_AFTER = [
        "# RequestID: refreqCCCC3333 | GrantedAt: 1794935765",
        "human3 ALL=(ALL) NOPASSWD: ALL",
        "",
      ].join("\n");

      beforeEach(() => {
        writeFileSync(join(dir, "sudoers"), MAIN);
      });

      it.skipIf(!visudoFollowsTempIncludes)(
        "is added as two lines, in a file of mode 0440 that the main file includes (needs visudo)",
        () => {
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          expect(run.stderr).toBe("");
          expect(run.lastLine).toBe(RESULT_LINES.ok);
          expect(read("sudoers-p0")).toMatch(ENTRY);
          expect(modeOf("sudoers-p0")).toBe(0o440);
          expect(read("sudoers")).toBe(`${MAIN}#include sudoers-p0\n`);
          expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
        }
      );

      it.skipIf(!visudoFollowsTempIncludes)(
        "is left as it is by a second add (needs visudo)",
        () => {
          runFunctions("edit_sudoers add m1 alice-ai");
          const first = read("sudoers-p0");
          const inode = statSync(join(dir, "sudoers-p0")).ino;
          const mainInode = statSync(join(dir, "sudoers")).ino;
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          expect(run.status).toBe(0);
          expect(read("sudoers-p0")).toBe(first);
          expect(statSync(join(dir, "sudoers-p0")).ino).toBe(inode);
          expect(read("sudoers")).toBe(`${MAIN}#include sudoers-p0\n`);
          expect(statSync(join(dir, "sudoers")).ino).toBe(mainInode);
        }
      );

      it.skipIf(!visudoFollowsTempIncludes)(
        "puts the include line on a line of its own when the main file's last line has no line break (needs visudo)",
        () => {
          writeFileSync(join(dir, "sudoers"), MAIN.trimEnd());
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          expect(run.stderr).toBe("");
          expect(run.status).toBe(0);
          expect(read("sudoers")).toBe(`${MAIN}#include sudoers-p0\n`);
          expect(modeOf("sudoers")).toBe(0o440);
          expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
        }
      );

      it.skipIf(!visudoFollowsTempIncludes)(
        "adds the include line when the main file only has it commented out (needs visudo)",
        () => {
          const commented = `${MAIN}# #include sudoers-p0\n`;
          writeFileSync(join(dir, "sudoers"), commented);
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          expect(run.status).toBe(0);
          expect(read("sudoers")).toBe(`${commented}#include sudoers-p0\n`);
        }
      );

      it.skipIf(!visudoFollowsTempIncludes)(
        "leaves the main file as it was, and no draft, when visudo refuses it with the include line (needs visudo)",
        () => {
          const broken = `${MAIN}this is not sudoers syntax (\n`;
          writeFileSync(join(dir, "sudoers"), broken);
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          const reason = `visudo refused ${join(dir, "sudoers")} with P0's include line added, so the script left it as it was. Fix the line visudo names.`;
          expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
          expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
          expect(run.stdout).toBe(failedWith(reason));
          expect(read("sudoers")).toBe(broken);
          expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
        }
      );

      it.skipIf(!hasVisudo)(
        "is refused, with the file untouched and no draft left, when visudo rejects the file (needs visudo)",
        () => {
          const broken = `${REFERENCE_BEFORE}this is not sudoers syntax (\n`;
          writeFileSync(join(dir, "sudoers-p0"), broken);
          const run = runFunctions("edit_sudoers add m1 alice-ai");
          const reason = `visudo refused ${join(dir, "sudoers-p0")} with the agent's sudo entry added, so the script left it as it was. Fix the line visudo names.`;
          expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
          expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
          expect(run.stdout).toBe(failedWith(reason));
          expect(read("sudoers-p0")).toBe(broken);
          expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
        }
      );

      it("fails with the instance's code, with the file untouched and no draft left, when it can't write the draft", () => {
        const ours =
          "# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764\nalice-ai ALL=(ALL) NOPASSWD: ALL\n";
        writeFileSync(join(dir, "sudoers-p0"), ours);
        // A chmod that fails stops the edit after it wrote the draft.
        const run = runFunctions(
          "chmod() { return 1; }\nedit_sudoers remove m1"
        );
        const reason = `could not write a draft of ${join(dir, "sudoers-p0")} next to it`;
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
        expect(run.stdout).toBe(failedWith(reason));
        expect(read("sudoers-p0")).toBe(ours);
        expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
      });

      it("fails with the instance's code, with the file untouched and no draft left, when it can't replace the file", () => {
        const ours =
          "# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764\nalice-ai ALL=(ALL) NOPASSWD: ALL\n";
        writeFileSync(join(dir, "sudoers-p0"), ours);
        // A mount over the file or an immutable file makes a real rename
        // fail, and both need root. So a stand-in for mv fails instead.
        const run = runFunctions("mv() { return 1; }\nedit_sudoers remove m1");
        const reason = `could not replace ${join(dir, "sudoers-p0")} with its draft`;
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
        expect(run.stdout).toBe(failedWith(reason));
        expect(read("sudoers-p0")).toBe(ours);
        expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
      });

      it("fails with the instance's code, with the main file untouched and no draft left, when it can't write the main file's draft", () => {
        const run = runFunctions(
          "chmod() { return 1; }\nensure_sudoers_include"
        );
        const reason = `could not write a draft of ${join(dir, "sudoers")} next to it`;
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
        expect(run.stdout).toBe(failedWith(reason));
        expect(read("sudoers")).toBe(MAIN);
        expect(readdirSync(dir)).toEqual(["sudoers"]);
      });

      it.skipIf(!visudoFollowsTempIncludes)(
        "fails with the instance's code, with the main file untouched and no draft left, when it can't replace the main file (needs visudo)",
        () => {
          // visudo checks the draft with the file it includes.
          writeFileSync(join(dir, "sudoers-p0"), "");
          const run = runFunctions(
            "mv() { return 1; }\nensure_sudoers_include"
          );
          const reason = `could not replace ${join(dir, "sudoers")} with its draft`;
          expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
          expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
          expect(run.stdout).toBe(failedWith(reason));
          expect(read("sudoers")).toBe(MAIN);
          expect(readdirSync(dir).sort()).toEqual(["sudoers", "sudoers-p0"]);
        }
      );

      it("is removed from between the SSH integration's entries, which stay byte for byte", () => {
        const ours = [
          "# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764",
          "alice-ai ALL=(ALL) NOPASSWD: ALL",
          "",
        ].join("\n");
        writeFileSync(
          join(dir, "sudoers-p0"),
          `${REFERENCE_BEFORE}${ours}${REFERENCE_AFTER}`
        );
        const run = runFunctions("edit_sudoers remove m1");
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        expect(read("sudoers-p0")).toBe(
          `${REFERENCE_BEFORE}${REFERENCE_AFTER}`
        );
        expect(modeOf("sudoers-p0")).toBe(0o440);
      });

      it("is removed even when another line of the file is broken", () => {
        const garbage = "this is not sudoers syntax (\n";
        const ours = [
          "# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764",
          "alice-ai ALL=(ALL) NOPASSWD: ALL",
          "",
        ].join("\n");
        writeFileSync(join(dir, "sudoers-p0"), `${ours}${garbage}`);
        const run = runFunctions("edit_sudoers remove m1");
        expect(run.status).toBe(0);
        expect(run.lastLine).toBe(RESULT_LINES.ok);
        expect(read("sudoers-p0")).toBe(garbage);
      });

      it("loses only its first line when its second line is already gone", () => {
        writeFileSync(
          join(dir, "sudoers-p0"),
          `# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764\n${REFERENCE_AFTER}`
        );
        expect(runFunctions("edit_sudoers remove m1").status).toBe(0);
        expect(read("sudoers-p0")).toBe(REFERENCE_AFTER);
      });

      it("leaves the file alone when the marker has no entry, or there is no file", () => {
        expect(runFunctions("edit_sudoers remove m1").status).toBe(0);
        expect(existsSync(join(dir, "sudoers-p0"))).toBe(false);

        writeFileSync(join(dir, "sudoers-p0"), REFERENCE_BEFORE);
        const inode = statSync(join(dir, "sudoers-p0")).ino;
        // m is the start of another marker, and of nothing in the file.
        expect(runFunctions("edit_sudoers remove m").status).toBe(0);
        expect(read("sudoers-p0")).toBe(REFERENCE_BEFORE);
        expect(statSync(join(dir, "sudoers-p0")).ino).toBe(inode);
      });

      it("leaves the file in place, empty, when the last entry goes", () => {
        writeFileSync(
          join(dir, "sudoers-p0"),
          "# RequestID: p0-ssh-ai:m1 | GrantedAt: 1794935764\nalice-ai ALL=(ALL) NOPASSWD: ALL\n"
        );
        expect(runFunctions("edit_sudoers remove m1").status).toBe(0);
        expect(read("sudoers-p0")).toBe("");
        expect(read("sudoers")).toBe(MAIN);
      });
    });

    describe("the key line", () => {
      const TAG = "p0-ssh-ai:m1";
      const LINE = `${KEY} ${TAG}`;
      const HUMAN = "ssh-ed25519 AAAAhuman human@laptop";
      const keysFile = () => join(dir, "home", ".ssh", "authorized_keys");

      /** Runs `edit_keys` on the temp home, as the script's child shell does. */
      const editKeys = (line: string, tag = TAG) =>
        runFunctions(
          `( edit_keys ${quoteShellWord(join(dir, "home"))} ${quoteShellWord(tag)} ${quoteShellWord(line)} )`
        );

      /** `fail_edit`'s exit code. `as_user` treats every failed edit alike. */
      const EDIT_FAILED_EXIT_CODE = 1;
      const EDIT_REASON =
        "could not edit authorized_keys in the home directory of the agent's Linux user";

      // Stand-ins that run the command as the user running the tests, with
      // the open files run_with_timeout gives it.
      const AS_USER_STUBS = [
        'timeout() { shift 3; "$@"; }',
        'setpriv() { shift 3; "$@"; }',
      ].join("\n");

      /** Runs a function in a child shell through `as_user`. */
      const asUser = (fn: string, ...args: string[]) =>
        runFunctions(
          [
            AS_USER_STUBS,
            `as_user "$(id -un)" ${fn} ${args.map(quoteShellWord).join(" ")}`,
          ].join("\n")
        );

      const seed = (...lines: string[]) => {
        mkdirSync(join(dir, "home", ".ssh"), { recursive: true, mode: 0o700 });
        writeFileSync(keysFile(), lines.map((line) => `${line}\n`).join(""), {
          mode: 0o600,
        });
      };

      beforeEach(() => {
        mkdirSync(join(dir, "home"));
      });

      it("is added, in a .ssh and a file closed to everyone else", () => {
        const run = editKeys(LINE);
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${LINE}\n`);
        expect(modeOf("home/.ssh")).toBe(0o700);
        expect(modeOf("home/.ssh/authorized_keys")).toBe(0o600);
        expect(readdirSync(join(dir, "home", ".ssh"))).toEqual([
          "authorized_keys",
        ]);
      });

      it("is not written again when it is already there", () => {
        seed(LINE, HUMAN);
        const inode = statSync(keysFile()).ino;
        expect(editKeys(LINE).status).toBe(0);
        expect(statSync(keysFile()).ino).toBe(inode);
      });

      it("replaces the marker's old line, and no other", () => {
        seed(HUMAN, LINE, `${OTHER_KEY} p0-ssh-ai:xm1`);
        expect(editKeys(`${OTHER_KEY} ${TAG}`).status).toBe(0);
        expect(readFileSync(keysFile(), "utf8")).toBe(
          [HUMAN, `${OTHER_KEY} p0-ssh-ai:xm1`, `${OTHER_KEY} ${TAG}`, ""].join(
            "\n"
          )
        );
      });

      it("is removed, and the other lines stay", () => {
        seed(HUMAN, LINE);
        expect(editKeys("").status).toBe(0);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${HUMAN}\n`);
      });

      it("has nothing to remove when there is no .ssh or no file", () => {
        expect(editKeys("").status).toBe(0);
        expect(existsSync(join(dir, "home", ".ssh"))).toBe(false);
        mkdirSync(join(dir, "home", ".ssh"));
        expect(editKeys("").status).toBe(0);
        expect(existsSync(keysFile())).toBe(false);
      });

      it.each([
        ["a .ssh the agent made read-only", 0o500],
        ["a .ssh the agent closed to itself", 0o000],
      ])("is removed from %s", (_name, mode) => {
        seed(HUMAN, LINE);
        chmodSync(join(dir, "home", ".ssh"), mode);
        const run = editKeys("");
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        expect(modeOf("home/.ssh") & 0o700).toBe(0o700);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${HUMAN}\n`);
      });

      it("is removed from a file and a home the agent closed to itself", () => {
        seed(HUMAN, LINE);
        chmodSync(keysFile(), 0o000);
        chmodSync(join(dir, "home"), 0o000);
        const run = editKeys("");
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${HUMAN}\n`);
      });

      it("fails, and never reports ok, when .ssh is a link that leads nowhere", () => {
        symlinkSync(join(dir, "nowhere"), join(dir, "home", ".ssh"));
        for (const line of ["", LINE]) {
          const run = editKeys(line);
          expect(run.status).toBe(EDIT_FAILED_EXIT_CODE);
          expect(run.stderr).toBe("p0-ssh-ai: cannot use the .ssh directory\n");
          // The child's reason goes only to stderr.
          expect(run.stdout).toBe(`${RESULT_LINES.failed}\n`);
        }
      });

      it("fails when authorized_keys is a link that leads nowhere", () => {
        mkdirSync(join(dir, "home", ".ssh"));
        symlinkSync(join(dir, "nowhere"), keysFile());
        const run = editKeys("");
        expect(run.status).toBe(EDIT_FAILED_EXIT_CODE);
        expect(run.stderr).toBe("p0-ssh-ai: cannot read authorized_keys\n");
      });

      it("is added through the child shell, and the script carries on", () => {
        const run = asUser("edit_keys", join(dir, "home"), TAG, LINE);
        expect(run.stderr).toBe("");
        expect(run.stdout).toBe(`${RESULT_LINES.ok}\n`);
        expect(readFileSync(keysFile(), "utf8")).toBe(`${LINE}\n`);
      });

      it("gives a failed edit the script's own reason, after the child's on stderr", () => {
        symlinkSync(join(dir, "nowhere"), join(dir, "home", ".ssh"));
        const run = asUser("edit_keys", join(dir, "home"), TAG, "");
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stderr).toBe(
          `p0-ssh-ai: cannot use the .ssh directory\np0-ssh-ai: ${EDIT_REASON}\n`
        );
        expect(run.stdout).toBe(failedWith(EDIT_REASON));
      });

      it("keeps whatever the child shell writes out of the script's stdout", () => {
        const forge = [
          "forge() {",
          `  echo '${REASON_PREFIX}forged on stderr' >&2`,
          `  echo '${REASON_PREFIX}forged on stdout'`,
          `  { echo '${REASON_PREFIX}forged on the result channel' >&3; } 2>/dev/null`,
          "  fail_edit 'forged'",
          "}",
        ].join("\n");
        const run = runFunctions(
          [AS_USER_STUBS, forge, 'as_user "$(id -un)" forge'].join("\n")
        );
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stdout).toBe(failedWith(EDIT_REASON));
        expect(run.stderr).toBe(
          `${REASON_PREFIX}forged on stderr\np0-ssh-ai: forged\np0-ssh-ai: ${EDIT_REASON}\n`
        );
      });

      // A directory this user may not read, as /root is to an agent.
      const closed =
        ["/root", "/var/root"].find((path) => {
          if (!existsSync(path)) return false;
          try {
            accessSync(path, constants.R_OK);
            return false;
          } catch {
            return true;
          }
        }) ?? "";

      it.skipIf(!closed)(
        `fails when .ssh is a link to a directory it may not read (${closed})`,
        () => {
          symlinkSync(closed, join(dir, "home", ".ssh"));
          for (const line of ["", LINE]) {
            const run = editKeys(line);
            expect(run.status).toBe(EDIT_FAILED_EXIT_CODE);
            expect(run.stderr).toBe(
              "p0-ssh-ai: cannot use the .ssh directory\n"
            );
          }
        }
      );
    });

    // Making a home needs root, and this repo has no container tests, so no
    // test here makes one.
    it("leaves a missing home alone for a user outside P0's id range", () => {
      const home = join(dir, "alice-ai");
      const entry = `alice-ai:x:1500:1500::${home}:/bin/bash`;
      const run = runFunctions(
        [
          `getent() { echo ${quoteShellWord(entry)}; }`,
          "add_missing_home alice-ai",
        ].join("\n")
      );
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
      expect(existsSync(home)).toBe(false);
    });

    describe("a user that already has the agent's name", () => {
      const REASON =
        "the agent's Linux user name belongs to an account outside P0's user ids. Ask your P0 admin to rename the agent, or rename that account on the instance";

      /**
       * Runs `ensure_user` for alice-ai, which exists with this id. Every
       * command that changes an account runs under timeout, so its stand-in
       * says what it would run: no test changes this machine's accounts,
       * even as root, and any change shows on stderr.
       */
      const ensureExisting = (uid: number) =>
        runFunctions(
          [
            `id() { [ "$*" = '-u alice-ai' ] && echo ${uid}; }`,
            'timeout() { echo "would run: $*" >&2; }',
            "ensure_user alice-ai",
          ].join("\n")
        );

      it.each([
        ["root's", 0],
        ["a person's", 1000],
        ["just below P0's range", 65535],
        ["just above P0's range", 90001],
      ])(
        "is refused with the instance's code, before any change, when its id is %s (%i)",
        (_name, uid) => {
          const run = ensureExisting(uid);
          expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
          expect(run.stderr).toBe(`p0-ssh-ai: ${REASON}\n`);
          expect(run.stdout).toBe(failedWith(REASON));
        }
      );

      it.each([65536, 90000])(
        "is used as it is when its id is %i, an end of P0's range",
        (uid) => {
          const run = ensureExisting(uid);
          expect(run.stderr).toBe("");
          expect(run.status).toBe(0);
          expect(run.stdout).toBe(`${RESULT_LINES.ok}\n`);
        }
      );

      // The user has a home, so a check that came after the key edit would
      // let setpriv run under timeout, and its stand-in would say so.
      it("stops ensure-key before the key edit when its id is outside P0's range", () => {
        const home = join(dir, "alice-ai");
        mkdirSync(home);
        const entry = `alice-ai:x:1500:1500::${home}:/bin/bash`;
        const run = runFunctions(
          [
            "host_keys() { echo 'p0-ssh-ai-host-key: ssh-ed25519 AAAA'; }",
            `id() { [ "$*" = '-u alice-ai' ] && echo 1500; }`,
            `getent() { echo ${quoteShellWord(entry)}; }`,
            'timeout() { echo "would run: $*" >&2; }',
            `ensure_key alice-ai m1 ${quoteShellWord(KEY)}`,
          ].join("\n")
        );
        expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
        expect(run.stderr).toBe(`p0-ssh-ai: ${REASON}\n`);
        expect(run.stdout).toBe(failedWith(REASON));
      });
    });

    describe("a group that already has the agent's name, and no user", () => {
      const REASON =
        "the agent's Linux user name is taken by a group outside P0's group ids. Ask your P0 admin to rename the agent, or rename that group on the instance";

      /**
       * Runs `ensure_group` for alice-ai, whose group exists with this id and
       * a member, with 65537 as the new user's id. Every command that changes
       * a group runs under timeout, so its stand-in says what it would run,
       * less timeout's own arguments: no test changes this machine's groups,
       * even as root.
       */
      const ensureGroup = (gid: number) =>
        runFunctions(
          [
            `getent() { [ "$*" = 'group alice-ai' ] && echo 'alice-ai:x:${gid}:bob'; }`,
            'timeout() { shift 3; echo "would run: $*" >&2; }',
            "ensure_group alice-ai 65537",
          ].join("\n")
        );

      it.each([
        ["root's", 0],
        ["a person's", 1000],
        ["just below P0's range", 65535],
        ["just above P0's range", 90001],
      ])(
        "is refused with the instance's code, before any change, when its id is %s (%i)",
        (_name, gid) => {
          const run = ensureGroup(gid);
          expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
          expect(run.stderr).toBe(`p0-ssh-ai: ${REASON}\n`);
          expect(run.stdout).toBe(failedWith(REASON));
        }
      );

      it.each([65536, 90000])(
        "is deleted and made again with the new user's id when its id is %i, an end of P0's range",
        (gid) => {
          const run = ensureGroup(gid);
          expect(run.stderr).toBe(
            "would run: groupdel alice-ai\nwould run: groupadd -g 65537 alice-ai\n"
          );
          expect(run.status).toBe(0);
          expect(run.stdout).toBe(`${RESULT_LINES.ok}\n`);
        }
      );
    });

    it("fails with the instance's code when it can't open the lock file", () => {
      const lock = join(dir, "missing", "lock");
      const run = runFunctions(
        [`LOCK_FILE=${quoteShellWord(lock)}`, "take_lock"].join("\n")
      );
      const reason = `could not open ${lock}`;
      expect(run.status).toBe(INSTANCE_STATE_EXIT_CODE);
      expect(run.stderr).toContain(`p0-ssh-ai: ${reason}\n`);
      expect(run.stdout).toBe(failedWith(reason));
    });

    describe.skipIf(!hasFlock)("the lock (needs flock)", () => {
      it("is taken when no other change holds it", () => {
        const run = runFunctions("take_lock");
        expect(run.stderr).toBe("");
        expect(run.status).toBe(0);
        expect(modeOf("lock")).toBe(0o600);
      });

      it("ends the run with its own exit code when another change holds it", () => {
        const run = runFunctions(
          [
            // Another change, which holds the lock for longer than the wait.
            // It gets none of the test's output, so the test needn't wait
            // for it to end.
            '( flock -x 8; : >"$LOCK_FILE.held"; sleep 4 ) 8>"$LOCK_FILE" </dev/null >/dev/null 2>&1 3>&- &',
            'while [ ! -e "$LOCK_FILE.held" ]; do sleep 0.1; done',
            "LOCK_WAIT_SECONDS=2",
            "take_lock",
          ].join("\n")
        );
        expect(run.status).toBe(TRY_AGAIN_EXIT_CODE);
        expect(run.stderr).toBe(
          "p0-ssh-ai: another P0 change held the instance for 2 seconds. Try again.\n"
        );
        expect(run.lastLine).toBe(RESULT_LINES.failed);
      });
    });

    describe.skipIf(!hasTimeout)("the time limit (needs timeout)", () => {
      it.each([
        ["runs too long", "sleep 10"],
        ["stops itself, as the agent can stop the key edit", "kill -STOP $$"],
        ["ignores TERM", 'trap "" TERM; sleep 10'],
      ])("ends a command that %s, and says which", (_name, command) => {
        const run = runFunctions(
          `run_with_timeout 1 'the test command' bash -c ${quoteShellWord(command)}`
        );
        expect(run.status).toBe(TRY_AGAIN_EXIT_CODE);
        // After KILL, bash also reports the killed timeout on a line before.
        expect(run.stderr).toMatch(
          /(^|\n)p0-ssh-ai: the test command took longer than 1 seconds\n$/
        );
        expect(run.lastLine).toBe(RESULT_LINES.failed);
      });

      it("gives the command the script's stderr and none of its other files", () => {
        const check = [
          'for fd in 3 9; do [ ! -e "/proc/$$/fd/$fd" ] || exit 1; done',
          '[ "$(readlink "/proc/$$/fd/0")" = /dev/null ] || exit 1',
          '[ "$(readlink "/proc/$$/fd/1")" = /dev/null ] || exit 1',
          "echo 'only stderr' >&2",
        ].join("\n");
        const run = runFunctions(
          [
            'exec 9>"$LOCK_FILE"',
            `run_with_timeout 5 'the test command' bash -c ${quoteShellWord(check)}`,
          ].join("\n")
        );
        expect(run.stderr).toBe("only stderr\n");
        expect(run.status).toBe(0);
        expect(run.lastLine).toBe(RESULT_LINES.ok);
      });
    });
  }
);

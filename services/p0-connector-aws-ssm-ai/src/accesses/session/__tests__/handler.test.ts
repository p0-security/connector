import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";

import {
  HOST_KEYS,
  connectorErrorOf,
  dataOf,
  errorOf,
  fakeEc2,
  fakeInstance,
  fakeSecretsManager,
  recordingLogger,
  sdkError,
} from "../../../__tests__/fakes.ts";
import { publicKeyOf } from "../../../__tests__/openssh.ts";
import { markerFor } from "../../../marker.ts";
import { t } from "../../../router.ts";
import {
  INSTANCE_STATE_EXIT_CODE,
  P0_BUG_EXIT_CODE,
  REASON_PREFIX,
  TRY_AGAIN_EXIT_CODE,
} from "../../../script/provision.ts";
import type { SessionSecret } from "../definition.ts";
import { router } from "../handler.ts";

const context = {
  requestId: "r1",
  secrets: { manager: "aws" as const, region: "us-west-2" },
  instance: { id: "i-0123456789abcdef0", region: "us-east-1" },
};
const SECRET = "p0/ssh-ai/i-0123456789abcdef0/alice-ai/7f3a";
const ARN = `arn:aws:secretsmanager:us-west-2:123456789012:secret:${SECRET}-AbCdEf`;
const MARKER = markerFor(SECRET);
const userBody = { user: "alice-ai", secretName: SECRET };

let instance = fakeInstance();
let vault = fakeSecretsManager();
let tags = fakeEc2();
let log = recordingLogger();

beforeEach(() => {
  instance = fakeInstance();
  vault = fakeSecretsManager();
  tags = fakeEc2();
  log = recordingLogger();
});

const session = () =>
  router(t, {
    ssm: instance.ssm,
    secrets: vault.dependencies,
    ec2: tags.client,
  }).createCaller({ logger: log.logger });

const grant = (body = userBody) =>
  session().provisionUser({ userBody: body, context });

const identify = () => session().identifyUser({ userBody, context });

const setPolicies = (policies: { sudo: boolean }[], body = userBody) =>
  session().setPoliciesForUser({
    userId: ARN,
    userBody: body,
    policies,
    context,
  });

const revoke = (userId = ARN) =>
  session().deleteUser({ userId, userBody, context });

/** A secret's value as the gateway reads it. */
const parseSecret = (value = "null"): SessionSecret => JSON.parse(value);

const stored = (name = SECRET) => parseSecret(vault.valueOf(name));

describe("grant", () => {
  it("installs a new key for the group's marker, then stores the private half", async () => {
    await expect(grant()).resolves.toBe(ARN);

    const installed = instance.keys.get(MARKER)?.publicKey;
    expect(instance.actions).toEqual([
      ["ensure-key", "alice-ai", MARKER, installed],
    ]);
    const secret = stored();
    expect(Object.keys(secret)).toEqual(["privateKey", "user", "hostKeys"]);
    expect(secret.user).toBe("alice-ai");
    expect(secret.hostKeys).toEqual(HOST_KEYS);
    expect(secret.privateKey).toMatch(
      /^-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END OPENSSH PRIVATE KEY-----\n$/
    );
    expect(publicKeyOf(secret.privateKey)).toBe(installed);
  });

  it("opens the vault in the region the request names", async () => {
    await session().provisionUser({
      userBody,
      context: {
        ...context,
        secrets: { manager: "aws", region: "eu-central-1" },
      },
    });
    expect(vault.configs.length).toBeGreaterThan(0);
    for (const config of vault.configs) {
      expect(config).toEqual({ provider: "aws", region: "eu-central-1" });
    }
  });

  it("does nothing the second time", async () => {
    await grant();
    const value = vault.valueOf(SECRET);
    await expect(grant()).resolves.toBe(ARN);
    expect(instance.actions).toHaveLength(1);
    expect(vault.secrets.get(SECRET)?.values).toHaveLength(1);
    expect(vault.valueOf(SECRET)).toBe(value);
  });

  it("identifies the group only once its secret holds a value", async () => {
    await expect(identify()).resolves.toBeNull();
    vault.secrets.set(SECRET, { arn: ARN, values: [] });
    await expect(identify()).resolves.toBeNull();
    vault.secrets.set(SECRET, { arn: ARN, values: [Buffer.from("{}")] });
    await expect(identify()).resolves.toBe(ARN);
    expect(instance.actions).toEqual([]);
  });

  it("refuses a Linux user outside the -ai namespace before it calls AWS", async () => {
    await errorOf(grant({ user: "root", secretName: SECRET }));
    await errorOf(grant({ user: "alice-ai", secretName: "a secret" }));
    expect(instance.actions).toEqual([]);
    expect(vault.calls).toEqual([]);
  });
});

describe("a grant that stopped halfway", () => {
  it("finishes on the next try, with one key on the instance: the one it stored", async () => {
    vault.state.failNextWrite = () => sdkError("InternalServiceError");
    const data = await dataOf(grant());
    expect(data).toMatchObject({
      type: "upstream_unavailable",
      payload: {
        step: "write_secret",
        requestId: "r1",
        awsError: "InternalServiceError",
      },
    });
    const firstKey = instance.keys.get(MARKER)?.publicKey;
    expect(firstKey).toBeDefined();
    expect(vault.secrets.get(SECRET)?.values).toHaveLength(0);

    await expect(grant()).resolves.toBe(ARN);
    expect(instance.actions.map(([action]) => action)).toEqual([
      "ensure-key",
      "ensure-key",
    ]);
    const secondKey = instance.keys.get(MARKER)?.publicKey;
    expect(secondKey).not.toBe(firstKey);
    expect(instance.keys.size).toBe(1);
    expect(publicKeyOf(stored().privateKey)).toBe(secondKey);
    expect(vault.secrets.get(SECRET)?.values).toHaveLength(1);
  });

  it("leaves a secret with no value when the script fails, and fills it on the next try", async () => {
    instance.state.failNext = {
      stderr: "p0-ssh-ai: no SSH host keys in /etc/ssh",
      exitCode: INSTANCE_STATE_EXIT_CODE,
    };
    const data = await dataOf(grant());
    expect(data).toMatchObject({
      type: "dependency_violation",
      payload: {
        reason: "command_failed",
        requestId: "r1",
        instanceId: context.instance.id,
      },
    });
    expect(vault.secrets.get(SECRET)?.values).toHaveLength(0);
    await expect(identify()).resolves.toBeNull();

    await expect(grant()).resolves.toBe(ARN);
    expect(stored().hostKeys).toEqual(HOST_KEYS);
    expect(vault.secrets.size).toBe(1);
  });

  it("fails when SSM can't reach the instance, with no value stored", async () => {
    instance.state.unreachable = true;
    const data = await dataOf(grant());
    expect(data).toMatchObject({
      type: "object_not_found",
      payload: { reason: "instance_unreachable", requestId: "r1" },
    });
    expect(vault.valueOf(SECRET)).toBeUndefined();
  });

  it("asks to retry, with the instance untouched, while AWS still deletes the group's last secret", async () => {
    await grant();
    vault.state.deleteInBackground = true;
    await revoke();
    instance.actions.length = 0;

    // AWS still describes the old secret, with the date its deletion began.
    expect(vault.secrets.has(SECRET)).toBe(true);
    await expect(identify()).resolves.toBeNull();
    const data = await dataOf(grant());
    expect(data).toEqual({
      type: "upstream_unavailable",
      message:
        "Secrets Manager is still deleting the previous secret with this name. Try again in a moment.",
      payload: {
        step: "create_secret",
        requestId: "r1",
        awsError: "InvalidRequestException",
      },
    });
    expect(instance.actions).toEqual([]);

    vault.finishDeleting();
    await expect(grant()).resolves.toBe(ARN);
    expect(instance.actions.map(([action]) => action)).toEqual(["ensure-key"]);
    expect(publicKeyOf(stored().privateKey)).toBe(
      instance.keys.get(MARKER)?.publicKey
    );
  });

  it("leaves the instance untouched when the secret can't be created", async () => {
    vault.state.failNextCreate = sdkError(
      "InvalidRequestException",
      "The name is not valid."
    );
    const data = await dataOf(grant());
    expect(data).toMatchObject({
      type: "upstream_unavailable",
      payload: { step: "create_secret", awsError: "InvalidRequestException" },
    });
    expect(instance.actions).toEqual([]);
  });

  it("reports a role that may not write the secret, in AWS's words", async () => {
    vault.state.failNextWrite = () =>
      new UnauthorizedError("aws", {
        cause: sdkError(
          "AccessDeniedException",
          "User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: secretsmanager:PutSecretValue on resource: p0/ssh-ai"
        ),
      });
    const data = await dataOf(grant());
    expect(data).toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "write_secret", requestId: "r1" },
    });
    expect(data.message).toContain(
      "not authorized to perform: secretsmanager:PutSecretValue"
    );
  });

  it("names the request in an error about the host keys", async () => {
    instance.state.hostKeys = [];
    const data = await dataOf(grant());
    expect(data).toEqual({
      type: "dependency_violation",
      message:
        "The instance returned no SSH host keys P0 can read. Check the host keys in /etc/ssh/ssh_host_*_key.pub on the instance.",
      payload: { nHostKeys: 0, requestId: "r1" },
    });
    expect(vault.valueOf(SECRET)).toBeUndefined();
  });

  it("logs each call's lines under its request and its instance", async () => {
    await grant();
    expect(log.lines).toContainEqual([
      { requestId: "r1", instanceId: context.instance.id, user: "alice-ai" },
    ]);
    expect(log.lines).toContainEqual([
      { instanceId: context.instance.id, commandId: "command-1" },
      "sent the SSM command",
    ]);
  });
});

describe("sudo", () => {
  beforeEach(async () => {
    await grant();
    instance.actions.length = 0;
  });

  it("is on while any holder of the group was granted it", async () => {
    await expect(
      setPolicies([{ sudo: false }, { sudo: true }])
    ).resolves.toBeNull();
    expect(instance.actions).toEqual([
      ["set-run-as", "alice-ai", MARKER, "root"],
    ]);
    expect(instance.sudo.get(MARKER)).toEqual({
      user: "alice-ai",
      runAs: ["root"],
    });
  });

  it("goes off when the holder that had it leaves, and when no holder is left", async () => {
    await setPolicies([{ sudo: false }, { sudo: true }]);
    await setPolicies([{ sudo: false }]);
    expect(instance.sudo.has(MARKER)).toBe(false);
    await setPolicies([{ sudo: true }]);
    await setPolicies([]);
    expect(instance.sudo.has(MARKER)).toBe(false);
    expect(instance.actions.map(([, , , ...runAs]) => runAs)).toEqual([
      ["root"],
      [],
      ["root"],
      [],
    ]);
  });

  it("sends the same script again when the same set is applied again", async () => {
    await setPolicies([{ sudo: true }]);
    await setPolicies([{ sudo: true }]);
    expect(instance.actions).toEqual([
      ["set-run-as", "alice-ai", MARKER, "root"],
      ["set-run-as", "alice-ai", MARKER, "root"],
    ]);
  });

  // sudo belongs to the Linux user, not to a group. The marker only says
  // which group asked for the entry, so that each can take its own away.
  it("leaves a shared Linux user with sudo while either group's entry names it", async () => {
    const other = { user: "alice-ai", secretName: `${SECRET}/other` };
    await grant(other);
    await setPolicies([{ sudo: true }]);
    await setPolicies([{ sudo: false }], other);

    // One entry, asked for by the first group, and it names the user that
    // the other group logs in as too.
    expect([...instance.sudo.entries()]).toEqual([
      [MARKER, { user: "alice-ai", runAs: ["root"] }],
    ]);
    expect(instance.keys.get(markerFor(other.secretName))?.user).toBe(
      "alice-ai"
    );

    await setPolicies([{ sudo: false }]);
    expect(instance.sudo.size).toBe(0);
  });

  it("fails to give sudo when SSM can't reach the instance", async () => {
    instance.state.unreachable = true;
    const data = await dataOf(setPolicies([{ sudo: true }]));
    expect(data.payload).toMatchObject({
      reason: "instance_unreachable",
      requestId: "r1",
    });
  });

  it("fails to take sudo away when SSM can't reach the instance, so the revoke stops", async () => {
    await setPolicies([{ sudo: true }]);
    instance.state.unreachable = true;
    for (const policies of [[{ sudo: false }], []]) {
      const data = await dataOf(setPolicies(policies));
      expect(data).toMatchObject({
        type: "object_not_found",
        payload: { reason: "instance_unreachable", requestId: "r1" },
      });
    }
    expect(instance.sudo.get(MARKER)?.user).toBe("alice-ai");
  });

  it("fails to take sudo away when the script itself fails", async () => {
    instance.state.failNext = {
      stderr: "p0-ssh-ai: could not lock /run/p0/p0-operations.lock with flock",
      exitCode: INSTANCE_STATE_EXIT_CODE,
    };
    const data = await dataOf(setPolicies([{ sudo: false }]));
    expect(data).toMatchObject({
      type: "dependency_violation",
      payload: { reason: "command_failed", exitCode: INSTANCE_STATE_EXIT_CODE },
    });
  });
});

describe("a failed script", () => {
  beforeEach(async () => {
    await grant();
  });

  const failWith = (stderr: string, exitCode: number, reason?: string) => {
    instance.state.failNext = { stderr, exitCode, reason };
    return dataOf(setPolicies([{ sudo: true }]));
  };

  /** Where the requester reads the rest, for the script that failed here. */
  const DETAILS = "The output of SSM command command-2 has the details.";

  // What the agent can write to the script's stderr through the key edit's
  // child, before and after the script's own last line.
  const FORGED_STDERR = [
    "p0-ssh-ai: forged by the agent",
    `${REASON_PREFIX}forged by the agent`,
    "p0-ssh-ai: sudo is not installed",
    "p0-ssh-ai: forged after the script's own line",
    "any other text the agent wrote",
  ].join("\n");

  const payloadFor = (exitCode: number) => ({
    reason: "command_failed",
    exitCode,
    status: "Failed",
    instanceId: context.instance.id,
    commandId: "command-2",
    requestId: "r1",
  });

  // P0 never shows an upstream_unavailable's message, so it keeps the end
  // of stderr.
  it("asks to retry when another P0 change held the instance's lock for the whole wait", async () => {
    const busy =
      "p0-ssh-ai: another P0 change held the instance for 10 seconds. Try again.";
    const data = await failWith(busy, TRY_AGAIN_EXIT_CODE);
    expect(data).toEqual({
      type: "upstream_unavailable",
      message: `P0's script on ${context.instance.id} exited with code ${TRY_AGAIN_EXIT_CODE}: ${busy}`,
      payload: payloadFor(TRY_AGAIN_EXIT_CODE),
    });
    await expect(setPolicies([{ sudo: true }])).resolves.toBeNull();
  });

  it.each([
    ["sudo is not installed", "sudo is not installed"],
    [
      "visudo refused /etc/sudoers with P0's include line added, so the script left it as it was. Fix the line visudo names.",
      "visudo refused /etc/sudoers with P0's include line added, so the script left it as it was. Fix the line visudo names",
    ],
  ])(
    "shows the requester the instance's own state in the script's reason: %s",
    async (reason, shown) => {
      const data = await failWith(
        `p0-ssh-ai: ${reason}`,
        INSTANCE_STATE_EXIT_CODE,
        reason
      );
      expect(data).toEqual({
        type: "dependency_violation",
        message: `P0's script couldn't change ${context.instance.id}: ${shown}. ${DETAILS}`,
        payload: payloadFor(INSTANCE_STATE_EXIT_CODE),
      });
    }
  );

  it("keeps everything on stderr out of that error, even a forged reason after the script's own", async () => {
    const data = await failWith(
      FORGED_STDERR,
      INSTANCE_STATE_EXIT_CODE,
      "sudo is not installed"
    );
    expect(data.message).toBe(
      `P0's script couldn't change ${context.instance.id}: sudo is not installed. ${DETAILS}`
    );
    expect(JSON.stringify(data)).not.toMatch(/forged|other text/);
  });

  it("shows a fixed text, and nothing from stderr, when the script gave no reason", async () => {
    const data = await failWith(FORGED_STDERR, INSTANCE_STATE_EXIT_CODE);
    expect(data).toEqual({
      type: "dependency_violation",
      message: `P0's script couldn't change ${context.instance.id}. ${DETAILS}`,
      payload: payloadFor(INSTANCE_STATE_EXIT_CODE),
    });
  });

  it("logs the end of stderr that the error leaves out", async () => {
    await failWith(
      `${FORGED_STDERR}\n`,
      INSTANCE_STATE_EXIT_CODE,
      "sudo is not installed"
    );
    expect(log.lines).toContainEqual([
      { commandId: "command-2", stderrTail: FORGED_STDERR },
      "the script failed on the instance's state",
    ]);
  });

  // P0 never shows an unknown error's message either.
  it.each([P0_BUG_EXIT_CODE, 143])(
    "keeps exit code %i as P0's own bug",
    async (exitCode) => {
      const data = await failWith("p0-ssh-ai: the reason", exitCode);
      expect(data).toEqual({
        type: "unknown",
        message: `P0's script on ${context.instance.id} exited with code ${exitCode}: p0-ssh-ai: the reason`,
        payload: payloadFor(exitCode),
      });
    }
  );
});

describe("revoke", () => {
  it("removes the group's key and sudo, then deletes the secret", async () => {
    await grant();
    await setPolicies([{ sudo: true }]);
    await expect(revoke()).resolves.toBeNull();

    expect(instance.actions.at(-1)).toEqual(["remove-key", "alice-ai", MARKER]);
    expect(instance.keys.size).toBe(0);
    expect(instance.sudo.size).toBe(0);
    expect(vault.secrets.size).toBe(0);
    expect(vault.calls.at(-1)).toBe("deleteSecret");
  });

  it("gives the same result the second time", async () => {
    await grant();
    await revoke();
    await expect(revoke()).resolves.toBeNull();
    expect(instance.actions.slice(-2)).toEqual([
      ["remove-key", "alice-ai", MARKER],
      ["remove-key", "alice-ai", MARKER],
    ]);
  });

  it("leaves another group's key and secret alone", async () => {
    const other = { user: "alice-ai", secretName: `${SECRET}/other` };
    await grant();
    await grant(other);
    await revoke();
    expect([...instance.keys.keys()]).toEqual([markerFor(other.secretName)]);
    expect([...vault.secrets.keys()]).toEqual([other.secretName]);
  });

  it("fails and keeps the secret when SSM can't reach the instance, every time", async () => {
    await grant();
    const { privateKey } = stored();
    instance.state.unreachable = true;
    log.lines.length = 0;

    for (const _attempt of [1, 2, 3]) {
      const data = await dataOf(revoke());
      expect(data).toMatchObject({
        type: "object_not_found",
        payload: { reason: "instance_unreachable", requestId: "r1" },
      });
    }
    expect(instance.keys.has(MARKER)).toBe(true);
    expect(vault.calls).not.toContain("deleteSecret");
    // P0 finds the group by its secret, so whoever clears the instance by
    // hand can still find it.
    await expect(identify()).resolves.toBe(ARN);
    expect(log.lines).toContainEqual([
      { requestId: "r1", instanceId: context.instance.id, user: "alice-ai" },
    ]);
    const logged = inspect(log.lines, { depth: 10 });
    expect(logged).not.toContain("PRIVATE KEY");
    expect(logged).not.toContain(privateKey.split("\n")[1]);
  });

  it("fails and keeps the secret when the script can't remove the key line", async () => {
    await grant();
    const reason =
      "could not edit authorized_keys in the home directory of the agent's Linux user";
    instance.state.failNext = {
      stderr: `p0-ssh-ai: cannot use the .ssh directory\np0-ssh-ai: ${reason}`,
      exitCode: INSTANCE_STATE_EXIT_CODE,
      reason,
    };
    const data = await dataOf(revoke());

    expect(data).toMatchObject({
      type: "dependency_violation",
      payload: { reason: "command_failed", requestId: "r1" },
    });
    // The requester reads the script's own reason, not the edit's.
    expect(data.message).toContain(reason);
    expect(data.message).not.toContain(".ssh");
    expect(vault.valueOf(SECRET)).toBeDefined();
    expect(vault.calls).not.toContain("deleteSecret");
  });

  it("fails when it can't delete the secret, after it cleared the instance", async () => {
    await grant();
    await setPolicies([{ sudo: true }]);
    vault.state.failDelete = sdkError("InternalServiceError");
    const data = await dataOf(revoke());
    expect(data).toMatchObject({
      type: "upstream_unavailable",
      payload: {
        step: "delete_secret",
        requestId: "r1",
        awsError: "InternalServiceError",
      },
    });
    expect(instance.keys.size).toBe(0);
    expect(instance.sudo.size).toBe(0);
    expect(vault.secrets.has(SECRET)).toBe(true);

    vault.state.failDelete = undefined;
    await expect(revoke()).resolves.toBeNull();
    expect(vault.secrets.size).toBe(0);
  });

  it.each([
    ["another secret", ARN.replace(SECRET, "p0/another")],
    ["a longer name", ARN.replace(SECRET, `${SECRET}/more`)],
    ["another region", ARN.replace("us-west-2", "us-east-1")],
    ["another service", ARN.replace("secretsmanager", "ssm")],
    ["a bare name", SECRET],
  ])(
    "refuses an ARN that names %s, as P0's own mistake",
    async (_name, userId) => {
      await grant();
      instance.actions.length = 0;
      const data = await dataOf(revoke(userId));
      expect(data).toEqual({
        type: "unknown",
        message:
          "The secret P0 asked to delete doesn't belong to this access, so the connector kept it. Contact P0 support.",
        payload: { requestId: "r1" },
      });
      expect(instance.actions).toEqual([]);
      expect(vault.secrets.has(SECRET)).toBe(true);
    }
  );
});

describe("the private key", () => {
  it("never shows up in a thrown error or a logged object", async () => {
    let written = "";
    // An SDK validation error quotes the value it refused.
    vault.state.failNextWrite = (value) => {
      written = value.toString();
      return sdkError(
        "ValidationException",
        `Value '${written}' at 'secretBinary' failed to satisfy constraint`
      );
    };
    const error = await errorOf(grant());
    await grant();

    const keys = [written, vault.valueOf(SECRET)].map(
      (value) => parseSecret(value).privateKey
    );
    expect(keys[0]).not.toBe(keys[1]);
    const seen = [
      inspect(error, { depth: 10 }),
      JSON.stringify(error),
      JSON.stringify(connectorErrorOf(error).data),
      inspect(log.lines, { depth: 10 }),
    ].join("\n");
    expect(log.lines.length).toBeGreaterThan(0);
    expect(seen).toContain("write_secret");
    expect(seen).not.toContain("PRIVATE KEY");
    for (const key of keys) {
      // Every line of the key's body, so no part of it slips through.
      for (const line of key.split("\n").slice(1, -2)) {
        expect(seen).not.toContain(line);
      }
    }
  });
});

describe("list", () => {
  it("lists the instances a request can name, by their Name tags", async () => {
    const online = {
      PingStatus: "Online",
      ResourceType: "EC2Instance",
      PlatformType: "Linux",
    } as const;
    instance.state.managed = [
      { ...online, InstanceId: "i-0aaaaaaaaaaaaaaaa" },
      { ...online, InstanceId: "i-0bbbbbbbbbbbbbbbb" },
    ];
    tags = fakeEc2({ "i-0aaaaaaaaaaaaaaaa": "web-1" });
    await expect(
      session().list({
        query: { type: "instance", context: { region: "us-west-2" } },
      })
    ).resolves.toEqual([
      { key: "i-0aaaaaaaaaaaaaaaa", value: "web-1" },
      { key: "i-0bbbbbbbbbbbbbbbb", value: "i-0bbbbbbbbbbbbbbbb" },
    ]);
    expect(log.lines).toContainEqual([
      { type: "instance", count: 2 },
      "listed the instances",
    ]);
  });

  it("refuses a query type it doesn't know", async () => {
    await expect(
      session().list({
        query: { type: "user" as "instance", context: { region: "us-west-2" } },
      })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});

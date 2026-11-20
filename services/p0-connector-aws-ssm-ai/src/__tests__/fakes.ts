import {
  DescribeTagsCommand,
  type DescribeTagsCommandInput,
} from "@aws-sdk/client-ec2";
import { DescribeSecretCommand } from "@aws-sdk/client-secrets-manager";
import {
  DescribeInstanceInformationCommand,
  GetCommandInvocationCommand,
  type InstanceInformation,
  SendCommandCommand,
} from "@aws-sdk/client-ssm";
import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  type SecretVersionRef,
} from "@p0security/connector-secret-manager-client";

import {
  HOST_KEY_PREFIX,
  REASON_PREFIX,
  RESULT_LINES,
} from "../script/provision.ts";
import type { SecretStoreDependencies } from "../secrets.ts";
import type { RunScriptDependencies } from "../ssm/run-script.ts";

/** An SDK command as a fake AWS client gets it: its class and its input. */
export type Command = {
  constructor: { name: string };
  input: Record<string, unknown>;
};

/** An SDK failure, which the SDK names by `name`. */
export const sdkError = (name: string, message = name) =>
  Object.assign(new Error(message), { name });

/**
 * A logger that keeps every line, and the bindings of every child, to check
 * what the code never logs.
 */
export const recordingLogger = () => {
  const lines: unknown[][] = [];
  const record = (...line: unknown[]) => {
    lines.push(line);
  };
  // A pino logger has many more members, and the code calls only these.
  const logger = {
    debug: record,
    info: record,
    warn: record,
    error: record,
    child: (bindings: unknown) => {
      lines.push([bindings]);
      return logger;
    },
  } as unknown as Logger;
  return { logger, lines };
};

/** The error a call rejected with. */
export const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  if (!(error instanceof Error)) {
    throw new Error(`expected an Error, got ${String(error)}`);
  }
  return error;
};

/** The connector error a call threw, which tRPC can wrap. */
export const connectorErrorOf = (error: Error) => {
  if (error instanceof ConnectorError) return error;
  if (error.cause instanceof ConnectorError) return error.cause;
  throw new Error(`expected a ConnectorError, got ${String(error)}`);
};

/** The data of the connector error a call rejected with. */
export const dataOf = async (promise: Promise<unknown>) =>
  connectorErrorOf(await errorOf(promise)).data;

export const HOST_KEYS = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostHostHostHostHostHostHostHostHostHostHos",
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHost=",
];

type FakeInstanceState = {
  /**
   * The next script fails with exit code 1 or `exitCode`. It prints
   * `stderr` on stderr, and `reason` on a reason line, as the script does.
   */
  failNext?: { stderr: string; exitCode?: number; reason?: string };
  /** SSM refuses the instance. */
  unreachable: boolean;
  /** The host keys `ensure-key` prints. */
  hostKeys: string[];
  /** What SSM answers when asked for its managed instances. */
  managed: InstanceInformation[];
};

/**
 * An instance behind SSM. It reads the action off each script it gets and
 * keeps what the real script keeps: each marker's key line and each
 * marker's sudoers entry.
 */
export const fakeInstance = () => {
  /** Marker to the key line's user and public key. */
  const keys = new Map<
    string,
    { user: string; publicKey: string; runAs?: string }
  >();
  /** Marker to the sudoers entry's user and run-as users. */
  const sudo = new Map<string, { user: string; runAs: string[] }>();
  /** The arguments of every script that ran, in order. */
  const actions: string[][] = [];
  const state: FakeInstanceState = {
    unreachable: false,
    hostKeys: HOST_KEYS,
    managed: [],
  };
  let invocation: Record<string, unknown> = {};

  const ok = (lines: string[]) => ({
    Status: "Success",
    ResponseCode: 0,
    StandardOutputContent: [...lines, RESULT_LINES.ok, ""].join("\n"),
    StandardErrorContent: "",
  });

  const runScript = (script: string) => {
    const [, set = ""] = script.split("\n");
    const args = [...set.matchAll(/'([^']*)'/g)].map(([, arg = ""]) => arg);
    actions.push(args);
    const { failNext } = state;
    if (failNext) {
      state.failNext = undefined;
      const { stderr, exitCode = 1, reason } = failNext;
      const reasonLines =
        reason === undefined ? [] : [`${REASON_PREFIX}${reason}`];
      return {
        Status: "Failed",
        ResponseCode: exitCode,
        StandardOutputContent: [...reasonLines, RESULT_LINES.failed, ""].join(
          "\n"
        ),
        StandardErrorContent: stderr,
      };
    }
    const [action, user = "", marker = "", value = "", ...rest] = args;
    switch (action) {
      case "ensure-key":
        keys.set(marker, { user, publicKey: value, runAs: rest[0] });
        return ok(state.hostKeys.map((key) => `${HOST_KEY_PREFIX}${key}`));
      case "set-run-as":
        if (value) sudo.set(marker, { user, runAs: [value, ...rest] });
        else sudo.delete(marker);
        return ok([]);
      case "remove-key":
        keys.delete(marker);
        sudo.delete(marker);
        return ok([]);
      default:
        throw new Error(`unexpected action ${action}`);
    }
  };

  const send = async (command: Command) => {
    if (command instanceof SendCommandCommand) {
      if (state.unreachable) throw sdkError("InvalidInstanceId");
      invocation = runScript(command.input.Parameters?.commands?.[0] ?? "");
      return { Command: { CommandId: `command-${actions.length}` } };
    }
    if (command instanceof GetCommandInvocationCommand) return invocation;
    if (command instanceof DescribeInstanceInformationCommand) {
      return { InstanceInformationList: state.managed };
    }
    return {};
  };

  const ssm: RunScriptDependencies = {
    client: { send },
    wait: async () => {},
  };
  return { ssm, keys, sudo, actions, state };
};

type FakeEc2State = {
  /** Every call throws this. */
  fail?: Error;
  /** The most tags one answer holds. */
  pageSize?: number;
};

/**
 * EC2 with these `Name` tags, by instance id. It answers `DescribeTags` for
 * the instances the call names, and keeps each call's input.
 */
export const fakeEc2 = (names: Record<string, string> = {}) => {
  const calls: DescribeTagsCommandInput[] = [];
  const state: FakeEc2State = {};
  const send = async (command: Command) => {
    if (!(command instanceof DescribeTagsCommand)) {
      throw new Error(`unexpected AWS call ${command.constructor.name}`);
    }
    calls.push(command.input);
    if (state.fail) throw state.fail;
    const filters = command.input.Filters ?? [];
    const ids = filters.find(({ Name }) => Name === "resource-id")?.Values;
    const tags = (ids ?? [])
      .filter((id) => id in names)
      .map((id) => ({ ResourceId: id, Key: "Name", Value: names[id] }));
    const start = Number(command.input.NextToken ?? 0);
    const end = start + (state.pageSize ?? tags.length);
    return {
      Tags: tags.slice(start, end),
      NextToken: end < tags.length ? String(end) : undefined,
    };
  };
  return { client: { send }, calls, state };
};

type FakeSecret = {
  arn: string;
  values: Buffer[];
  /** Set while AWS deletes the secret in the background. */
  deletedDate?: Date;
};

type FakeSecretsManagerState = {
  /** The next write throws what this returns, given the value to write. */
  failNextWrite?: (value: Buffer) => Error;
  /** The next create throws this. */
  failNextCreate?: Error;
  /** Every delete throws this. */
  failDelete?: Error;
  /** Every describe throws this. */
  failDescribe?: Error;
  /**
   * A delete leaves the secret until `finishDeleting`, as AWS does. Until
   * then AWS describes it with a `DeletedDate`, and refuses a new secret
   * with its name.
   */
  deleteInBackground?: boolean;
};

// The shared client's refs are brands on a string, which only a cast makes.
const refOf = (ref: string) => ref as SecretRef;
const versionRefOf = (ref: string) => ref as SecretVersionRef;

/**
 * Secrets Manager in memory: the shared client that the store creates,
 * writes and deletes with, and the SDK client it describes with. It creates
 * a secret with no value, as the real client does.
 */
export const fakeSecretsManager = () => {
  /** Name to secret. */
  const secrets = new Map<string, FakeSecret>();
  const configs: SecretManagerProviderConfig[] = [];
  const calls: string[] = [];
  const state: FakeSecretsManagerState = {};
  let region = "";

  const findSecret = (ref: string) =>
    [...secrets].find(([name, { arn }]) => name === ref || arn === ref);

  /** The secret a name or an ARN names. It throws as the shared client does. */
  const secretAt = (ref: string) => {
    const found = findSecret(ref);
    if (!found) throw new SecretNotFoundError(refOf(ref));
    return found;
  };

  const unused = async (): Promise<never> => {
    throw new Error("the secret store doesn't call this");
  };

  const client = {
    createSecret: async ({ name }) => {
      calls.push("createSecret");
      const { failNextCreate } = state;
      if (failNextCreate) {
        state.failNextCreate = undefined;
        throw failNextCreate;
      }
      const existing = secrets.get(name);
      if (existing?.deletedDate) {
        throw sdkError(
          "InvalidRequestException",
          "You can't create this secret because a secret with this name is already scheduled for deletion."
        );
      }
      if (existing) throw new SecretAlreadyExistsError(name);
      const arn = `arn:aws:secretsmanager:${region}:123456789012:secret:${name}-AbCdEf`;
      secrets.set(name, { arn, values: [] });
      return { ref: refOf(arn), name, createTime: new Date(0) };
    },
    createSecretVersion: async (input) => {
      calls.push("createSecretVersion");
      if (input.type !== "value") throw new Error("the store writes values");
      const { ref, value } = input;
      const [, secret] = secretAt(ref);
      const { failNextWrite } = state;
      if (failNextWrite) {
        state.failNextWrite = undefined;
        throw failNextWrite(value);
      }
      secret.values.push(value);
      return {
        ref: versionRefOf(`${ref}/versions/${secret.values.length}`),
        secretRef: ref,
        state: "enabled",
        createTime: new Date(0),
      };
    },
    deleteSecret: async ({ ref }) => {
      calls.push("deleteSecret");
      if (state.failDelete) throw state.failDelete;
      const [name, secret] = secretAt(ref);
      if (state.deleteInBackground) secret.deletedDate = new Date(0);
      else secrets.delete(name);
    },
    getSecretValue: async () => {
      throw new Error("the connector must never read a secret's value");
    },
    getSecret: unused,
    getAllSecrets: unused,
    getSecretVersions: unused,
    disableSecretVersion: unused,
    deleteSecretVersion: unused,
  } satisfies SecretManagerClient;

  const send = async (command: Command) => {
    if (!(command instanceof DescribeSecretCommand)) {
      throw new Error(`the store doesn't send ${command.constructor.name}`);
    }
    calls.push("describeSecret");
    if (state.failDescribe) throw state.failDescribe;
    const found = findSecret(command.input.SecretId ?? "");
    if (!found) {
      throw sdkError(
        "ResourceNotFoundException",
        "Secrets Manager can't find the specified secret."
      );
    }
    const [name, { arn, values, deletedDate }] = found;
    return {
      ARN: arn,
      Name: name,
      DeletedDate: deletedDate,
      VersionIdsToStages:
        values.length > 0 ? { [`v${values.length}`]: ["AWSCURRENT"] } : {},
    };
  };

  const dependencies: SecretStoreDependencies = {
    connect: async (config) => {
      configs.push(config);
      if (config.provider === "aws") region = config.region;
      return client;
    },
    client: { send },
  };

  return {
    dependencies,
    secrets,
    configs,
    calls,
    state,
    /** The current value of the named secret, as text. */
    valueOf: (name: string) => secrets.get(name)?.values.at(-1)?.toString(),
    /** AWS finishes every deletion it runs in the background. */
    finishDeleting: () => {
      for (const [name, { deletedDate }] of secrets) {
        if (deletedDate) secrets.delete(name);
      }
    },
  };
};

import { UnauthorizedError } from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it } from "vitest";

import { newSecretStore } from "../secrets.ts";
import { dataOf, fakeSecretsManager, sdkError } from "./fakes.ts";

const NAME = "p0/ssh-ai/one";
const ARN = `arn:aws:secretsmanager:eu-west-1:123456789012:secret:${NAME}-AbCdEf`;

let vault = fakeSecretsManager();

beforeEach(() => {
  vault = fakeSecretsManager();
});

const store = () =>
  newSecretStore({ region: "eu-west-1", requestId: "r1" }, vault.dependencies);

describe("newSecretStore", () => {
  it("opens AWS Secrets Manager in the region it is given", async () => {
    await store().findOrCreate(NAME);
    expect(vault.configs).toEqual([{ provider: "aws", region: "eu-west-1" }]);
  });

  it("describes a missing secret, an empty one and one with a value", async () => {
    await expect(store().describe(NAME)).resolves.toBeNull();
    await expect(store().findOrCreate(NAME)).resolves.toBe(ARN);
    await expect(store().describe(NAME)).resolves.toEqual({
      arn: ARN,
      hasValue: false,
    });
    await store().write(ARN, "{}");
    await expect(store().describe(NAME)).resolves.toEqual({
      arn: ARN,
      hasValue: true,
    });
  });

  it("describes a secret with DescribeSecret, without reading its value", async () => {
    await store().findOrCreate(NAME);
    await store().write(ARN, "{}");
    await store().describe(NAME);
    expect(vault.calls).toEqual([
      "createSecret",
      "createSecretVersion",
      "describeSecret",
    ]);
  });

  it("counts a secret AWS is still deleting as gone, and asks to retry a create until it is", async () => {
    await store().findOrCreate(NAME);
    await store().write(ARN, "{}");
    vault.state.deleteInBackground = true;
    await store().remove(ARN);

    expect(vault.secrets.has(NAME)).toBe(true);
    await expect(store().describe(NAME)).resolves.toBeNull();
    await expect(dataOf(store().findOrCreate(NAME))).resolves.toEqual({
      type: "upstream_unavailable",
      message:
        "Secrets Manager is still deleting the previous secret with this name. Try again in a moment.",
      payload: {
        step: "create_secret",
        requestId: "r1",
        awsError: "InvalidRequestException",
      },
    });

    vault.finishDeleting();
    await expect(store().findOrCreate(NAME)).resolves.toBe(ARN);
    await expect(store().describe(NAME)).resolves.toEqual({
      arn: ARN,
      hasValue: false,
    });
  });

  it("finds a secret that an earlier try created", async () => {
    await store().findOrCreate(NAME);
    await expect(store().findOrCreate(NAME)).resolves.toBe(ARN);
    expect(vault.secrets.size).toBe(1);
  });

  it("writes the value as it is given", async () => {
    await store().findOrCreate(NAME);
    await store().write(ARN, '{"a":"é"}');
    expect(vault.valueOf(NAME)).toBe('{"a":"é"}');
  });

  it("counts a secret that is already gone as deleted", async () => {
    await store().findOrCreate(NAME);
    await store().remove(ARN);
    await expect(store().remove(ARN)).resolves.toBeUndefined();
    expect(vault.secrets.size).toBe(0);
  });

  it("keeps AWS's account of a refused lookup, which names the action and the secret", async () => {
    const denied =
      "User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: secretsmanager:DescribeSecret on resource: p0/ssh-ai/one";
    vault.state.failDescribe = sdkError("AccessDeniedException", denied);
    await expect(dataOf(store().describe(NAME))).resolves.toEqual({
      type: "insufficient_privileges",
      message: `Secrets Manager refused to let the connector's role look up the secret: ${denied}. Give the connector's role this action on the secret.`,
      payload: {
        step: "describe_secret",
        requestId: "r1",
        awsError: "AccessDeniedException",
      },
    });
  });

  it("keeps AWS's account of a refusal that the shared client reports", async () => {
    await store().findOrCreate(NAME);
    const denied =
      "User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: secretsmanager:PutSecretValue on resource: p0/ssh-ai/one";
    vault.state.failNextWrite = () =>
      new UnauthorizedError("aws", {
        cause: sdkError("AccessDeniedException", denied),
      });
    await expect(dataOf(store().write(ARN, "the value"))).resolves.toEqual({
      type: "insufficient_privileges",
      message: `Secrets Manager refused to let the connector's role write the secret: ${denied}. Give the connector's role this action on the secret.`,
      payload: {
        step: "write_secret",
        requestId: "r1",
        awsError: "UnauthorizedError",
      },
    });
  });

  it("names the step of a refusal that comes with no account", async () => {
    vault.dependencies.connect = async () => {
      throw new UnauthorizedError("aws");
    };
    await expect(dataOf(store().findOrCreate(NAME))).resolves.toEqual({
      type: "insufficient_privileges",
      message:
        "Secrets Manager refused to let the connector's role create the secret. Give the connector's role this action on the secret.",
      payload: {
        step: "create_secret",
        requestId: "r1",
        awsError: "UnauthorizedError",
      },
    });
  });

  it("keeps the name of any other failure and drops its message", async () => {
    await store().findOrCreate(NAME);
    vault.state.failNextWrite = (value) =>
      sdkError("InvalidRequestException", `refused: ${value.toString()}`);
    await expect(dataOf(store().write(ARN, "the value"))).resolves.toEqual({
      type: "upstream_unavailable",
      message:
        "Secrets Manager failed when the connector tried to write the secret (InvalidRequestException). Try again, and contact P0 support if it keeps failing.",
      payload: {
        step: "write_secret",
        requestId: "r1",
        awsError: "InvalidRequestException",
      },
    });
  });

  it.each([
    ["InternalServiceError", "upstream_unavailable"],
    ["ThrottlingException", "rate_limited"],
    ["TimeoutError", "upstream_unavailable"],
  ])("fails a lookup that meets %s as %s", async (name, type) => {
    vault.state.failDescribe = sdkError(name);
    await expect(dataOf(store().describe(NAME))).resolves.toEqual({
      type,
      message: `Secrets Manager failed when the connector tried to look up the secret (${name}). Try again, and contact P0 support if it keeps failing.`,
      payload: { step: "describe_secret", requestId: "r1", awsError: name },
    });
  });

  it("counts a reset socket as Secrets Manager being unavailable", async () => {
    vault.state.failDescribe = Object.assign(new Error("read ECONNRESET"), {
      code: "ECONNRESET",
    });
    await expect(dataOf(store().describe(NAME))).resolves.toMatchObject({
      type: "upstream_unavailable",
      payload: { step: "describe_secret", awsError: "Error" },
    });
  });

  it("asks to retry a create that meets a secret AWS is still deleting", async () => {
    vault.state.failNextCreate = sdkError(
      "InvalidRequestException",
      "You can't create this secret because a secret with this name is already scheduled for deletion."
    );
    await expect(dataOf(store().findOrCreate(NAME))).resolves.toMatchObject({
      type: "upstream_unavailable",
      payload: { step: "create_secret", awsError: "InvalidRequestException" },
    });
    await expect(store().findOrCreate(NAME)).resolves.toBe(ARN);
  });

  it("does not take every refused create for a pending deletion", async () => {
    vault.state.failNextCreate = sdkError(
      "InvalidRequestException",
      "The name is not valid."
    );
    const data = await dataOf(store().findOrCreate(NAME));
    expect(data.message).toBe(
      "Secrets Manager failed when the connector tried to create the secret (InvalidRequestException). Try again, and contact P0 support if it keeps failing."
    );
  });
});

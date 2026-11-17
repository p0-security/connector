import type { DescribeTagsCommandInput } from "@aws-sdk/client-ec2";
import type { InstanceInformation } from "@aws-sdk/client-ssm";
import { describe, expect, it } from "vitest";

import {
  type Command,
  dataOf,
  fakeEc2,
  recordingLogger,
  sdkError,
} from "../../__tests__/fakes.ts";
import { listFor } from "../lister.ts";

const query = { type: "instance" as const, context: { region: "eu-west-1" } };

/** An EC2 instance SSM can reach. */
const online = (id: string): InstanceInformation => ({
  InstanceId: id,
  PingStatus: "Online",
  ResourceType: "EC2Instance",
  PlatformType: "Linux",
});

/** SSM with its managed instances in the given pages. */
const fakeSsm = (pages: InstanceInformation[][]) => {
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const send = async (command: Command) => {
    calls.push({ command: command.constructor.name, input: command.input });
    const index = Number(command.input.NextToken ?? 0);
    return {
      InstanceInformationList: pages[index] ?? [],
      NextToken: index + 1 < pages.length ? `${index + 1}` : undefined,
    };
  };
  return { client: { send }, calls };
};

const A = "i-0aaaaaaaaaaaaaaaa";
const B = "i-0bbbbbbbbbbbbbbbb";
const C = "i-0cccccccccccccccc";

const list = (
  ssm: ReturnType<typeof fakeSsm>,
  ec2 = fakeEc2(),
  log = recordingLogger()
) => listFor(query, log.logger, { ssm: ssm.client, ec2: ec2.client });

/** The ids a `DescribeTags` call asked for. */
const idsOf = ({ Filters = [] }: DescribeTagsCommandInput) =>
  Filters.find(({ Name }) => Name === "resource-id")?.Values;

describe("the instance lister", () => {
  it("asks SSM for online Linux EC2 instances, 50 a page, and EC2 for their Name tags", async () => {
    const ssm = fakeSsm([[online(A)]]);
    const ec2 = fakeEc2({ [A]: "web-1" });
    await expect(list(ssm, ec2)).resolves.toEqual([{ key: A, value: "web-1" }]);
    expect(ssm.calls).toEqual([
      {
        command: "DescribeInstanceInformationCommand",
        input: {
          Filters: [
            { Key: "PingStatus", Values: ["Online"] },
            { Key: "ResourceType", Values: ["EC2Instance"] },
            { Key: "PlatformTypes", Values: ["Linux"] },
          ],
          MaxResults: 50,
          NextToken: undefined,
        },
      },
    ]);
    expect(ec2.calls).toEqual([
      {
        Filters: [
          { Name: "resource-type", Values: ["instance"] },
          { Name: "key", Values: ["Name"] },
          { Name: "resource-id", Values: [A] },
        ],
        NextToken: undefined,
      },
    ]);
  });

  it("labels an instance with no Name tag by its id", async () => {
    const ssm = fakeSsm([[online(A), online(B), online(C)]]);
    const ec2 = fakeEc2({ [A]: "web-1", [C]: "" });
    await expect(list(ssm, ec2)).resolves.toEqual([
      { key: A, value: "web-1" },
      { key: B, value: B },
      { key: C, value: C },
    ]);
  });

  it("labels the instances by id, and warns, when EC2 refuses to describe the tags", async () => {
    const ssm = fakeSsm([[online(A), online(B)]]);
    const ec2 = fakeEc2({ [A]: "web-1" });
    ec2.state.fail = sdkError(
      "UnauthorizedOperation",
      "You are not authorized to perform this operation."
    );
    const log = recordingLogger();
    await expect(list(ssm, ec2, log)).resolves.toEqual([
      { key: A, value: A },
      { key: B, value: B },
    ]);
    expect(log.lines).toEqual([
      [
        { awsError: "UnauthorizedOperation", nInstances: 2 },
        "could not read the Name tags of the instances",
      ],
    ]);
  });

  it("reads every page, in SSM's order, with one tags call for each page", async () => {
    const ssm = fakeSsm([[online(B), online(A)], [], [online(C)]]);
    const ec2 = fakeEc2({ [A]: "web-1", [B]: "web-2", [C]: "db-1" });
    await expect(list(ssm, ec2)).resolves.toEqual([
      { key: B, value: "web-2" },
      { key: A, value: "web-1" },
      { key: C, value: "db-1" },
    ]);
    expect(ssm.calls.map(({ input }) => input.NextToken)).toEqual([
      undefined,
      "1",
      "2",
    ]);
    // The empty page asks EC2 for nothing.
    expect(ec2.calls.map(idsOf)).toEqual([[B, A], [C]]);
  });

  it("reads every page of tags EC2 returns", async () => {
    const ssm = fakeSsm([[online(A), online(B), online(C)]]);
    const ec2 = fakeEc2({ [A]: "web-1", [B]: "web-2", [C]: "db-1" });
    ec2.state.pageSize = 2;
    await expect(list(ssm, ec2)).resolves.toEqual([
      { key: A, value: "web-1" },
      { key: B, value: "web-2" },
      { key: C, value: "db-1" },
    ]);
    expect(ec2.calls.map(({ NextToken }) => NextToken)).toEqual([
      undefined,
      "2",
    ]);
  });

  it("leaves out an instance SSM can't reach, even if SSM returns it", async () => {
    const ssm = fakeSsm([
      [
        online(A),
        { ...online(B), PingStatus: "ConnectionLost" },
        { ...online(C), PingStatus: "Inactive" },
      ],
    ]);
    await expect(list(ssm)).resolves.toEqual([{ key: A, value: A }]);
  });

  it("leaves out a node that isn't an EC2 instance", async () => {
    const ssm = fakeSsm([
      [
        { ...online("mi-0123456789abcdef0"), ResourceType: "ManagedInstance" },
        online("mi-0fedcba9876543210"),
        { PingStatus: "Online", ResourceType: "EC2Instance" },
        online(A),
      ],
    ]);
    const ec2 = fakeEc2();
    await expect(list(ssm, ec2)).resolves.toEqual([{ key: A, value: A }]);
    expect(ec2.calls.map(idsOf)).toEqual([[A]]);
  });

  it("leaves out an instance that isn't Linux, even if SSM returns it", async () => {
    const ssm = fakeSsm([
      [
        { ...online(B), PlatformType: "Windows" },
        { ...online(C), PlatformType: "MacOS" },
        { ...online(A), PlatformType: undefined },
        online(A),
      ],
    ]);
    await expect(list(ssm)).resolves.toEqual([{ key: A, value: A }]);
  });

  it("returns nothing for a region with no managed instance, and asks EC2 for nothing", async () => {
    const ssm = fakeSsm([[]]);
    const ec2 = fakeEc2();
    await expect(list(ssm, ec2)).resolves.toEqual([]);
    expect(ssm.calls).toHaveLength(1);
    expect(ec2.calls).toEqual([]);
  });

  it("fails when the role may not describe managed instances", async () => {
    const client = {
      send: async () => {
        throw sdkError(
          "AccessDeniedException",
          "not authorized to perform: ssm:DescribeInstanceInformation"
        );
      },
    };
    const data = await dataOf(
      listFor(query, recordingLogger().logger, {
        ssm: client,
        ec2: fakeEc2().client,
      })
    );
    expect(data.type).toBe("insufficient_privileges");
  });
});

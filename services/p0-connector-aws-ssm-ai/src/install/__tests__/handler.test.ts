import { describe, expect, it } from "vitest";

import { type Command, dataOf, sdkError } from "../../__tests__/fakes.ts";
import { validateInstall } from "../handler.ts";

const install = { region: "us-west-2" };

const fakeSsm = (answer: () => unknown = () => ({})) => {
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const send = async (command: Command) => {
    calls.push({ command: command.constructor.name, input: command.input });
    return answer();
  };
  return { client: { send }, calls };
};

describe("install validation", () => {
  it("passes when the role can describe managed instances, and returns the region", async () => {
    const ssm = fakeSsm(() => ({ InstanceInformationList: [] }));
    await expect(
      validateInstall(install, { client: ssm.client })
    ).resolves.toEqual({ region: "us-west-2" });
    expect(ssm.calls).toEqual([
      {
        command: "DescribeInstanceInformationCommand",
        input: { MaxResults: 5 },
      },
    ]);
  });

  it("fails at managed_instances when the role can't describe them", async () => {
    const ssm = fakeSsm(() => {
      throw sdkError(
        "AccessDeniedException",
        "User: arn:aws:sts::123456789012:assumed-role/p0 is not authorized to perform: ssm:DescribeInstanceInformation"
      );
    });
    const data = await dataOf(validateInstall(install, { client: ssm.client }));
    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({
      awsError: "AccessDeniedException",
      step: "managed_instances",
      region: "us-west-2",
    });
    expect(data.message).toContain("ssm:DescribeInstanceInformation");
  });
});

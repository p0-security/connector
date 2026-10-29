import type { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { install, provisioned } from "../../__tests__/fakes.ts";
import { lookupTargetArn } from "../target.ts";

const answering = (answer: () => unknown) => {
  const inputs: unknown[] = [];
  return {
    inputs,
    client: {
      send: async (command: { input: unknown }) => {
        inputs.push(command.input);
        return answer();
      },
    } as never,
  };
};

const refusing = (name: string) =>
  answering(() => {
    throw Object.assign(new Error(name), { name });
  });

describe("lookupTargetArn", () => {
  it("builds a cluster's ARN from its namespace ARN", async () => {
    const redshift = answering(() => ({
      Clusters: [
        {
          ClusterNamespaceArn:
            "arn:aws:redshift:us-west-2:123456789012:namespace:9b1c",
        },
      ],
    }));
    await expect(
      lookupTargetArn(provisioned, { redshift: redshift.client })
    ).resolves.toBe(
      "arn:aws:redshift:us-west-2:123456789012:cluster:analytics"
    );
    expect(redshift.inputs).toEqual([{ ClusterIdentifier: "analytics" }]);
  });

  it("returns a workgroup's ARN", async () => {
    const arn =
      "arn:aws:redshift-serverless:us-west-2:123456789012:workgroup/ca41";
    const serverless = answering(() => ({ workgroup: { workgroupArn: arn } }));
    await expect(
      lookupTargetArn(install, { serverless: serverless.client })
    ).resolves.toBe(arn);
    expect(serverless.inputs).toEqual([{ workgroupName: "analytics" }]);
  });

  it.each([
    [provisioned, { redshift: refusing("ClusterNotFoundFault").client }],
    [install, { serverless: refusing("ResourceNotFoundException").client }],
  ])("reports a missing target", async (context, dependencies) => {
    const error = await lookupTargetArn(context, dependencies).catch(
      (e: unknown) => e
    );
    expect((error as ConnectorError).data.type).toBe("object_not_found");
  });

  it("reports a refusal", async () => {
    const error = await lookupTargetArn(install, {
      serverless: refusing("AccessDeniedException").client,
    }).catch((e: unknown) => e);
    expect((error as ConnectorError).data.type).toBe("insufficient_privileges");
  });
});

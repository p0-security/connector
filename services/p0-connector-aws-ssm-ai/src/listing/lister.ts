import {
  DescribeTagsCommand,
  EC2Client,
  type TagDescription,
} from "@aws-sdk/client-ec2";
import {
  DescribeInstanceInformationCommand,
  type InstanceInformation,
  SSMClient,
} from "@aws-sdk/client-ssm";
import type { Logger } from "@p0security/connector-core";

import type {
  ListerQuery,
  ListerResponse,
} from "../accesses/session/definition.ts";
import { type InstallContext, instance } from "../context.ts";
import { nameOf, toConnectorError } from "../ssm/errors.ts";

export type ListerDependencies = {
  ssm?: Pick<SSMClient, "send">;
  ec2?: Pick<EC2Client, "send">;
};

/** The most SSM returns in one page. */
const MAX_PAGE_SIZE = 50;

type GrantableNode = InstanceInformation & { InstanceId: string };

/**
 * Whether a grant can name this node: a Linux EC2 instance SSM can reach
 * now. A grant on Windows or macOS fails, because the provisioning script
 * is a Linux one. The lister asks SSM for only these nodes and checks each
 * one again here, so a filter SSM ignored can't put another node in the
 * list.
 */
const isGrantable = (node: InstanceInformation): node is GrantableNode =>
  node.PingStatus === "Online" &&
  node.ResourceType === "EC2Instance" &&
  node.PlatformType === "Linux" &&
  instance.shape.id.safeParse(node.InstanceId).success;

type NameTag = TagDescription & { ResourceId: string; Value: string };

const isNameTag = (tag: TagDescription): tag is NameTag =>
  Boolean(tag.ResourceId) && Boolean(tag.Value);

/**
 * The `Name` tag of each instance that has one, by instance id, as P0's SSH
 * integration reads it. A tag is only a label, so when EC2 fails the call
 * the lister warns and labels those instances by id.
 */
const fetchNameTags = async (
  ids: string[],
  client: Pick<EC2Client, "send">,
  logger: Logger
) => {
  const tags: TagDescription[] = [];
  let nextToken: string | undefined;
  try {
    do {
      const page = await client.send(
        new DescribeTagsCommand({
          Filters: [
            { Name: "resource-type", Values: ["instance"] },
            { Name: "key", Values: ["Name"] },
            { Name: "resource-id", Values: ids },
          ],
          NextToken: nextToken,
        })
      );
      tags.push(...(page.Tags ?? []));
      nextToken = page.NextToken;
    } while (nextToken);
  } catch (error) {
    const awsError = nameOf(error) ?? "unknown";
    logger.warn(
      { awsError, nInstances: ids.length },
      "could not read the Name tags of the instances"
    );
    return new Map<string, string>();
  }
  return new Map(
    tags.filter(isNameTag).map(({ ResourceId, Value }) => [ResourceId, Value])
  );
};

/** An instance as a list item: its id, and its `Name` tag or else its id. */
const toItem =
  (names: ReadonlyMap<string, string>) =>
  ({ InstanceId }: GrantableNode) => ({
    key: InstanceId,
    value: names.get(InstanceId) ?? InstanceId,
  });

/**
 * The Linux EC2 instances SSM manages in the region and can reach now, by
 * id, labeled by their `Name` tags.
 */
const listInstances = async (
  context: InstallContext,
  logger: Logger,
  dependencies: ListerDependencies
): Promise<ListerResponse> => {
  const { region } = context;
  const ssm = dependencies.ssm ?? new SSMClient({ region });
  const ec2 = dependencies.ec2 ?? new EC2Client({ region });
  const items: ListerResponse = [];
  let nextToken: string | undefined;
  do {
    const page = await ssm
      .send(
        new DescribeInstanceInformationCommand({
          Filters: [
            { Key: "PingStatus", Values: ["Online"] },
            { Key: "ResourceType", Values: ["EC2Instance"] },
            { Key: "PlatformTypes", Values: ["Linux"] },
          ],
          MaxResults: MAX_PAGE_SIZE,
          NextToken: nextToken,
        })
      )
      .catch((error: unknown) => {
        throw toConnectorError(error);
      });
    const nodes = (page.InstanceInformationList ?? []).filter(isGrantable);
    if (nodes.length > 0) {
      const ids = nodes.map(({ InstanceId }) => InstanceId);
      const names = await fetchNameTags(ids, ec2, logger);
      items.push(...nodes.map(toItem(names)));
    }
    nextToken = page.NextToken;
  } while (nextToken);
  return items;
};

type Lister = (
  context: InstallContext,
  logger: Logger,
  dependencies: ListerDependencies
) => Promise<ListerResponse>;

const listers: Record<ListerQuery["type"], Lister> = {
  instance: listInstances,
};

/** The lister for each request parameter. */
export const listFor = (
  query: ListerQuery,
  logger: Logger,
  dependencies: ListerDependencies = {}
) => {
  const { type, context } = query;
  return listers[type](context, logger, dependencies);
};

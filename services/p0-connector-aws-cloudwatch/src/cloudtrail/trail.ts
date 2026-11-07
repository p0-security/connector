import {
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  type Trail,
} from "@aws-sdk/client-cloudtrail";

import { type Aws, toConnectorError } from "../aws.ts";
import { DATA_EVENT_TYPES } from "./services.ts";

/** The log group name in a `CloudWatchLogsLogGroupArn`
 * (`arn:aws:logs:<region>:<account>:log-group:<name>:*`). */
const logGroupNameOf = (arn: string | undefined) =>
  arn?.match(/:log-group:(.+?)(:\*)?$/)?.[1];

/**
 * The trail delivering to a log group, or undefined when none in this
 * account and region names it (an organization trail is listed in its
 * member accounts as a shadow trail, which may not).
 */
export const findDeliveringTrail = async (
  aws: Aws,
  logGroupName: string
): Promise<Trail | undefined> => {
  const { trailList = [] } = await aws.cloudtrail
    .send(new DescribeTrailsCommand({ includeShadowTrails: true }))
    .catch((error: unknown) => {
      throw toConnectorError(error);
    });
  return trailList.find(
    (trail) => logGroupNameOf(trail.CloudWatchLogsLogGroupArn) === logGroupName
  );
};

/**
 * The data-event resource types a trail delivers, from its basic or
 * advanced event selectors. A selector scoped to some buckets or functions
 * counts: P0 can't tell which resources a grant will touch.
 */
export const deliveredDataEventTypes = async (
  aws: Aws,
  trail: Trail
): Promise<Set<string>> => {
  const { EventSelectors = [], AdvancedEventSelectors = [] } =
    await aws.cloudtrail
      .send(new GetEventSelectorsCommand({ TrailName: trail.TrailARN }))
      .catch((error: unknown) => {
        throw toConnectorError(error);
      });
  const types = new Set<string>();
  for (const selector of EventSelectors) {
    for (const resource of selector.DataResources ?? []) {
      if (resource.Type) types.add(resource.Type);
    }
  }
  for (const selector of AdvancedEventSelectors) {
    const fields = selector.FieldSelectors ?? [];
    const category = fields.find((f) => f.Field === "eventCategory");
    if (!category?.Equals?.includes("Data")) continue;
    const resourceTypes = fields.find((f) => f.Field === "resources.type");
    for (const type of resourceTypes?.Equals ?? []) types.add(type);
  }
  return types;
};

/** The data-event types P0 knows that a trail doesn't deliver. */
export const missingDataEventTypes = (delivered: Set<string>) =>
  DATA_EVENT_TYPES.filter((t) => !delivered.has(t.resourceType));

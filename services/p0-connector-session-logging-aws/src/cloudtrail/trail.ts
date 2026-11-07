import {
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  type Trail,
} from "@aws-sdk/client-cloudtrail";

import { type Aws, toConnectorError } from "../aws.ts";
import { DATA_EVENT_TYPES } from "./services.ts";

/** A log group ARN without the `:*` that some APIs append. */
const groupArn = (arn: string | undefined) => arn?.replace(/:\*$/, "");

/** The log group name in a `CloudWatchLogsLogGroupArn`
 * (`arn:aws:logs:<region>:<account>:log-group:<name>:*`). */
const logGroupNameOf = (arn: string | undefined) =>
  arn?.match(/:log-group:(.+?)(:\*)?$/)?.[1];

/**
 * The trail delivering to a log group, or undefined when none in this
 * account and region names it (an organization trail is listed in its
 * member accounts as a shadow trail, which may not).
 *
 * Shadow trails are listed too, and another region's trail can deliver to
 * a group of the same name in its own region, so a trail is matched on the
 * group's full ARN. Only when the group's ARN isn't known does the name
 * decide.
 */
export const findDeliveringTrail = async (
  aws: Aws,
  logGroupName: string,
  logGroupArn: string | undefined
): Promise<Trail | undefined> => {
  const { trailList = [] } = await aws.cloudtrail
    .send(new DescribeTrailsCommand({ includeShadowTrails: true }))
    .catch((error: unknown) => {
      throw toConnectorError(error);
    });
  const arn = groupArn(logGroupArn);
  return trailList.find((trail) =>
    arn !== undefined
      ? groupArn(trail.CloudWatchLogsLogGroupArn) === arn
      : logGroupNameOf(trail.CloudWatchLogsLogGroupArn) === logGroupName
  );
};

/** Which of a data-event type's reads and writes a trail delivers. */
export type DataEventCoverage = { read: boolean; write: boolean };

const BOTH: DataEventCoverage = { read: true, write: true };

const coverageOf = (readOnly: boolean | undefined): DataEventCoverage =>
  readOnly === undefined ? BOTH : { read: readOnly, write: !readOnly };

const merge = (
  into: Map<string, DataEventCoverage>,
  type: string,
  coverage: DataEventCoverage
) => {
  const had = into.get(type);
  into.set(type, {
    read: coverage.read || (had?.read ?? false),
    write: coverage.write || (had?.write ?? false),
  });
};

/** Advanced selector fields that leave the type's events covered as a
 * whole; any other (such as `eventName`) delivers only some of them. */
const WHOLE_TYPE_FIELDS = new Set([
  "eventCategory",
  "resources.type",
  "resources.ARN",
  "readOnly",
]);

/**
 * The data-event resource types a trail delivers, from its basic or
 * advanced event selectors, and whether it delivers their reads, writes or
 * both (`ReadWriteType`, or an advanced `readOnly` field). A selector
 * scoped to some buckets or functions counts: P0 can't tell which resources
 * a grant will touch. One that picks some event names doesn't, since P0
 * can't tell whether it holds the ones the grant uses.
 */
export const deliveredDataEventTypes = async (
  aws: Aws,
  trail: Trail
): Promise<Map<string, DataEventCoverage>> => {
  const { EventSelectors = [], AdvancedEventSelectors = [] } =
    await aws.cloudtrail
      .send(new GetEventSelectorsCommand({ TrailName: trail.TrailARN }))
      .catch((error: unknown) => {
        throw toConnectorError(error);
      });
  const types = new Map<string, DataEventCoverage>();
  for (const selector of EventSelectors) {
    const coverage =
      selector.ReadWriteType === "ReadOnly"
        ? coverageOf(true)
        : selector.ReadWriteType === "WriteOnly"
          ? coverageOf(false)
          : BOTH;
    for (const resource of selector.DataResources ?? []) {
      if (resource.Type) merge(types, resource.Type, coverage);
    }
  }
  for (const selector of AdvancedEventSelectors) {
    const fields = selector.FieldSelectors ?? [];
    const category = fields.find((f) => f.Field === "eventCategory");
    if (!category?.Equals?.includes("Data")) continue;
    if (fields.some((f) => !WHOLE_TYPE_FIELDS.has(f.Field ?? ""))) continue;
    const readOnly = fields.find((f) => f.Field === "readOnly")?.Equals;
    const coverage =
      readOnly?.length === 1 ? coverageOf(readOnly[0] === "true") : BOTH;
    const resourceTypes = fields.find((f) => f.Field === "resources.type");
    for (const type of resourceTypes?.Equals ?? []) {
      merge(types, type, coverage);
    }
  }
  return types;
};

/** The data-event types P0 knows that a trail doesn't deliver at all. */
export const missingDataEventTypes = (
  delivered: ReadonlyMap<string, DataEventCoverage>
) => DATA_EVENT_TYPES.filter((t) => !delivered.has(t.resourceType));

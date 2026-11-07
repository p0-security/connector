import { z } from "zod";

/**
 * The checks install validation runs, in order, by the name a failure
 * reports in `payload.step`. P0 reads these, so the set is closed and the
 * order fixed.
 *
 * - `log_group`: the CloudTrail log group exists.
 * - `recent_events`: it holds a CloudTrail event from the last 24 hours.
 * - `coverage`: an `organization` item's group gets an organization trail.
 * - `data_events`: reading the trail's event selectors (never fails the
 *   install on what it finds; see {@link InstallWarning}).
 */
export const AWS_CLOUDWATCH_INSTALL_STEPS = [
  "log_group",
  "recent_events",
  "coverage",
  "data_events",
] as const;

export type AwsCloudWatchInstallStep =
  (typeof AWS_CLOUDWATCH_INSTALL_STEPS)[number];

export const CLOUDTRAIL_COVERAGES = ["account", "organization"] as const;

/**
 * The item's CloudTrail config. Both fields are absent for an item that
 * reads only RDS logs; then validation checks nothing and passes.
 * `coverage` defaults to `account`.
 */
export const installInput = z.strictObject({
  logGroupName: z.string().min(1).optional(),
  coverage: z.enum(CLOUDTRAIL_COVERAGES).optional(),
});

export type InstallInput = z.infer<typeof installInput>;

/**
 * What works but needs the customer's attention. P0 shows each one; none
 * fails the install.
 */
export type InstallWarning =
  /** An `account` item whose group gets an organization trail: it works,
   * but an `organization` item would cover every account. */
  | { check: "coverage"; message: string }
  /** The trail doesn't deliver these data-event resource types
   * (`AWS::S3::Object`, `AWS::Lambda::Function`, `AWS::DynamoDB::Table`). */
  | { check: "data_events"; resourceTypes: string[] }
  /** No trail in this account and region names the group (an organization
   * trail seen from a member account, or a group fed some other way), so
   * coverage was judged from a sample of `recipientAccountId`s and data
   * events couldn't be read. */
  | { check: "trail_not_found"; message: string };

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown as a `ConnectorError` whose payload holds `step`.
 */
export type InstallValidation = {
  cloudtrail?: {
    logGroupName: string;
    logGroupArn?: string;
    /** Absent when the group keeps events forever. */
    retentionInDays?: number;
    /** The newest event in the last 24 hours. */
    latestEventTime: string;
    /** The accounts whose events the group holds, sampled from the last 24 hours. */
    accounts: string[];
    trail?: { arn: string; name: string; isOrganizationTrail: boolean };
    /** The data-event resource types the trail delivers. */
    dataEventTypes: string[];
  };
  warnings: InstallWarning[];
};

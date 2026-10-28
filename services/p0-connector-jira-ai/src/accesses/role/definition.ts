import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  accountId,
  projectKey,
  roleId,
  site,
} from "../../install/definition.ts";
import { listerQuery, listerResponse } from "../lister.ts";

/**
 * The account to put in, or take out of, a project's roles. An Atlassian
 * account id is global, and P0 groups and locks a user's open requests by
 * this body, so the site is part of it: the same account on two sites is two
 * users.
 */
export const userBody = z.object({
  cloudId: z.guid("must be an Atlassian cloud id"),
  accountId,
});

// The framework's user id is a string, so it is the account id alone. Every
// call that takes it also carries the site, in its request context.
export const userId = accountId;

/** The access level of one of P0's own roles in a company-managed project. */
export const p0Level = z.enum(["read", "write"]);

export type P0Level = z.infer<typeof p0Level>;

/**
 * P0's two site roles, by level: their fixed names, and the permissions the
 * connector grants each in a company-managed project's permission scheme.
 *
 * The write role holds what P0's grantable write tools need, by the Jira
 * endpoints behind them. It leaves out what only acts for other people:
 * editing their comments or worklogs, and changing their watchers. It also
 * leaves out Move work items: convertJiraIssueHierarchy, its only user, also
 * needs the global Bulk change permission, so P0 refuses that tool.
 */
export const P0_ROLES: Record<
  P0Level,
  { name: string; permissions: readonly string[] }
> = {
  read: { name: "P0 agent: read", permissions: ["BROWSE_PROJECTS"] },
  write: {
    name: "P0 agent: write",
    permissions: [
      "BROWSE_PROJECTS",
      "ADD_COMMENTS",
      "CREATE_ISSUES",
      "EDIT_ISSUES",
      "TRANSITION_ISSUES",
      // addOrEditJiraIssueComment edits a comment the agent wrote.
      "EDIT_OWN_COMMENTS",
      // addOrEditJiraIssueWorklog logs work, and edits the agent's own.
      "WORK_ON_ISSUES",
      "EDIT_OWN_WORKLOGS",
      // createJiraIssueLink and createJiraIssueRemoteIssueLink.
      "LINK_ISSUES",
      // uploadAttachmentToJiraIssue.
      "CREATE_ATTACHMENTS",
      // createJiraIssue and editJiraIssue set the assignee.
      "ASSIGN_ISSUES",
      // Due dates and ranking (editJiraIssue), and sprint moves
      // (transitionJiraIssue).
      "SCHEDULE_ISSUES",
      // manageJiraProjectVersionRelatedWork.
      "RESOLVE_ISSUES",
    ],
  },
};

/**
 * A role the account should hold on the project: one of P0's own roles in a
 * company-managed project, or one of a team-managed project's roles, by the
 * id `install.project.get` reported.
 */
export const rolePolicy = z.discriminatedUnion("type", [
  z.object({ type: z.literal("p0"), level: p0Level }),
  z.object({ type: z.literal("space"), roleId }),
]);

export type RolePolicy = z.infer<typeof rolePolicy>;

/**
 * The project, and the role ids P0 recorded for this request when it staged
 * it (empty for a company-managed project). P0 always sends the full set of
 * roles the account should keep on the project. The connector removes it
 * from P0's own roles and from the recorded ids outside that set.
 */
const requestContext = z.object({
  requestId: z.string(),
  site,
  projectKey,
  roleIds: z.array(roleId),
});

export const schema = {
  userBody,
  userId,
  policy: rolePolicy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import { isNotFound, parse } from "./api.ts";
import {
  type DatabricksClient,
  type DatabricksWorkspaceClient,
  scimRoles,
} from "./client.ts";

export const scimUser = scimRoles.extend({
  id: z.string().min(1),
  userName: z.string().min(1),
  emails: z.array(z.object({ value: z.string() })).optional(),
});

/** A user as account SCIM reports it. */
export type ScimUser = z.infer<typeof scimUser>;

const scimUserList = z.object({ Resources: z.array(scimUser).optional() });

/**
 * Where to read account SCIM `Users`: the account itself, or a workspace's
 * proxy of it. Both return account SCIM IDs.
 */
export type ScimUsersEndpoint = {
  requestId: string;
  /** The API, as errors name it. */
  what: string;
  /** Reads `path`, which is `""` or `/<id>`, relative to the Users endpoint. */
  get: (path: string, query?: Record<string, string>) => Promise<unknown>;
};

/** Account SCIM `Users` on the account console, which needs account admin. */
export const accountScimUsers = (
  client: DatabricksClient
): ScimUsersEndpoint => ({
  requestId: client.context.requestId,
  what: "account SCIM Users",
  get: async (path, query) =>
    await client.account({
      method: "GET",
      path: `/scim/v2/Users${path}`,
      query,
    }),
});

/**
 * Account SCIM `Users` through a workspace's proxy, which a workspace admin
 * can read.
 */
export const workspaceScimUsers = (
  workspace: DatabricksWorkspaceClient
): ScimUsersEndpoint => ({
  requestId: workspace.requestId,
  what: "account SCIM Users through the workspace",
  get: async (path, query) =>
    await workspace.call({
      method: "GET",
      path: `/api/2.0/account/scim/v2/Users${path}`,
      query,
    }),
});

const sameText = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Quotes a value for a SCIM filter, escaping `\` and `"`. */
const scimString = (value: string) =>
  `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/**
 * Finds requestors' Databricks users in account SCIM `Users`, on whichever
 * endpoint `admin`'s scope reads. The endpoint sees every user in the
 * account, including one who has been unassigned from every workspace, and
 * only ever returns users, never groups or service principals. Every filter
 * value is escaped, and every result is re-checked against the filter, so a
 * server that ignored the filter can't hand back someone else.
 */
export const newScimUsers = ({ requestId, what, get }: ScimUsersEndpoint) => {
  const search = async (filter: string) =>
    parse({
      schema: scimUserList,
      data: await get("", { filter }),
      what,
      requestId,
    }).Resources ?? [];

  const ambiguous = (query: string, users: ScimUser[]) =>
    new ConnectorError({
      type: "validation_error",
      message: `More than one Databricks user matches ${query}: ${users
        .map((u) => `${u.userName} (${u.id})`)
        .join(", ")}`,
      payload: { requestId, query },
    });

  /** The user whose `userName` is `userName`, if there is one. */
  const byUserName = async (userName: string) => {
    const users = (await search(`userName eq ${scimString(userName)}`)).filter(
      (user) => sameText(user.userName, userName)
    );
    if (users.length > 1) throw ambiguous(userName, users);
    return users[0] ?? null;
  };

  /**
   * Matches a requestor's email to their user: by `userName`, then by any of
   * the user's emails. Two matches fail and name both.
   *
   * The `emails` fallback is for users whose `userName` isn't their email,
   * such as an Azure UPN. An IdP or an admin can edit `emails`, so they are
   * trusted only this far: they are searched only when no `userName`
   * matches, the match must be unique, and the user found is still judged by
   * their `userName`, which must pass domain verification for any grant.
   */
  const byEmail = async (email: string) => {
    const user = await byUserName(email);
    if (user) return user;

    const users = (await search(`emails.value eq ${scimString(email)}`)).filter(
      (user) => user.emails?.some(({ value }) => sameText(value, email))
    );
    if (users.length > 1) throw ambiguous(email, users);
    return users[0] ?? null;
  };

  /**
   * The user with this account SCIM ID, or `null` when no user has it. A
   * service principal's or group's ID is not found here, which is what keeps
   * every grantee a user.
   */
  const byId = async (userId: string): Promise<ScimUser | null> => {
    try {
      return parse({
        schema: scimUser,
        data: await get(`/${encodeURIComponent(userId)}`),
        what,
        requestId,
      });
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  };

  return { byUserName, byEmail, byId };
};

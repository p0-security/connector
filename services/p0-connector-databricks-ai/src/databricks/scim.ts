import { ConnectorError } from "@p0security/connector-core";
import { z } from "zod";

import { isNotFound, parse } from "./api.ts";
import { type DatabricksClient, asAccountAdmin } from "./client.ts";

export const scimUser = z.object({
  id: z.string().min(1),
  userName: z.string().min(1),
});

/** A user as account SCIM reports it. */
export type ScimUser = z.infer<typeof scimUser>;

export const scimServicePrincipal = z.object({
  id: z.string().min(1),
  applicationId: z.string().min(1),
  displayName: z.string().optional(),
  active: z.boolean().optional(),
});

/** A service principal as account SCIM reports it. */
export type ScimServicePrincipal = z.infer<typeof scimServicePrincipal>;

export const scimGroup = z.object({
  id: z.string().min(1),
  displayName: z.string().min(1),
});

/** A group as account SCIM reports it. */
export type ScimGroup = z.infer<typeof scimGroup>;

const scimGroupWithMembers = scimGroup.extend({
  /** The group's direct members, each by account SCIM ID. */
  members: z.array(z.object({ value: z.string() })).optional(),
});

/** A group and its direct members, as account SCIM reports one group. */
export type ScimGroupWithMembers = z.infer<typeof scimGroupWithMembers>;

/** The account SCIM endpoints this connector reads. */
type ScimResource = "Groups" | "ServicePrincipals" | "Users";

const sameText = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Quotes a value for a SCIM filter, escaping `\` and `"`. */
const scimString = (value: string) =>
  `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/**
 * Finds users, service principals and groups in account SCIM, which needs
 * account admin: a 403 says P0's principal isn't one. Every filter value is
 * escaped, and every result is re-checked against the filter, so a server
 * that ignored the filter can't hand back someone else. A lookup that
 * matches more than one fails and names them all.
 */
export const newAccountScim = (client: DatabricksClient) => {
  const { context } = client;
  const { requestId } = context;

  const get = async (
    resource: ScimResource,
    path: string,
    query?: Record<string, string>
  ) =>
    await asAccountAdmin(context, async () =>
      client.account({
        method: "GET",
        path: `/scim/v2/${resource}${path}`,
        query,
      })
    );

  const search = async <T>(
    resource: ScimResource,
    schema: z.ZodType<T>,
    filter: string
  ): Promise<T[]> =>
    parse({
      schema: z.object({ Resources: z.array(schema).optional() }),
      data: await get(resource, "", { filter }),
      what: `account SCIM ${resource}`,
      requestId,
    }).Resources ?? [];

  /** The one match, `null` for none, or a refusal naming every match. */
  const one = <T extends { id: string }>(
    resource: ScimResource,
    query: string,
    matches: T[]
  ): T | null => {
    if (matches.length > 1) {
      throw new ConnectorError({
        type: "validation_error",
        message: `More than one Databricks account SCIM ${resource} entry matches ${query}: ${matches
          .map(({ id }) => id)
          .join(", ")}.`,
        payload: { requestId, query },
      });
    }
    return matches[0] ?? null;
  };

  /** The entry with this account SCIM ID, or `null` when there is none. */
  const byId = async <T>(
    resource: ScimResource,
    schema: z.ZodType<T>,
    id: string
  ): Promise<T | null> => {
    try {
      return parse({
        schema,
        data: await get(resource, `/${encodeURIComponent(id)}`),
        what: `account SCIM ${resource}`,
        requestId,
      });
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  };

  /** The user whose `userName` is `userName`, if there is one. */
  const userByUserName = async (userName: string) =>
    one(
      "Users",
      userName,
      (
        await search("Users", scimUser, `userName eq ${scimString(userName)}`)
      ).filter((user) => sameText(user.userName, userName))
    );

  /** The service principal with this `applicationId`, if there is one. */
  const servicePrincipalByApplicationId = async (applicationId: string) =>
    one(
      "ServicePrincipals",
      applicationId,
      (
        await search(
          "ServicePrincipals",
          scimServicePrincipal,
          `applicationId eq ${scimString(applicationId)}`
        )
      ).filter((principal) => sameText(principal.applicationId, applicationId))
    );

  /**
   * The service principal whose `displayName` is `displayName`, if there is
   * one. Display names needn't be unique, so two matches fail.
   */
  const servicePrincipalByDisplayName = async (displayName: string) =>
    one(
      "ServicePrincipals",
      displayName,
      (
        await search(
          "ServicePrincipals",
          scimServicePrincipal,
          `displayName eq ${scimString(displayName)}`
        )
      ).filter(
        (principal) =>
          principal.displayName !== undefined &&
          sameText(principal.displayName, displayName)
      )
    );

  /** The service principal with this account SCIM ID, if there is one. */
  const servicePrincipalById = async (id: string) =>
    await byId("ServicePrincipals", scimServicePrincipal, id);

  /**
   * The group whose `displayName` is `displayName`, if there is one, without
   * its members: the Groups list stopped returning `members` for accounts
   * created since 2025-08-22. Read them with {@link groupById}.
   */
  const groupByDisplayName = async (displayName: string) =>
    one(
      "Groups",
      displayName,
      (
        await search(
          "Groups",
          scimGroup,
          `displayName eq ${scimString(displayName)}`
        )
      ).filter((group) => sameText(group.displayName, displayName))
    );

  /**
   * The group with this account SCIM ID and its direct members, if there is
   * one. Nested groups are listed as members, not followed.
   */
  const groupById = async (id: string) =>
    await byId("Groups", scimGroupWithMembers, id);

  return {
    userByUserName,
    servicePrincipalByApplicationId,
    servicePrincipalByDisplayName,
    servicePrincipalById,
    groupByDisplayName,
    groupById,
  };
};

export type AccountScim = ReturnType<typeof newAccountScim>;

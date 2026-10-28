import { type Logger, throwAssertNever } from "@p0security/connector";

import { newAuth0Client } from "../../auth0/client.ts";
import { callAuth0 } from "../../auth0/errors.ts";
import {
  type ListerQuery,
  type ListerResponse,
  MEMBER,
  ROLE_GROUP,
  listerQuery,
} from "./definition.ts";
import { requireAllowedEmail, requireRequestor } from "./user.ts";

const byName = ({ id, name }: { id: string; name: string }) => ({
  key: id,
  value: name,
});

/**
 * Answers a {@link ListerQuery}, for every access: `list` is one of each
 * access's primitives, and they share the queries.
 *
 * The queries about a user are gated by the allowed domains, and check that
 * the user still has the requestor's email. The tenant-wide listings aren't
 * about anyone, so they aren't gated.
 */
export const list = async (
  logger: Logger,
  input: ListerQuery
): Promise<ListerResponse> => {
  // The framework never runs `validation` before `list`, and the router's
  // parser is the access's own, so each query is checked again here.
  const query = listerQuery.parse(input);
  const { context } = query;
  const { tenant } = context;
  const log = logger.child({ tenant, type: query.type });
  const auth0 = newAuth0Client({ ...context, log });

  switch (query.type) {
    case "users": {
      const { email } = query;
      requireAllowedEmail({ tenant, email }, log);
      const users = await callAuth0(() => auth0.findUsersByEmail(email), {
        tenant,
      });
      return users.map(({ userId, connection, email: found }) => ({
        key: userId,
        value: connection ?? "",
        group: found ?? "",
      }));
    }
    case "roles":
      return (await callAuth0(() => auth0.listRoles(), { tenant })).map(byName);
    case "apis":
      return (
        await callAuth0(() => auth0.listResourceServers(), { tenant })
      ).map(({ identifier, name }) => ({ key: identifier, value: name }));
    case "permissions": {
      const { resourceServerIdentifier } = query;
      const apis = await callAuth0(() => auth0.listResourceServers(), {
        tenant,
      });
      const api = apis.find(
        ({ identifier }) => identifier === resourceServerIdentifier
      );
      // `[]` for an API that isn't there: nothing can be requested on it.
      return (api?.permissions ?? []).map(({ value, description }) => ({
        key: value,
        value: description ?? value,
      }));
    }
    case "organizations":
      return (await callAuth0(() => auth0.listOrganizations(), { tenant })).map(
        byName
      );
    case "user-roles": {
      const { email, userId } = query;
      const target = { tenant, subject: `user ${userId}` };
      return callAuth0(async () => {
        await requireRequestor(auth0, log, { tenant, email, userId });
        return (await auth0.listUserRoles(userId)).map(byName);
      }, target);
    }
    case "user-permissions": {
      const { email, userId, resourceServerIdentifier } = query;
      const target = { tenant, subject: `user ${userId}` };
      return callAuth0(async () => {
        await requireRequestor(auth0, log, { tenant, email, userId });
        const permissions = await auth0.listUserPermissions(
          userId,
          resourceServerIdentifier
        );
        // Only direct ones: P0 never touches a permission a role gives.
        return permissions
          .filter(({ direct }) => direct)
          .map(({ resourceServerIdentifier, permissionName }) => ({
            key: permissionName,
            value: permissionName,
            group: resourceServerIdentifier,
          }));
      }, target);
    }
    case "org-membership": {
      const { email, userId, organizationId } = query;
      const target = { tenant, subject: `organization ${organizationId}` };
      return callAuth0(async () => {
        await requireRequestor(auth0, log, { tenant, email, userId });
        const organizations = await auth0.listUserOrganizations(userId);
        if (!organizations.some(({ id }) => id === organizationId)) return [];
        const roles = await auth0.listMemberRoles(organizationId, userId);
        return [
          { key: MEMBER, value: userId },
          ...roles.map(({ id, name }) => ({
            key: id,
            value: name,
            group: ROLE_GROUP,
          })),
        ];
      }, target);
    }
    default:
      throw throwAssertNever(query);
  }
};

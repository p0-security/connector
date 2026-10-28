import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  newUserProvisioningRouter,
} from "@p0security/connector-core";
import {
  createClients,
  gcloudServiceMetadata,
  newMemberVerifier,
} from "@p0security/gcloud-common";
import { noop } from "lodash-es";

import {
  mapMemberVerificationError,
  mapSqlAdminError,
  memoizeAsync,
} from "../../util.ts";
import {
  MAX_LIMIT_BY_ENGINE,
  dbUsernameExceedsLimit,
  toDbUsername,
} from "./cloudsql-user.ts";
import { iamUserType, newMember, spec } from "./definition.ts";

// Created once per process and reused: GoogleAuth refreshes its own token, and
// metadata is immutable for the process lifetime.
const loadClients = memoizeAsync(createClients);
const loadMetadata = memoizeAsync(gcloudServiceMetadata);

export const router = (t: AnyConnectorTRPCInstance) =>
  newUserProvisioningRouter(t, spec, () => {
    return {
      // IAM users have no P0-ownership marker to namespace; eligibility is the gate.
      validation: () => null,

      isEligible: async (_context, { email }) => {
        const [clients, metadata] = await Promise.all([
          loadClients(),
          loadMetadata(),
        ]);

        const verifier = newMemberVerifier(clients, metadata);
        try {
          await verifier.verifyMember(newMember(email));
        } catch (error) {
          throw mapMemberVerificationError(error);
        }
        return true;
      },

      getUser: async (context, { email }) => {
        const clients = await loadClients();

        const { projectId, instanceId, engine } = context.gcp;
        const dbUsername = toDbUsername(engine, email);
        try {
          const response = await clients.sqladmin.users.list({
            project: projectId,
            instance: instanceId,
          });
          const exists = response.data.items?.some(
            (user) => user.name === dbUsername
          );
          return exists ? dbUsername : null;
        } catch (error) {
          throw mapSqlAdminError(error, email);
        }
      },

      createUser: async (context, { email }) => {
        const clients = await loadClients();

        const { projectId, instanceId, engine } = context.gcp;
        const dbUsername = toDbUsername(engine, email);
        if (dbUsernameExceedsLimit(engine, dbUsername)) {
          throw new ConnectorError({
            type: "validation_error",
            message: `Cannot provision CloudSQL user '${email}': the ${engine} database username '${dbUsername}' is ${dbUsername.length} characters, exceeding ${engine}'s ${MAX_LIMIT_BY_ENGINE[engine]}-character limit. Use a shorter service-account ID or project ID, or grant access via an IAM group.`,
            payload: { email },
          });
        }
        try {
          await clients.sqladmin.users.insert({
            project: projectId,
            instance: instanceId,
            requestBody: {
              name: dbUsername,
              type: iamUserType(email),
            },
          });
        } catch (error) {
          throw mapSqlAdminError(error, email);
        }
        return dbUsername;
      },

      deleteUser: async () => noop(),
    };
  });

import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  type SecretManagerClient,
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import { getInstallSecret } from "../../secrets.ts";
import {
  AGENT_KEY_PATTERN,
  AGENT_USER_PREFIX,
  agentUserName,
  mintUserToken,
  newProvisionerClient,
} from "../../servicenow/client.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type InstanceContext = ResourceSchema["ListerQuery"]["context"];
type RequestContext = ResourceSchema["RequestContext"];

/** Roles that P0 never grants an agent, even if ServiceNow lists them as
 * not elevated. */
const REFUSED_ROLES = new Set([
  "admin",
  "impersonator",
  "maint",
  "mi_admin",
  "oauth_admin",
  "security_admin",
  "user_admin",
]);

const secretRef = (name: string) => name as SecretRef;

const secretManagerConfig = (
  secrets: InstanceContext["secrets"]
): SecretManagerProviderConfig => {
  switch (secrets.manager) {
    case "aws":
      return { provider: "aws", region: secrets.region };
    case "gcp":
      return { provider: "gcp", projectId: secrets.projectId };
    default:
      throw throwAssertNever(secrets);
  }
};

const createSecretManager = async (context: InstanceContext) => {
  try {
    return await createSecretManagerClient(
      secretManagerConfig(context.secrets)
    );
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: context.secrets.manager },
    });
  }
};

const clientsFor = async (context: InstanceContext) => {
  const secretManager = await createSecretManager(context);
  const install = await getInstallSecret(
    secretManager,
    secretRef(context.secrets.installSecretId)
  );
  const provisioner = await newProvisionerClient({
    domain: context.domain,
    clientId: context.provisionerClientId,
    clientSecret: install.provisionerClientSecret,
  });
  const jwtBearer = {
    domain: context.domain,
    clientId: context.jwtClientId,
    clientSecret: install.jwtClientSecret,
    signingKey: install.signingKey,
    keyId: context.keyId,
  };
  return { secretManager, provisioner, jwtBearer };
};

const writeToken = async (
  secretManager: SecretManagerClient,
  name: string,
  token: string
) => {
  try {
    await secretManager.getSecret({ ref: secretRef(name) });
  } catch (error) {
    if (!(error instanceof SecretNotFoundError)) throw error;
    await secretManager.createSecret({ name });
  }
  await secretManager.createSecretVersion({
    ref: secretRef(name),
    type: "value",
    value: Buffer.from(token),
  });
};

const deleteToken = async (
  secretManager: SecretManagerClient,
  name: string
) => {
  try {
    await secretManager.deleteSecret({ ref: secretRef(name) });
  } catch (error) {
    if (!(error instanceof SecretNotFoundError)) throw error;
  }
};

const refuseRoles = (context: RequestContext, roles: string[]) => {
  const refused = roles.filter((role) => REFUSED_ROLES.has(role));
  if (refused.length > 0) {
    throw new ConnectorError({
      type: "validation_error",
      message: `P0 does not grant these ServiceNow roles to agents: ${refused.join(", ")}`,
      payload: { requestId: context.requestId, refused: refused.join(",") },
    });
  }
};

/**
 * ServiceNow agent user lifecycle
 *
 * The abstract "user" of the resource-root paradigm is one ServiceNow machine
 * user per gateway session, named from the agent key that P0 computes. Its
 * policies are the roles assigned to it directly. Each time the roles are set,
 * the connector gets a new token for the user with the JWT bearer grant and
 * writes it to the session's token secret, which the gateway reads.
 *
 * Deleting the user stops its tokens at once, so `deleteUser` is the revoke.
 *
 * The P0 control plane must serialize calls for the same user.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    validation: (context) => ({
      user: {
        userIsNamespacedByBody: async (agentKey) =>
          AGENT_KEY_PATTERN.test(agentKey),
        userIsNamespacedById: async (sysId) => {
          const { provisioner } = await clientsFor(context);
          const user = await provisioner.getUser(sysId);
          return !!user?.userName.startsWith(AGENT_USER_PREFIX);
        },
      },
    }),

    getUser: async (context, agentKey) => {
      const { provisioner } = await clientsFor(context);
      const user = await provisioner.findUser(agentUserName(agentKey));
      ctx.logger.debug(
        { agentKey, requestId: context.requestId, found: !!user },
        "looked up agent user"
      );
      return user?.sysId ?? null;
    },

    createUser: async (context, agentKey) => {
      const { provisioner } = await clientsFor(context);
      const sysId = await provisioner.createUser(agentUserName(agentKey));
      ctx.logger.info(
        { agentKey, sysId, requestId: context.requestId },
        "created agent user"
      );
      return sysId;
    },

    deleteUser: async (context, sysId) => {
      const { provisioner, secretManager } = await clientsFor(context);
      await provisioner.deleteUser(sysId);
      await deleteToken(secretManager, context.tokenSecretName);
      ctx.logger.info(
        { sysId, requestId: context.requestId },
        "deleted agent user and its token"
      );
    },

    setPoliciesForUser: async (context, sysId, _user, policies) => {
      const roles = [...new Set(policies)].sort();
      refuseRoles(context, roles);
      const { provisioner, secretManager, jwtBearer } =
        await clientsFor(context);

      const current = await provisioner.userRoles(sysId);
      for (const row of current) {
        if (!roles.includes(row.roleName))
          await provisioner.removeRole(row.rowId);
      }
      for (const role of roles) {
        if (!current.some((row) => row.roleName === role))
          await provisioner.addRole(sysId, role);
      }

      // ServiceNow answers 201 to a role the provisioner may not grant, but
      // keeps the row without the role.
      const granted = await provisioner.userRoles(sysId);
      for (const row of granted) {
        if (!row.roleName) await provisioner.removeRole(row.rowId);
      }
      const missing = roles.filter(
        (role) => !granted.some((row) => row.roleName === role)
      );
      if (missing.length > 0) {
        throw new ConnectorError({
          type: "validation_error",
          message: `ServiceNow did not grant these roles; the provisioner may not grant them: ${missing.join(", ")}`,
          payload: { requestId: context.requestId, missing: missing.join(",") },
        });
      }

      if (roles.length === 0) {
        await deleteToken(secretManager, context.tokenSecretName);
        return;
      }
      const user = await provisioner.getUser(sysId);
      if (!user) {
        throw new ConnectorError({
          type: "unknown",
          message: "The ServiceNow agent user is gone",
          payload: { requestId: context.requestId, sysId },
        });
      }
      const token = await mintUserToken(jwtBearer, user.userName);
      await writeToken(secretManager, context.tokenSecretName, token);
      ctx.logger.info(
        { sysId, requestId: context.requestId, nRoles: roles.length },
        "set agent roles and wrote its token"
      );
    },

    list: async ({ type, context }) => {
      switch (type) {
        case "role": {
          const { provisioner } = await clientsFor(context);
          const names = await provisioner.listRoles();
          return names
            .filter((name) => !REFUSED_ROLES.has(name))
            .map((name) => ({ key: name, value: name }));
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));

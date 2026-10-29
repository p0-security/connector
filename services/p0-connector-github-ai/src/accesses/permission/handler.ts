import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import { githubClientFor } from "../../github/github-client.ts";
import { getGithubPrivateKey } from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

const secretRef = (secretArn: string) => secretArn as SecretRef;

const invalidSecretManagerError = (
  context: ResourceSchema["RequestContext"],
  extra?: Record<string, boolean | number | string>
) =>
  new ConnectorError({
    type: "validation_error",
    message: "Invalid secret manager",
    payload: {
      requestId: context.requestId,
      manager: context.secrets.manager,
      ...extra,
    },
  });

const secretManagerConfig = (
  secrets: ResourceSchema["RequestContext"]["secrets"]
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

const createSecretManager = async (
  context: ResourceSchema["RequestContext"]
) => {
  try {
    return await createSecretManagerClient(
      secretManagerConfig(context.secrets)
    );
  } catch {
    throw invalidSecretManagerError(context);
  }
};

const updateSecretToken = async (
  log: Logger,
  context: ResourceSchema["RequestContext"],
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for GitHub access token generation"
    );
    throw new ConnectorError({
      // Note: using unknown instead of validation_error here because a validation_error will get
      // directly surfaced to the user. This is not particularly useful because it this indicates
      // a problem with the P0 backend, rather than an issue with the user's request.
      // Using unknown will allow the P0 backend to treat it as an internal error rather than a
      // user error
      type: "unknown",
      message: `Invalid parameters for GitHub access token generation, expected exactly 1 policy`,
      payload: {
        requestId: context.requestId,
        nPolicies: policies.length,
      },
    });
  }

  const secretManager = await createSecretManager(context);
  const { repository, permissions } = policies[0];
  const privateKey = await getGithubPrivateKey(
    secretManagerConfig(context.secrets),
    secretRef(context.secrets.privateKeySecretId)
  );
  const githubClient = await githubClientFor({
    privateKey,
    appId: context.appId,
  });

  const accessToken = await githubClient.mintInstallationAccessToken({
    repository,
    permissions,
  });
  await secretManager.createSecretVersion({
    ref: secretRef(userId),
    type: "value",
    value: Buffer.from(accessToken),
  });
  log.info(
    { repository },
    "minted installation access token and stored new secret version"
  );
  return;
};

/**
 * GitHub token lifecycle
 *
 * This lifecycle provisions an access tokens for NHI usage. This does a token exchange
 * where a GitHub App private key (read from a secret in the target system) is exchanged for
 * an app install token, and subsequently a usable access token by the end user/NHI.
 *
 * Note: in this context, the abstract "user" in this lifecycle paradigm is actually concretely
 * represented by the secret itself. This is a seemingly odd naming convention, but this is
 * correct because in the resource root paradigm, the user is the shared thing to which policies
 * are added to and from. In this case the policies are the actual permissions.
 *
 * The P0 control plane is responsible for ensuring that appropriate
 * concurrency controls are enabled to prevent race conditions on that shared item.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    // TODO: add validation later.
    validation: () => ({ user: null }),

    getUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
        appId: context.appId,
      });
      const secretManager = await createSecretManager(context);
      try {
        const { name } = await secretManager.getSecret({
          ref: secretRef(username),
        });
        // TODO: revisit if name is not a valid identifier for GSM
        return name;
      } catch (error) {
        // A missing secret means the user doesn't exist yet; return null so the
        // framework provisions one. Any other error (auth, network, etc.) is a
        // real failure and must propagate.
        if (error instanceof SecretNotFoundError) {
          logger.debug("no existing secret found; user will be provisioned");
          return null;
        }
        logger.error(
          { error, ref: secretRef(username) },
          "failed to look up secret"
        );
        throw error;
      }
    },

    createUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
        appId: context.appId,
      });

      const secretManager = await createSecretManager(context);
      const secret = await secretManager.createSecret({ name: username });
      logger.info({ secretRef: secret.ref }, "created new secret");
      return secret.ref;
    },

    // The framework passes the UserId — the secret's ref (its ARN), as returned by
    // getUser/createUser — so delete directly by ref, same as setPoliciesForUser.
    deleteUser: async (context, userId) => {
      const logger = ctx.logger.child({
        userId,
        requestId: context.requestId,
        appId: context.appId,
      });

      const secretManager = await createSecretManager(context);
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info({ ref: secretRef(userId) }, "deleted secret");
    },

    /**
     * Updates the user (secret) with a new version with a new version derived from
     * the policies (permissions). The P0 control plane is responsible for ensuring
     * that the access policy passed-in reflects the new global permissions that the
     * new access token should contain, with the appropriate concurrency controls
     */
    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ appId: context.appId });
      await updateSecretToken(logger, context, userId, policies);
      logger.info({ ref: secretRef(userId) }, "updated secret");
      return;
    },

    list: async ({ type, context }) => {
      const logger = ctx.logger.child({ appId: context.appId });
      switch (type) {
        case "repository": {
          const privateKey = await getGithubPrivateKey(
            secretManagerConfig(context.secrets),
            secretRef(context.secrets.privateKeySecretId)
          );
          const client = await githubClientFor({
            appId: context.appId,
            privateKey,
          });
          const repositories = await client.listAllRepositories();
          logger.info({ count: repositories.length }, "listed repositories");
          return repositories.map((item) => ({
            key: item.full_name,
            value: item.name,
            group: item.full_name.includes("/")
              ? item.full_name.split("/")[0]
              : undefined,
          }));
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));

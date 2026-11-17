import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { newKeyPair } from "../../keys.ts";
import { markerFor } from "../../marker.ts";
import {
  INSTANCE_STATE_EXIT_CODE,
  type ProvisionAction,
  TRY_AGAIN_EXIT_CODE,
  buildProvisionScript,
  commandTagFor,
  hostKeysOf,
  reasonOf,
} from "../../script/provision.ts";
import { type SecretStoreDependencies, newSecretStore } from "../../secrets.ts";
import {
  CommandFailedError,
  type RunScriptDependencies,
  runScript,
  stderrTailOf,
} from "../../ssm/run-script.ts";
import { type SessionSecret, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type RequestContext = ResourceSchema["RequestContext"];

/** What stands in for AWS in tests. */
export type SessionDependencies = {
  ssm?: RunScriptDependencies;
  secrets?: SecretStoreDependencies;
};

/**
 * Refuses a secret ARN that doesn't name the request's secret in the
 * request's region, so that a revoke deletes only the request's own secret.
 * Secrets Manager ends an ARN with the name, a hyphen and six characters of
 * its own.
 */
const validateSecretArn = (
  arn: string,
  secretName: string,
  context: RequestContext
) => {
  const { requestId, secrets } = context;
  const [prefix, , service, region, , type, resource = "", ...rest] =
    arn.split(":");
  const named =
    prefix === "arn" &&
    service === "secretsmanager" &&
    region === secrets.region &&
    type === "secret" &&
    rest.length === 0 &&
    resource.startsWith(`${secretName}-`) &&
    resource.length === secretName.length + 7;
  if (!named) {
    throw new ConnectorError({
      // Not `validation_error`, which P0 shows the user as their own
      // mistake. P0 sends both the ARN and the name, so a mismatch is P0's
      // bug.
      type: "unknown",
      message:
        "The secret P0 asked to delete doesn't belong to this access, so the connector kept it. Contact P0 support.",
      payload: { requestId },
    });
  }
};

/**
 * The type of a failed script's error, by the script's exit code, for the
 * failures that aren't P0's bug. The type sets what the requester reads. P0
 * shows a `dependency_violation`'s message word for word, so the requester
 * learns what to fix on the instance, and shows an `upstream_unavailable`
 * as a short outage. Any other code stays `unknown`, which P0 records as its
 * own bug. P0 retries a failed call the same way, whatever its type.
 */
const EXIT_CODE_TYPES: Record<number, ConnectorErrorOptions["type"]> = {
  [INSTANCE_STATE_EXIT_CODE]: "dependency_violation",
  [TRY_AGAIN_EXIT_CODE]: "upstream_unavailable",
};

/**
 * What P0 shows the requester when the instance's own state stopped the
 * script: the reason the script gave on stdout, and where to read the rest.
 * Nothing in it comes from stderr, which the agent can write to.
 */
const toInstanceStateMessage = (
  error: CommandFailedError,
  instanceId: string
) => {
  const reason = reasonOf(error.output.stdout);
  const details = `The output of SSM command ${error.data.payload.commandId} has the details.`;
  return reason
    ? `P0's script couldn't change ${instanceId}: ${reason.replace(/\.$/, "")}. ${details}`
    : `P0's script couldn't change ${instanceId}. ${details}`;
};

/**
 * Gives a failed script's error the type of its exit code. A
 * `dependency_violation` gets a message P0 can show the requester, and the
 * end of stderr goes to the connector's log instead. An
 * `upstream_unavailable` or an `unknown` keeps runScript's message, which
 * ends with the last 500 characters of stderr, because P0 never shows
 * either one's message.
 */
const withExitCodeType = (
  error: unknown,
  instanceId: string,
  logger: Logger
) => {
  if (!(error instanceof CommandFailedError)) return error;
  const { data, output } = error;
  const type = EXIT_CODE_TYPES[output.exitCode];
  if (type !== "dependency_violation") {
    return type ? new ConnectorError({ ...data, type }) : error;
  }
  logger.warn(
    {
      commandId: data.payload.commandId,
      stderrTail: stderrTailOf(output.stderr),
    },
    "the script failed on the instance's state"
  );
  return new ConnectorError({
    ...data,
    type,
    message: toInstanceStateMessage(error, instanceId),
  });
};

/**
 * The session lifecycle. It gives a holder group a key to one instance: an
 * ed25519 key pair whose public half goes into the agent's
 * `authorized_keys`, and whose private half goes into a secret the gateway
 * reads.
 *
 * The "user" of this lifecycle is that secret, as it is for
 * `p0-connector-github-ai`. The policies are what P0 granted each holder of
 * the group, and they decide one thing: whether the Linux user has sudo.
 *
 * A revoke that can't remove access from the instance fails and keeps the
 * secret. P0 then marks the request errored, and a person cleans up by
 * hand: first the key line and the sudoers entry on the instance, then the
 * secret. P0 finds the group by its secret, so a secret deleted first hides
 * what is left on the instance.
 *
 * Every primitive can run again and gives the same result. The P0 control
 * plane makes sure that two calls for one instance don't run at once.
 *
 * Nothing here puts the private key in an error, or logs a key pair, a
 * script or a secret's value.
 */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: SessionDependencies = {}
) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => {
    const secretsFor = ({ secrets, requestId }: RequestContext) =>
      newSecretStore(
        { region: secrets.region, requestId },
        dependencies.secrets
      );

    /** Bound to the request, so each log line names its request. */
    const loggerFor = (context: RequestContext, user: string) =>
      ctx.logger.child({
        requestId: context.requestId,
        instanceId: context.instance.id,
        user,
      });

    const run = (
      context: RequestContext,
      logger: Logger,
      action: ProvisionAction
    ) =>
      runScript(
        {
          instance: context.instance,
          script: buildProvisionScript(action),
          tag: commandTagFor(action),
          requestId: context.requestId,
        },
        logger,
        dependencies.ssm
      ).catch((error: unknown) => {
        throw withExitCodeType(error, context.instance.id, logger);
      });

    return {
      // The schema holds the Linux user to the `-ai` namespace, and
      // deleteUser checks the secret's ARN against the secret's name.
      validation: () => ({ user: null }),

      getUser: async (context, { secretName }) => {
        const secret = await secretsFor(context).describe(secretName);
        // A secret with no value is a grant that stopped halfway. `null`
        // sends the framework to createUser, which finishes it.
        return secret?.hasValue ? secret.arn : null;
      },

      createUser: async (context, { user, secretName }) => {
        const logger = loggerFor(context, user);
        const secrets = secretsFor(context);
        // The empty secret comes first, so that when Secrets Manager
        // refuses it the instance is still as it was.
        const arn = await secrets.findOrCreate(secretName);
        const keys = newKeyPair();
        // A marker's new key replaces its old one, so a second try after a
        // failure below leaves one key on the instance, the one it stores.
        const { stdout } = await run(context, logger, {
          action: "ensure-key",
          user,
          marker: markerFor(secretName),
          publicKey: keys.publicKey,
        });
        const value: SessionSecret = {
          privateKey: keys.privateKey,
          user,
          hostKeys: hostKeysOf(stdout, context.requestId),
        };
        await secrets.write(arn, JSON.stringify(value));
        logger.info(
          { nHostKeys: value.hostKeys.length },
          "installed a new key and stored it"
        );
        return arn;
      },

      setPoliciesForUser: async (context, _userId, body, policies) => {
        const { user, secretName } = body;
        const logger = loggerFor(context, user);
        // The full set every time: the user has sudo while P0 grants it to
        // any holder of the group.
        const sudo = policies.some((policy) => policy.sudo);
        await run(context, logger, {
          action: "set-sudo",
          user,
          marker: markerFor(secretName),
          sudo,
        });
        logger.info({ sudo, nPolicies: policies.length }, "set sudo");
      },

      deleteUser: async (context, userId, { user, secretName }) => {
        validateSecretArn(userId, secretName, context);
        const logger = loggerFor(context, user);
        // A failure here fails the revoke and keeps the secret, so a person
        // can still find the group and clear the instance.
        await run(context, logger, {
          action: "remove-key",
          user,
          marker: markerFor(secretName),
        });
        await secretsFor(context).remove(userId);
        logger.info("removed the key line and deleted the secret");
      },

      list: async () => {
        throw new ConnectorError({
          type: "unknown",
          message: "The aws-ssm-ai connector can't list instances yet",
          payload: {},
        });
      },
    };
  });

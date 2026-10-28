import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import type { ConnectorDeps } from "../../deps.ts";
import {
  type AttributeChange,
  patchDeviceAttributes,
} from "../../tailscale/attributes.ts";
import {
  type TailscaleClient,
  newTailscaleClient,
} from "../../tailscale/client.ts";
import {
  attributeRefusalMessage,
  callTailscale,
  isAttributeRefusal,
  isForbidden,
  isNotFound,
  notFoundHint,
} from "../../tailscale/errors.ts";
import {
  getDevice,
  getDeviceAttributes,
  listDevices,
} from "../../tailscale/tailnet.ts";
import { list } from "../common/list.ts";
import {
  type PostureContext,
  attributeKeyFor,
  p0AttributeKey,
  spec,
} from "./definition.ts";

type PostureSchema = ResourceRootSchemaOf<typeof spec>;

/**
 * A grant's refusal when its device isn't on the tailnet. `cause` is the
 * 404 that said so, which may also be a scope the token lacks.
 */
const notOnTailnet = (
  context: PostureContext,
  deviceId: string,
  cause?: unknown
) =>
  new ConnectorError({
    type: "validation_error",
    message: `Device ${deviceId} isn't on tailnet ${context.tailnet}. Choose one of your devices on the tailnet, then request again.${notFoundHint(cause)}`,
    payload: { tailnet: context.tailnet, deviceId },
  });

/**
 * Whether the tailnet's device list answers without the device. Tailscale
 * answers a device's own read with 404 both when it's gone and when the
 * token lacks a scope, so a revoke takes the device as gone only on this,
 * and otherwise fails and is retried rather than leave its attributes.
 */
const verifyOffTailnet = async (client: TailscaleClient, deviceId: string) =>
  !(await client.read(listDevices)).some(({ nodeId }) => nodeId === deviceId);

/**
 * The latest end for each attribute key across `policies`: sorted by end,
 * so a key's later end replaces its earlier one in the map. A policy whose
 * end has passed is left out, so its key is deleted rather than set again
 * with a past expiry, which could fail the whole write and with it a revoke.
 */
const wantedKeys = (
  policies: readonly { posture: string; expiresAt: string }[],
  now = Date.now()
): Map<string, string> =>
  new Map(
    policies
      .filter(({ expiresAt }) => Date.parse(expiresAt) > now)
      .sort((a, b) => Date.parse(a.expiresAt) - Date.parse(b.expiresAt))
      .map(({ posture, expiresAt }) => [attributeKeyFor(posture), expiresAt])
  );

const isP0Key = (key: string) => p0AttributeKey.safeParse(key).success;

/**
 * Tailscale keeps an attribute's expiry to the second and drops the
 * milliseconds P0 sends (spec check A49), so a held key is compared to the
 * second, or every run would set it again.
 */
const toWholeSeconds = (instant: string) =>
  Math.floor(Date.parse(instant) / 1000);

/**
 * The changes that bring the device's P0 attributes to `wanted`: each
 * wanted key set to `true` with its end, unless it already is, and every
 * other P0 key deleted. Only keys `p0AttributeKey` accepts are touched, so
 * a customer's `custom:p0_Prod` stays.
 */
const changesFor = (
  current: {
    attributes: Record<string, unknown>;
    expiries: Record<string, string>;
  },
  wanted: Map<string, string>
): Record<string, AttributeChange> => {
  const isHeld = (key: string, expiry: string) => {
    const heldExpiry = current.expiries[key];
    return (
      current.attributes[key] === true &&
      heldExpiry !== undefined &&
      toWholeSeconds(heldExpiry) === toWholeSeconds(expiry)
    );
  };
  const sets = [...wanted]
    .filter(([key, expiry]) => isP0Key(key) && !isHeld(key, expiry))
    .map(([key, expiry]): [string, AttributeChange] => [
      key,
      { value: true, expiry },
    ]);
  const deletes = Object.keys(current.attributes)
    .filter((key) => isP0Key(key) && !wanted.has(key))
    .map((key): [string, AttributeChange] => [key, null]);
  return Object.fromEntries([...sets, ...deletes]);
};

/**
 * The `posture` access. The customer's grants are gated on `posture:p0_<name>`,
 * whose assertion is `custom:p0_<name> == true`, and P0 sets that attribute
 * on the requestor's chosen device until the grant ends. It never writes
 * the policy file: its write token is `devices:posture_attributes` alone.
 *
 * `setPoliciesForUser` gets the union of every open request on the device,
 * with each one's end, and makes the device's P0 attributes exactly that,
 * in one call. A revoke deletes the key itself; Tailscale's
 * expiry is only the safety net.
 */
export const newPosturePrimitives = (
  logger: Logger,
  deps: ConnectorDeps
): ResourceRootConnectorPrimitives<PostureSchema> => {
  const session = (context: PostureContext, deviceId: string) => {
    const log = logger.child({
      tailnet: context.tailnet,
      requestId: context.requestId,
      deviceId,
      operation: context.operation,
    });
    const client = newTailscaleClient({
      credentials: context,
      log,
      identityToken: deps.identityToken,
    });
    const target = {
      tailnet: context.tailnet,
      subject: `device ${deviceId}`,
      missingMeansTailnet: false,
    };
    return { log, client, target };
  };

  return {
    // The device's owner is checked on a grant, in `setPoliciesForUser`: a
    // check here would also run on a revoke.
    validation: () => ({ user: null }),

    /**
     * The device, or `null` when it isn't on the tailnet (a revoke then has
     * nothing to do, see {@link verifyOffTailnet}). A grant is refused here,
     * so the refusal can say when the 404 may be a scope the token lacks.
     */
    getUser: async (context, { deviceId }) => {
      const { client, target } = session(context, deviceId);
      return callTailscale(async () => {
        try {
          return (await client.read((call) => getDevice(call, deviceId)))
            .nodeId;
        } catch (error) {
          if (!isNotFound(error)) throw error;
          if (context.operation === "grant") {
            throw notOnTailnet(context, deviceId, error);
          }
          if (await verifyOffTailnet(client, deviceId)) return null;
          throw error;
        }
      }, target);
    },

    // Reached only on a grant whose device isn't on the tailnet.
    createUser: async (context, { deviceId }) => {
      throw notOnTailnet(context, deviceId);
    },

    // `setPoliciesForUser` with no policy has already removed every P0 key.
    deleteUser: async () => {},

    setPoliciesForUser: async (context, deviceId, _user, policies) => {
      const { log, client, target } = session(context, deviceId);
      await callTailscale(async () => {
        if (context.operation === "grant") {
          // A device that left the tailnet since the request was made.
          const device = await client
            .read((call) => getDevice(call, deviceId))
            .catch((error: unknown) => {
              throw isNotFound(error)
                ? notOnTailnet(context, deviceId, error)
                : error;
            });
          // A shared-in device's user is someone on its own tailnet, whose
          // login can match the requestor's without being them.
          if (device.isExternal === true) {
            throw new ConnectorError({
              type: "validation_error",
              message: `Device ${deviceId} is shared into tailnet ${context.tailnet} from another tailnet. Choose one of your own devices on tailnet ${context.tailnet}.`,
              payload: { tailnet: context.tailnet, deviceId },
            });
          }
          // A tagged device's user is whoever registered it, not its owner.
          if ((device.tags ?? []).length > 0) {
            throw new ConnectorError({
              type: "validation_error",
              message: `Device ${deviceId} is tagged, so it belongs to its tags, not to ${context.email}. Choose one of your own devices.`,
              payload: { tailnet: context.tailnet, deviceId },
            });
          }
          if (
            (device.user ?? "").toLowerCase() !== context.email.toLowerCase()
          ) {
            throw new ConnectorError({
              type: "validation_error",
              message: `Device ${deviceId} isn't ${context.email}'s. Choose one of your own devices.`,
              payload: { tailnet: context.tailnet, deviceId },
            });
          }
        }
        const wanted = wantedKeys(policies);
        const write = client.write(async (call) => {
          const current = await getDeviceAttributes(call, deviceId).catch(
            async (error: unknown) => {
              if (!isNotFound(error)) throw error;
              if (context.operation === "grant") {
                throw notOnTailnet(context, deviceId, error);
              }
              // The device is gone, and its attributes with it.
              if (await verifyOffTailnet(client, deviceId)) return undefined;
              throw error;
            }
          );
          if (current === undefined) {
            log.info("the device is gone");
            return;
          }
          const changes = changesFor(current, wanted);
          if (Object.keys(changes).length === 0) {
            log.info("the device's P0 attributes are already right");
            return;
          }
          await patchDeviceAttributes(call, {
            deviceId,
            changes,
            comment: `P0 request ${context.requestId} (${context.operation})`,
          });
          log.info(
            {
              set: Object.values(changes).filter((change) => change !== null)
                .length,
              deleted: Object.values(changes).filter(
                (change) => change === null
              ).length,
            },
            "set the device's P0 attributes"
          );
        });
        await write.catch(async (error: unknown) => {
          if (!isAttributeRefusal(error)) throw error;
          // Tailscale answers an attribute write for a device that isn't on
          // the tailnet with 403, as it does a plan or a scope that won't
          // allow it. Only the device's own read tells them apart.
          const gone = !isForbidden(error)
            ? undefined
            : await client
                .read((call) => getDevice(call, deviceId))
                .then(
                  () => undefined,
                  (readError: unknown) => {
                    if (!isNotFound(readError)) throw error;
                    return readError;
                  }
                );
          if (gone === undefined) {
            throw new ConnectorError({
              type: "insufficient_privileges",
              message: attributeRefusalMessage(context.tailnet, error),
              payload: {
                tailnet: context.tailnet,
                deviceId,
                status: error.status,
              },
            });
          }
          if (context.operation === "grant") {
            throw notOnTailnet(context, deviceId, gone);
          }
          // Still listed: the 404 was the token, so the 403 stands.
          if (!(await verifyOffTailnet(client, deviceId))) throw error;
          log.info("the device is gone");
        });
      }, target);
    },

    list: (query) => list(logger, deps, query),
  };
};

export const router = (t: AnyConnectorTRPCInstance, deps: ConnectorDeps) =>
  newResourceRootRouter<PostureSchema>(t, spec, (ctx: ConnectorContext) =>
    newPosturePrimitives(ctx.logger, deps)
  );

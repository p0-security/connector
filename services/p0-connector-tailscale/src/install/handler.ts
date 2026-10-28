import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import {
  INSTALL_CHECK_POSTURE,
  attributeKeyFor,
  postureName,
} from "../accesses/posture/definition.ts";
import type { ConnectorDeps } from "../deps.ts";
import type { TailnetCall } from "../tailscale/api.ts";
import {
  deleteDeviceAttribute,
  setDeviceAttribute,
} from "../tailscale/attributes.ts";
import {
  type TailscaleClient,
  newTailscaleClient,
} from "../tailscale/client.ts";
import {
  TokenRejectedError,
  attributeRefusalMessage,
  isAnyNotFound,
  isAttributeRefusal,
  isForbidden,
  isNotFound,
  isScopeRefusal,
  lacksScope,
  toConnectorError,
} from "../tailscale/errors.ts";
import { posturesOf } from "../tailscale/inventory.ts";
import {
  READ_SCOPES,
  REFUSED_SCOPES,
  REQUIRED_SCOPES,
  WRITE_SCOPES,
  covers,
} from "../tailscale/scopes.ts";
import {
  type TailscaleDevice,
  getDeviceAttributes,
  getDeviceRoutes,
  getPolicyJson,
  listDevices,
  listServices,
  listUsers,
} from "../tailscale/tailnet.ts";
import {
  type Discovery,
  type InstallValidation,
  type InstallValidationInput,
  installValidationInput,
} from "./definition.ts";

/** The checks, in the order they run, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "credential" | "discovery" | "posture" | "scopes";

/**
 * The attribute the `posture` check sets and removes. A request can't name
 * its posture, so the check opens no grant P0 approved.
 */
export const POSTURE_CHECK_KEY = attributeKeyFor(INSTALL_CHECK_POSTURE);

/** How long the `posture` check's attribute lives if its removal fails. */
const POSTURE_CHECK_LIFETIME_MS = 60 * 1000;

/**
 * The error for a failed check. The answer carries facts, not results, so a
 * failure is thrown, and `payload.step` is how P0 tells one from another.
 * `payload.tailnet` says which tailnet was being validated.
 */
const failedCheck = ({
  step,
  tailnet,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & {
    step: Step;
    tailnet: string;
  }) =>
  new ConnectorError({ type, message, payload: { ...payload, step, tailnet } });

/** Runs one check, naming its step on whatever it fails with. */
const runStep = async <T>(
  step: Step,
  tailnet: string,
  check: () => Promise<T>
): Promise<T> => {
  try {
    return await check();
  } catch (error) {
    const mapped = toConnectorError(error, { tailnet });
    throw mapped instanceof ConnectorError
      ? failedCheck({ ...mapped.data, step, tailnet })
      : mapped;
  }
};

/** `credential`: the OAuth client's secret reads, or the connector's cloud identity mints a token. */
const checkCredential = (client: TailscaleClient) =>
  runStep("credential", client.tailnet, () => client.checkCredential());

/**
 * `authenticate`: Tailscale exchanges the credential for a token, and
 * answers the scopes it carries. An OAuth client asks for no scope here, so
 * the token carries all of its own, and a missing one is left for `scopes`
 * to name.
 */
const authenticate = (client: TailscaleClient) =>
  runStep("authenticate", client.tailnet, async (): Promise<string[]> => {
    try {
      return await client.exchangeFor([]);
    } catch (error) {
      if (!(error instanceof TokenRejectedError)) throw error;
      throw failedCheck({
        step: "authenticate",
        tailnet: client.tailnet,
        type: "insufficient_privileges",
        message: `Tailscale didn't accept the connector's credential (${error.status}): ${error.reason}. Check the client ID, then the OAuth client's secret, or the federated identity's issuer and subject. The client ID can't be changed in place: if it's wrong, remove this tailnet from P0 and add it again with the right one.`,
        payload: { status: error.status },
      });
    }
  });

/**
 * A missing scope as the list names it: `devices:posture_attributes:read`
 * is `devices:posture_attributes`, so an admin who adds exactly what's named
 * gets the scope P0 needs.
 */
const asListed = (scope: string): string =>
  REQUIRED_SCOPES.find(
    (listed) => listed === scope || `${listed}:read` === scope
  ) ?? scope;

/**
 * The scopes of `scopes` an OAuth client can't get a token for. One
 * exchange for the set, and only when it's refused, one per scope to say
 * which. Tailscale answers a scope the client lacks with 403 `OAuth client
 * cannot grant scopes "..."`, naming every scope asked for.
 */
const unexchangeable = async (
  client: TailscaleClient,
  scopes: readonly string[]
): Promise<string[]> => {
  const refused = async (asked: readonly string[]) => {
    try {
      await client.exchangeFor(asked);
      return false;
    } catch (error) {
      if (isScopeRefusal(error)) return true;
      throw error;
    }
  };
  if (!(await refused(scopes))) return [];
  const each = await Promise.all(scopes.map((scope) => refused([scope])));
  return scopes.filter((_, index) => each[index]);
};

/**
 * Whether the OAuth client can get a token with `policy_file`, for when
 * Tailscale doesn't name the scopes it holds. The exchange writes nothing.
 * A token whose answer names its scopes holds `policy_file` only if they
 * cover it. One that names none holds what it was asked for.
 */
const verifyHoldsPolicyFile = async (client: TailscaleClient) => {
  try {
    return covers(await client.exchangeFor(["policy_file"]), "policy_file");
  } catch (error) {
    if (isScopeRefusal(error)) return false;
    throw error;
  }
};

type Probe<T> = { scope: string; run: () => Promise<T> };

/** What the `scopes` check read, which the later checks reuse. */
type Read = {
  devices: TailscaleDevice[];
  policy: Record<string, unknown>;
};

/**
 * Runs `probe`, answering `undefined` and noting its scope when Tailscale
 * says the token lacks it. Tailscale answers a missing scope with 404 "not
 * found", as it does a mistyped Tailnet ID, so a 404 is taken as the scope
 * when the token is known to lack it, or once `tailnetAnswered` says an
 * earlier read found the tailnet. A 404 before that, from a token whose
 * scopes aren't known, says it may be either.
 */
const probing = async <T>(
  { scope, run }: Probe<T>,
  missing: string[],
  tailnetAnswered: boolean
): Promise<T | undefined> => {
  try {
    return await run();
  } catch (error) {
    const lacking =
      isForbidden(error) ||
      lacksScope(error) ||
      (tailnetAnswered && isAnyNotFound(error));
    if (!lacking) throw error;
    missing.push(scope);
    return undefined;
  }
};

/**
 * `scopes`: each endpoint P0 needs answers. A refusal names the scope
 * that's missing (see {@link probing}). An OAuth client's write scope is
 * proved by exchanging for a write token, which writes nothing. A federated
 * identity's token carries every scope it was configured with, so they're
 * compared with the list. When Tailscale doesn't say which it carries, the
 * check fails, since nothing else can show it can't write the policy file.
 *
 * A credential that carries a scope able to write the policy file is
 * refused: a federated token's, or an OAuth client's own, which a token
 * asked for with no scope carries. When Tailscale names none of an OAuth
 * client's, an exchange for `policy_file` shows whether it holds it.
 */
const checkScopes = (client: TailscaleClient, granted: readonly string[]) =>
  runStep("scopes", client.tailnet, async (): Promise<Read> => {
    const { tailnet } = client;
    const missing: string[] = [];
    const refuse = () => {
      const named = [...new Set(missing.map(asListed))];
      return failedCheck({
        step: "scopes",
        tailnet,
        type: "insufficient_privileges",
        message: `The connector's Tailscale credential is missing ${
          named.length === 1 ? "a scope" : "scopes"
        }: ${named.join(", ")}. It needs ${REQUIRED_SCOPES.join(", ")}. Add ${
          named.length === 1 ? "it" : "them"
        }, then validate again.`,
        payload: { missing: named.join(" ") },
      });
    };
    const isVault = client.credentialKind === "vault";

    if (isVault) {
      missing.push(...(await unexchangeable(client, READ_SCOPES)));
    } else if (granted.length > 0) {
      missing.push(
        ...REQUIRED_SCOPES.filter((scope) => !covers(granted, scope))
      );
    } else {
      // Fail closed: nothing else can tell P0 the token can't write the
      // policy file.
      throw failedCheck({
        step: "scopes",
        tailnet,
        type: "validation_error",
        message: `Tailscale didn't say which scopes the connector's federated credential carries, so P0 can't confirm it can't write the policy file. Check that the federated identity has only ${REQUIRED_SCOPES.join(", ")}, then validate again, or use an OAuth client instead.`,
      });
    }
    if (missing.length > 0) throw refuse();

    const holdsPolicyFile =
      isVault && granted.length === 0 && (await verifyHoldsPolicyFile(client));
    const extra = [
      ...REFUSED_SCOPES.filter((scope) => granted.includes(scope)),
      ...(holdsPolicyFile ? ["policy_file"] : []),
    ];
    if (extra.length > 0) {
      throw failedCheck({
        step: "scopes",
        tailnet,
        type: "validation_error",
        message: `The connector's Tailscale credential carries ${extra.join(" and ")}, more than P0 needs, and could write the policy file, which P0 never does. Use a credential with only ${REQUIRED_SCOPES.join(", ")}, then validate again.`,
        payload: { extra: extra.join(" ") },
      });
    }

    const read = <T>(
      scope: string,
      request: (call: TailnetCall) => Promise<T>,
      tailnetAnswered: boolean
    ) =>
      probing<T>(
        { scope, run: () => client.read(request) },
        missing,
        tailnetAnswered
      );

    // Once the users read finds the tailnet, a 404 can only be the scope.
    const found = (await read("users:read", listUsers, false)) !== undefined;
    const devices =
      (await read<TailscaleDevice[]>(
        "devices:core:read",
        listDevices,
        found
      )) ?? [];
    await read<unknown[]>("services:read", listServices, found);
    const policy = await read<Record<string, unknown>>(
      "policy_file:read",
      getPolicyJson,
      found
    );
    // Tailscale may refuse a read of a device another tailnet shares in, and
    // that refusal would read as a missing scope. With no device of the
    // tailnet's own, these two go unchecked, as on an empty tailnet.
    const probe = sortedDevices(devices).find(
      ({ isExternal }) => isExternal !== true
    );
    if (probe !== undefined) {
      await read(
        "devices:routes:read",
        (call) => getDeviceRoutes(call, probe.nodeId),
        found
      );
      await read(
        "devices:posture_attributes:read",
        (call) => getDeviceAttributes(call, probe.nodeId),
        found
      );
    }

    if (missing.length === 0 && isVault) {
      missing.push(...(await unexchangeable(client, WRITE_SCOPES)));
    }
    if (missing.length > 0) throw refuse();
    return { devices, policy: policy ?? {} };
  });

/** The tailnet's devices in a fixed order, so the checks always pick the same one. */
const sortedDevices = (devices: readonly TailscaleDevice[]) =>
  [...devices].sort((a, b) =>
    a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0
  );

/**
 * `posture`: sets `custom:p0_install_check` on one device, with a one-minute
 * expiry, and removes it at once. It's the one check that writes, and it
 * proves the plan allows custom attributes and the credential may set them. The device is the first untagged one of the
 * tailnet's own by node id, so a re-run picks the same one, and no server
 * or shared-in device carries the attribute.
 */
const checkPosture = (
  client: TailscaleClient,
  devices: readonly TailscaleDevice[],
  now: () => number
) =>
  runStep("posture", client.tailnet, async () => {
    const device = sortedDevices(devices).find(
      ({ tags, isExternal }) => (tags ?? []).length === 0 && isExternal !== true
    );
    if (device === undefined) {
      throw failedCheck({
        step: "posture",
        tailnet: client.tailnet,
        type: "validation_error",
        message: `Tailnet ${client.tailnet} has no untagged device of its own, so P0 can't check that it may set device attributes. Add one, then validate again.`,
      });
    }
    const deviceId = device.nodeId;
    try {
      await client.write((call) =>
        setDeviceAttribute(call, {
          deviceId,
          key: POSTURE_CHECK_KEY,
          value: true,
          expiry: new Date(now() + POSTURE_CHECK_LIFETIME_MS).toISOString(),
          comment: "P0 install check",
        })
      );
    } catch (error) {
      if (isAttributeRefusal(error)) {
        const { status } = error;
        throw failedCheck({
          step: "posture",
          tailnet: client.tailnet,
          type: "validation_error",
          message: attributeRefusalMessage(client.tailnet, error),
          payload: { status, deviceId },
        });
      }
      throw error;
    }
    await client
      .write((call) =>
        deleteDeviceAttribute(call, { deviceId, key: POSTURE_CHECK_KEY })
      )
      .catch((error: unknown) => {
        // Gone already: the check's job is done either way.
        if (!isNotFound(error)) throw error;
      });
    return deviceId;
  });

/**
 * The tailnet's DNS name: the domain of the MagicDNS name, such as
 * `laptop.tail1234.ts.net`, of its first own device by node id. A device
 * shared in from another tailnet has that tailnet's domain, so it's skipped.
 */
const dnsNameOf = (devices: readonly TailscaleDevice[]) =>
  sortedDevices(devices)
    .filter(({ isExternal }) => isExternal !== true)
    .map(({ name }) => name?.slice(name.indexOf(".") + 1))
    .find((domain) => domain !== undefined && domain.includes("."));

/** `discovery`: counts the P0 postures a request can name, from what `scopes` read. */
const discover = (tailnet: string, read: Read) =>
  runStep("discovery", tailnet, async (): Promise<Discovery> => ({
    p0Postures: posturesOf(read.policy).filter(
      ({ name }) => postureName.safeParse(name).success
    ).length,
  }));

export const getInstallValidation = async (
  { skipPostureWrite = false, ...credentials }: InstallValidationInput,
  {
    logger,
    deps,
    now = Date.now,
  }: { logger: Logger; deps: ConnectorDeps; now?: () => number }
): Promise<InstallValidation> => {
  const { tailnet } = credentials;
  const client = newTailscaleClient({
    credentials,
    log: logger,
    identityToken: deps.identityToken,
  });
  await checkCredential(client);
  const granted = await authenticate(client);
  const read = await checkScopes(client, granted);
  const postureCheckDevice = skipPostureWrite
    ? undefined
    : await checkPosture(client, read.devices, now);
  const discovery = await discover(tailnet, read);
  const dnsName = dnsNameOf(read.devices);
  return {
    tailnet,
    ...(postureCheckDevice !== undefined ? { postureCheckDevice } : {}),
    ...(dnsName !== undefined ? { dnsName } : {}),
    discovery,
  };
};

export const router = (t: AnyConnectorTRPCInstance, deps: ConnectorDeps) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(installValidationInput.parse)
      .query(async ({ input, ctx }) => {
        const logger = ctx.logger.child({
          tailnet: input.tailnet,
          clientId: input.credential.clientId,
        });
        const validation = await getInstallValidation(input, { logger, deps });
        logger.info(
          { discovery: validation.discovery },
          "validated the Tailscale tailnet"
        );
        return validation;
      }),
  });
};

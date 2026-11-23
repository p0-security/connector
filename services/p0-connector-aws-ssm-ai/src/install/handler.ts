import {
  DescribeInstanceInformationCommand,
  SSMClient,
} from "@aws-sdk/client-ssm";
import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  withRouteLogging,
} from "@p0security/connector-core";

import { type InstallContext, installContext } from "../context.ts";
import { toConnectorError } from "../ssm/errors.ts";
import type { AwsSsmAiInstallStep, InstallValidation } from "./definition.ts";

export type InstallDependencies = {
  client?: Pick<SSMClient, "send">;
};

// The smallest page SSM allows. The check only needs SSM to allow the call.
const MIN_PAGE_SIZE = 5;

/**
 * Checks that the connector's role can describe the SSM managed instances in
 * the install's region. A failure carries `managed_instances` in
 * `payload.step`, and the region.
 */
export const validateInstall = async (
  install: InstallContext,
  dependencies: InstallDependencies = {}
): Promise<InstallValidation> => {
  const { region } = install;
  const { client = new SSMClient({ region }) } = dependencies;
  try {
    await client.send(
      new DescribeInstanceInformationCommand({ MaxResults: MIN_PAGE_SIZE })
    );
  } catch (error) {
    const { data } = toConnectorError(error);
    const step: AwsSsmAiInstallStep = "managed_instances";
    throw new ConnectorError({
      ...data,
      payload: { ...data.payload, step, region },
    });
  }
  return { region };
};

/**
 * Lets the installer confirm the connector can reach SSM in the install's
 * region. `get` is what install validation runs, so it never writes.
 */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: InstallDependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);

  return t.router({
    get: procedure
      .input(installContext.parse)
      .query(({ input }): Promise<InstallValidation> =>
        validateInstall(input, dependencies)
      ),
  });
};

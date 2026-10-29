import {
  DescribeClustersCommand,
  RedshiftClient,
} from "@aws-sdk/client-redshift";
import {
  GetWorkgroupCommand,
  RedshiftServerlessClient,
} from "@aws-sdk/client-redshift-serverless";
import { ConnectorError } from "@p0security/connector-core";

import type { InstallContext, TargetType } from "../context.ts";
import { toConnectorError } from "./data-api.ts";

export type TargetLookupDependencies = {
  redshift?: Pick<RedshiftClient, "send">;
  serverless?: Pick<RedshiftServerlessClient, "send">;
};

/**
 * `DescribeClusters` returns no cluster ARN, only the ARN of the cluster's
 * namespace, `arn:<partition>:redshift:<region>:<account>:namespace:<id>`.
 * The cluster ARN has the same partition, region and account.
 */
const clusterArn = (namespaceArn: string, clusterIdentifier: string) => {
  const [arn, partition, service, region, account] = namespaceArn.split(":");
  if (arn !== "arn" || service !== "redshift" || !region || !account) {
    throw new ConnectorError({
      type: "unknown",
      message: "Redshift returned a cluster namespace ARN P0 can't read",
      payload: { clusterIdentifier },
    });
  }
  return `arn:${partition}:redshift:${region}:${account}:cluster:${clusterIdentifier}`;
};

const notFound = (type: TargetType, name: string) =>
  new ConnectorError({
    type: "object_not_found",
    message:
      type === "provisioned"
        ? `No Redshift cluster ${name} was found`
        : `No Redshift Serverless workgroup ${name} was found`,
    payload: { target: name },
  });

type Lookup = (
  install: InstallContext,
  dependencies: TargetLookupDependencies
) => Promise<string>;

const lookups: Record<TargetType, Lookup> = {
  provisioned: async ({ target, region }, { redshift }) => {
    const client = redshift ?? new RedshiftClient({ region });
    const { Clusters = [] } = await client
      .send(new DescribeClustersCommand({ ClusterIdentifier: target.name }))
      .catch((error: unknown) => {
        if ((error as { name?: string }).name === "ClusterNotFoundFault") {
          throw notFound(target.type, target.name);
        }
        throw toConnectorError(error);
      });
    const namespaceArn = Clusters[0]?.ClusterNamespaceArn;
    if (!namespaceArn) throw notFound(target.type, target.name);
    return clusterArn(namespaceArn, target.name);
  },
  serverless: async ({ target, region }, { serverless }) => {
    const client = serverless ?? new RedshiftServerlessClient({ region });
    const { workgroup } = await client
      .send(new GetWorkgroupCommand({ workgroupName: target.name }))
      .catch((error: unknown) => {
        if ((error as { name?: string }).name === "ResourceNotFoundException") {
          throw notFound(target.type, target.name);
        }
        throw toConnectorError(error);
      });
    if (!workgroup?.workgroupArn) throw notFound(target.type, target.name);
    return workgroup.workgroupArn;
  },
};

/** Finds the install's cluster or workgroup through the execution role, and
 * returns its ARN. */
export const lookupTargetArn = (
  install: InstallContext,
  dependencies: TargetLookupDependencies = {}
) => lookups[install.target.type](install, dependencies);

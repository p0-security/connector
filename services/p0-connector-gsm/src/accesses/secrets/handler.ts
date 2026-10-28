import {
  ConnectorError,
  newSecretManagementRouter,
} from "@p0security/connector";
import type {
  AnyConnectorTRPCInstance,
  ConnectorErrorType,
} from "@p0security/connector";
import { getServiceAccountEmail } from "@p0security/gcloud-common";
import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";
import type {
  SecretManagerClient,
  SecretRef,
  SecretVersionRef,
  VersionMetadata,
} from "@p0security/secret-manager-client";

import { spec } from "./definition.ts";

const secretRef = (project: string, name: string) =>
  `projects/${project}/secrets/${name}` as SecretRef;

const versionRef = (project: string, name: string, version: string) =>
  `${secretRef(project, name)}/versions/${version}` as SecretVersionRef;

// GSM version resource names end in the version's (monotonically increasing)
// numeric id -- this is the only way to recover a version number from a ref.
const versionNumber = (ref: SecretVersionRef) => Number(ref.split("/").pop());

const toVersionStateSummary = (
  state: VersionMetadata["state"]
): "DESTROYED" | "DISABLED" | "ENABLED" => {
  switch (state) {
    case "enabled":
      return "ENABLED";
    case "disabled":
      return "DISABLED";
    case "destroyed":
      return "DESTROYED";
  }
};

// `project` is a per-request field (not fixed at connector startup), so the
// client is memoized per project rather than once at module load. A rejected
// promise is evicted so a transient auth failure can be retried.
const clientsByProject = new Map<string, Promise<SecretManagerClient>>();
const getClient = (project: string): Promise<SecretManagerClient> => {
  const cached = clientsByProject.get(project);
  if (cached) return cached;
  const client = createSecretManagerClient({
    provider: "gcp",
    projectId: project,
  }).catch((error) => {
    clientsByProject.delete(project);
    throw error;
  });
  clientsByProject.set(project, client);
  return client;
};

/** Maps a `secret-manager-client` failure to a categorized {@link ConnectorError}. */
const mapSecretManagerError = (
  error: unknown,
  payload: Record<string, string>
): ConnectorError => {
  const type: ConnectorErrorType =
    error instanceof SecretAlreadyExistsError
      ? "already_exists"
      : error instanceof SecretNotFoundError ||
          error instanceof SecretVersionNotFoundError
        ? "object_not_found"
        : error instanceof UnauthorizedError
          ? "insufficient_privileges"
          : "unknown";
  return new ConnectorError({
    type,
    message:
      error instanceof Error
        ? error.message
        : "GCP Secret Manager request failed.",
    payload,
    cause: error,
  });
};

const call = async <T>(
  fn: () => Promise<T>,
  payload: Record<string, string>
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    throw mapSecretManagerError(error, payload);
  }
};

export const router = (t: AnyConnectorTRPCInstance) =>
  newSecretManagementRouter(t, spec, () => ({
    listSecrets: async ({ project, filter, pageSize, pageToken }) => {
      const client = await getClient(project);
      const all = await call(() => client.getAllSecrets(), { project });
      // secret-manager-client's getAllSecrets has no server-side filter or
      // pagination (it already resolves all pages), so both are approximated
      // client-side here: filter as a substring match on name, pageToken as
      // a stringified offset into the (filtered) result set.
      const matching = filter
        ? all.filter((secret) => secret.name.includes(filter))
        : all;
      const start = pageToken ? Number(pageToken) : 0;
      const end = pageSize ? start + pageSize : matching.length;
      const page = matching.slice(start, end);
      return {
        secrets: page.map((secret) => ({
          project,
          name: secret.name,
          createTime: secret.createTime.toISOString(),
        })),
        nextPageToken: end < matching.length ? String(end) : undefined,
      };
    },

    getSecretMetadata: async ({ project, name }) => {
      const client = await getClient(project);
      const versions = await call(
        () => client.getSecretVersions({ ref: secretRef(project, name) }),
        { project, name }
      );
      return {
        project,
        name,
        versions: versions.map((version) => ({
          version: String(versionNumber(version.ref)),
          state: toVersionStateSummary(version.state),
          createTime: version.createTime.toISOString(),
        })),
      };
    },

    createNewVersion: async ({ project, name }) => {
      const client = await getClient(project);
      const ref = secretRef(project, name);
      await call(
        () => client.createSecretVersion({ ref, type: "random", bytes: 32 }),
        {
          project,
          name,
        }
      );
      // createSecretVersion returns void, so the new version is recovered by
      // re-listing and taking the highest version number (GSM's are monotonic).
      const versions = await call(() => client.getSecretVersions({ ref }), {
        project,
        name,
      });
      const latest = versions.reduce((max, version) =>
        versionNumber(version.ref) > versionNumber(max.ref) ? version : max
      );
      return {
        project,
        name,
        version: String(versionNumber(latest.ref)),
        state: toVersionStateSummary(latest.state),
        createTime: latest.createTime.toISOString(),
      };
    },

    disableVersion: async ({ project, name, version }) => {
      const client = await getClient(project);
      await call(
        () =>
          client.disableSecretVersion({
            ref: versionRef(project, name, version),
          }),
        { project, name, version }
      );
    },

    deleteVersion: async ({ project, name, version }) => {
      const client = await getClient(project);
      await call(
        () =>
          client.deleteSecretVersion({
            ref: versionRef(project, name, version),
          }),
        { project, name, version }
      );
    },

    getInstallValidation: async () => {
      try {
        return {
          canAuthenticate: true,
          serviceAccountEmail: await getServiceAccountEmail(),
        };
      } catch {
        return { canAuthenticate: false, serviceAccountEmail: null };
      }
    },
  }));

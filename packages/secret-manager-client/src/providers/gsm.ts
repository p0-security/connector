import type { secretmanager_v1 } from "@googleapis/secretmanager";
import { createClients } from "@p0security/connector-gcloud-common";
import { randomBytes } from "node:crypto";

import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
  UnauthorizedError,
} from "../errors.ts";
import { listAllPages } from "../pagination.ts";
import type {
  SecretManagerClient,
  SecretManagerProviderConfig,
  SecretMetadata,
  SecretRef,
  SecretValue,
  SecretVersionRef,
  SecretVersionState,
  VersionMetadata,
} from "../types.ts";

type GcpSecretManagerConfig = Extract<
  SecretManagerProviderConfig,
  { provider: "gcp" }
>;

type SecretManagerApi = Awaited<
  ReturnType<typeof createClients>
>["secretManager"];

/** Extracts an HTTP status code from a googleapis error, if present. */
const getHttpStatus = (error: unknown): number | undefined => {
  if (typeof error !== "object" || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  if (typeof status === "number") return status;
  const responseStatus = (error as { response?: { status?: unknown } }).response
    ?.status;
  return typeof responseStatus === "number" ? responseStatus : undefined;
};

type ErrorMapping = { status: number; toError: (error: unknown) => Error };

/** Standard 401/403 -> UnauthorizedError mappings shared by all GSM calls. */
const unauthorizedMappings = (): ErrorMapping[] => [
  {
    status: 401,
    toError: (error) => new UnauthorizedError("gcp", { cause: error }),
  },
  {
    status: 403,
    toError: (error) => new UnauthorizedError("gcp", { cause: error }),
  },
];

/** Runs `fn`, rethrowing as a mapped error type if its HTTP status matches one of `mappings`. */
const withErrorMapping = async <T>(
  fn: () => Promise<T>,
  mappings: ErrorMapping[]
): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    const mapping = mappings.find((m) => m.status === getHttpStatus(error));
    throw mapping ? mapping.toError(error) : error;
  }
};

/** Converts a GCP secret resource into the client's SecretMetadata shape. */
const toSecretMetadata = (
  secret: secretmanager_v1.Schema$Secret
): SecretMetadata => {
  if (!secret.name) {
    throw new Error("GCP Secret Manager returned a secret with no name");
  }
  return {
    ref: secret.name as SecretRef,
    name: secret.name.split("/").pop() ?? secret.name,
    createTime: new Date(secret.createTime ?? 0),
  };
};

/** Maps a GCP secret version state string to the client's SecretVersionState. */
const toVersionState = (state?: string | null): SecretVersionState => {
  switch (state) {
    case "ENABLED":
      return "enabled";
    case "DISABLED":
      return "disabled";
    case "DESTROYED":
      return "destroyed";
    default:
      throw new Error(`Unrecognized GCP secret version state: ${state}`);
  }
};

/** Converts a GCP secret version resource into the client's VersionMetadata shape. */
const toVersionMetadata = (
  version: secretmanager_v1.Schema$SecretVersion,
  secretRef: SecretRef
): VersionMetadata => {
  if (!version.name) {
    throw new Error("GCP Secret Manager returned a version with no name");
  }
  return {
    ref: version.name as SecretVersionRef,
    secretRef,
    state: toVersionState(version.state),
    createTime: new Date(version.createTime ?? 0),
  };
};

/**
 * GCP Secret Manager implementation, built on the auth/client bundle from
 * `@p0security/connector-gcloud-common`. Uses the global (non-regionalized)
 * `projects.secrets.*` API; secret and version resource names are used
 * directly as `SecretRef`/`SecretVersionRef`.
 */
export const createGsmSecretManagerClient = async (
  config: GcpSecretManagerConfig
): Promise<SecretManagerClient> => {
  const { secretManager }: { secretManager: SecretManagerApi } =
    await createClients();
  const parent = `projects/${config.projectId}`;

  /**
   * GCP Secret Manager APIs require a fully-qualified secret resource name
   * (`projects/{projectId}/secrets/{id}`); a bare id resolves to a 404. Callers
   * may hold either the full ref (as returned by `createSecret`/`getSecret`) or
   * just the bare id, so normalize both here — this lets the GCP client accept a
   * bare id the same way AWS's `SecretId` does. Already-qualified refs pass
   * through unchanged, so this is safe to apply unconditionally.
   */
  const qualifySecretRef = (ref: SecretRef): string =>
    ref.startsWith("projects/") ? ref : `${parent}/secrets/${ref}`;

  return {
    /** Creates a new secret with automatic replication. */
    createSecret: async ({ name }) => {
      const created = await withErrorMapping(async () => {
        const response = await secretManager.projects.secrets.create({
          parent,
          secretId: name,
          requestBody: { replication: { automatic: {} } },
        });
        return response.data;
      }, [
        {
          status: 409,
          toError: (error) =>
            new SecretAlreadyExistsError(name, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]);

      return toSecretMetadata(created);
    },
    /** Fetches an existing secret by its name/identifier. */
    getSecret: async ({ ref }) => {
      const secret = await withErrorMapping(async () => {
        const response = await secretManager.projects.secrets.get({
          name: qualifySecretRef(ref),
        });
        return response.data;
      }, [
        {
          status: 404,
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]);
      return toSecretMetadata(secret);
    },
    /** Permanently deletes the secret at `ref`, along with all of its versions. */
    deleteSecret: ({ ref }) =>
      withErrorMapping(async () => {
        await secretManager.projects.secrets.delete({
          name: qualifySecretRef(ref),
        });
      }, [
        {
          status: 404,
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Lists all secrets in the configured project, across all pages. */
    getAllSecrets: async () => {
      const secrets = await withErrorMapping(
        () =>
          listAllPages(async (pageToken) => {
            const response = await secretManager.projects.secrets.list({
              parent,
              pageToken,
            });
            return {
              items: response.data.secrets ?? [],
              nextPageToken: response.data.nextPageToken,
            };
          }),
        unauthorizedMappings()
      );
      return secrets.map(toSecretMetadata);
    },

    /** Lists all versions of the secret at `ref`, across all pages. */
    getSecretVersions: async ({ ref }) => {
      const versions = await withErrorMapping(
        () =>
          listAllPages(async (pageToken) => {
            const response = await secretManager.projects.secrets.versions.list(
              {
                parent: qualifySecretRef(ref),
                pageToken,
              }
            );
            return {
              items: response.data.versions ?? [],
              nextPageToken: response.data.nextPageToken,
            };
          }),
        [
          {
            status: 404,
            toError: (error) => new SecretNotFoundError(ref, { cause: error }),
          },
          ...unauthorizedMappings(),
        ]
      );
      return versions.map((version) => toVersionMetadata(version, ref));
    },

    /**
     * Reads the value and metadata of the secret's latest (current) version.
     */
    getSecretValue: ({ ref }): Promise<SecretValue> =>
      withErrorMapping(async () => {
        const versionName = `${qualifySecretRef(ref)}/versions/latest`;
        const accessResponse =
          await secretManager.projects.secrets.versions.access({
            name: versionName,
          });
        const data = accessResponse.data.payload?.data;
        if (!data) {
          throw new Error(
            `GCP Secret Manager returned a version with no payload data for "${ref}"`
          );
        }
        if (!accessResponse.data.name) {
          throw new Error(`Invalid secret version name`);
        }
        const versionResponse =
          await secretManager.projects.secrets.versions.get({
            name: accessResponse.data.name,
          });
        return {
          value: Buffer.from(data, "base64"),
          version: toVersionMetadata(versionResponse.data, ref),
        };
      }, [
        {
          status: 404,
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Adds a new version to `ref` with either a random payload of `bytes` size or an explicit `value`. */
    createSecretVersion: ({ ref, ...rest }) =>
      withErrorMapping(async () => {
        const response = await secretManager.projects.secrets.addVersion({
          parent: qualifySecretRef(ref),
          requestBody: {
            payload: {
              data:
                rest.type === "value"
                  ? rest.value.toString("base64")
                  : randomBytes(rest.bytes).toString("base64"),
            },
          },
        });
        return toVersionMetadata(response.data, ref);
      }, [
        {
          status: 404,
          toError: (error) => new SecretNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Disables the secret version at `ref`. */
    disableSecretVersion: ({ ref }) =>
      withErrorMapping(async () => {
        await secretManager.projects.secrets.versions.disable({
          name: ref,
        });
      }, [
        {
          status: 404,
          toError: (error) =>
            new SecretVersionNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),

    /** Permanently destroys the secret version at `ref`. */
    deleteSecretVersion: ({ ref }) =>
      withErrorMapping(async () => {
        await secretManager.projects.secrets.versions.destroy({
          name: ref,
        });
      }, [
        {
          status: 404,
          toError: (error) =>
            new SecretVersionNotFoundError(ref, { cause: error }),
        },
        ...unauthorizedMappings(),
      ]),
  };
};

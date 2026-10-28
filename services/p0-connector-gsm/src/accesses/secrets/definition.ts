import { newZodSecretManagementParsers } from "@p0security/connector";
import { z } from "zod";

const secretId = z.object({
  project: z.string().min(1),
  name: z.string().min(1),
});

const versionId = secretId.extend({
  version: z.string().min(1),
});

const versionSummary = z.object({
  version: z.string(),
  state: z.enum(["ENABLED", "DISABLED", "DESTROYED", "STATE_UNSPECIFIED"]),
  createTime: z.string().optional(),
});

const secretMetadata = z.object({
  project: z.string(),
  name: z.string(),
  createTime: z.string().optional(),
  labels: z.record(z.string(), z.string()).optional(),
  versions: z.array(versionSummary),
});

const versionMetadata = z.object({
  project: z.string(),
  name: z.string(),
  version: z.string(),
  state: z.string().optional(),
  createTime: z.string().optional(),
});

const installValidation = z.object({
  canAuthenticate: z.boolean(),
  serviceAccountEmail: z.string().nullable(),
});

const listSecretsQuery = z.object({
  project: z.string().min(1),
  filter: z.string().optional(),
  pageSize: z.number().int().positive().optional(),
  pageToken: z.string().optional(),
});

const listSecretsResponse = z.object({
  secrets: z.array(secretMetadata.omit({ versions: true })),
  nextPageToken: z.string().optional(),
});

export const schema = {
  secretId,
  secretMetadata,
  versionId,
  versionMetadata,
  installValidation,
  listSecretsQuery,
  listSecretsResponse,
};

export const spec = newZodSecretManagementParsers(schema);

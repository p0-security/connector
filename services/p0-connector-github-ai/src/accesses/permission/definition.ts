import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

const userBody = z.string().min(1);
const userId = z.string().min(1);

// The policy can be directly passed to the GitHub API to generate an access token
// https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app
const policy = z.object({
  repository: z.string(),
  permissions: z.record(z.string(), z.enum(["admin", "read", "write"])),
});

const appPrivateKey = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    privateKeySecretId: z.string(),
    region: z.string(),
  }),
  z.object({
    manager: z.literal("gcp"),
    privateKeySecretId: z.string(),
    projectId: z.string(),
  }),
]);

const listerQuery = z.object({
  type: z.literal("repository"),
  context: z.object({
    appId: z.string(),
    secrets: appPrivateKey,
  }),
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

const requestContext = z.object({
  requestId: z.string(),
  appId: z.string(),
  secrets: appPrivateKey,
});

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

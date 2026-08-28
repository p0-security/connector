import type { AnyRouter } from "@trpc/server";
import {
  type FetchCreateContextFnOptions,
  fetchRequestHandler,
} from "@trpc/server/adapters/fetch";
import type { JsonValue } from "type-fest";
import { z } from "zod";

import { toSerialized } from "./headers.ts";

const CloudFunctionInputSchema = z.object({
  url: z.string(),
  body: z.string().optional(),
  method: z.string(),
  headers: z.record(z.string(), z.string()),
});

export const CloudFunctionOutputSchema = z.object({
  body: z.unknown(),
  status: z.number(),
  statusText: z.string(),
  headers: z.record(z.string(), z.array(z.string())),
});

/**
 * Cloud function input parameters.
 * @summary Cloud function input parameters.
 * @category Cloud Functions
 */
export type CloudFunctionInput = z.infer<typeof CloudFunctionInputSchema>;

/**
 * Cloud function outputs.
 * @summary Cloud function outputs.
 * @category Cloud Functions
 */
export type CloudFunctionOutput = z.infer<typeof CloudFunctionOutputSchema>;

/**
 * Creates a new cloud function handler that routes requests through a tRPC router.
 * @summary Creates a new cloud function handler that routes requests through a tRPC router.
 * @category Cloud Functions
 *
 * @param router The tRPC router to handle incoming requests from the cloud function.
 * @returns A function that can be used as a cloud function handler, which unpacks incoming
 *          requests and routes them through the provided tRPC router.
 */
export const newCloudFunction = <T>(
  router: AnyRouter,
  createContext?: (opts: FetchCreateContextFnOptions) => Promise<T>
): ((input: unknown) => Promise<CloudFunctionOutput>) => {
  return async (input) => {
    const { url, body, method, headers } =
      CloudFunctionInputSchema.parse(input);
    const res = await fetchRequestHandler({
      endpoint: "/trpc",
      req: new Request(url, { method, body, headers }),
      router,
      createContext,
    });
    return {
      body: (await res.json()) as JsonValue,
      status: res.status,
      statusText: res.statusText,
      headers: toSerialized(res.headers),
    };
  };
};

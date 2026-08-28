import type { TRPCLink } from "@trpc/client";
import { httpLink } from "@trpc/client";
import type { AnyRouter } from "@trpc/server";
import { z } from "zod";

import {
  type CloudFunctionInput,
  CloudFunctionOutputSchema,
} from "./function.ts";
import { fromSerialized } from "./headers.ts";

/**
 * A client to invoke cloud functions with structured input parameters.
 * @summary A client to invoke cloud functions with structured input parameters.
 * @category Cloud Functions
 *
 * @param input The structured input parameters for the cloud function, including URL, body, method, and headers.
 * @param signal An optional AbortSignal to cancel the cloud function invocation.
 * @returns A promise that resolves to an ArrayBuffer containing the response from the cloud function.
 */
export type CloudFunctionClient = (
  input: string,
  signal?: AbortSignal
) => Promise<ArrayBuffer>;

const fetchArgsSchema = z.tuple([
  z.string(),
  z.object({
    body: z.string().optional(),
    method: z.string(),
    headers: z.record(z.string(), z.string()),
    signal: z.instanceof(AbortSignal).optional(),
  }),
] as const);

/**
 * Creates a new tRPC link that allows tRPC clients to hit cloud functions.
 *
 * @summary Creates a new tRPC link that allows tRPC clients to hit cloud functions.
 * @category Cloud Functions
 *
 * @param func The cloud function client to invoke the cloud function.
 * @param headers Optional headers to include in the cloud function invocation.
 * @returns A client that invokes the cloud function.
 */
export const newCloudFunctionLink = (
  func: CloudFunctionClient,
  headers?: Record<string, string>
): TRPCLink<AnyRouter> =>
  httpLink({
    // This base URL doesn't matter - only the path needs to be correct w.r.t.
    // the `fetchRequestHandler` in the cloud function.
    url: "https://example.com/trpc",
    headers,
    fetch: async (...args) => {
      const { data, error } = fetchArgsSchema.safeParse(args);
      if (error) {
        throw new Error(
          `Invalid arguments provided to newCloudFunctionLink.fetch: ${error.message}`,
          { cause: error }
        );
      }

      const [url, { body, method, headers, signal }] = data;

      const obj: CloudFunctionInput = {
        url,
        body,
        method,
        headers,
      };

      const res = await func(JSON.stringify(obj), signal ?? undefined);
      const output = CloudFunctionOutputSchema.parse(
        JSON.parse(new TextDecoder().decode(res))
      );

      return new Response(JSON.stringify(output.body), {
        status: output.status,
        statusText: output.statusText,
        headers: fromSerialized(output.headers),
      });
    },
  });

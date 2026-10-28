import { z } from "zod";

// What an error may say about itself, across Node, the AWS SDK and Google's
// client. A field of the wrong type reads as absent.
const failure = z.object({
  name: z.string().optional().catch(undefined),
  code: z.union([z.string(), z.number()]).optional().catch(undefined),
  status: z.number().optional().catch(undefined),
  $metadata: z
    .object({
      httpStatusCode: z.number().optional().catch(undefined),
      requestId: z.string().optional().catch(undefined),
    })
    .optional()
    .catch(undefined),
});

/** The fields of a failure that are safe to log and to act on. */
export type FailureFacts = {
  /** The error's name, unless it is the bare `Error`. */
  name?: string;
  /** Node's or an SDK's code for it, such as `ENOTFOUND`. */
  code?: number | string;
  /** The HTTP status it was answered with. */
  status?: number;
  /** AWS's id for the request, which its support can look up. */
  requestId?: string;
};

/**
 * What a failure says about itself, short of its message. The message, the
 * stack and whatever else it carries are left behind, because nothing
 * promises they are free of the request that failed: a secret's id, the
 * request's URL, or a header.
 */
export const failureFacts = (error: unknown): FailureFacts => {
  const parsed = failure.safeParse(error);
  if (!parsed.success) return {};
  const { name, code, status, $metadata } = parsed.data;
  return {
    ...(name !== undefined && name !== "Error" ? { name } : {}),
    ...(code !== undefined ? { code } : {}),
    ...(status !== undefined || $metadata?.httpStatusCode !== undefined
      ? { status: status ?? $metadata?.httpStatusCode }
      : {}),
    ...($metadata?.requestId !== undefined
      ? { requestId: $metadata.requestId }
      : {}),
  };
};

/**
 * A failure in a few words, for a message a person reads: its code, or else
 * its name, and the HTTP status when it has one. `undefined` when it says
 * nothing about itself.
 */
export const describeFailure = (error: unknown): string | undefined => {
  const { name, code, status } = failureFacts(error);
  const parts = [
    typeof code === "string" ? code : name,
    status !== undefined ? `HTTP ${status}` : undefined,
  ].filter((part) => part !== undefined);
  return parts.length > 0 ? parts.join(", ") : undefined;
};

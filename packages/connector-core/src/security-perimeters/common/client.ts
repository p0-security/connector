import { TRPCClientError } from "@trpc/client";

export const action =
  <T, F extends (...args: any[]) => Promise<T>>(
    func: F,
    parser: (val: unknown) => T
  ) =>
  async (...data: Parameters<F>): Promise<T> => {
    try {
      const raw = await func(...data);
      return parser(raw);
    } catch (error: unknown) {
      if (error instanceof TRPCClientError) {
        // Note: If a ConnectorError is thrown on the lambda/cloud function
        // then error.cause will be undefined here, causing the TRPCClientError
        // to be re-thrown. Error.cause will be populated if the error happens on the
        // client-side (e.g. a JSON-deserialization issue), rather than an error
        // thrown on the server
        if (error.cause) throw error.cause;
      }
      throw error;
    }
  };

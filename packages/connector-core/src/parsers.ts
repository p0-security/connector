/**
 * A parser to parse an unknown JS Object into a specific type T.
 *
 * @summary A parser to parse an unknown JS Object into a specific type T.
 * @category Types
 *
 * @typeParam T The type to parse the JS Object into.
 * @param json The unknown JS Object to parse. This should *not* be a serialized JSON string!
 * @returns The parsed object of type T.
 */
export type JSONParser<T> = (json: unknown) => T;

/**
 * Extracts the parameter type of a one-argument function.
 *
 * @summary Extracts the parameter type of a one-argument function.
 * @category Types
 * @internal
 *
 * @typeParam T The function type to extract the parameter type from.
 */
export type OneArgFuncParameter<T> = T extends (arg: infer A) => unknown
  ? A
  : never;

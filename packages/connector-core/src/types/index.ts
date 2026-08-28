export const isDefined = <T>(value: T): value is NonNullable<T> =>
  value !== undefined && value !== null;

/**
 * Signals that a value the type system proved unreachable was nevertheless
 * received at runtime — an exhaustive `switch` fell through to its `default`.
 *
 * Returns the error rather than throwing so that call sites can `throw
 * throwAssertNever(value)`, which TypeScript recognizes as terminating.
 */
export const throwAssertNever = (value: never): Error =>
  new Error(`Unexpected value - should be never: ${String(value)}`);

export type SerializedHeaders = Record<string, string[]>;

/**
 * Converts response headers to a representation that can cross a
 * network boundary
 *
 * @param headers A Headers object
 * @returns A JSON-serializable representation of the Headers object
 */
export const toSerialized = (headers: Headers): SerializedHeaders => {
  const object: SerializedHeaders = {};

  for (const [key, value] of headers) {
    object[key] = object[key] ? [...object[key], value] : [value];
  }

  return object;
};

/**
 * Converts a JSON-serialized representation of Headers back
 * into its original form
 *
 * @param serializedHeaders A JSON-serializable representation of Headers
 * @returns The Headers object
 */
export const fromSerialized = (
  serializedHeaders: SerializedHeaders
): Headers => {
  const h = new Headers();
  for (const [key, values] of Object.entries(serializedHeaders)) {
    for (const v of values) {
      h.append(key, v);
    }
  }
  return h;
};

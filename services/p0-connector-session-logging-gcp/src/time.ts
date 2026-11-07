/**
 * Timestamps compared to the nanosecond. Cloud Audit Logs carry microsecond
 * timestamps and the query window may too, but `Date.parse` keeps only
 * milliseconds, so an entry a few microseconds before an exclusive end could
 * compare equal to it and be dropped.
 */

/** An ISO 8601 timestamp, with any offset, as nanoseconds since the epoch;
 * undefined when it can't be read. */
export const preciseTime = (iso: string | undefined): bigint | undefined => {
  if (iso === undefined) return undefined;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return undefined;
  // Date.parse has the offset and the first three fraction digits; the
  // next six are the nanoseconds within the millisecond.
  const fraction = /T[\d:]+\.(\d+)/.exec(iso)?.[1] ?? "";
  const subMs = fraction.slice(3, 9).padEnd(6, "0");
  return BigInt(ms) * 1_000_000n + BigInt(subMs);
};

/** `[start, end)`, in nanoseconds since the epoch. */
export type PreciseWindow = { start: bigint; end: bigint };

/** A query's window, to the nanosecond. */
export const preciseWindow = (window: {
  start: string;
  end: string;
}): PreciseWindow => ({
  start: preciseTime(window.start)!,
  end: preciseTime(window.end)!,
});

/** Whether a timestamp falls in `[start, end)`. */
export const inWindow = (iso: string | undefined, window: PreciseWindow) => {
  const time = preciseTime(iso);
  return time !== undefined && time >= window.start && time < window.end;
};

import type {
  ListEntriesRequest,
  ListEntriesResponse,
  LoggingDependencies,
} from "../logging.ts";

export const NOW = Date.parse("2026-11-01T14:00:00Z");

/**
 * Cloud Logging for tests: `answer` gets each `entries.list` request (and
 * the signal that aborts it) and returns a page, or throws (`{ status: 429 }`
 * for throttling). Waiting advances the clock instead of sleeping.
 */
export const fakeLogging = (
  answer: (
    request: ListEntriesRequest,
    signal: AbortSignal | undefined
  ) => ListEntriesResponse | Promise<ListEntriesResponse>
) => {
  let clock = NOW;
  const requests: ListEntriesRequest[] = [];
  const dependencies: LoggingDependencies = {
    listEntries: async (request, signal) => {
      requests.push(request);
      return answer(request, signal);
    },
    now: () => clock,
    wait: async (ms) => {
      clock += ms;
    },
  };
  return {
    dependencies,
    requests,
    advance: (ms: number) => {
      clock += ms;
    },
  };
};

/** A request that never answers until its signal aborts it. */
export const hang = (signal: AbortSignal | undefined) =>
  new Promise<never>((_, reject) => {
    signal?.addEventListener("abort", () =>
      reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
    );
  });

export const throttled = () =>
  Object.assign(new Error("Quota exceeded"), { status: 429 });

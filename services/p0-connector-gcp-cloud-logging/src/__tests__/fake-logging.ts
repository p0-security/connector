import type {
  ListEntriesRequest,
  ListEntriesResponse,
  LoggingDependencies,
} from "../logging.ts";

export const NOW = Date.parse("2026-11-01T14:00:00Z");

/**
 * Cloud Logging for tests: `answer` gets each `entries.list` request and
 * returns a page, or throws (`{ status: 429 }` for throttling). Waiting
 * advances the clock instead of sleeping.
 */
export const fakeLogging = (
  answer: (request: ListEntriesRequest) => ListEntriesResponse
) => {
  let clock = NOW;
  const requests: ListEntriesRequest[] = [];
  const dependencies: LoggingDependencies = {
    listEntries: async (request) => {
      requests.push(request);
      return answer(request);
    },
    now: () => clock,
    wait: async (ms) => {
      clock += ms;
    },
  };
  return { dependencies, requests };
};

export const throttled = () =>
  Object.assign(new Error("Quota exceeded"), { status: 429 });

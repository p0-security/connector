/**
 * Generated inputs for property tests.
 *
 * The repo has no property-testing library, so this is the least that does
 * the job: a seeded random source, and a runner that names the seed and the
 * input of the first run that fails.
 *
 * Each test file takes its seed once, when it is imported, from `FUZZ_SEED`
 * or else from the clock. Vitest's retries then replay the same inputs, and
 * cannot hide a failure behind new ones. To replay a failure, run the file
 * again with the seed it printed: `FUZZ_SEED=<seed> yarn :test <file>`.
 */
import { inspect } from "node:util";

export type Random = {
  /** A number in [0, 1) */
  next: () => number;
  /** An integer in [min, max] */
  int: (min: number, max: number) => number;
  chance: (probability: number) => boolean;
  pick: <T>(items: readonly T[]) => T;
  /** A string of `length` characters, each picked from `alphabet` */
  string: (alphabet: readonly string[], length: number) => string;
};

/** mulberry32: small, fast, and good enough to pick test inputs. */
const mulberry32 = (seed: number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

export const newRandom = (seed: number): Random => {
  const next = mulberry32(seed);
  const int = (min: number, max: number) =>
    min + Math.floor(next() * (max - min + 1));
  const pick = <T>(items: readonly T[]) => items[int(0, items.length - 1)];
  return {
    next,
    int,
    chance: (probability) => next() < probability,
    pick,
    string: (alphabet, length) =>
      Array.from({ length }, () => pick(alphabet)).join(""),
  };
};

/** The seed for a test file. Call it once, at the top of the file. */
export const fileSeed = () => {
  const fromEnv = Number(process.env.FUZZ_SEED);
  return Number.isInteger(fromEnv)
    ? fromEnv
    : Math.floor(Math.random() * 2 ** 31);
};

/**
 * Runs `check` on `runs` generated inputs, and counts the label that each run
 * returns, so that a test can show that every branch was reached.
 *
 * @throws The first failure, with the seed and the input that caused it
 */
export const forAll = async <T>(
  seed: number,
  runs: number,
  generate: (random: Random) => T,
  check: (input: T) => Promise<string> | string
): Promise<Record<string, number>> => {
  const random = newRandom(seed);
  const counts: Record<string, number> = {};
  for (let run = 0; run < runs; run++) {
    const input = generate(random);
    let label: string;
    try {
      label = await check(input);
    } catch (error) {
      throw new Error(
        `Failed with FUZZ_SEED=${seed}, run ${run}, input ${inspect(input)}: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error }
      );
    }
    counts[label] = (counts[label] ?? 0) + 1;
  }
  return counts;
};

/** Characters that tend to break parsers, URLs, headers and logs. */
export const AWKWARD_CHARACTERS = [
  "",
  " ",
  "\t",
  "\n",
  "\r",
  "\u0000",
  "\u001b",
  "\u007f",
  "\u0085",
  "\u00a0",
  "\u2028",
  "\u2029",
  "\ufeff",
  "%",
  "_",
  "%25",
  "%0a",
  "/",
  "\\",
  ".",
  "..",
  ":",
  "@",
  "#",
  "?",
  "&",
  "=",
  '"',
  "'",
  "<",
  "{",
  "}",
  "é",
  "É",
  "ß",
  "İ",
  "秘",
  "😀",
];

const LETTERS = [..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"];
const DIGITS = [..."0123456789"];

/** Mostly plain ASCII, sometimes with awkward characters in it. */
export const anyString = (random: Random, maxLength = 12) =>
  Array.from({ length: random.int(0, maxLength) }, () =>
    random.chance(0.15)
      ? random.pick(AWKWARD_CHARACTERS)
      : random.pick([...LETTERS, ...DIGITS, "-", "_"])
  ).join("");

/** Any JSON value, nested up to `depth`, with keys drawn from `keys` most of
 * the time. */
export const anyJson = (
  random: Random,
  keys: readonly string[] = [],
  depth = 2
): unknown => {
  const kind = random.int(0, depth > 0 ? 7 : 4);
  switch (kind) {
    case 0:
      return null;
    case 1:
      return random.chance(0.5);
    case 2:
      return random.pick([0, 1, -1, 42, 1.5, 2 ** 53, -0]);
    case 3:
    case 4:
      return anyString(random);
    case 5:
      return Array.from({ length: random.int(0, 3) }, () =>
        anyJson(random, keys, depth - 1)
      );
    default:
      return Object.fromEntries(
        Array.from({ length: random.int(0, 4) }, () => [
          keys.length > 0 && random.chance(0.8)
            ? random.pick(keys)
            : anyString(random, 6),
          anyJson(random, keys, depth - 1),
        ])
      );
  }
};

/**
 * Starts from a value of the right shape and, most of the time, breaks it a
 * little: drops a field, changes one to any other JSON value, adds one, or
 * replaces the whole value. So both a parser's accept and refuse branches are
 * reached often.
 */
export const mutateJson = (
  random: Random,
  valid: unknown,
  keys: readonly string[] = []
): unknown => {
  if (random.chance(0.35)) return valid;
  if (random.chance(0.15)) return anyJson(random, keys);
  if (Array.isArray(valid)) {
    if (valid.length === 0 || random.chance(0.2)) {
      return [...valid, anyJson(random, keys)];
    }
    const index = random.int(0, valid.length - 1);
    return valid.map((item, i) =>
      i === index ? mutateJson(random, item, keys) : item
    );
  }
  if (valid !== null && typeof valid === "object") {
    const entries = Object.entries(valid);
    const action = random.int(0, 2);
    if (action === 0 && entries.length > 0) {
      const drop = random.int(0, entries.length - 1);
      return Object.fromEntries(entries.filter((_, i) => i !== drop));
    }
    if (action === 1 && entries.length > 0) {
      const change = random.int(0, entries.length - 1);
      return Object.fromEntries(
        entries.map(([key, value], i) =>
          i === change ? [key, mutateJson(random, value, keys)] : [key, value]
        )
      );
    }
    return {
      ...valid,
      [keys.length > 0 ? random.pick(keys) : anyString(random, 6)]: anyJson(
        random,
        keys
      ),
    };
  }
  return anyJson(random, keys);
};

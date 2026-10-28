import type { Options } from "yargs";
import { z } from "zod";

export const yargsOptionsFromSchema = (
  schema: z.ZodTypeAny
): Record<string, Options> => {
  if (schema instanceof z.ZodIntersection) {
    const left = yargsOptionsFromSchema(schema.def.left as z.ZodTypeAny);
    const right = yargsOptionsFromSchema(schema.def.right as z.ZodTypeAny);
    const duplicates = Object.keys(left).filter((k) => k in right);
    if (duplicates.length > 0) {
      throw new Error(
        `Duplicate option keys in schema intersection: ${duplicates.join(", ")}`
      );
    }
    return { ...left, ...right };
  }
  if (schema instanceof z.ZodXor) {
    // Each xor branch contributes its own options. No individual field is
    // demandOption since the constraint spans fields; zod enforces it at parse time.
    const merged: Record<string, Options> = {};
    for (const branch of schema.def.options as z.ZodTypeAny[]) {
      for (const [key, opt] of Object.entries(yargsOptionsFromSchema(branch))) {
        merged[key] = { ...opt, demandOption: false };
      }
    }
    return merged;
  }
  if (!(schema instanceof z.ZodObject)) return {};
  const result: Record<string, Options> = {};
  for (const [key, raw] of Object.entries(schema.shape) as [
    string,
    z.ZodTypeAny,
  ][]) {
    const description = raw.description;
    let field: z.ZodTypeAny = raw;
    let defaultValue: unknown;
    let hasDefault = false;
    let isOptional = false;

    if (field instanceof z.ZodDefault) {
      defaultValue = field.def.defaultValue;
      hasDefault = true;
      field = field.def.innerType as unknown as z.ZodTypeAny;
    }
    if (field instanceof z.ZodOptional) {
      isOptional = true;
      field = field.def.innerType as unknown as z.ZodTypeAny;
    }

    let type: Options["type"] = "string";
    let array = false;
    if (field instanceof z.ZodNumber) type = "number";
    else if (field instanceof z.ZodBoolean) type = "boolean";
    else if (field instanceof z.ZodArray) {
      array = true;
      const el = field.element as unknown as z.ZodTypeAny;
      if (el instanceof z.ZodNumber) type = "number";
      else if (el instanceof z.ZodBoolean) type = "boolean";
    }

    result[key] = {
      type,
      ...(array && { array: true }),
      ...(description !== undefined && { description }),
      ...(hasDefault && { default: defaultValue }),
      demandOption: !hasDefault && !isOptional,
    };
  }
  return result;
};

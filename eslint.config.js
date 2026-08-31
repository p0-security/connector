import js from "@eslint/js";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig([
  globalIgnores(["**/dist/**", "**/node_modules/**", "**/*.tsbuildinfo"]),
  {
    name: "Parser and language options",
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {
        // Every linted package has a tsconfig, so type-aware linting can
        // resolve each file to its project automatically.
        projectService: true,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
  },
  {
    name: "Universal JS/TS Config",
    files: ["packages/*/src/**"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommendedTypeChecked,
      eslintConfigPrettier,
    ],
    rules: {
      "no-inner-declarations": "off",
      "require-yield": "off",

      // Require === / !== so loose-equality slips (e.g. `!=` for `!==`) fail lint.
      eqeqeq: ["error", "always"],

      "no-duplicate-imports": ["error", { allowSeparateTypeImports: true }],
      "@typescript-eslint/consistent-type-imports": [
        "warn",
        { fixStyle: "separate-type-imports", prefer: "type-imports" },
      ],
      "@typescript-eslint/no-import-type-side-effects": "error",

      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/prefer-promise-reject-errors": "off",
      "@typescript-eslint/only-throw-error": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",

      "@typescript-eslint/restrict-template-expressions": [
        "warn",
        {
          allowNumber: true,
          allowNullish: true,
          allowBoolean: true,
        },
      ],

      "@typescript-eslint/require-await": "off",

      "@typescript-eslint/sort-type-constituents": [
        "warn",
        { checkIntersections: false },
      ],

      "@typescript-eslint/unbound-method": "off",
      "no-console": "warn",
    },
  },
  {
    name: "Universal TS/JS Rules",
    files: ["packages/*/src/**"],
    rules: {
      // Explicit any should be used judiciously to avoid undue wrestling with TS
      "@typescript-eslint/no-explicit-any": "off",
      // no-empty-function is just pedantic
      "@typescript-eslint/no-empty-function": "off",
      // We may want to improve namespaces at some point, but at this juncture
      // they make our type system more readable
      "@typescript-eslint/no-namespace": "off",

      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_.*",
          varsIgnorePattern: "^_.*",
          caughtErrorsIgnorePattern: "^(_.*|error|err)",
          destructuredArrayIgnorePattern: "^_.*",
          ignoreRestSiblings: true,
        },
      ],
    },
  },
]);

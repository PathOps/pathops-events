import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", ".npm-cache/"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  // A leading underscore marks a parameter a signature requires but the body does not use.
  { rules: { "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }] } },
);

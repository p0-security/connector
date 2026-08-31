/** @type {import('prettier').Config} */
export default {
  plugins: ["@trivago/prettier-plugin-sort-imports"],
  importOrder: ["^(cli|testing)([/]|$)", "^[.][.]?([/]|$)"],
  importOrderSeparation: true,
  importOrderSortSpecifiers: true,
  trailingComma: "es5",
};

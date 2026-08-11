const FORMULA_PREFIX = /^[\u0000-\u0020]*[=+\-@]/;
const CONTROL_PREFIX = /^[\t\r]/;

export function csvCell(value) {
  const text = typeof value === "string" ? neutralizeSpreadsheetFormula(value) : String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function neutralizeSpreadsheetFormula(value) {
  const text = String(value ?? "");
  return FORMULA_PREFIX.test(text) || CONTROL_PREFIX.test(text) ? `'${text}` : text;
}

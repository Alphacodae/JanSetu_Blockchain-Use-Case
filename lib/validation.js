function bad(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  throw error;
}

function requiredText(value, field, maxBytes = 120) {
  if (typeof value !== "string") return bad(`${field} must be text.`);
  const result = value.normalize("NFKC").trim();
  if (!result || Buffer.byteLength(result, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/.test(result)) return bad(`${field} is required and must be at most ${maxBytes} bytes.`);
  return result;
}

function parcelId(value) {
  const result = requiredText(value, "Parcel ID", 40).toUpperCase();
  if (!/^[A-Z0-9][A-Z0-9._-]{2,39}$/.test(result)) return bad("Parcel ID must use 3–40 letters, numbers, dot, underscore or hyphen.");
  return result;
}

function ownerName(value) { return requiredText(value, "Owner name", 100); }
function villageName(value) { return requiredText(value, "Village / district", 120); }

function documentReference(value) {
  const result = requiredText(value, "Off-chain document reference", 120);
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{2,119}$/.test(result)) return bad("Document reference may contain letters, numbers, dot, underscore, slash or hyphen.");
  return result;
}

function areaAcres(value) {
  const result = Number(value);
  if (!Number.isFinite(result) || result <= 0 || result > 100000 || !/^\d{1,6}(\.\d{1,4})?$/.test(String(value))) return bad("Area must be between 0 and 100,000 acres, with up to four decimal places.");
  return result;
}

function beneficiaryReference(value) {
  const result = requiredText(value, "Synthetic beneficiary reference", 80).toUpperCase();
  if (/^\d{10,16}$/.test(result)) return bad("Use a synthetic beneficiary reference, not a real identity number.");
  if (!/^[A-Z0-9][A-Z0-9-]{5,79}$/.test(result)) return bad("Beneficiary reference must be a synthetic code using letters, numbers and hyphens.");
  return result;
}

function cycle(value) {
  const input = requiredText(value, "Distribution cycle", 20).toUpperCase();
  const named = /^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-(20\d{2})$/.exec(input);
  if (named) return `${named[2]}-${String(["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"].indexOf(named[1]) + 1).padStart(2,"0")}`;
  if (/^20\d{2}-(0[1-9]|1[0-2])$/.test(input)) return input;
  return bad("Cycle must be YYYY-MM.");
}

function validDays(value) {
  const days = Number(value ?? 90);
  if (!Number.isInteger(days) || days < 1 || days > 365) return bad("Claim validity must be between 1 and 365 days.");
  return days;
}

function department(value) {
  if (value !== "land" && value !== "survey") return bad("Choose land or survey department.");
  return value;
}

function page(value, defaultValue = 50, max = 100) {
  if (value === undefined) return defaultValue;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) return bad(`Page size must be between 1 and ${max}.`);
  return n;
}

function offset(value) {
  if (value === undefined) return 0;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0 || n > 1000000) return bad("Page offset is invalid.");
  return n;
}

module.exports = { requiredText, parcelId, ownerName, villageName, documentReference, areaAcres, beneficiaryReference, cycle, validDays, department, page, offset, bad };

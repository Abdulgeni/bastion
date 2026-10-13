/** Splits a Node `subjectaltname` string on top-level commas, honouring JSON-style quoting. */
function splitEntries(san: string): string[] {
  const entries: string[] = [];
  let current = '';
  let inQuotes = false;
  let escaped = false;
  for (const ch of san) {
    if (escaped) {
      current += ch;
      escaped = false;
    } else if (inQuotes && ch === '\\') {
      current += ch;
      escaped = true;
    } else if (ch === ',' && !inQuotes) {
      entries.push(current.trim());
      current = '';
    } else {
      if (ch === '"') inQuotes = !inQuotes;
      current += ch;
    }
  }
  entries.push(current.trim());
  return entries.filter((e) => e.length > 0);
}

function unquote(value: string): string | undefined {
  if (!value.startsWith('"')) return value;
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === 'string' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Returns every URI SAN in a Node `subjectaltname` string. Quoted values (which
 * Node uses for entries containing special characters) are decoded, so a DNS SAN
 * that merely contains the text "URI:" can never be mistaken for a URI entry.
 */
export function extractUriSans(san: string | undefined): string[] {
  if (typeof san !== 'string' || san.length === 0) return [];
  const uris: string[] = [];
  for (const entry of splitEntries(san)) {
    if (!entry.startsWith('URI:')) continue;
    const value = unquote(entry.slice('URI:'.length));
    if (value !== undefined) uris.push(value);
  }
  return uris;
}

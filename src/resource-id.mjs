const RESOURCE_TYPES = new Set(['memo', 'instructor-announcement']);

/** Create a stable, type-qualified ID without changing the underlying database ID. */
export function createResourceId(type, id) {
  if (!RESOURCE_TYPES.has(type)) throw new TypeError('지원하지 않는 자원 종류입니다.');
  if (typeof id !== 'string' || id.length === 0) throw new TypeError('자원 ID는 비어 있을 수 없습니다.');
  return `${type}:${encodeURIComponent(id)}`;
}

/** Parse a type-qualified resource ID. Returns null for unknown or malformed IDs. */
export function parseResourceId(value) {
  if (typeof value !== 'string') return null;
  const separator = value.indexOf(':');
  if (separator < 1) return null;

  const type = value.slice(0, separator);
  if (!RESOURCE_TYPES.has(type)) return null;

  try {
    const id = decodeURIComponent(value.slice(separator + 1));
    if (!id) return null;
    return { type, id };
  } catch {
    return null;
  }
}

/** Accept old bare note IDs for existing links, but never treat another typed ID as a memo. */
export function parseMemoResourceId(value) {
  if (typeof value !== 'string' || !value) return null;

  // Some routers expose the path parameter with its type separator still percent-encoded.
  if (/^(?:memo|instructor-announcement)%3a/iu.test(value)) {
    try {
      return parseMemoResourceId(decodeURIComponent(value));
    } catch {
      return null;
    }
  }

  const parsed = parseResourceId(value);
  if (parsed) return parsed.type === 'memo' ? parsed : null;
  if (value.includes(':')) return null;
  return { type: 'memo', id: value };
}

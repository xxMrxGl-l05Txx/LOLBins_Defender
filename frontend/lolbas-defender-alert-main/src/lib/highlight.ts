export interface TextPart {
  text: string;
  match: boolean;
}

/** Split text into matched / unmatched parts for case-insensitive pattern highlighting */
export function highlightParts(text: string, patterns: string[]): TextPart[] {
  const lower = text.toLowerCase();
  const ranges: Array<[number, number]> = [];

  for (const raw of patterns) {
    const pattern = raw.toLowerCase();
    if (!pattern) continue;
    let index = lower.indexOf(pattern);
    while (index !== -1) {
      ranges.push([index, index + pattern.length]);
      index = lower.indexOf(pattern, index + pattern.length);
    }
  }

  if (ranges.length === 0) {
    return [{ text, match: false }];
  }

  ranges.sort((a, b) => a[0] - b[0]);
  const merged: Array<[number, number]> = [];
  for (const [start, end] of ranges) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      merged.push([start, end]);
    }
  }

  const parts: TextPart[] = [];
  let cursor = 0;
  for (const [start, end] of merged) {
    if (start > cursor) parts.push({ text: text.slice(cursor, start), match: false });
    parts.push({ text: text.slice(start, end), match: true });
    cursor = end;
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), match: false });
  return parts;
}

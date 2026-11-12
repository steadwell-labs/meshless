/**
 * Strict JSON and RFC 8785 canonicalization.
 *
 * MLP/1 §10.1 requires a parser that rejects duplicate members, invalid UTF-8,
 * non-finite numbers, and integers outside the safe range. `JSON.parse` accepts
 * all four, silently, so this module carries its own parser. It is small enough
 * to read in one sitting and that is the point: every implementation of MLP/1
 * has to agree on this behaviour byte for byte.
 *
 * §10.2 then requires signatures over the canonical form, and requires a
 * verifier to reject a payload that is not already canonical. `assertCanonical`
 * is that check.
 */

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

const MAX_DEPTH = 64;

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class JsonError extends Error {
  readonly offset: number;
  constructor(message: string, offset: number) {
    super(`${message} at offset ${offset}`);
    this.name = 'JsonError';
    this.offset = offset;
  }
}

/** Decode bytes as UTF-8, failing on any malformed sequence. */
export function decodeUtf8Strict(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
}

/**
 * Parse JSON with MLP/1 rules. Accepts a string or UTF-8 bytes.
 * Throws `JsonError` on any deviation, including a trailing newline.
 */
export function parseJsonStrict(input: string | Uint8Array): JsonValue {
  const text = typeof input === 'string' ? input : decodeUtf8Strict(input);
  const parser = new Parser(text);
  return parser.parseDocument();
}

class Parser {
  private index = 0;
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
    if (text.charCodeAt(0) === 0xfeff) throw new JsonError('byte order mark is not permitted', 0);
  }

  parseDocument(): JsonValue {
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) throw new JsonError('unexpected trailing content', this.index);
    return value;
  }

  private skipWhitespace(): void {
    const { text } = this;
    while (this.index < text.length) {
      const code = text.charCodeAt(this.index);
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) this.index += 1;
      else break;
    }
  }

  private parseValue(depth: number): JsonValue {
    if (depth > MAX_DEPTH) throw new JsonError('maximum nesting depth exceeded', this.index);
    this.skipWhitespace();
    if (this.index >= this.text.length) throw new JsonError('unexpected end of input', this.index);
    const char = this.text[this.index]!;
    switch (char) {
      case '{':
        return this.parseObject(depth + 1);
      case '[':
        return this.parseArray(depth + 1);
      case '"':
        return this.parseString();
      case 't':
        return this.literal('true', true);
      case 'f':
        return this.literal('false', false);
      case 'n':
        return this.literal('null', null);
      default:
        if (char === '-' || (char >= '0' && char <= '9')) return this.parseNumber();
        throw new JsonError(`unexpected character ${JSON.stringify(char)}`, this.index);
    }
  }

  private literal<T extends JsonValue>(word: string, value: T): T {
    if (this.text.slice(this.index, this.index + word.length) !== word) {
      throw new JsonError(`expected ${word}`, this.index);
    }
    this.index += word.length;
    return value;
  }

  private parseObject(depth: number): JsonObject {
    const result: JsonObject = {};
    const seen = new Set<string>();
    this.index += 1; // {
    this.skipWhitespace();
    if (this.text[this.index] === '}') {
      this.index += 1;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') throw new JsonError('expected member name', this.index);
      const key = this.parseString();
      if (seen.has(key)) throw new JsonError(`duplicate member ${JSON.stringify(key)}`, this.index);
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ':') throw new JsonError('expected ":"', this.index);
      this.index += 1;
      result[key] = this.parseValue(depth);
      this.skipWhitespace();
      const delimiter = this.text[this.index];
      if (delimiter === ',') {
        this.index += 1;
        continue;
      }
      if (delimiter === '}') {
        this.index += 1;
        return result;
      }
      throw new JsonError('expected "," or "}"', this.index);
    }
  }

  private parseArray(depth: number): JsonValue[] {
    const result: JsonValue[] = [];
    this.index += 1; // [
    this.skipWhitespace();
    if (this.text[this.index] === ']') {
      this.index += 1;
      return result;
    }
    for (;;) {
      result.push(this.parseValue(depth));
      this.skipWhitespace();
      const delimiter = this.text[this.index];
      if (delimiter === ',') {
        this.index += 1;
        continue;
      }
      if (delimiter === ']') {
        this.index += 1;
        return result;
      }
      throw new JsonError('expected "," or "]"', this.index);
    }
  }

  private parseString(): string {
    const { text } = this;
    this.index += 1; // opening quote
    let out = '';
    for (;;) {
      if (this.index >= text.length) throw new JsonError('unterminated string', this.index);
      const char = text.charCodeAt(this.index);
      if (char === 0x22) {
        this.index += 1;
        if (LONE_SURROGATE.test(out)) throw new JsonError('lone surrogate in string', this.index);
        return out;
      }
      if (char === 0x5c) {
        const escape = text[this.index + 1];
        switch (escape) {
          case '"':
            out += '"';
            this.index += 2;
            continue;
          case '\\':
            out += '\\';
            this.index += 2;
            continue;
          case '/':
            out += '/';
            this.index += 2;
            continue;
          case 'b':
            out += '\b';
            this.index += 2;
            continue;
          case 'f':
            out += '\f';
            this.index += 2;
            continue;
          case 'n':
            out += '\n';
            this.index += 2;
            continue;
          case 'r':
            out += '\r';
            this.index += 2;
            continue;
          case 't':
            out += '\t';
            this.index += 2;
            continue;
          case 'u': {
            const hex = text.slice(this.index + 2, this.index + 6);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JsonError('invalid unicode escape', this.index);
            out += String.fromCharCode(parseInt(hex, 16));
            this.index += 6;
            continue;
          }
          default:
            throw new JsonError('invalid escape sequence', this.index);
        }
      }
      if (char < 0x20) throw new JsonError('unescaped control character in string', this.index);
      out += text[this.index];
      this.index += 1;
    }
  }

  private parseNumber(): number {
    const start = this.index;
    const { text } = this;
    if (text[this.index] === '-') this.index += 1;
    if (text[this.index] === '0') {
      this.index += 1;
    } else if (text[this.index]! >= '1' && text[this.index]! <= '9') {
      while (this.index < text.length && text[this.index]! >= '0' && text[this.index]! <= '9') this.index += 1;
    } else {
      throw new JsonError('invalid number', this.index);
    }
    let isInteger = true;
    if (text[this.index] === '.') {
      isInteger = false;
      this.index += 1;
      if (!(text[this.index]! >= '0' && text[this.index]! <= '9')) throw new JsonError('invalid fraction', this.index);
      while (this.index < text.length && text[this.index]! >= '0' && text[this.index]! <= '9') this.index += 1;
    }
    if (text[this.index] === 'e' || text[this.index] === 'E') {
      isInteger = false;
      this.index += 1;
      if (text[this.index] === '+' || text[this.index] === '-') this.index += 1;
      if (!(text[this.index]! >= '0' && text[this.index]! <= '9')) throw new JsonError('invalid exponent', this.index);
      while (this.index < text.length && text[this.index]! >= '0' && text[this.index]! <= '9') this.index += 1;
    }
    const raw = text.slice(start, this.index);
    const value = Number(raw);
    if (!Number.isFinite(value)) throw new JsonError('number is not finite', start);
    if (isInteger && !Number.isSafeInteger(value)) throw new JsonError('integer outside safe range', start);
    return value;
  }
}

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Members are sorted by UTF-16 code unit, numbers use ECMAScript
 * `Number::toString`, strings use JSON escaping, and no insignificant
 * whitespace is emitted. `-0` canonicalizes to `0`.
 */
export function canonicalize(value: JsonValue): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return canonicalNumber(value);
    case 'string':
      return canonicalString(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
      const keys = Object.keys(value).sort();
      const members: string[] = [];
      for (const key of keys) {
        const member = value[key]!;
        if (member === undefined) throw new JsonError(`undefined value for member ${JSON.stringify(key)}`, 0);
        members.push(`${canonicalString(key)}:${canonicalize(member)}`);
      }
      return `{${members.join(',')}}`;
    }
    default:
      throw new JsonError(`value of type ${typeof value} is not JSON`, 0);
  }
}

export function canonicalBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

function canonicalNumber(value: number): string {
  // RFC 8785 covers every finite double. The safe-integer rule in §10.1 is a
  // *parsing* rule: it rejects an integer token that cannot survive a round
  // trip, which is the only place the precision was already lost.
  if (!Number.isFinite(value)) throw new JsonError('number is not finite', 0);
  if (Object.is(value, -0)) return '0';
  return JSON.stringify(value);
}

function canonicalString(value: string): string {
  if (LONE_SURROGATE.test(value)) throw new JsonError('lone surrogate in string', 0);
  return JSON.stringify(value);
}

/**
 * Parse a signed payload and require it to already be in canonical form.
 *
 * Returns the decoded value on success. Rejects with `JsonError` when the bytes
 * are not canonical, which is what §10.2 requires of a verifier: otherwise the
 * same authority could be re-encoded to produce a different `parent` or
 * `grant_hash` while remaining signature-valid.
 */
export function assertCanonical(payloadBytes: Uint8Array): JsonValue {
  const value = parseJsonStrict(payloadBytes);
  const recanonicalized = canonicalBytes(value);
  const original = Buffer.from(payloadBytes.buffer, payloadBytes.byteOffset, payloadBytes.byteLength);
  if (!recanonicalized.equals(original)) {
    throw new JsonError('payload is not in RFC 8785 canonical form', 0);
  }
  return value;
}

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Read a required member with a shape check, throwing `invalid_request`-style errors. */
export function requireString(object: JsonObject, key: string, label = key): string {
  const value = object[key];
  if (typeof value !== 'string' || value.length === 0) throw new JsonError(`${label} must be a non-empty string`, 0);
  return value;
}

export function requireInteger(object: JsonObject, key: string, label = key): number {
  const value = object[key];
  if (typeof value !== 'number' || !Number.isInteger(value)) throw new JsonError(`${label} must be an integer`, 0);
  return value;
}

export function optionalObject(object: JsonObject, key: string): JsonObject | undefined {
  const value = object[key];
  if (value === undefined) return undefined;
  if (!isJsonObject(value)) throw new JsonError(`${key} must be an object`, 0);
  return value;
}

export function requireStringArray(object: JsonObject, key: string, label = key): string[] {
  const value = object[key];
  if (!Array.isArray(value) || value.length === 0) throw new JsonError(`${label} must be a non-empty array`, 0);
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) throw new JsonError(`${label} must contain strings`, 0);
    out.push(item);
  }
  return out;
}

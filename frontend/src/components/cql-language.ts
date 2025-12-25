import { StreamLanguage } from '@codemirror/language';
import { StreamParser } from '@codemirror/language';

// CQL keywords and operators
const keywords = new Set([
  'AND', 'OR', 'NOT', 'and', 'or', 'not',
  'in', 'IN',
  'contains', 'CONTAINS',
  'startswith', 'STARTSWITH', 'starts_with',
  'endswith', 'ENDSWITH', 'ends_with',
  'matches', 'MATCHES',
  'exists', 'EXISTS'
]);

// Operators for future reference (currently not used but may be needed for validation)
// const operators = new Set(['=', '!=', '>', '<', '>=', '<=']);

// CQL StreamParser
const cqlParser: StreamParser<unknown> = {
  token(stream) {
    // Skip whitespace
    if (stream.eatSpace()) return null;

    // Comments
    if (stream.match(/^#.*/)) return 'comment';

    // Strings
    if (stream.match(/^"([^"\\]|\\.)*"/)) return 'string';
    if (stream.match(/^'([^'\\]|\\.)*'/)) return 'string';

    // Numbers
    if (stream.match(/^[0-9]+(\.[0-9]+)?/)) return 'number';

    // Operators
    if (stream.match(/^(!=|>=|<=|>|<|=)/)) return 'operator';

    // Brackets
    if (stream.match(/^[()[\]{}]/)) return 'bracket';

    // Keywords and field names
    const word = stream.match(/^[a-zA-Z_][a-zA-Z0-9_.]*/)
    if (word) {
      const w = word[0];
      if (keywords.has(w)) return 'keyword';
      if (w.includes('.')) return 'propertyName'; // fields.* syntax
      return 'variableName';
    }

    // Fallback
    stream.next();
    return null;
  }
};

// Export CQL language support
export function cql() {
  return StreamLanguage.define(cqlParser);
}

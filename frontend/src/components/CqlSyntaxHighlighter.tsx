/**
 * CQL Syntax Highlighter Component
 *
 * Provides syntax highlighting for Cerberus Query Language (CQL) with
 * special emphasis on SIGMA field names.
 */

import React from 'react';
import { Box, styled } from '@mui/material';
import { resolveFieldAlias } from '../services/sigmaFields';

interface CqlSyntaxHighlighterProps {
  code: string;
  className?: string;
}

// Styled components for different syntax elements
const SyntaxContainer = styled('pre')(({ theme }) => ({
  fontFamily: 'Consolas, Monaco, "Courier New", monospace',
  fontSize: '0.875rem',
  lineHeight: 1.6,
  margin: 0,
  padding: theme.spacing(2),
  backgroundColor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5',
  borderRadius: theme.shape.borderRadius,
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word'
}));

const FieldName = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#9cdcfe' : '#0066cc', // Light blue
  fontWeight: 600
}));

const Operator = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#d4d4d4' : '#666666', // Gray
  fontWeight: 500
}));

const LogicalOperator = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#c586c0' : '#af00db', // Purple/Magenta
  fontWeight: 700
}));

const StringValue = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#ce9178' : '#a31515', // Orange/Red
}));

const NumberValue = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#b5cea8' : '#098658', // Green
}));

const Bracket = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#ffd700' : '#d4a300', // Gold
  fontWeight: 600
}));

const Parenthesis = styled('span')(({ theme }) => ({
  color: theme.palette.mode === 'dark' ? '#808080' : '#999999', // Gray
}));

/**
 * Token types for CQL syntax
 */
enum TokenType {
  FIELD = 'field',
  OPERATOR = 'operator',
  LOGICAL = 'logical',
  STRING = 'string',
  NUMBER = 'number',
  BRACKET = 'bracket',
  PARENTHESIS = 'parenthesis',
  WHITESPACE = 'whitespace',
  TEXT = 'text'
}

interface Token {
  type: TokenType;
  value: string;
  isSigmaField?: boolean;
}

/**
 * Tokenize CQL code
 */
function tokenizeCql(code: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  // CQL operators
  const operators = [
    'contains',
    'startswith',
    'endswith',
    'matches',
    'exists',
    'not exists',
    'not in',
    'in',
    '~=',
    '>=',
    '<=',
    '!=',
    '=',
    '>',
    '<'
  ];

  // Logical operators
  const logicalOperators = ['AND', 'OR', 'NOT'];

  while (i < code.length) {
    const char = code[i];

    // Whitespace
    if (/\s/.test(char)) {
      let ws = '';
      while (i < code.length && /\s/.test(code[i])) {
        ws += code[i];
        i++;
      }
      tokens.push({ type: TokenType.WHITESPACE, value: ws });
      continue;
    }

    // Parentheses
    if (char === '(' || char === ')') {
      tokens.push({ type: TokenType.PARENTHESIS, value: char });
      i++;
      continue;
    }

    // Brackets
    if (char === '[' || char === ']') {
      tokens.push({ type: TokenType.BRACKET, value: char });
      i++;
      continue;
    }

    // Quoted strings
    if (char === '"' || char === "'") {
      const quote = char;
      let str = quote;
      i++;
      while (i < code.length && code[i] !== quote) {
        if (code[i] === '\\' && i + 1 < code.length) {
          str += code[i] + code[i + 1];
          i += 2;
        } else {
          str += code[i];
          i++;
        }
      }
      if (i < code.length) {
        str += code[i]; // Closing quote
        i++;
      }
      tokens.push({ type: TokenType.STRING, value: str });
      continue;
    }

    // Numbers
    if (/\d/.test(char)) {
      let num = '';
      while (i < code.length && /[\d.]/.test(code[i])) {
        num += code[i];
        i++;
      }
      tokens.push({ type: TokenType.NUMBER, value: num });
      continue;
    }

    // Check for multi-character operators first
    let foundOperator = false;
    for (const op of operators.sort((a, b) => b.length - a.length)) {
      const substr = code.substring(i, i + op.length);
      if (substr === op) {
        // Check if it's part of a word or a standalone operator
        const beforeOk = i === 0 || /\s/.test(code[i - 1]);
        const afterOk = i + op.length >= code.length || /\s/.test(code[i + op.length]);

        if (beforeOk && afterOk) {
          const isLogical = logicalOperators.includes(op);
          tokens.push({
            type: isLogical ? TokenType.LOGICAL : TokenType.OPERATOR,
            value: op
          });
          i += op.length;
          foundOperator = true;
          break;
        }
      }
    }
    if (foundOperator) continue;

    // Check for logical operators (AND, OR, NOT)
    let foundLogical = false;
    for (const op of logicalOperators) {
      const substr = code.substring(i, i + op.length).toUpperCase();
      if (substr === op) {
        const beforeOk = i === 0 || /\s/.test(code[i - 1]);
        const afterOk = i + op.length >= code.length || /\s/.test(code[i + op.length]);

        if (beforeOk && afterOk) {
          tokens.push({ type: TokenType.LOGICAL, value: code.substring(i, i + op.length) });
          i += op.length;
          foundLogical = true;
          break;
        }
      }
    }
    if (foundLogical) continue;

    // Words (field names or text)
    if (/[a-zA-Z_]/.test(char)) {
      let word = '';
      while (i < code.length && /[a-zA-Z0-9_.-]/.test(code[i])) {
        word += code[i];
        i++;
      }

      // Check if this is a SIGMA field
      const resolvedField = resolveFieldAlias(word);
      const isSigmaField = resolvedField !== word || /^[A-Z]/.test(word);

      tokens.push({
        type: TokenType.FIELD,
        value: word,
        isSigmaField
      });
      continue;
    }

    // Everything else
    tokens.push({ type: TokenType.TEXT, value: char });
    i++;
  }

  return tokens;
}

/**
 * Render a token with appropriate styling
 */
function renderToken(token: Token, index: number): React.ReactNode {
  switch (token.type) {
    case TokenType.FIELD:
      if (token.isSigmaField) {
        return (
          <FieldName key={index} title="SIGMA Field">
            {token.value}
          </FieldName>
        );
      }
      return <span key={index}>{token.value}</span>;

    case TokenType.OPERATOR:
      return <Operator key={index}>{token.value}</Operator>;

    case TokenType.LOGICAL:
      return <LogicalOperator key={index}>{token.value}</LogicalOperator>;

    case TokenType.STRING:
      return <StringValue key={index}>{token.value}</StringValue>;

    case TokenType.NUMBER:
      return <NumberValue key={index}>{token.value}</NumberValue>;

    case TokenType.BRACKET:
      return <Bracket key={index}>{token.value}</Bracket>;

    case TokenType.PARENTHESIS:
      return <Parenthesis key={index}>{token.value}</Parenthesis>;

    case TokenType.WHITESPACE:
      return <span key={index}>{token.value}</span>;

    case TokenType.TEXT:
    default:
      return <span key={index}>{token.value}</span>;
  }
}

/**
 * CQL Syntax Highlighter Component
 */
export function CqlSyntaxHighlighter({ code, className }: CqlSyntaxHighlighterProps) {
  if (!code || code.trim() === '') {
    return (
      <SyntaxContainer className={className}>
        <span style={{ color: '#999', fontStyle: 'italic' }}>No conditions defined</span>
      </SyntaxContainer>
    );
  }

  const tokens = tokenizeCql(code);

  return (
    <SyntaxContainer className={className}>
      {tokens.map((token, index) => renderToken(token, index))}
    </SyntaxContainer>
  );
}

/**
 * Inline CQL syntax highlighter for smaller displays
 */
export function InlineCqlHighlighter({ code, className }: CqlSyntaxHighlighterProps) {
  const tokens = tokenizeCql(code);

  return (
    <Box
      component="code"
      className={className}
      sx={{
        fontFamily: 'Consolas, Monaco, "Courier New", monospace',
        fontSize: '0.875rem',
        display: 'inline',
        whiteSpace: 'pre-wrap'
      }}
    >
      {tokens.map((token, index) => renderToken(token, index))}
    </Box>
  );
}

export default CqlSyntaxHighlighter;

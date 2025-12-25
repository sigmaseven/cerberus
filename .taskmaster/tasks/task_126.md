# Task ID: 126

**Title:** Build AST-based SIGMA condition expression parser

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Implement complete Abstract Syntax Tree parser for SIGMA condition expressions with support for parentheses, operator precedence (NOT > AND > OR), aggregations (all/any/1 of), and wildcard patterns

**Details:**

Create detect/sigma_condition_parser.go:

1. AST Node Types:
   - IdentifierNode (detection block name)
   - BinaryOpNode (AND/OR with left/right children)
   - NotNode (NOT unary operator)
   - AggregationNode (all/any/1 of them/pattern)

2. ConditionParser with tokenization:
   - Tokenize expression into tokens (AND, OR, NOT, LPAREN, RPAREN, OF, ALL, ANY, 1, THEM, IDENTIFIER)
   - Use regex patterns for token recognition
   - Handle whitespace, lowercase conversion

3. Recursive descent parser:
   - parseExpression → parseOrExpression (lowest precedence)
   - parseOrExpression → parseAndExpression (medium)
   - parseAndExpression → parseNotExpression (high)
   - parseNotExpression → parsePrimaryExpression
   - parsePrimaryExpression handles parentheses, aggregations, identifiers

4. Aggregation support:
   - "all of them" → matches all identifiers
   - "1 of selection_*" → matches any with prefix
   - "any of selection_*" → same as 1 of
   - getMatchingIdentifiers with wildcard support

5. Evaluation:
   - Each node implements Evaluate(context map[string]bool) (bool, error)
   - Short-circuit evaluation for AND/OR
   - Undefined identifier returns error

See Phase 3.2 in PRD for complete parser implementation (BLOCKER #2 fix).

**Test Strategy:**

1. Unit tests (200+ tests):
   - Simple expressions ("selection1 or selection2")
   - Nested parentheses ("(a or b) and not (c or d)")
   - Operator precedence without parens
   - All aggregation types (all/any/1 of them/pattern/*)
   - Edge cases (single identifier, empty context)

2. Tokenizer tests:
   - All token types recognized
   - Whitespace handling
   - Invalid characters rejected

3. Parser error tests:
   - Unmatched parentheses
   - Invalid operators
   - Unexpected tokens
   - Empty expressions

4. Evaluation tests:
   - Correct boolean logic
   - Short-circuit behavior
   - Undefined identifier errors
   - Wildcard matching

5. Real-world SIGMA conditions from public repos

## Subtasks

### 126.1. Define AST node types and Evaluate interface

**Status:** done  
**Dependencies:** None  

Create the core AST node type definitions with a common Evaluate interface. Implement IdentifierNode, BinaryOpNode (for AND/OR), NotNode (for NOT unary operator), and AggregationNode (for all/any/1 of patterns) structs.

**Details:**

In detect/sigma_condition_parser.go, define:

1. ConditionNode interface with Evaluate(context map[string]bool) (bool, error) method
2. IdentifierNode struct holding detection block name, implementing Evaluate by looking up in context
3. BinaryOpNode struct with operator (AND/OR), left/right ConditionNode children, implementing Evaluate with short-circuit logic
4. NotNode struct wrapping a child ConditionNode, implementing Evaluate by negating child result
5. AggregationNode struct with aggregation type (all/any/1), pattern string, and list of identifiers to match

Each node type must implement the ConditionNode interface. Keep structs simple and focused on their specific role in the AST.

### 126.2. Implement tokenizer with regex-based token recognition

**Status:** done  
**Dependencies:** 126.1  

Build the tokenization layer that converts raw SIGMA condition strings into a stream of typed tokens. Support all token types: AND, OR, NOT, LPAREN, RPAREN, OF, ALL, ANY, 1, THEM, and IDENTIFIER.

**Details:**

Create tokenizer in detect/sigma_condition_parser.go:

1. Define TokenType enum (AND, OR, NOT, LPAREN, RPAREN, OF, ALL, ANY, ONE, THEM, IDENTIFIER)
2. Define Token struct with Type and Value fields
3. Implement Tokenize(expression string) ([]Token, error) function:
   - Normalize input to lowercase
   - Use regex patterns to match each token type in priority order
   - Handle whitespace between tokens
   - Track position for error messages
4. Token matching order: keywords first (AND, OR, NOT, OF, ALL, ANY, 1, THEM), then operators (parentheses), then identifiers (alphanumeric + underscore + wildcard)
5. Return error for unrecognized characters

### 126.3. Implement recursive descent parser with operator precedence

**Status:** done  
**Dependencies:** 126.2  

Build the recursive descent parser that constructs the AST from token stream, respecting operator precedence: NOT > AND > OR. Implement parseExpression, parseOrExpression, parseAndExpression, parseNotExpression, and parsePrimaryExpression methods.

**Details:**

Create parser in detect/sigma_condition_parser.go:

1. ConditionParser struct with tokens []Token, position int fields
2. Parse(expression string) (ConditionNode, error) - main entry point calling Tokenize then parseExpression
3. parseExpression() calls parseOrExpression (lowest precedence)
4. parseOrExpression() handles OR operators, calls parseAndExpression for each operand, builds BinaryOpNode chain
5. parseAndExpression() handles AND operators, calls parseNotExpression, builds BinaryOpNode chain
6. parseNotExpression() handles optional NOT prefix, calls parsePrimaryExpression
7. parsePrimaryExpression() handles: parentheses (recursive call to parseExpression), aggregations (delegates to parseAggregation), identifiers (creates IdentifierNode)
8. Helper methods: peek(), consume(), expect(), isAtEnd()
9. Error handling for unexpected tokens, unmatched parentheses

### 126.4. Implement aggregation parsing with wildcard matching

**Status:** done  
**Dependencies:** 126.3  

Build aggregation expression parser to handle 'all of them', 'any of pattern', '1 of selection_*' syntax with wildcard identifier matching using getMatchingIdentifiers helper.

**Details:**

Extend parser in detect/sigma_condition_parser.go:

1. parseAggregation() method:
   - Parse quantifier: 'all', 'any', or number (e.g., '1')
   - Expect 'of' keyword
   - Parse target: 'them' (all identifiers) or pattern with wildcards
   - Create AggregationNode with quantifier, pattern
2. getMatchingIdentifiers(pattern string, availableIdentifiers []string) []string:
   - If pattern is 'them', return all identifiers
   - If pattern contains '*', use wildcard matching (convert to regex)
   - Otherwise exact match
   - Return matched identifier list
3. AggregationNode.Evaluate implementation:
   - Call getMatchingIdentifiers with pattern and context keys
   - Evaluate matched identifiers based on quantifier:
     - 'all': all must be true (AND logic)
     - 'any' or number > 0: at least N must be true
   - Return error if pattern matches no identifiers

### 126.5. Implement Evaluate methods with short-circuit logic

**Status:** done  
**Dependencies:** 126.4  

Complete the Evaluate() method implementations for all AST node types with proper short-circuit evaluation for AND/OR operators and comprehensive error propagation.

**Details:**

Implement Evaluate methods in detect/sigma_condition_parser.go:

1. IdentifierNode.Evaluate(context map[string]bool):
   - Look up identifier in context
   - Return error if identifier not found (undefined identifier)
   - Return boolean value if found
2. BinaryOpNode.Evaluate(context map[string]bool):
   - For AND: evaluate left, short-circuit if false, then evaluate right
   - For OR: evaluate left, short-circuit if true, then evaluate right
   - Propagate errors from child evaluations
3. NotNode.Evaluate(context map[string]bool):
   - Evaluate child node
   - Return negated result
   - Propagate errors
4. AggregationNode.Evaluate(context map[string]bool):
   - Get matching identifiers using getMatchingIdentifiers
   - Evaluate each matched identifier from context
   - Apply quantifier logic (all/any/N of)
   - Return error if any matched identifier undefined
5. Add detailed error messages with context (which identifier, which operator)

### 126.6. Add comprehensive error handling and validation

**Status:** done  
**Dependencies:** 126.5  

Implement robust error handling for all failure modes: undefined identifiers, unmatched parentheses, invalid operators, malformed aggregations, empty expressions, and tokenization errors.

**Details:**

Add error handling throughout detect/sigma_condition_parser.go:

1. Custom error types:
   - UndefinedIdentifierError with identifier name
   - ParseError with position, token, expected vs actual
   - TokenizationError with position, invalid character
   - AggregationError with pattern, reason (no matches, insufficient matches)
2. Parser error cases:
   - Unmatched parentheses (LPAREN without RPAREN, vice versa)
   - Missing operands (AND/OR/NOT without right side)
   - Unexpected end of expression
   - Invalid aggregation syntax (missing 'of', invalid quantifier)
   - Empty expression handling
3. Evaluator error cases:
   - Undefined identifiers with helpful messages
   - Aggregation pattern matches zero identifiers
   - Type mismatches (should not occur with boolean context)
4. Add position tracking to all errors for debugging
5. Validate expression before evaluation (detect errors early)
6. Add descriptive error messages referencing SIGMA spec

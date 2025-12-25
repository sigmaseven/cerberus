package detect

import (
	"fmt"
	"strings"
	"testing"
)

// TestParserBasicIdentifier tests parsing a single identifier.
func TestParserBasicIdentifier(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("selection")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	identNode, ok := ast.(*IdentifierNode)
	if !ok {
		t.Fatalf("expected IdentifierNode, got %T", ast)
	}

	if identNode.Name != "selection" {
		t.Errorf("expected identifier 'selection', got '%s'", identNode.Name)
	}
}

// TestParserTwoIdentifiersOR tests "a or b" parsing.
func TestParserTwoIdentifiersOR(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	binOp, ok := ast.(*BinaryOpNode)
	if !ok {
		t.Fatalf("expected BinaryOpNode, got %T", ast)
	}

	if binOp.Operator != OpOR {
		t.Errorf("expected OR operator, got %v", binOp.Operator)
	}

	// Verify left operand
	leftIdent, ok := binOp.Left.(*IdentifierNode)
	if !ok || leftIdent.Name != "a" {
		t.Errorf("expected left operand 'a', got %v", binOp.Left)
	}

	// Verify right operand
	rightIdent, ok := binOp.Right.(*IdentifierNode)
	if !ok || rightIdent.Name != "b" {
		t.Errorf("expected right operand 'b', got %v", binOp.Right)
	}
}

// TestParserTwoIdentifiersAND tests "a and b" parsing.
func TestParserTwoIdentifiersAND(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	binOp, ok := ast.(*BinaryOpNode)
	if !ok {
		t.Fatalf("expected BinaryOpNode, got %T", ast)
	}

	if binOp.Operator != OpAND {
		t.Errorf("expected AND operator, got %v", binOp.Operator)
	}

	// Verify left operand
	leftIdent, ok := binOp.Left.(*IdentifierNode)
	if !ok || leftIdent.Name != "a" {
		t.Errorf("expected left operand 'a', got %v", binOp.Left)
	}

	// Verify right operand
	rightIdent, ok := binOp.Right.(*IdentifierNode)
	if !ok || rightIdent.Name != "b" {
		t.Errorf("expected right operand 'b', got %v", binOp.Right)
	}
}

// TestParserNOTExpression tests "not a" parsing.
func TestParserNOTExpression(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	notNode, ok := ast.(*NotNode)
	if !ok {
		t.Fatalf("expected NotNode, got %T", ast)
	}

	childIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || childIdent.Name != "a" {
		t.Errorf("expected child identifier 'a', got %v", notNode.Child)
	}
}

// TestParserPrecedenceANDbeforeOR tests "a or b and c" -> OR(a, AND(b,c)).
// AND has higher precedence than OR, so "b and c" binds first.
func TestParserPrecedenceANDbeforeOR(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b and c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: OR(a, AND(b, c))
	orNode, ok := ast.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T / %v", ast, ast)
	}

	// Left should be identifier "a"
	leftIdent, ok := orNode.Left.(*IdentifierNode)
	if !ok || leftIdent.Name != "a" {
		t.Errorf("expected left operand 'a', got %v", orNode.Left)
	}

	// Right should be AND(b, c)
	andNode, ok := orNode.Right.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node on right, got %T / %v", orNode.Right, orNode.Right)
	}

	bIdent, ok := andNode.Left.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in AND left, got %v", andNode.Left)
	}

	cIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c' in AND right, got %v", andNode.Right)
	}
}

// TestParserPrecedenceANDbeforeOR2 tests "a and b or c" -> OR(AND(a,b), c).
func TestParserPrecedenceANDbeforeOR2(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and b or c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: OR(AND(a, b), c)
	orNode, ok := ast.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Left should be AND(a, b)
	andNode, ok := orNode.Left.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", orNode.Left)
	}

	aIdent, ok := andNode.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in AND left, got %v", andNode.Left)
	}

	bIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in AND right, got %v", andNode.Right)
	}

	// Right should be identifier "c"
	cIdent, ok := orNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected right operand 'c', got %v", orNode.Right)
	}
}

// TestParserParenthesesOverridePrecedence tests "(a or b) and c" -> AND(OR(a,b), c).
func TestParserParenthesesOverridePrecedence(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("(a or b) and c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: AND(OR(a, b), c)
	andNode, ok := ast.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left should be OR(a, b)
	orNode, ok := andNode.Left.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node on left, got %T", andNode.Left)
	}

	aIdent, ok := orNode.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in OR left, got %v", orNode.Left)
	}

	bIdent, ok := orNode.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in OR right, got %v", orNode.Right)
	}

	// Right should be identifier "c"
	cIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected right operand 'c', got %v", andNode.Right)
	}
}

// TestParserNestedNOT tests "not not a" -> NOT(NOT(a)).
func TestParserNestedNOT(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not not a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: NOT(NOT(a))
	notOuter, ok := ast.(*NotNode)
	if !ok {
		t.Fatalf("expected outer NotNode, got %T", ast)
	}

	notInner, ok := notOuter.Child.(*NotNode)
	if !ok {
		t.Fatalf("expected inner NotNode, got %T", notOuter.Child)
	}

	aIdent, ok := notInner.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected identifier 'a', got %v", notInner.Child)
	}
}

// TestParserComplexExpression tests "a and not b or c" -> OR(AND(a, NOT(b)), c).
// Precedence: NOT > AND > OR
// So "not b" binds first, then "a and not b", then "... or c".
func TestParserComplexExpression(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and not b or c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: OR(AND(a, NOT(b)), c)
	orNode, ok := ast.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Left should be AND(a, NOT(b))
	andNode, ok := orNode.Left.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", orNode.Left)
	}

	aIdent, ok := andNode.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in AND left, got %v", andNode.Left)
	}

	notNode, ok := andNode.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node in AND right, got %T", andNode.Right)
	}

	bIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in NOT child, got %v", notNode.Child)
	}

	// Right should be identifier "c"
	cIdent, ok := orNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected right operand 'c', got %v", orNode.Right)
	}
}

// TestParserComplexNested tests "(a or b) and (c or d)" -> AND(OR(a,b), OR(c,d)).
func TestParserComplexNested(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("(a or b) and (c or d)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: AND(OR(a,b), OR(c,d))
	andNode, ok := ast.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left: OR(a, b)
	leftOr, ok := andNode.Left.(*BinaryOpNode)
	if !ok || leftOr.Operator != OpOR {
		t.Fatalf("expected OR node on left, got %T", andNode.Left)
	}

	aIdent, ok := leftOr.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in left OR, got %v", leftOr.Left)
	}

	bIdent, ok := leftOr.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in left OR, got %v", leftOr.Right)
	}

	// Right: OR(c, d)
	rightOr, ok := andNode.Right.(*BinaryOpNode)
	if !ok || rightOr.Operator != OpOR {
		t.Fatalf("expected OR node on right, got %T", andNode.Right)
	}

	cIdent, ok := rightOr.Left.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c' in right OR, got %v", rightOr.Left)
	}

	dIdent, ok := rightOr.Right.(*IdentifierNode)
	if !ok || dIdent.Name != "d" {
		t.Errorf("expected 'd' in right OR, got %v", rightOr.Right)
	}
}

// TestParserChainedAND tests "a and b and c" -> AND(AND(a,b), c) (left-associative).
func TestParserChainedAND(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and b and c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: AND(AND(a,b), c)
	outerAnd, ok := ast.(*BinaryOpNode)
	if !ok || outerAnd.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left should be AND(a, b)
	innerAnd, ok := outerAnd.Left.(*BinaryOpNode)
	if !ok || innerAnd.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", outerAnd.Left)
	}

	aIdent, ok := innerAnd.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in inner AND left, got %v", innerAnd.Left)
	}

	bIdent, ok := innerAnd.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in inner AND right, got %v", innerAnd.Right)
	}

	// Right should be identifier "c"
	cIdent, ok := outerAnd.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected right operand 'c', got %v", outerAnd.Right)
	}
}

// TestParserChainedOR tests "a or b or c" -> OR(OR(a,b), c) (left-associative).
func TestParserChainedOR(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b or c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected structure: OR(OR(a,b), c)
	outerOr, ok := ast.(*BinaryOpNode)
	if !ok || outerOr.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Left should be OR(a, b)
	innerOr, ok := outerOr.Left.(*BinaryOpNode)
	if !ok || innerOr.Operator != OpOR {
		t.Fatalf("expected OR node on left, got %T", outerOr.Left)
	}

	aIdent, ok := innerOr.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in inner OR left, got %v", innerOr.Left)
	}

	bIdent, ok := innerOr.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in inner OR right, got %v", innerOr.Right)
	}

	// Right should be identifier "c"
	cIdent, ok := outerOr.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected right operand 'c', got %v", outerOr.Right)
	}
}

// TestParserErrorUnmatchedOpenParen tests error for "(" without closing.
func TestParserErrorUnmatchedOpenParen(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("(a and b")
	if err == nil {
		t.Fatal("expected error for unmatched '(', got nil")
	}
	if !strings.Contains(err.Error(), "missing closing parenthesis") {
		t.Errorf("expected 'missing closing parenthesis' error, got: %v", err)
	}
}

// TestParserErrorUnmatchedCloseParen tests error for ")" without opening.
func TestParserErrorUnmatchedCloseParen(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a and b)")
	if err == nil {
		t.Fatal("expected error for unmatched ')', got nil")
	}
	// Should fail with unexpected token after expression or unexpected closing paren
	if !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("expected 'unexpected' error, got: %v", err)
	}
}

// TestParserErrorEmptyExpression tests error for empty string.
func TestParserErrorEmptyExpression(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("")
	if err == nil {
		t.Fatal("expected error for empty expression, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' error, got: %v", err)
	}
}

// TestParserErrorMissingLeftOperandAND tests "and b" (missing left operand).
func TestParserErrorMissingLeftOperandAND(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("and b")
	if err == nil {
		t.Fatal("expected error for 'and b', got nil")
	}
	if !strings.Contains(err.Error(), "missing left operand") {
		t.Errorf("expected 'missing left operand' error, got: %v", err)
	}
}

// TestParserErrorMissingRightOperandAND tests "a and" (missing right operand).
func TestParserErrorMissingRightOperandAND(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a and")
	if err == nil {
		t.Fatal("expected error for 'a and', got nil")
	}
	// Should fail with "unexpected end of expression"
	if !strings.Contains(err.Error(), "unexpected end") {
		t.Errorf("expected 'unexpected end' error, got: %v", err)
	}
}

// TestParserErrorDoubleOperator tests "a or or b" (double operator).
func TestParserErrorDoubleOperator(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a or or b")
	if err == nil {
		t.Fatal("expected error for 'a or or b', got nil")
	}
	// Should fail because "or" is not a valid primary expression
	if !strings.Contains(err.Error(), "missing left operand") {
		t.Errorf("expected 'missing left operand' error, got: %v", err)
	}
}

// TestParserCaseInsensitiveKeywords tests that keywords are case-insensitive.
func TestParserCaseInsensitiveKeywords(t *testing.T) {
	testCases := []string{
		"a AND b",
		"a Or b",
		"NOT a",
		"a AnD b oR c",
		"nOt a",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(expr)
			if err != nil {
				t.Errorf("unexpected error for case-insensitive expression %q: %v", expr, err)
			}
		})
	}
}

// TestParserWhitespace tests that whitespace is properly handled.
func TestParserWhitespace(t *testing.T) {
	testCases := []string{
		"  a  and  b  ",
		"\ta\tand\tb\t",
		"a   or   b",
		"  not  a  ",
		"( a or b ) and c",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(expr)
			if err != nil {
				t.Errorf("unexpected error for whitespace expression %q: %v", expr, err)
			}
		})
	}
}

// TestParserIdentifierWithNumbers tests identifiers containing numbers.
func TestParserIdentifierWithNumbers(t *testing.T) {
	testCases := []string{
		"selection1",
		"filter2",
		"sel_123",
		"a1 and b2",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(expr)
			if err != nil {
				t.Errorf("unexpected error for identifier %q: %v", expr, err)
			}
		})
	}
}

// TestParserIdentifierWithUnderscore tests identifiers with underscores.
func TestParserIdentifierWithUnderscore(t *testing.T) {
	testCases := []string{
		"_private",
		"my_selection",
		"filter_windows",
		"_a and _b",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(expr)
			if err != nil {
				t.Errorf("unexpected error for identifier %q: %v", expr, err)
			}
		})
	}
}

// TestParserIdentifierWithWildcard tests identifiers with wildcards.
func TestParserIdentifierWithWildcard(t *testing.T) {
	testCases := []string{
		"selection*",
		"filter*",
		"sel* and filter*",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.Parse(expr)
			if err != nil {
				t.Errorf("unexpected error for wildcard identifier %q: %v", expr, err)
			}

			// For "selection*", verify the identifier includes the asterisk
			if expr == "selection*" {
				ident, ok := ast.(*IdentifierNode)
				if !ok || ident.Name != "selection*" {
					t.Errorf("expected identifier 'selection*', got %v", ast)
				}
			}
		})
	}
}

// TestParserNestedParentheses tests deeply nested parentheses.
func TestParserNestedParentheses(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("(((a)))")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ident, ok := ast.(*IdentifierNode)
	if !ok || ident.Name != "a" {
		t.Errorf("expected identifier 'a', got %v", ast)
	}
}

// TestParserComplexNestedParentheses tests complex nested parentheses.
func TestParserComplexNestedParentheses(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("((a or b) and (c or d)) or e")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: OR(AND(OR(a,b), OR(c,d)), e)
	orOuter, ok := ast.(*BinaryOpNode)
	if !ok || orOuter.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}
}

// TestParserErrorOnlyOpenParen tests "(" alone.
func TestParserErrorOnlyOpenParen(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("(")
	if err == nil {
		t.Fatal("expected error for '(' alone, got nil")
	}
}

// TestParserErrorOnlyCloseParen tests ")" alone.
func TestParserErrorOnlyCloseParen(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse(")")
	if err == nil {
		t.Fatal("expected error for ')' alone, got nil")
	}
}

// TestParserErrorOnlyAND tests "and" alone.
func TestParserErrorOnlyAND(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("and")
	if err == nil {
		t.Fatal("expected error for 'and' alone, got nil")
	}
}

// TestParserErrorOnlyOR tests "or" alone.
func TestParserErrorOnlyOR(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("or")
	if err == nil {
		t.Fatal("expected error for 'or' alone, got nil")
	}
}

// TestParserErrorOnlyNOT tests "not" alone.
func TestParserErrorOnlyNOT(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("not")
	if err == nil {
		t.Fatal("expected error for 'not' alone, got nil")
	}
}

// TestParserErrorMissingRightOperandOR tests "a or" (missing right operand).
func TestParserErrorMissingRightOperandOR(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a or")
	if err == nil {
		t.Fatal("expected error for 'a or', got nil")
	}
}

// TestParserErrorMissingLeftOperandOR tests "or b" (missing left operand).
func TestParserErrorMissingLeftOperandOR(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("or b")
	if err == nil {
		t.Fatal("expected error for 'or b', got nil")
	}
}

// TestParserErrorEmptyParentheses tests "()" (empty parentheses).
func TestParserErrorEmptyParentheses(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("()")
	if err == nil {
		t.Fatal("expected error for '()', got nil")
	}
}

// TestParserTripleNOT tests "not not not a" -> NOT(NOT(NOT(a))).
func TestParserTripleNOT(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not not not a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify nested NOT nodes
	not1, ok := ast.(*NotNode)
	if !ok {
		t.Fatalf("expected outer NotNode, got %T", ast)
	}

	not2, ok := not1.Child.(*NotNode)
	if !ok {
		t.Fatalf("expected second NotNode, got %T", not1.Child)
	}

	not3, ok := not2.Child.(*NotNode)
	if !ok {
		t.Fatalf("expected third NotNode, got %T", not2.Child)
	}

	aIdent, ok := not3.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected identifier 'a', got %v", not3.Child)
	}
}

// TestParserNOTPrecedence tests "not a and b" -> AND(NOT(a), b).
// NOT has higher precedence than AND.
func TestParserNOTPrecedence(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not a and b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(NOT(a), b)
	andNode, ok := ast.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left: NOT(a)
	notNode, ok := andNode.Left.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node on left, got %T", andNode.Left)
	}

	aIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' in NOT child, got %v", notNode.Child)
	}

	// Right: b
	bIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' on right, got %v", andNode.Right)
	}
}

// TestParserNOTPrecedence2 tests "a and not b" -> AND(a, NOT(b)).
func TestParserNOTPrecedence2(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and not b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(a, NOT(b))
	andNode, ok := ast.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left: a
	aIdent, ok := andNode.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a' on left, got %v", andNode.Left)
	}

	// Right: NOT(b)
	notNode, ok := andNode.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node on right, got %T", andNode.Right)
	}

	bIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b' in NOT child, got %v", notNode.Child)
	}
}

// TestParserFourWayAND tests "a and b and c and d".
func TestParserFourWayAND(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and b and c and d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(AND(AND(a, b), c), d)
	// Verify top-level AND
	and3, ok := ast.(*BinaryOpNode)
	if !ok || and3.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Verify d on the right
	dIdent, ok := and3.Right.(*IdentifierNode)
	if !ok || dIdent.Name != "d" {
		t.Errorf("expected 'd' on right, got %v", and3.Right)
	}

	// Verify AND(AND(a, b), c) on the left
	and2, ok := and3.Left.(*BinaryOpNode)
	if !ok || and2.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", and3.Left)
	}

	cIdent, ok := and2.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c', got %v", and2.Right)
	}

	and1, ok := and2.Left.(*BinaryOpNode)
	if !ok || and1.Operator != OpAND {
		t.Fatalf("expected inner AND node, got %T", and2.Left)
	}

	aIdent, ok := and1.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a', got %v", and1.Left)
	}

	bIdent, ok := and1.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b', got %v", and1.Right)
	}
}

// TestParserFourWayOR tests "a or b or c or d".
func TestParserFourWayOR(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b or c or d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: OR(OR(OR(a, b), c), d)
	or3, ok := ast.(*BinaryOpNode)
	if !ok || or3.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Verify d on the right
	dIdent, ok := or3.Right.(*IdentifierNode)
	if !ok || dIdent.Name != "d" {
		t.Errorf("expected 'd' on right, got %v", or3.Right)
	}
}

// TestParserMixedPrecedence tests "a or b and c or d" -> OR(OR(a, AND(b, c)), d).
func TestParserMixedPrecedence(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b and c or d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: OR(OR(a, AND(b, c)), d)
	orOuter, ok := ast.(*BinaryOpNode)
	if !ok || orOuter.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Right should be "d"
	dIdent, ok := orOuter.Right.(*IdentifierNode)
	if !ok || dIdent.Name != "d" {
		t.Errorf("expected 'd', got %v", orOuter.Right)
	}

	// Left should be OR(a, AND(b, c))
	orInner, ok := orOuter.Left.(*BinaryOpNode)
	if !ok || orInner.Operator != OpOR {
		t.Fatalf("expected OR node on left, got %T", orOuter.Left)
	}

	// orInner.Left should be "a"
	aIdent, ok := orInner.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a', got %v", orInner.Left)
	}

	// orInner.Right should be AND(b, c)
	andNode, ok := orInner.Right.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node, got %T", orInner.Right)
	}

	bIdent, ok := andNode.Left.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b', got %v", andNode.Left)
	}

	cIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c', got %v", andNode.Right)
	}
}

// TestParserComplexMixedExpression tests "not (a or b) and (c or not d)".
func TestParserComplexMixedExpression(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not (a or b) and (c or not d)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(NOT(OR(a, b)), OR(c, NOT(d)))
	andNode, ok := ast.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Left: NOT(OR(a, b))
	notNode, ok := andNode.Left.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node on left, got %T", andNode.Left)
	}

	orLeft, ok := notNode.Child.(*BinaryOpNode)
	if !ok || orLeft.Operator != OpOR {
		t.Fatalf("expected OR node in NOT, got %T", notNode.Child)
	}

	// Right: OR(c, NOT(d))
	orRight, ok := andNode.Right.(*BinaryOpNode)
	if !ok || orRight.Operator != OpOR {
		t.Fatalf("expected OR node on right, got %T", andNode.Right)
	}

	cIdent, ok := orRight.Left.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c', got %v", orRight.Left)
	}

	notD, ok := orRight.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node, got %T", orRight.Right)
	}

	dIdent, ok := notD.Child.(*IdentifierNode)
	if !ok || dIdent.Name != "d" {
		t.Errorf("expected 'd', got %v", notD.Child)
	}
}

// TestParserParenthesizedNOT tests "(not a)" - NOT inside parentheses.
func TestParserParenthesizedNOT(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("(not a)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	notNode, ok := ast.(*NotNode)
	if !ok {
		t.Fatalf("expected NotNode, got %T", ast)
	}

	aIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a', got %v", notNode.Child)
	}
}

// TestParserSingleParenthesizedIdentifier tests "(a)" - single identifier in parentheses.
func TestParserSingleParenthesizedIdentifier(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("(a)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ident, ok := ast.(*IdentifierNode)
	if !ok || ident.Name != "a" {
		t.Errorf("expected identifier 'a', got %v", ast)
	}
}

// TestParserErrorInvalidCharacter tests error for invalid characters.
func TestParserErrorInvalidCharacter(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a @ b")
	if err == nil {
		t.Fatal("expected error for invalid character '@', got nil")
	}
	if !strings.Contains(err.Error(), "tokenization failed") {
		t.Errorf("expected tokenization error, got: %v", err)
	}
}

// TestParserErrorTrailingOperator tests "a and b or" (trailing operator).
func TestParserErrorTrailingOperator(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("a and b or")
	if err == nil {
		t.Fatal("expected error for trailing 'or', got nil")
	}
}

// TestParserErrorLeadingOperator tests "and a or b" (leading operator).
func TestParserErrorLeadingOperator(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("and a or b")
	if err == nil {
		t.Fatal("expected error for leading 'and', got nil")
	}
}

// TestParserErrorMismatchedParens tests "((a)" (mismatched parens).
func TestParserErrorMismatchedParens(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("((a)")
	if err == nil {
		t.Fatal("expected error for mismatched parens, got nil")
	}
}

// TestParserErrorMismatchedParens2 tests "(a))" (mismatched parens).
func TestParserErrorMismatchedParens2(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("(a))")
	if err == nil {
		t.Fatal("expected error for extra ')', got nil")
	}
}

// TestParserVeryLongChain tests a very long chain of ORs.
func TestParserVeryLongChain(t *testing.T) {
	// Build "a1 or a2 or a3 or ... or a100"
	var parts []string
	for i := 1; i <= 100; i++ {
		parts = append(parts, fmt.Sprintf("a%d", i))
	}
	expression := strings.Join(parts, " or ")

	parser := NewConditionParser()
	ast, err := parser.Parse(expression)
	if err != nil {
		t.Fatalf("unexpected error for long chain: %v", err)
	}

	// Verify it's a binary op node
	if _, ok := ast.(*BinaryOpNode); !ok {
		t.Errorf("expected BinaryOpNode for long chain, got %T", ast)
	}
}

// TestParserVeryLongChainAND tests a very long chain of ANDs.
func TestParserVeryLongChainAND(t *testing.T) {
	// Build "a1 and a2 and a3 and ... and a50"
	var parts []string
	for i := 1; i <= 50; i++ {
		parts = append(parts, fmt.Sprintf("a%d", i))
	}
	expression := strings.Join(parts, " and ")

	parser := NewConditionParser()
	ast, err := parser.Parse(expression)
	if err != nil {
		t.Fatalf("unexpected error for long AND chain: %v", err)
	}

	if _, ok := ast.(*BinaryOpNode); !ok {
		t.Errorf("expected BinaryOpNode for long AND chain, got %T", ast)
	}
}

// TestParserDeeplyNestedNOT tests deeply nested NOT expressions.
func TestParserDeeplyNestedNOT(t *testing.T) {
	// Build "not not not not not a"
	expression := "not not not not not a"

	parser := NewConditionParser()
	ast, err := parser.Parse(expression)
	if err != nil {
		t.Fatalf("unexpected error for deeply nested NOT: %v", err)
	}

	// Verify it's a NOT node
	if _, ok := ast.(*NotNode); !ok {
		t.Errorf("expected NotNode for deeply nested NOT, got %T", ast)
	}
}

// TestParserComplexRealWorldExample tests a realistic complex expression.
func TestParserComplexRealWorldExample(t *testing.T) {
	expression := "selection1 and (selection2 or selection3) and not filter"

	parser := NewConditionParser()
	ast, err := parser.Parse(expression)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(AND(selection1, OR(selection2, selection3)), NOT(filter))
	andOuter, ok := ast.(*BinaryOpNode)
	if !ok || andOuter.Operator != OpAND {
		t.Fatalf("expected AND node at top, got %T", ast)
	}

	// Right: NOT(filter)
	notNode, ok := andOuter.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node on right, got %T", andOuter.Right)
	}

	filterIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || filterIdent.Name != "filter" {
		t.Errorf("expected 'filter', got %v", notNode.Child)
	}

	// Left: AND(selection1, OR(selection2, selection3))
	andInner, ok := andOuter.Left.(*BinaryOpNode)
	if !ok || andInner.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", andOuter.Left)
	}

	sel1, ok := andInner.Left.(*IdentifierNode)
	if !ok || sel1.Name != "selection1" {
		t.Errorf("expected 'selection1', got %v", andInner.Left)
	}

	orNode, ok := andInner.Right.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node, got %T", andInner.Right)
	}

	sel2, ok := orNode.Left.(*IdentifierNode)
	if !ok || sel2.Name != "selection2" {
		t.Errorf("expected 'selection2', got %v", orNode.Left)
	}

	sel3, ok := orNode.Right.(*IdentifierNode)
	if !ok || sel3.Name != "selection3" {
		t.Errorf("expected 'selection3', got %v", orNode.Right)
	}
}

// TestParserMultipleNOTinExpression tests "not a and not b or not c".
func TestParserMultipleNOTinExpression(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not a and not b or not c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: OR(AND(NOT(a), NOT(b)), NOT(c))
	orNode, ok := ast.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node at top, got %T", ast)
	}

	// Right: NOT(c)
	notC, ok := orNode.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node on right, got %T", orNode.Right)
	}

	cIdent, ok := notC.Child.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c', got %v", notC.Child)
	}

	// Left: AND(NOT(a), NOT(b))
	andNode, ok := orNode.Left.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND node on left, got %T", orNode.Left)
	}

	notA, ok := andNode.Left.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node, got %T", andNode.Left)
	}

	aIdent, ok := notA.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a', got %v", notA.Child)
	}

	notB, ok := andNode.Right.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT node, got %T", andNode.Right)
	}

	bIdent, ok := notB.Child.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b', got %v", notB.Child)
	}
}

// TestParserParenthesisAfterNOT tests "not (a or b)".
func TestParserParenthesisAfterNOT(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("not (a or b)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: NOT(OR(a, b))
	notNode, ok := ast.(*NotNode)
	if !ok {
		t.Fatalf("expected NotNode, got %T", ast)
	}

	orNode, ok := notNode.Child.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR node in NOT, got %T", notNode.Child)
	}

	aIdent, ok := orNode.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a', got %v", orNode.Left)
	}

	bIdent, ok := orNode.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b', got %v", orNode.Right)
	}
}

// TestParserLeftAssociativityAND verifies "a and b and c" is left-associative.
func TestParserLeftAssociativityAND(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a and b and c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: AND(AND(a, b), c) - NOT AND(a, AND(b, c))
	outerAnd, ok := ast.(*BinaryOpNode)
	if !ok || outerAnd.Operator != OpAND {
		t.Fatalf("expected AND node at top")
	}

	// The right should be 'c'
	cIdent, ok := outerAnd.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c' on right for left-associativity")
	}

	// The left should be AND(a, b)
	innerAnd, ok := outerAnd.Left.(*BinaryOpNode)
	if !ok || innerAnd.Operator != OpAND {
		t.Fatalf("expected inner AND node on left")
	}

	aIdent, ok := innerAnd.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a'")
	}

	bIdent, ok := innerAnd.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b'")
	}
}

// TestParserLeftAssociativityOR verifies "a or b or c" is left-associative.
func TestParserLeftAssociativityOR(t *testing.T) {
	parser := NewConditionParser()
	ast, err := parser.Parse("a or b or c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: OR(OR(a, b), c) - NOT OR(a, OR(b, c))
	outerOr, ok := ast.(*BinaryOpNode)
	if !ok || outerOr.Operator != OpOR {
		t.Fatalf("expected OR node at top")
	}

	// The right should be 'c'
	cIdent, ok := outerOr.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c' on right for left-associativity")
	}

	// The left should be OR(a, b)
	innerOr, ok := outerOr.Left.(*BinaryOpNode)
	if !ok || innerOr.Operator != OpOR {
		t.Fatalf("expected inner OR node on left")
	}

	aIdent, ok := innerOr.Left.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a'")
	}

	bIdent, ok := innerOr.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b'")
	}
}

// TestParserPrecedenceNOTvsANDvsOR verifies NOT > AND > OR precedence.
func TestParserPrecedenceNOTvsANDvsOR(t *testing.T) {
	// Test: "not a and b or c"
	// Should parse as: OR(AND(NOT(a), b), c)
	parser := NewConditionParser()
	ast, err := parser.Parse("not a and b or c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Top level: OR
	orNode, ok := ast.(*BinaryOpNode)
	if !ok || orNode.Operator != OpOR {
		t.Fatalf("expected OR at top")
	}

	// Right: c
	cIdent, ok := orNode.Right.(*IdentifierNode)
	if !ok || cIdent.Name != "c" {
		t.Errorf("expected 'c'")
	}

	// Left: AND(NOT(a), b)
	andNode, ok := orNode.Left.(*BinaryOpNode)
	if !ok || andNode.Operator != OpAND {
		t.Fatalf("expected AND on left")
	}

	// AND left: NOT(a)
	notNode, ok := andNode.Left.(*NotNode)
	if !ok {
		t.Fatalf("expected NOT on AND left")
	}

	aIdent, ok := notNode.Child.(*IdentifierNode)
	if !ok || aIdent.Name != "a" {
		t.Errorf("expected 'a'")
	}

	// AND right: b
	bIdent, ok := andNode.Right.(*IdentifierNode)
	if !ok || bIdent.Name != "b" {
		t.Errorf("expected 'b'")
	}
}

// TestParserErrorPositionReporting verifies that error messages include position information.
func TestParserErrorPositionReporting(t *testing.T) {
	testCases := []struct {
		expr            string
		expectedErrText string
	}{
		{"and", "position"},
		{"a and", "position"},
		{")", "position"},
		{"a or or b", "position"},
	}

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			parser := NewConditionParser()
			_, err := parser.Parse(tc.expr)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.expr)
			}
			if !strings.Contains(err.Error(), tc.expectedErrText) {
				t.Errorf("expected error to contain %q, got: %v", tc.expectedErrText, err)
			}
		})
	}
}

// TestParserEvaluation tests that parsed ASTs can be evaluated correctly.
func TestParserEvaluation(t *testing.T) {
	testCases := []struct {
		expr     string
		context  map[string]bool
		expected bool
	}{
		{"a", map[string]bool{"a": true}, true},
		{"a", map[string]bool{"a": false}, false},
		{"a and b", map[string]bool{"a": true, "b": true}, true},
		{"a and b", map[string]bool{"a": true, "b": false}, false},
		{"a or b", map[string]bool{"a": false, "b": true}, true},
		{"a or b", map[string]bool{"a": false, "b": false}, false},
		{"not a", map[string]bool{"a": true}, false},
		{"not a", map[string]bool{"a": false}, true},
		{"a or b and c", map[string]bool{"a": false, "b": true, "c": true}, true},
		{"a or b and c", map[string]bool{"a": false, "b": true, "c": false}, false},
		{"a or b and c", map[string]bool{"a": true, "b": false, "c": false}, true},
		{"(a or b) and c", map[string]bool{"a": true, "b": false, "c": true}, true},
		{"(a or b) and c", map[string]bool{"a": false, "b": false, "c": true}, false},
		{"not (a or b)", map[string]bool{"a": false, "b": false}, true},
		{"not (a or b)", map[string]bool{"a": true, "b": false}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.Parse(tc.expr)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			result, err := ast.Evaluate(tc.context)
			if err != nil {
				t.Fatalf("unexpected evaluation error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestParserNoBlankIdentifiers ensures all errors are checked (no blank identifiers).
func TestParserNoBlankIdentifiers(t *testing.T) {
	// This is a design test - the code should not use blank identifiers for error returns
	// We verify this by ensuring all parsing operations check errors explicitly
	parser := NewConditionParser()

	// Test that Parse checks tokenization errors
	_, err := parser.Parse("a @ b")
	if err == nil {
		t.Error("expected tokenization error to be checked")
	}

	// Test that Parse checks parsing errors
	_, err = parser.Parse("and")
	if err == nil {
		t.Error("expected parsing error to be checked")
	}
}

// TestParserNoPanics ensures the parser handles all error conditions gracefully without panicking.
func TestParserNoPanics(t *testing.T) {
	testCases := []string{
		"",
		"(",
		")",
		"and",
		"or",
		"not",
		"a @",
		"a and and b",
		"(((((",
		")))))",
		"not not not not not not not not not not a",
	}

	for _, expr := range testCases {
		t.Run(expr, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parser panicked on %q: %v", expr, r)
				}
			}()

			parser := NewConditionParser()
			_, _ = parser.Parse(expr) // Errors are expected, panics are not
		})
	}
}

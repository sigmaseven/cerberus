package detect

import (
	"strings"
	"testing"
)

// TestIdentifierNode_Evaluate_Present verifies that IdentifierNode returns true
// when the identifier exists in the context and is set to true.
func TestIdentifierNode_Evaluate_Present(t *testing.T) {
	node := &IdentifierNode{Name: "selection1"}
	context := map[string]bool{
		"selection1": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("expected true, got false")
	}
}

// TestIdentifierNode_Evaluate_Missing verifies that IdentifierNode returns
// an error when the identifier is not found in the context.
func TestIdentifierNode_Evaluate_Missing(t *testing.T) {
	node := &IdentifierNode{Name: "unknown"}
	context := map[string]bool{
		"selection1": true,
	}

	_, err := node.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for missing identifier, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error message should mention 'not found', got: %v", err)
	}

	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error message should mention identifier name 'unknown', got: %v", err)
	}
}

// TestIdentifierNode_Evaluate_False verifies that IdentifierNode returns false
// when the identifier exists in the context but is set to false.
func TestIdentifierNode_Evaluate_False(t *testing.T) {
	node := &IdentifierNode{Name: "selection1"}
	context := map[string]bool{
		"selection1": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("expected false, got true")
	}
}

// TestBinaryOpNode_AND_TrueTrue verifies that AND returns true
// when both operands are true.
func TestBinaryOpNode_AND_TrueTrue(t *testing.T) {
	node := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel1": true,
		"sel2": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("AND(true, true) should return true, got false")
	}
}

// TestBinaryOpNode_AND_TrueFalse verifies that AND returns false
// when the second operand is false, and verifies short-circuit by ensuring
// the right side is still evaluated (returns false).
func TestBinaryOpNode_AND_TrueFalse(t *testing.T) {
	node := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel1": true,
		"sel2": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("AND(true, false) should return false, got true")
	}
}

// shortCircuitTracker tracks whether Evaluate was called to verify short-circuit behavior.
type shortCircuitTracker struct {
	evaluated bool
	result    bool
}

func (s *shortCircuitTracker) Evaluate(context map[string]bool) (bool, error) {
	s.evaluated = true
	return s.result, nil
}

// TestBinaryOpNode_AND_ShortCircuit verifies that AND does not evaluate
// the right operand when the left operand is false.
func TestBinaryOpNode_AND_ShortCircuit(t *testing.T) {
	rightTracker := &shortCircuitTracker{result: true}

	node := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    rightTracker,
	}
	context := map[string]bool{
		"sel1": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("AND(false, X) should return false, got true")
	}

	if rightTracker.evaluated {
		t.Errorf("AND(false, X) should short-circuit and not evaluate right operand")
	}
}

// TestBinaryOpNode_OR_FalseTrue verifies that OR returns true
// when the second operand is true.
func TestBinaryOpNode_OR_FalseTrue(t *testing.T) {
	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel1": false,
		"sel2": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("OR(false, true) should return true, got false")
	}
}

// TestBinaryOpNode_OR_ShortCircuit verifies that OR does not evaluate
// the right operand when the left operand is true.
func TestBinaryOpNode_OR_ShortCircuit(t *testing.T) {
	rightTracker := &shortCircuitTracker{result: false}

	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    rightTracker,
	}
	context := map[string]bool{
		"sel1": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("OR(true, X) should return true, got false")
	}

	if rightTracker.evaluated {
		t.Errorf("OR(true, X) should short-circuit and not evaluate right operand")
	}
}

// TestNotNode_True verifies that NOT returns false when the child is true.
func TestNotNode_True(t *testing.T) {
	node := &NotNode{
		Child: &IdentifierNode{Name: "sel1"},
	}
	context := map[string]bool{
		"sel1": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("NOT(true) should return false, got true")
	}
}

// TestNotNode_False verifies that NOT returns true when the child is false.
func TestNotNode_False(t *testing.T) {
	node := &NotNode{
		Child: &IdentifierNode{Name: "sel1"},
	}
	context := map[string]bool{
		"sel1": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("NOT(false) should return true, got false")
	}
}

// TestAggregationNode_AllOf_AllTrue verifies that "all of" returns true
// when all identifiers are true.
func TestAggregationNode_AllOf_AllTrue(t *testing.T) {
	node := &AggregationNode{
		Type:        AggAll,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": true,
		"selection2": true,
		"selection3": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("all of [true, true, true] should return true, got false")
	}
}

// TestAggregationNode_AllOf_AnyFalse verifies that "all of" returns false
// when any identifier is false.
func TestAggregationNode_AllOf_AnyFalse(t *testing.T) {
	node := &AggregationNode{
		Type:        AggAll,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": true,
		"selection2": false,
		"selection3": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("all of [true, false, true] should return false, got true")
	}
}

// TestAggregationNode_AnyOf_AnyTrue verifies that "any of" returns true
// when at least one identifier is true.
func TestAggregationNode_AnyOf_AnyTrue(t *testing.T) {
	node := &AggregationNode{
		Type:        AggAny,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": false,
		"selection2": true,
		"selection3": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("any of [false, true, false] should return true, got false")
	}
}

// TestAggregationNode_AnyOf_AllFalse verifies that "any of" returns false
// when all identifiers are false.
func TestAggregationNode_AnyOf_AllFalse(t *testing.T) {
	node := &AggregationNode{
		Type:        AggAny,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": false,
		"selection2": false,
		"selection3": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("any of [false, false, false] should return false, got true")
	}
}

// TestAggregationNode_CountOf_OneTrue verifies that "1 of" returns true
// when exactly one identifier is true.
func TestAggregationNode_CountOf_OneTrue(t *testing.T) {
	node := &AggregationNode{
		Type:        AggCount,
		Count:       1,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": false,
		"selection2": true,
		"selection3": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("1 of [false, true, false] should return true, got false")
	}
}

// TestErrorPropagation_IdentifierNode verifies that errors from IdentifierNode
// are properly propagated through parent nodes.
func TestErrorPropagation_IdentifierNode(t *testing.T) {
	// Test error propagation through BinaryOpNode
	node := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "missing"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel2": true,
	}

	_, err := node.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for missing identifier, got nil")
	}

	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention missing identifier, got: %v", err)
	}
}

// TestErrorPropagation_ThroughNotNode verifies that errors are properly
// propagated through NotNode.
func TestErrorPropagation_ThroughNotNode(t *testing.T) {
	node := &NotNode{
		Child: &IdentifierNode{Name: "missing"},
	}
	context := map[string]bool{
		"other": true,
	}

	_, err := node.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for missing identifier, got nil")
	}

	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention missing identifier, got: %v", err)
	}
}

// TestErrorPropagation_ThroughAggregation verifies that errors are properly
// propagated through AggregationNode.
func TestErrorPropagation_ThroughAggregation(t *testing.T) {
	node := &AggregationNode{
		Type:        AggAll,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "missing", "selection3"},
	}
	context := map[string]bool{
		"selection1": true,
		"selection3": true,
	}

	_, err := node.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for missing identifier, got nil")
	}

	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention missing identifier, got: %v", err)
	}
}

// TestNilHandling_IdentifierNode verifies that IdentifierNode handles
// nil receiver gracefully without panicking.
func TestNilHandling_IdentifierNode(t *testing.T) {
	var node *IdentifierNode
	context := map[string]bool{
		"sel1": true,
	}

	_, err := node.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil IdentifierNode, got nil")
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

// TestNilHandling_BinaryOpNode verifies that BinaryOpNode handles
// nil receiver and nil children gracefully without panicking.
func TestNilHandling_BinaryOpNode(t *testing.T) {
	context := map[string]bool{
		"sel1": true,
	}

	// Nil receiver
	var nilNode *BinaryOpNode
	_, err := nilNode.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil BinaryOpNode, got nil")
	}

	// Nil left child
	nodeNilLeft := &BinaryOpNode{
		Operator: OpAND,
		Left:     nil,
		Right:    &IdentifierNode{Name: "sel1"},
	}
	_, err = nodeNilLeft.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil left child, got nil")
	}

	// Nil right child
	nodeNilRight := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    nil,
	}
	_, err = nodeNilRight.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil right child, got nil")
	}
}

// TestNilHandling_NotNode verifies that NotNode handles
// nil receiver and nil child gracefully without panicking.
func TestNilHandling_NotNode(t *testing.T) {
	context := map[string]bool{
		"sel1": true,
	}

	// Nil receiver
	var nilNode *NotNode
	_, err := nilNode.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil NotNode, got nil")
	}

	// Nil child
	nodeNilChild := &NotNode{
		Child: nil,
	}
	_, err = nodeNilChild.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil child, got nil")
	}
}

// TestNilHandling_AggregationNode verifies that AggregationNode handles
// nil receiver and nil context gracefully without panicking.
func TestNilHandling_AggregationNode(t *testing.T) {
	// Nil receiver
	var nilNode *AggregationNode
	context := map[string]bool{
		"sel1": true,
	}
	_, err := nilNode.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for nil AggregationNode, got nil")
	}

	// Nil context
	node := &AggregationNode{
		Type:        AggAll,
		Identifiers: []string{"sel1"},
	}
	_, err = node.Evaluate(nil)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}

	// Empty identifiers
	nodeEmpty := &AggregationNode{
		Type:        AggAll,
		Identifiers: []string{},
	}
	_, err = nodeEmpty.Evaluate(context)
	if err == nil {
		t.Fatal("expected error for empty identifiers, got nil")
	}
}

// TestNilHandling_IdentifierNode_NilContext verifies that IdentifierNode
// handles nil context gracefully.
func TestNilHandling_IdentifierNode_NilContext(t *testing.T) {
	node := &IdentifierNode{Name: "sel1"}

	_, err := node.Evaluate(nil)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

// TestBinaryOpNode_OR_FalseFalse verifies that OR returns false
// when both operands are false.
func TestBinaryOpNode_OR_FalseFalse(t *testing.T) {
	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel1": false,
		"sel2": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("OR(false, false) should return false, got true")
	}
}

// TestBinaryOpNode_OR_TrueTrue verifies that OR returns true
// when both operands are true.
func TestBinaryOpNode_OR_TrueTrue(t *testing.T) {
	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     &IdentifierNode{Name: "sel1"},
		Right:    &IdentifierNode{Name: "sel2"},
	}
	context := map[string]bool{
		"sel1": true,
		"sel2": true,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("OR(true, true) should return true, got false")
	}
}

// TestAggregationNode_CountOf_TwoOfThree verifies that "2 of" returns true
// when exactly two identifiers are true.
func TestAggregationNode_CountOf_TwoOfThree(t *testing.T) {
	node := &AggregationNode{
		Type:        AggCount,
		Count:       2,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": true,
		"selection2": true,
		"selection3": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result {
		t.Errorf("2 of [true, true, false] should return true, got false")
	}
}

// TestAggregationNode_CountOf_WrongCount verifies that "2 of" returns false
// when the count doesn't match.
func TestAggregationNode_CountOf_WrongCount(t *testing.T) {
	node := &AggregationNode{
		Type:        AggCount,
		Count:       2,
		Pattern:     "selection*",
		Identifiers: []string{"selection1", "selection2", "selection3"},
	}
	context := map[string]bool{
		"selection1": true,
		"selection2": false,
		"selection3": false,
	}

	result, err := node.Evaluate(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result {
		t.Errorf("2 of [true, false, false] should return false, got true")
	}
}

// TestParsePatternIdentifiers_Wildcard verifies that pattern matching
// works correctly for wildcard patterns.
func TestParsePatternIdentifiers_Wildcard(t *testing.T) {
	availableBlocks := []string{"selection1", "selection2", "filter1", "filter2"}

	matches := ParsePatternIdentifiers("selection*", availableBlocks)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}

	expected := map[string]bool{"selection1": true, "selection2": true}
	for _, match := range matches {
		if !expected[match] {
			t.Errorf("unexpected match: %s", match)
		}
	}
}

// TestParsePatternIdentifiers_Exact verifies that pattern matching
// works correctly for exact patterns.
func TestParsePatternIdentifiers_Exact(t *testing.T) {
	availableBlocks := []string{"selection1", "selection2", "filter1"}

	matches := ParsePatternIdentifiers("selection1", availableBlocks)
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}

	if len(matches) > 0 && matches[0] != "selection1" {
		t.Errorf("expected 'selection1', got %s", matches[0])
	}
}

// TestComplexCondition verifies that complex nested conditions work correctly.
func TestComplexCondition(t *testing.T) {
	// (selection1 AND selection2) OR (NOT filter1)
	node := &BinaryOpNode{
		Operator: OpOR,
		Left: &BinaryOpNode{
			Operator: OpAND,
			Left:     &IdentifierNode{Name: "selection1"},
			Right:    &IdentifierNode{Name: "selection2"},
		},
		Right: &NotNode{
			Child: &IdentifierNode{Name: "filter1"},
		},
	}

	// Test case 1: selection1=true, selection2=true, filter1=true
	// (true AND true) OR (NOT true) = true OR false = true
	context1 := map[string]bool{
		"selection1": true,
		"selection2": true,
		"filter1":    true,
	}
	result1, err := node.Evaluate(context1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result1 {
		t.Errorf("case 1: expected true, got false")
	}

	// Test case 2: selection1=false, selection2=true, filter1=true
	// (false AND true) OR (NOT true) = false OR false = false
	context2 := map[string]bool{
		"selection1": false,
		"selection2": true,
		"filter1":    true,
	}
	result2, err := node.Evaluate(context2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2 {
		t.Errorf("case 2: expected false, got true")
	}

	// Test case 3: selection1=false, selection2=false, filter1=false
	// (false AND false) OR (NOT false) = false OR true = true
	context3 := map[string]bool{
		"selection1": false,
		"selection2": false,
		"filter1":    false,
	}
	result3, err := node.Evaluate(context3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result3 {
		t.Errorf("case 3: expected true, got false")
	}
}

// TestInterfaceSatisfaction verifies that all node types implement ConditionNode.
func TestInterfaceSatisfaction(t *testing.T) {
	var _ ConditionNode = (*IdentifierNode)(nil)
	var _ ConditionNode = (*BinaryOpNode)(nil)
	var _ ConditionNode = (*NotNode)(nil)
	var _ ConditionNode = (*AggregationNode)(nil)

	// Also verify with actual instances
	nodes := []ConditionNode{
		&IdentifierNode{Name: "test"},
		&BinaryOpNode{Operator: OpAND, Left: &IdentifierNode{Name: "a"}, Right: &IdentifierNode{Name: "b"}},
		&NotNode{Child: &IdentifierNode{Name: "test"}},
		&AggregationNode{Type: AggAll, Identifiers: []string{"test"}},
	}

	for i, node := range nodes {
		if node == nil {
			t.Errorf("node %d is nil", i)
		}
	}
}

// TestBinaryOperator_String verifies string representation of operators.
func TestBinaryOperator_String(t *testing.T) {
	if OpAND.String() != "AND" {
		t.Errorf("expected 'AND', got '%s'", OpAND.String())
	}

	if OpOR.String() != "OR" {
		t.Errorf("expected 'OR', got '%s'", OpOR.String())
	}

	// Test unknown operator
	unknownOp := BinaryOperator(999)
	if unknownOp.String() != "UNKNOWN" {
		t.Errorf("expected 'UNKNOWN', got '%s'", unknownOp.String())
	}
}

// TestAggregationType_String verifies string representation of aggregation types.
func TestAggregationType_String(t *testing.T) {
	if AggAll.String() != "all of" {
		t.Errorf("expected 'all of', got '%s'", AggAll.String())
	}

	if AggAny.String() != "any of" {
		t.Errorf("expected 'any of', got '%s'", AggAny.String())
	}

	if AggCount.String() != "count of" {
		t.Errorf("expected 'count of', got '%s'", AggCount.String())
	}

	// Test unknown aggregation
	unknownAgg := AggregationType(999)
	if unknownAgg.String() != "unknown" {
		t.Errorf("expected 'unknown', got '%s'", unknownAgg.String())
	}
}

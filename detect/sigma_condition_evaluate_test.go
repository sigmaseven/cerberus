package detect

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

// evaluationTracker tracks whether an identifier was accessed during evaluation.
// Used to verify short-circuit behavior.
type evaluationTracker struct {
	accessCount map[string]*int32 // Pointer to int32 for atomic operations
}

// newEvaluationTracker creates a new tracker for monitoring identifier accesses.
func newEvaluationTracker() *evaluationTracker {
	return &evaluationTracker{
		accessCount: make(map[string]*int32),
	}
}

// register registers an identifier for tracking.
func (t *evaluationTracker) register(name string) {
	counter := int32(0)
	t.accessCount[name] = &counter
}

// accessed returns the number of times an identifier was accessed.
func (t *evaluationTracker) accessed(name string) int {
	if counter, exists := t.accessCount[name]; exists {
		return int(atomic.LoadInt32(counter))
	}
	return 0
}

// trackingContext creates an evaluation context that tracks accesses.
// When an identifier is accessed, it increments the access counter and returns the stored value.
type trackingContext struct {
	values  map[string]bool
	tracker *evaluationTracker
}

// newTrackingContext creates a context that wraps a regular map with tracking.
func newTrackingContext(values map[string]bool, tracker *evaluationTracker) *trackingContext {
	return &trackingContext{
		values:  values,
		tracker: tracker,
	}
}

// get retrieves a value and records the access.
func (tc *trackingContext) get(name string) (bool, bool) {
	if counter, exists := tc.tracker.accessCount[name]; exists {
		atomic.AddInt32(counter, 1)
	}

	value, exists := tc.values[name]
	return value, exists
}

// TestIdentifierNode_Evaluate tests basic identifier evaluation.
func TestIdentifierNode_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		identifier  string
		context     map[string]bool
		expected    bool
		expectError bool
		errorMsg    string
	}{
		{
			name:       "identifier_true",
			identifier: "selection1",
			context:    map[string]bool{"selection1": true},
			expected:   true,
		},
		{
			name:       "identifier_false",
			identifier: "selection1",
			context:    map[string]bool{"selection1": false},
			expected:   false,
		},
		{
			name:        "identifier_not_found",
			identifier:  "missing",
			context:     map[string]bool{"selection1": true},
			expectError: true,
			errorMsg:    "identifier 'missing' not found",
		},
		{
			name:        "nil_context",
			identifier:  "selection1",
			context:     nil,
			expectError: true,
			errorMsg:    "evaluation context is nil",
		},
		{
			name:        "empty_context",
			identifier:  "selection1",
			context:     map[string]bool{},
			expectError: true,
			errorMsg:    "identifier 'selection1' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &IdentifierNode{Name: tt.identifier}

			result, err := node.Evaluate(tt.context)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIdentifierNode_Evaluate_NilNode tests nil node handling.
func TestIdentifierNode_Evaluate_NilNode(t *testing.T) {
	var node *IdentifierNode = nil
	context := map[string]bool{"test": true}

	result, err := node.Evaluate(context)

	if err == nil {
		t.Fatal("expected error for nil node, got nil")
	}

	if !strings.Contains(err.Error(), "identifier node is nil") {
		t.Errorf("expected error about nil node, got: %v", err)
	}

	if result != false {
		t.Errorf("expected false result for nil node, got %v", result)
	}
}

// TestBinaryOpNode_AND_ShortCircuit_Comprehensive verifies AND short-circuit behavior comprehensively.
func TestBinaryOpNode_AND_ShortCircuit_Comprehensive(t *testing.T) {
	tests := []struct {
		name           string
		leftValue      bool
		rightValue     bool
		expected       bool
		rightEvaluated bool // Should right be evaluated?
	}{
		{
			name:           "false_AND_true_short_circuits",
			leftValue:      false,
			rightValue:     true,
			expected:       false,
			rightEvaluated: false, // Right should NOT be evaluated
		},
		{
			name:           "false_AND_false_short_circuits",
			leftValue:      false,
			rightValue:     false,
			expected:       false,
			rightEvaluated: false, // Right should NOT be evaluated
		},
		{
			name:           "true_AND_true_evaluates_both",
			leftValue:      true,
			rightValue:     true,
			expected:       true,
			rightEvaluated: true, // Right MUST be evaluated
		},
		{
			name:           "true_AND_false_evaluates_both",
			leftValue:      true,
			rightValue:     false,
			expected:       false,
			rightEvaluated: true, // Right MUST be evaluated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := newEvaluationTracker()
			tracker.register("left")
			tracker.register("right")

			tc := newTrackingContext(map[string]bool{
				"left":  tt.leftValue,
				"right": tt.rightValue,
			}, tracker)

			// Create custom nodes that use tracking context
			leftNode := &trackingIdentifierNode{name: "left", tc: tc}
			rightNode := &trackingIdentifierNode{name: "right", tc: tc}

			node := &BinaryOpNode{
				Operator: OpAND,
				Left:     leftNode,
				Right:    rightNode,
			}

			// Create a dummy context (not used by tracking nodes)
			result, err := node.Evaluate(map[string]bool{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}

			// Verify left was always evaluated
			if tracker.accessed("left") != 1 {
				t.Errorf("left operand access count: expected 1, got %d", tracker.accessed("left"))
			}

			// Verify right was evaluated based on expectation
			rightAccess := tracker.accessed("right")
			if tt.rightEvaluated && rightAccess != 1 {
				t.Errorf("right operand should be evaluated: expected 1 access, got %d", rightAccess)
			}
			if !tt.rightEvaluated && rightAccess != 0 {
				t.Errorf("right operand should NOT be evaluated (short-circuit): expected 0 accesses, got %d", rightAccess)
			}
		})
	}
}

// TestBinaryOpNode_OR_ShortCircuit_Comprehensive verifies OR short-circuit behavior comprehensively.
func TestBinaryOpNode_OR_ShortCircuit_Comprehensive(t *testing.T) {
	tests := []struct {
		name           string
		leftValue      bool
		rightValue     bool
		expected       bool
		rightEvaluated bool
	}{
		{
			name:           "true_OR_true_short_circuits",
			leftValue:      true,
			rightValue:     true,
			expected:       true,
			rightEvaluated: false, // Right should NOT be evaluated
		},
		{
			name:           "true_OR_false_short_circuits",
			leftValue:      true,
			rightValue:     false,
			expected:       true,
			rightEvaluated: false, // Right should NOT be evaluated
		},
		{
			name:           "false_OR_true_evaluates_both",
			leftValue:      false,
			rightValue:     true,
			expected:       true,
			rightEvaluated: true, // Right MUST be evaluated
		},
		{
			name:           "false_OR_false_evaluates_both",
			leftValue:      false,
			rightValue:     false,
			expected:       false,
			rightEvaluated: true, // Right MUST be evaluated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := newEvaluationTracker()
			tracker.register("left")
			tracker.register("right")

			tc := newTrackingContext(map[string]bool{
				"left":  tt.leftValue,
				"right": tt.rightValue,
			}, tracker)

			leftNode := &trackingIdentifierNode{name: "left", tc: tc}
			rightNode := &trackingIdentifierNode{name: "right", tc: tc}

			node := &BinaryOpNode{
				Operator: OpOR,
				Left:     leftNode,
				Right:    rightNode,
			}

			result, err := node.Evaluate(map[string]bool{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}

			// Verify left was always evaluated
			if tracker.accessed("left") != 1 {
				t.Errorf("left operand access count: expected 1, got %d", tracker.accessed("left"))
			}

			// Verify right evaluation
			rightAccess := tracker.accessed("right")
			if tt.rightEvaluated && rightAccess != 1 {
				t.Errorf("right operand should be evaluated: expected 1 access, got %d", rightAccess)
			}
			if !tt.rightEvaluated && rightAccess != 0 {
				t.Errorf("right operand should NOT be evaluated (short-circuit): expected 0 accesses, got %d", rightAccess)
			}
		})
	}
}

// trackingIdentifierNode is a custom node for testing short-circuit behavior.
type trackingIdentifierNode struct {
	name string
	tc   *trackingContext
}

func (n *trackingIdentifierNode) Evaluate(context map[string]bool) (bool, error) {
	value, exists := n.tc.get(n.name)
	if !exists {
		return false, fmt.Errorf("identifier '%s' not found", n.name)
	}
	return value, nil
}

// TestBinaryOpNode_ErrorPropagation tests error handling in binary operations.
func TestBinaryOpNode_ErrorPropagation(t *testing.T) {
	tests := []struct {
		name        string
		operator    BinaryOperator
		leftError   bool
		rightError  bool
		leftValue   bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "AND_left_error",
			operator:    OpAND,
			leftError:   true,
			expectError: true,
			errorMsg:    "failed to evaluate left operand of AND",
		},
		{
			name:        "AND_right_error_when_left_true",
			operator:    OpAND,
			leftValue:   true,
			rightError:  true,
			expectError: true,
			errorMsg:    "failed to evaluate right operand of AND",
		},
		{
			name:        "OR_left_error",
			operator:    OpOR,
			leftError:   true,
			expectError: true,
			errorMsg:    "failed to evaluate left operand of OR",
		},
		{
			name:        "OR_right_error_when_left_false",
			operator:    OpOR,
			leftValue:   false,
			rightError:  true,
			expectError: true,
			errorMsg:    "failed to evaluate right operand of OR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var leftNode, rightNode ConditionNode

			if tt.leftError {
				leftNode = &errorNode{msg: "left error"}
			} else {
				leftNode = &IdentifierNode{Name: "left"}
			}

			if tt.rightError {
				rightNode = &errorNode{msg: "right error"}
			} else {
				rightNode = &IdentifierNode{Name: "right"}
			}

			node := &BinaryOpNode{
				Operator: tt.operator,
				Left:     leftNode,
				Right:    rightNode,
			}

			context := map[string]bool{
				"left":  tt.leftValue,
				"right": true,
			}

			result, err := node.Evaluate(context)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != false {
				t.Errorf("expected false, got %v", result)
			}
		})
	}
}

// errorNode always returns an error during evaluation.
type errorNode struct {
	msg string
}

func (n *errorNode) Evaluate(context map[string]bool) (bool, error) {
	return false, fmt.Errorf("%s", n.msg)
}

// TestBinaryOpNode_NilChecks tests nil validation.
func TestBinaryOpNode_NilChecks(t *testing.T) {
	validNode := &IdentifierNode{Name: "test"}
	context := map[string]bool{"test": true}

	tests := []struct {
		name     string
		node     *BinaryOpNode
		errorMsg string
	}{
		{
			name:     "nil_node",
			node:     nil,
			errorMsg: "binary operation node is nil",
		},
		{
			name: "nil_left_operand",
			node: &BinaryOpNode{
				Operator: OpAND,
				Left:     nil,
				Right:    validNode,
			},
			errorMsg: "binary operation left operand is nil",
		},
		{
			name: "nil_right_operand",
			node: &BinaryOpNode{
				Operator: OpAND,
				Left:     validNode,
				Right:    nil,
			},
			errorMsg: "binary operation right operand is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.node.Evaluate(context)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
			}

			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}

			if result != false {
				t.Errorf("expected false result, got %v", result)
			}
		})
	}
}

// TestNotNode_Evaluate tests NOT operation.
func TestNotNode_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		childValue  bool
		expected    bool
		expectError bool
	}{
		{
			name:       "not_true",
			childValue: true,
			expected:   false,
		},
		{
			name:       "not_false",
			childValue: false,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &NotNode{
				Child: &IdentifierNode{Name: "child"},
			}

			context := map[string]bool{"child": tt.childValue}

			result, err := node.Evaluate(context)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestNotNode_ErrorPropagation tests NOT error handling.
func TestNotNode_ErrorPropagation(t *testing.T) {
	node := &NotNode{
		Child: &errorNode{msg: "child error"},
	}

	context := map[string]bool{}

	result, err := node.Evaluate(context)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to evaluate NOT child") {
		t.Errorf("expected error about NOT child, got: %v", err)
	}

	if result != false {
		t.Errorf("expected false result, got %v", result)
	}
}

// TestNotNode_NilChecks tests NOT nil validation.
func TestNotNode_NilChecks(t *testing.T) {
	context := map[string]bool{"test": true}

	tests := []struct {
		name     string
		node     *NotNode
		errorMsg string
	}{
		{
			name:     "nil_node",
			node:     nil,
			errorMsg: "not node is nil",
		},
		{
			name: "nil_child",
			node: &NotNode{
				Child: nil,
			},
			errorMsg: "not node child is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.node.Evaluate(context)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
			}

			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}

			if result != false {
				t.Errorf("expected false result, got %v", result)
			}
		})
	}
}

// TestAggregationNode_All tests "all of" aggregation.
func TestAggregationNode_All(t *testing.T) {
	tests := []struct {
		name        string
		identifiers []string
		context     map[string]bool
		expected    bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "all_true",
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expected:    true,
		},
		{
			name:        "one_false",
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": false, "sel3": true},
			expected:    false,
		},
		{
			name:        "all_false",
			identifiers: []string{"sel1", "sel2"},
			context:     map[string]bool{"sel1": false, "sel2": false},
			expected:    false,
		},
		{
			name:        "missing_identifier",
			identifiers: []string{"sel1", "missing"},
			context:     map[string]bool{"sel1": true},
			expectError: true,
			errorMsg:    "identifier 'missing' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &AggregationNode{
				Type:        AggAll,
				Pattern:     "test*",
				Identifiers: tt.identifiers,
				Count:       0,
			}

			result, err := node.Evaluate(tt.context)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestAggregationNode_Any tests "any of" aggregation.
func TestAggregationNode_Any(t *testing.T) {
	tests := []struct {
		name        string
		identifiers []string
		context     map[string]bool
		expected    bool
	}{
		{
			name:        "one_true",
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": false, "sel2": true, "sel3": false},
			expected:    true,
		},
		{
			name:        "all_true",
			identifiers: []string{"sel1", "sel2"},
			context:     map[string]bool{"sel1": true, "sel2": true},
			expected:    true,
		},
		{
			name:        "all_false",
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": false, "sel2": false, "sel3": false},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &AggregationNode{
				Type:        AggAny,
				Pattern:     "test*",
				Identifiers: tt.identifiers,
				Count:       1,
			}

			result, err := node.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestAggregationNode_Count tests "N of" aggregation.
func TestAggregationNode_Count(t *testing.T) {
	tests := []struct {
		name        string
		count       int
		identifiers []string
		context     map[string]bool
		expected    bool
	}{
		{
			name:        "1_of_3_exactly_one_true",
			count:       1,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": false, "sel3": false},
			expected:    true,
		},
		{
			name:        "2_of_3_exactly_two_true",
			count:       2,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": true, "sel3": false},
			expected:    true,
		},
		{
			name:        "2_of_3_all_true",
			count:       2,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expected:    true,
		},
		{
			name:        "2_of_3_only_one_true",
			count:       2,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": false, "sel3": false},
			expected:    false,
		},
		{
			name:        "3_of_3_all_true",
			count:       3,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expected:    true,
		},
		{
			name:        "3_of_3_only_two_true",
			count:       3,
			identifiers: []string{"sel1", "sel2", "sel3"},
			context:     map[string]bool{"sel1": true, "sel2": true, "sel3": false},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &AggregationNode{
				Type:        AggCount,
				Pattern:     "test*",
				Identifiers: tt.identifiers,
				Count:       tt.count,
			}

			result, err := node.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestAggregationNode_NilChecks tests aggregation nil validation.
func TestAggregationNode_NilChecks(t *testing.T) {
	tests := []struct {
		name     string
		node     *AggregationNode
		context  map[string]bool
		errorMsg string
	}{
		{
			name:     "nil_node",
			node:     nil,
			context:  map[string]bool{"test": true},
			errorMsg: "aggregation node is nil",
		},
		{
			name: "nil_context",
			node: &AggregationNode{
				Type:        AggAll,
				Pattern:     "test*",
				Identifiers: []string{"test"},
				Count:       0,
			},
			context:  nil,
			errorMsg: "evaluation context is nil",
		},
		{
			name: "no_identifiers",
			node: &AggregationNode{
				Type:        AggAll,
				Pattern:     "test*",
				Identifiers: []string{},
				Count:       0,
			},
			context:  map[string]bool{"test": true},
			errorMsg: "aggregation node has no identifiers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.node.Evaluate(tt.context)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
			}

			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}

			if result != false {
				t.Errorf("expected false result, got %v", result)
			}
		})
	}
}

// TestComplexExpressions tests nested and complex evaluation scenarios.
func TestComplexExpressions(t *testing.T) {
	tests := []struct {
		name     string
		node     ConditionNode
		context  map[string]bool
		expected bool
	}{
		{
			name: "(a_and_b)_or_c",
			node: &BinaryOpNode{
				Operator: OpOR,
				Left: &BinaryOpNode{
					Operator: OpAND,
					Left:     &IdentifierNode{Name: "a"},
					Right:    &IdentifierNode{Name: "b"},
				},
				Right: &IdentifierNode{Name: "c"},
			},
			context:  map[string]bool{"a": false, "b": true, "c": true},
			expected: true,
		},
		{
			name: "a_and_(b_or_c)",
			node: &BinaryOpNode{
				Operator: OpAND,
				Left:     &IdentifierNode{Name: "a"},
				Right: &BinaryOpNode{
					Operator: OpOR,
					Left:     &IdentifierNode{Name: "b"},
					Right:    &IdentifierNode{Name: "c"},
				},
			},
			context:  map[string]bool{"a": true, "b": false, "c": true},
			expected: true,
		},
		{
			name: "(a_and_not_b)_or_(c_and_d)",
			node: &BinaryOpNode{
				Operator: OpOR,
				Left: &BinaryOpNode{
					Operator: OpAND,
					Left:     &IdentifierNode{Name: "a"},
					Right: &NotNode{
						Child: &IdentifierNode{Name: "b"},
					},
				},
				Right: &BinaryOpNode{
					Operator: OpAND,
					Left:     &IdentifierNode{Name: "c"},
					Right:    &IdentifierNode{Name: "d"},
				},
			},
			context:  map[string]bool{"a": true, "b": false, "c": false, "d": true},
			expected: true,
		},
		{
			name: "not_(a_or_b)",
			node: &NotNode{
				Child: &BinaryOpNode{
					Operator: OpOR,
					Left:     &IdentifierNode{Name: "a"},
					Right:    &IdentifierNode{Name: "b"},
				},
			},
			context:  map[string]bool{"a": false, "b": false},
			expected: true,
		},
		{
			name: "not_not_a",
			node: &NotNode{
				Child: &NotNode{
					Child: &IdentifierNode{Name: "a"},
				},
			},
			context:  map[string]bool{"a": true},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.node.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIntegration_ParseAndEvaluate tests end-to-end parse and evaluate.
func TestIntegration_ParseAndEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		context    map[string]bool
		expected   bool
	}{
		{
			name:       "simple_and",
			expression: "a and b",
			context:    map[string]bool{"a": true, "b": true},
			expected:   true,
		},
		{
			name:       "simple_or",
			expression: "a or b",
			context:    map[string]bool{"a": false, "b": true},
			expected:   true,
		},
		{
			name:       "simple_not",
			expression: "not a",
			context:    map[string]bool{"a": false},
			expected:   true,
		},
		{
			name:       "complex_with_parens",
			expression: "(a and b) or (c and d)",
			context:    map[string]bool{"a": false, "b": true, "c": true, "d": true},
			expected:   true,
		},
		{
			name:       "complex_with_not",
			expression: "a and not b",
			context:    map[string]bool{"a": true, "b": false},
			expected:   true,
		},
		{
			name:       "nested_not",
			expression: "not (a or b)",
			context:    map[string]bool{"a": false, "b": false},
			expected:   true,
		},
		{
			name:       "left_associative_and",
			expression: "a and b and c",
			context:    map[string]bool{"a": true, "b": true, "c": true},
			expected:   true,
		},
		{
			name:       "left_associative_or",
			expression: "a or b or c",
			context:    map[string]bool{"a": false, "b": false, "c": true},
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.Parse(tt.expression)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			result, err := ast.Evaluate(tt.context)
			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIntegration_ParseAndEvaluateWithAggregation tests aggregation end-to-end.
func TestIntegration_ParseAndEvaluateWithAggregation(t *testing.T) {
	tests := []struct {
		name                string
		expression          string
		availableIDs        []string
		context             map[string]bool
		expected            bool
		expectParseError    bool
		expectEvaluateError bool
	}{
		{
			name:         "all_of_them",
			expression:   "all of them",
			availableIDs: []string{"sel1", "sel2", "sel3"},
			context:      map[string]bool{"sel1": true, "sel2": true, "sel3": true},
			expected:     true,
		},
		{
			name:         "any_of_them",
			expression:   "any of them",
			availableIDs: []string{"sel1", "sel2"},
			context:      map[string]bool{"sel1": false, "sel2": true},
			expected:     true,
		},
		{
			name:         "1_of_pattern",
			expression:   "1 of sel*",
			availableIDs: []string{"sel1", "sel2", "filter"},
			context:      map[string]bool{"sel1": true, "sel2": false, "filter": false},
			expected:     true,
		},
		{
			name:         "2_of_pattern",
			expression:   "2 of sel*",
			availableIDs: []string{"sel1", "sel2", "sel3"},
			context:      map[string]bool{"sel1": true, "sel2": true, "sel3": false},
			expected:     true,
		},
		{
			name:         "aggregation_and_identifier",
			expression:   "all of sel* and filter",
			availableIDs: []string{"sel1", "sel2", "filter"},
			context:      map[string]bool{"sel1": true, "sel2": true, "filter": true},
			expected:     true,
		},
		{
			name:         "aggregation_or_identifier",
			expression:   "1 of sel* or filter",
			availableIDs: []string{"sel1", "sel2", "filter"},
			context:      map[string]bool{"sel1": false, "sel2": false, "filter": true},
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewConditionParser()
			ast, err := parser.ParseWithContext(tt.expression, tt.availableIDs)

			if tt.expectParseError {
				if err == nil {
					t.Fatal("expected parse error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			result, err := ast.Evaluate(tt.context)

			if tt.expectEvaluateError {
				if err == nil {
					t.Fatal("expected evaluation error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestShortCircuit_ComplexNesting verifies short-circuit in deep nesting.
func TestShortCircuit_ComplexNesting(t *testing.T) {
	// Test: (false AND a) OR b
	// The 'a' should NOT be evaluated due to short-circuit
	tracker := newEvaluationTracker()
	tracker.register("a")
	tracker.register("b")

	tc := newTrackingContext(map[string]bool{
		"a": true,
		"b": true,
	}, tracker)

	falseNode := &trackingIdentifierNode{name: "false", tc: &trackingContext{
		values:  map[string]bool{"false": false},
		tracker: tracker,
	}}
	aNode := &trackingIdentifierNode{name: "a", tc: tc}
	bNode := &trackingIdentifierNode{name: "b", tc: tc}

	node := &BinaryOpNode{
		Operator: OpOR,
		Left: &BinaryOpNode{
			Operator: OpAND,
			Left:     falseNode,
			Right:    aNode,
		},
		Right: bNode,
	}

	result, err := node.Evaluate(map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != true {
		t.Errorf("expected true, got %v", result)
	}

	// 'a' should NOT be evaluated (short-circuit in AND)
	if tracker.accessed("a") != 0 {
		t.Errorf("'a' should not be evaluated due to short-circuit, accessed %d times", tracker.accessed("a"))
	}

	// 'b' MUST be evaluated (OR right side)
	if tracker.accessed("b") != 1 {
		t.Errorf("'b' should be evaluated, accessed %d times", tracker.accessed("b"))
	}
}

// TestShortCircuit_NoEvaluationWaste verifies minimal evaluation.
func TestShortCircuit_NoEvaluationWaste(t *testing.T) {
	// Test: true OR (a AND b AND c AND d)
	// None of a, b, c, d should be evaluated
	tracker := newEvaluationTracker()
	for _, name := range []string{"a", "b", "c", "d"} {
		tracker.register(name)
	}

	values := map[string]bool{
		"true": true,
		"a":    true,
		"b":    true,
		"c":    true,
		"d":    true,
	}

	tc := newTrackingContext(values, tracker)

	trueNode := &trackingIdentifierNode{name: "true", tc: tc}

	// Build complex right side: a AND b AND c AND d
	rightSide := &BinaryOpNode{
		Operator: OpAND,
		Left: &BinaryOpNode{
			Operator: OpAND,
			Left: &BinaryOpNode{
				Operator: OpAND,
				Left:     &trackingIdentifierNode{name: "a", tc: tc},
				Right:    &trackingIdentifierNode{name: "b", tc: tc},
			},
			Right: &trackingIdentifierNode{name: "c", tc: tc},
		},
		Right: &trackingIdentifierNode{name: "d", tc: tc},
	}

	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     trueNode,
		Right:    rightSide,
	}

	result, err := node.Evaluate(map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != true {
		t.Errorf("expected true, got %v", result)
	}

	// None of a, b, c, d should be evaluated
	for _, name := range []string{"a", "b", "c", "d"} {
		if tracker.accessed(name) != 0 {
			t.Errorf("'%s' should not be evaluated due to short-circuit, accessed %d times", name, tracker.accessed(name))
		}
	}
}

// TestErrorMessages verifies descriptive error messages.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		node     ConditionNode
		context  map[string]bool
		errorMsg string
	}{
		{
			name:     "identifier_not_found",
			node:     &IdentifierNode{Name: "unknown"},
			context:  map[string]bool{"known": true},
			errorMsg: "identifier 'unknown' not found in evaluation context",
		},
		{
			name: "aggregation_identifier_not_found",
			node: &AggregationNode{
				Type:        AggAll,
				Pattern:     "sel*",
				Identifiers: []string{"sel1", "sel2"},
				Count:       0,
			},
			context:  map[string]bool{"sel1": true},
			errorMsg: "identifier 'sel2' not found in evaluation context (aggregation: all of sel*)",
		},
		{
			name: "left_operand_error",
			node: &BinaryOpNode{
				Operator: OpAND,
				Left:     &IdentifierNode{Name: "missing"},
				Right:    &IdentifierNode{Name: "right"},
			},
			context:  map[string]bool{"right": true},
			errorMsg: "failed to evaluate left operand of AND",
		},
		{
			name: "right_operand_error",
			node: &BinaryOpNode{
				Operator: OpOR,
				Left:     &IdentifierNode{Name: "left"},
				Right:    &IdentifierNode{Name: "missing"},
			},
			context:  map[string]bool{"left": false},
			errorMsg: "failed to evaluate right operand of OR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.node.Evaluate(tt.context)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errorMsg)
			}

			if !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
			}
		})
	}
}

// TestEdgeCases tests boundary conditions.
func TestEdgeCases(t *testing.T) {
	t.Run("empty_context_map", func(t *testing.T) {
		node := &IdentifierNode{Name: "test"}
		result, err := node.Evaluate(map[string]bool{})

		if err == nil {
			t.Fatal("expected error for empty context")
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected 'not found' error, got: %v", err)
		}

		if result != false {
			t.Errorf("expected false result, got %v", result)
		}
	})

	t.Run("aggregation_single_identifier", func(t *testing.T) {
		node := &AggregationNode{
			Type:        AggAll,
			Pattern:     "single",
			Identifiers: []string{"single"},
			Count:       0,
		}
		context := map[string]bool{"single": true}

		result, err := node.Evaluate(context)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != true {
			t.Errorf("expected true, got %v", result)
		}
	})

	t.Run("aggregation_count_equals_identifiers", func(t *testing.T) {
		node := &AggregationNode{
			Type:        AggCount,
			Pattern:     "sel*",
			Identifiers: []string{"sel1", "sel2", "sel3"},
			Count:       3,
		}
		context := map[string]bool{"sel1": true, "sel2": true, "sel3": true}

		result, err := node.Evaluate(context)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != true {
			t.Errorf("expected true, got %v", result)
		}
	})
}

// Benchmark_ShortCircuitAND benchmarks AND short-circuit performance.
func Benchmark_ShortCircuitAND(b *testing.B) {
	node := &BinaryOpNode{
		Operator: OpAND,
		Left:     &IdentifierNode{Name: "left"},
		Right:    &IdentifierNode{Name: "right"},
	}
	context := map[string]bool{"left": false, "right": true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = node.Evaluate(context)
	}
}

// Benchmark_ShortCircuitOR benchmarks OR short-circuit performance.
func Benchmark_ShortCircuitOR(b *testing.B) {
	node := &BinaryOpNode{
		Operator: OpOR,
		Left:     &IdentifierNode{Name: "left"},
		Right:    &IdentifierNode{Name: "right"},
	}
	context := map[string]bool{"left": true, "right": false}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = node.Evaluate(context)
	}
}

// Benchmark_ComplexExpression benchmarks nested evaluation.
func Benchmark_ComplexExpression(b *testing.B) {
	// (a AND b) OR (c AND d)
	node := &BinaryOpNode{
		Operator: OpOR,
		Left: &BinaryOpNode{
			Operator: OpAND,
			Left:     &IdentifierNode{Name: "a"},
			Right:    &IdentifierNode{Name: "b"},
		},
		Right: &BinaryOpNode{
			Operator: OpAND,
			Left:     &IdentifierNode{Name: "c"},
			Right:    &IdentifierNode{Name: "d"},
		},
	}
	context := map[string]bool{"a": true, "b": true, "c": false, "d": true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = node.Evaluate(context)
	}
}

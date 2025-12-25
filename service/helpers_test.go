package service

import (
	"testing"
)

// ============================================================================
// deepCopyValue Tests
// ============================================================================

func TestDeepCopyValue_Nil(t *testing.T) {
	result := deepCopyValue(nil)
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}
}

func TestDeepCopyValue_Primitives(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
	}{
		{"string", "test string"},
		{"int", 42},
		{"int64", int64(12345)},
		{"float64", 3.14159},
		{"bool true", true},
		{"bool false", false},
		{"empty string", ""},
		{"zero int", 0},
		{"zero float", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deepCopyValue(tt.value)
			if result != tt.value {
				t.Errorf("Expected %v, got %v", tt.value, result)
			}
		})
	}
}

func TestDeepCopyValue_SimpleMap(t *testing.T) {
	original := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	copied := deepCopyValue(original)

	// Verify it's a map
	copiedMap, ok := copied.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{}")
	}

	// Verify values match
	if copiedMap["key1"] != "value1" {
		t.Errorf("Expected key1='value1', got %v", copiedMap["key1"])
	}
	if copiedMap["key2"] != 42 {
		t.Errorf("Expected key2=42, got %v", copiedMap["key2"])
	}
	if copiedMap["key3"] != true {
		t.Errorf("Expected key3=true, got %v", copiedMap["key3"])
	}

	// Verify it's a different instance
	copiedMap["key4"] = "new value"
	if _, exists := original["key4"]; exists {
		t.Error("Modifying copy affected original map")
	}
}

func TestDeepCopyValue_NestedMap(t *testing.T) {
	original := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner1": "value1",
			"inner2": map[string]interface{}{
				"deep": "nested",
			},
		},
		"top": "level",
	}

	copied := deepCopyValue(original)

	// Verify structure
	copiedMap, ok := copied.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{}")
	}

	outer, ok := copiedMap["outer"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected nested map")
	}

	if outer["inner1"] != "value1" {
		t.Errorf("Expected inner1='value1', got %v", outer["inner1"])
	}

	inner2, ok := outer["inner2"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected deeply nested map")
	}

	if inner2["deep"] != "nested" {
		t.Errorf("Expected deep='nested', got %v", inner2["deep"])
	}

	// Verify mutation protection
	inner2["modified"] = "value"
	originalOuter := original["outer"].(map[string]interface{})
	originalInner2 := originalOuter["inner2"].(map[string]interface{})
	if _, exists := originalInner2["modified"]; exists {
		t.Error("Modifying nested copy affected original")
	}
}

func TestDeepCopyValue_SimpleSlice(t *testing.T) {
	original := []interface{}{"a", "b", "c", 1, 2, 3}

	copied := deepCopyValue(original)

	// Verify it's a slice
	copiedSlice, ok := copied.([]interface{})
	if !ok {
		t.Fatal("Expected []interface{}")
	}

	// Verify values match
	if len(copiedSlice) != len(original) {
		t.Errorf("Expected length %d, got %d", len(original), len(copiedSlice))
	}

	for i, v := range original {
		if copiedSlice[i] != v {
			t.Errorf("Index %d: expected %v, got %v", i, v, copiedSlice[i])
		}
	}

	// Verify it's a different instance
	copiedSlice[0] = "modified"
	if original[0] == "modified" {
		t.Error("Modifying copy affected original slice")
	}
}

func TestDeepCopyValue_NestedSlice(t *testing.T) {
	original := []interface{}{
		"top",
		[]interface{}{"nested1", "nested2"},
		map[string]interface{}{
			"key": "value",
		},
	}

	copied := deepCopyValue(original)

	// Verify structure
	copiedSlice, ok := copied.([]interface{})
	if !ok {
		t.Fatal("Expected []interface{}")
	}

	if copiedSlice[0] != "top" {
		t.Errorf("Expected 'top', got %v", copiedSlice[0])
	}

	nested, ok := copiedSlice[1].([]interface{})
	if !ok {
		t.Fatal("Expected nested slice")
	}

	if nested[0] != "nested1" {
		t.Errorf("Expected 'nested1', got %v", nested[0])
	}

	nestedMap, ok := copiedSlice[2].(map[string]interface{})
	if !ok {
		t.Fatal("Expected nested map")
	}

	if nestedMap["key"] != "value" {
		t.Errorf("Expected 'value', got %v", nestedMap["key"])
	}

	// Verify mutation protection
	nested[0] = "modified"
	originalNested := original[1].([]interface{})
	if originalNested[0] == "modified" {
		t.Error("Modifying nested slice affected original")
	}
}

func TestDeepCopyValue_MixedStructure(t *testing.T) {
	// Complex structure combining maps, slices, and primitives
	original := map[string]interface{}{
		"string_field": "test",
		"int_field":    42,
		"bool_field":   true,
		"array_field": []interface{}{
			"item1",
			map[string]interface{}{
				"nested": "value",
			},
			[]interface{}{1, 2, 3},
		},
		"map_field": map[string]interface{}{
			"nested_array": []interface{}{"a", "b", "c"},
			"nested_map": map[string]interface{}{
				"deep": "value",
			},
		},
	}

	copied := deepCopyValue(original)

	// Verify it's a map
	copiedMap, ok := copied.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{}")
	}

	// Verify primitive fields
	if copiedMap["string_field"] != "test" {
		t.Error("String field not copied correctly")
	}
	if copiedMap["int_field"] != 42 {
		t.Error("Int field not copied correctly")
	}
	if copiedMap["bool_field"] != true {
		t.Error("Bool field not copied correctly")
	}

	// Verify array field
	arrayField, ok := copiedMap["array_field"].([]interface{})
	if !ok {
		t.Fatal("Expected array_field to be slice")
	}
	if arrayField[0] != "item1" {
		t.Error("Array element not copied correctly")
	}

	// Verify mutation protection at multiple levels
	copiedMap["new_field"] = "new"
	if _, exists := original["new_field"]; exists {
		t.Error("Top-level modification affected original")
	}

	arrayField[0] = "modified"
	if original["array_field"].([]interface{})[0] == "modified" {
		t.Error("Array modification affected original")
	}

	mapField := copiedMap["map_field"].(map[string]interface{})
	mapField["new_key"] = "new_value"
	originalMapField := original["map_field"].(map[string]interface{})
	if _, exists := originalMapField["new_key"]; exists {
		t.Error("Map field modification affected original")
	}
}

func TestDeepCopyValue_EmptyContainers(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
	}{
		{"empty map", map[string]interface{}{}},
		{"empty slice", []interface{}{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copied := deepCopyValue(tt.value)

			switch original := tt.value.(type) {
			case map[string]interface{}:
				copiedMap, ok := copied.(map[string]interface{})
				if !ok {
					t.Fatal("Expected map[string]interface{}")
				}
				if len(copiedMap) != 0 {
					t.Error("Expected empty map")
				}
				// Verify different instances
				copiedMap["key"] = "value"
				if len(original) != 0 {
					t.Error("Modifying copy affected original empty map")
				}

			case []interface{}:
				copiedSlice, ok := copied.([]interface{})
				if !ok {
					t.Fatal("Expected []interface{}")
				}
				if len(copiedSlice) != 0 {
					t.Error("Expected empty slice")
				}
			}
		})
	}
}

func TestDeepCopyValue_LargeStructure(t *testing.T) {
	// Test with a larger structure to ensure performance is reasonable
	original := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		original[string(rune(i))] = map[string]interface{}{
			"index": i,
			"data":  []interface{}{i, i + 1, i + 2},
		}
	}

	copied := deepCopyValue(original)

	copiedMap, ok := copied.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{}")
	}

	if len(copiedMap) != 100 {
		t.Errorf("Expected 100 entries, got %d", len(copiedMap))
	}

	// Verify structure is intact
	for i := 0; i < 100; i++ {
		key := string(rune(i))
		entry, ok := copiedMap[key].(map[string]interface{})
		if !ok {
			t.Fatalf("Entry %d not a map", i)
		}
		if entry["index"] != i {
			t.Errorf("Entry %d index mismatch", i)
		}
	}

	// Verify mutation protection
	entry0 := copiedMap[string(rune(0))].(map[string]interface{})
	entry0["modified"] = true
	originalEntry0 := original[string(rune(0))].(map[string]interface{})
	if _, exists := originalEntry0["modified"]; exists {
		t.Error("Modifying large structure copy affected original")
	}
}

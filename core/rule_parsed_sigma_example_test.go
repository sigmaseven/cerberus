package core_test

import (
	"fmt"
	"log"

	"cerberus/core"
)

// ExampleRule_ParsedSigmaRule demonstrates basic usage of ParsedSigmaRule
func ExampleRule_ParsedSigmaRule() {
	rule := &core.Rule{
		ID:   "example-rule",
		Type: "sigma",
		SigmaYAML: `
title: Example SIGMA Rule
id: example-123
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
level: medium
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		log.Fatalf("Failed to parse SIGMA YAML: %v", err)
	}

	// Access parsed fields
	title := parsed["title"].(string)
	level := parsed["level"].(string)

	fmt.Printf("Title: %s\n", title)
	fmt.Printf("Level: %s\n", level)

	// Output:
	// Title: Example SIGMA Rule
	// Level: medium
}

// ExampleRule_ParsedSigmaRule_errorHandling demonstrates error handling
func ExampleRule_ParsedSigmaRule_errorHandling() {
	// Empty sigma_yaml field
	rule := &core.Rule{
		ID:        "empty-rule",
		Type:      "sigma",
		SigmaYAML: "",
	}

	_, err := rule.ParsedSigmaRule()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Output:
	// Error: sigma_yaml field is empty
}

// ExampleRule_ParsedSigmaRule_nestedAccess demonstrates accessing nested fields
func ExampleRule_ParsedSigmaRule_nestedAccess() {
	rule := &core.Rule{
		ID:   "nested-example",
		Type: "sigma",
		SigmaYAML: `
title: Nested Field Example
logsource:
  category: file_event
  product: linux
  service: auditd
detection:
  selection:
    action: create
    path: /tmp/
  condition: selection
level: low
`,
	}

	parsed, err := rule.ParsedSigmaRule()
	if err != nil {
		log.Fatalf("Failed to parse: %v", err)
	}

	// Access nested logsource fields
	logsource, ok := parsed["logsource"].(map[string]interface{})
	if !ok {
		log.Fatal("logsource not found")
	}

	category := logsource["category"].(string)
	product := logsource["product"].(string)

	fmt.Printf("Category: %s\n", category)
	fmt.Printf("Product: %s\n", product)

	// Output:
	// Category: file_event
	// Product: linux
}

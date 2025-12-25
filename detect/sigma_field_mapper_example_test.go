package detect_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"cerberus/core"
	"cerberus/detect"
)

// ExampleFieldMapper_basic demonstrates basic field mapping usage
func ExampleFieldMapper_basic() {
	// Create a new field mapper
	fm := detect.NewFieldMapper()

	// Create a temporary config for demonstration
	configContent := `
generic:
  process: Image
  command: CommandLine
  user: User

windows_sysmon:
  image: Image
  command_line: CommandLine
  process_id: ProcessId
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	// Load mappings from config file
	if err := fm.LoadMappings(tmpFile); err != nil {
		log.Fatalf("Failed to load mappings: %v", err)
	}

	// Define a logsource (from a SIGMA rule)
	logsource := map[string]interface{}{
		"product": "windows",
		"service": "sysmon",
	}

	// Map field names
	field1 := fm.MapField("image", logsource)
	field2 := fm.MapField("command_line", logsource)
	field3 := fm.MapField("process", logsource) // Falls back to generic

	fmt.Println(field1)
	fmt.Println(field2)
	fmt.Println(field3)

	// Output:
	// Image
	// CommandLine
	// Image
}

// ExampleFieldMapper_GetEventFieldValue demonstrates extracting field values from events
func ExampleFieldMapper_GetEventFieldValue() {
	fm := detect.NewFieldMapper()

	// Create a sample event
	event := &core.Event{
		EventID:   "evt-123",
		EventType: "process_creation",
		Fields: map[string]interface{}{
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "cmd.exe /c whoami",
			"ProcessId":   4567,
		},
	}

	// Extract field values
	image, found := fm.GetEventFieldValue(event, "Image")
	if found {
		fmt.Printf("Image: %v\n", image)
	}

	cmdLine, found := fm.GetEventFieldValue(event, "CommandLine")
	if found {
		fmt.Printf("CommandLine: %v\n", cmdLine)
	}

	pid, found := fm.GetEventFieldValue(event, "ProcessId")
	if found {
		fmt.Printf("ProcessId: %v\n", pid)
	}

	// Output:
	// Image: C:\Windows\System32\cmd.exe
	// CommandLine: cmd.exe /c whoami
	// ProcessId: 4567
}

// ExampleFieldMapper_MapFieldWithContext demonstrates mapping with context information
func ExampleFieldMapper_MapFieldWithContext() {
	fm := detect.NewFieldMapper()

	configContent := `
generic:
  process: Image

windows_sysmon:
  image: Image
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	fm.LoadMappings(tmpFile)

	logsource := map[string]interface{}{
		"product": "windows",
		"service": "sysmon",
	}

	// Map with context to see which mapping was used
	mappedField, source := fm.MapFieldWithContext("image", logsource)
	fmt.Printf("Field: %s, Source: %s\n", mappedField, source)

	mappedField, source = fm.MapFieldWithContext("unknown_field", logsource)
	fmt.Printf("Field: %s, Source: %s\n", mappedField, source)

	// Output:
	// Field: Image, Source: logsource:windows_sysmon
	// Field: unknown_field, Source: passthrough
}

// ExampleFieldMapper_GetStats demonstrates getting mapping statistics
func ExampleFieldMapper_GetStats() {
	fm := detect.NewFieldMapper()

	configContent := `
generic:
  process: Image
  user: User

windows_sysmon:
  image: Image
  command_line: CommandLine
  process_id: ProcessId
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	fm.LoadMappings(tmpFile)

	stats := fm.GetStats()
	fmt.Printf("Logsource count: %d\n", stats.LogsourceCount)
	fmt.Printf("Generic field count: %d\n", stats.GenericFieldCount)
	fmt.Printf("Total field mappings: %d\n", stats.TotalFieldMappings)

	// Output:
	// Logsource count: 1
	// Generic field count: 2
	// Total field mappings: 5
}

// ExampleInitGlobalFieldMapper demonstrates initializing the global field mapper
func ExampleInitGlobalFieldMapper() {
	// Create a config file
	configContent := `
generic:
  process: Image
  command: CommandLine
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	// Initialize global field mapper (typically done at application startup)
	ctx := context.Background()
	if err := detect.InitGlobalFieldMapper(ctx, tmpFile); err != nil {
		log.Fatalf("Failed to initialize global field mapper: %v", err)
	}

	// Get the global instance
	fm := detect.GetGlobalFieldMapper()
	if fm == nil {
		log.Fatal("Global field mapper not initialized")
	}

	// Use it
	logsource := map[string]interface{}{
		"product": "linux",
	}
	mapped := fm.MapField("process", logsource)

	fmt.Println(mapped)

	// Output:
	// Image
}

// ExampleFieldMapper_fallbackChain demonstrates the 4-level fallback chain
func ExampleFieldMapper_fallbackChain() {
	fm := detect.NewFieldMapper()

	configContent := `
generic:
  generic_field: GenericMapping

windows_sysmon:
  sysmon_field: SysmonMapping
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	fm.LoadMappings(tmpFile)

	logsource := map[string]interface{}{
		"product": "windows",
		"service": "sysmon",
	}

	// Level 1: Logsource-specific mapping
	field1 := fm.MapField("sysmon_field", logsource)
	fmt.Printf("Level 1 (logsource): %s\n", field1)

	// Level 2: Generic mapping
	field2 := fm.MapField("generic_field", logsource)
	fmt.Printf("Level 2 (generic): %s\n", field2)

	// Level 3: core.FieldAliases (pid -> ProcessId)
	field3 := fm.MapField("pid", logsource)
	fmt.Printf("Level 3 (alias): %s\n", field3)

	// Level 4: Pass-through (no mapping found)
	field4 := fm.MapField("CustomField", logsource)
	fmt.Printf("Level 4 (passthrough): %s\n", field4)

	// Output:
	// Level 1 (logsource): SysmonMapping
	// Level 2 (generic): GenericMapping
	// Level 3 (alias): ProcessId
	// Level 4 (passthrough): CustomField
}

// Helper function to create temporary config file
func createExampleConfig(content string) string {
	tmpFile, err := os.CreateTemp("", "example_field_mapping_*.yaml")
	if err != nil {
		log.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		log.Fatalf("Failed to write temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		log.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}

// ExampleFieldMapper_productionUsage demonstrates production usage pattern
func ExampleFieldMapper_productionUsage() {
	// In production, initialize once at startup
	// For this example, we'll use a local config
	configContent := `
windows_sysmon:
  image: Image
  command_line: CommandLine
  parent_image: ParentImage
`
	tmpFile := createExampleConfig(configContent)
	defer os.Remove(tmpFile)

	// Create a local field mapper for this example
	fm := detect.NewFieldMapper()
	if err := fm.LoadMappings(tmpFile); err != nil {
		log.Fatalf("Failed to load mappings: %v", err)
	}

	// When evaluating a SIGMA rule, extract logsource from the rule
	logsource := map[string]interface{}{
		"product":  "windows",
		"service":  "sysmon",
		"category": "process_creation",
	}

	// Map field names from SIGMA rule to internal field names
	detectionFields := []string{"image", "command_line", "parent_image"}
	for _, field := range detectionFields {
		mapped := fm.MapField(field, logsource)
		fmt.Printf("SIGMA field %q maps to %q\n", field, mapped)
	}

	// Output:
	// SIGMA field "image" maps to "Image"
	// SIGMA field "command_line" maps to "CommandLine"
	// SIGMA field "parent_image" maps to "ParentImage"
}

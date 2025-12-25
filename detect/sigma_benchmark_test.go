package detect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"cerberus/core"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// benchmarkLogger creates a no-op logger for benchmark tests
func benchmarkLogger() *zap.SugaredLogger {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	logger, _ := config.Build()
	return logger.Sugar()
}

// BenchmarkSigmaEngine_SimpleRule benchmarks simple rule evaluation
func BenchmarkSigmaEngine_SimpleRule(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-simple",
		Type: "sigma",
		SigmaYAML: `
title: Simple Benchmark Rule
id: bench-simple
logsource:
    category: process_creation
detection:
    selection:
        Image: 'C:\Windows\System32\cmd.exe'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image": `C:\Windows\System32\cmd.exe`,
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_ComplexCondition benchmarks complex condition evaluation
func BenchmarkSigmaEngine_ComplexCondition(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-complex",
		Type: "sigma",
		SigmaYAML: `
title: Complex Benchmark Rule
id: bench-complex
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_powershell:
        Image|endswith: '\powershell.exe'
    selection_args:
        CommandLine|contains:
            - '-enc'
            - '-ExecutionPolicy'
            - 'bypass'
    filter_system:
        User: 'SYSTEM'
        ParentImage|endswith: '\services.exe'
    condition: (selection_cmd or selection_powershell) and selection_args and not filter_system
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": `powershell.exe -enc aWVYIChOZXctT2JqZWN0`,
			"User":        `DOMAIN\admin`,
			"ParentImage": `C:\Windows\explorer.exe`,
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_ContainsModifier benchmarks contains modifier
func BenchmarkSigmaEngine_ContainsModifier(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-contains",
		Type: "sigma",
		SigmaYAML: `
title: Contains Benchmark Rule
id: bench-contains
logsource:
    category: test
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
            - 'cmd'
            - 'wscript'
            - 'cscript'
            - 'mshta'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"CommandLine": `C:\Windows\System32\mshta.exe javascript:code`,
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_RegexModifier benchmarks regex modifier
func BenchmarkSigmaEngine_RegexModifier(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-regex",
		Type: "sigma",
		SigmaYAML: `
title: Regex Benchmark Rule
id: bench-regex
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '(powershell|cmd|wscript)\.exe.*-[eE](nc|xec)'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"CommandLine": `powershell.exe -enc aWVYIChOZXctT2JqZWN0`,
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_CIDRModifier benchmarks CIDR modifier
func BenchmarkSigmaEngine_CIDRModifier(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-cidr",
		Type: "sigma",
		SigmaYAML: `
title: CIDR Benchmark Rule
id: bench-cidr
logsource:
    category: network
detection:
    selection:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"DestinationIp": "192.168.1.100",
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_LargeValueList benchmarks rule with large value list
func BenchmarkSigmaEngine_LargeValueList(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	// Build a list of 100 values
	var values []string
	for i := 0; i < 100; i++ {
		values = append(values, fmt.Sprintf("malware%d.exe", i))
	}
	valueListYAML := "            - '" + strings.Join(values, "'\n            - '") + "'"

	rule := &core.Rule{
		ID:   "bench-large-list",
		Type: "sigma",
		SigmaYAML: fmt.Sprintf(`
title: Large List Benchmark Rule
id: bench-large-list
logsource:
    category: test
detection:
    selection:
        Image|endswith:
%s
    condition: selection
`, valueListYAML),
		Enabled: true,
	}

	// Test with value that matches the last item
	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image": `C:\temp\malware99.exe`,
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_LargeEvent benchmarks evaluation with large event
func BenchmarkSigmaEngine_LargeEvent(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-large-event",
		Type: "sigma",
		SigmaYAML: `
title: Large Event Benchmark Rule
id: bench-large-event
logsource:
    category: test
detection:
    selection:
        field_target: 'target_value'
    condition: selection
`,
		Enabled: true,
	}

	// Event with 500 fields
	fields := make(map[string]interface{})
	for i := 0; i < 500; i++ {
		fields[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}
	fields["field_target"] = "target_value"

	event := &core.Event{
		EventID: "bench-event",
		Fields:  fields,
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_CacheHit benchmarks cache hit performance
func BenchmarkSigmaEngine_CacheHit(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-cache",
		Type: "sigma",
		SigmaYAML: `
title: Cache Benchmark Rule
id: bench-cache
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image": `C:\Windows\System32\cmd.exe`,
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.EventID = fmt.Sprintf("event-%d", i)
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_CacheMiss benchmarks cache miss performance
func BenchmarkSigmaEngine_CacheMiss(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image": `C:\Windows\System32\cmd.exe`,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := &core.Rule{
			ID:   fmt.Sprintf("bench-miss-%d", i),
			Type: "sigma",
			SigmaYAML: fmt.Sprintf(`
title: Cache Miss Benchmark Rule %d
id: bench-miss-%d
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
`, i, i),
			Enabled: true,
		}
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_ParallelEvaluation benchmarks parallel rule evaluation
func BenchmarkSigmaEngine_ParallelEvaluation(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-parallel",
		Type: "sigma",
		SigmaYAML: `
title: Parallel Benchmark Rule
id: bench-parallel
logsource:
    category: test
detection:
    selection:
        Image|contains: 'test'
    condition: selection
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"Image": "test_process.exe",
		},
	}

	// Warm up cache
	engine.Evaluate(rule, event)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		localEvent := &core.Event{
			EventID: "parallel-event",
			Fields:  event.Fields,
		}
		for pb.Next() {
			engine.Evaluate(rule, localEvent)
		}
	})
}

// BenchmarkSigmaEngine_AllOfThem benchmarks "all of them" aggregation
func BenchmarkSigmaEngine_AllOfThem(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-all-of-them",
		Type: "sigma",
		SigmaYAML: `
title: All Of Them Benchmark Rule
id: bench-all-of-them
logsource:
    category: test
detection:
    selection1:
        field1: 'value1'
    selection2:
        field2: 'value2'
    selection3:
        field3: 'value3'
    selection4:
        field4: 'value4'
    selection5:
        field5: 'value5'
    condition: all of them
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"field1": "value1",
			"field2": "value2",
			"field3": "value3",
			"field4": "value4",
			"field5": "value5",
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

// BenchmarkSigmaEngine_OneOfSelection benchmarks "1 of selection*" pattern
func BenchmarkSigmaEngine_OneOfSelection(b *testing.B) {
	engine := NewSigmaEngine(context.Background(), nil, benchmarkLogger())
	engine.Start()
	defer engine.Stop()

	rule := &core.Rule{
		ID:   "bench-one-of",
		Type: "sigma",
		SigmaYAML: `
title: One Of Selection Benchmark Rule
id: bench-one-of
logsource:
    category: test
detection:
    selection_windows:
        os: 'windows'
    selection_linux:
        os: 'linux'
    selection_macos:
        os: 'macos'
    selection_bsd:
        os: 'bsd'
    selection_solaris:
        os: 'solaris'
    condition: 1 of selection*
`,
		Enabled: true,
	}

	event := &core.Event{
		EventID: "bench-event",
		Fields: map[string]interface{}{
			"os": "windows",
		},
	}

	engine.Evaluate(rule, event)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(rule, event)
	}
}

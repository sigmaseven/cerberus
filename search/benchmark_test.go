package search

import (
	"testing"
)

func BenchmarkCQLParser(b *testing.B) {
	query := "src_ip = '192.168.1.100' AND dst_port > 1024 AND event_type = 'login'"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser := NewParser(query)
		_, _ = parser.Parse()
	}
}

func BenchmarkQueryExecution(b *testing.B) {
	query := "src_ip = '192.168.1.100'"
	parser := NewParser(query)
	ast, _ := parser.Parse()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ast
	}
}

func BenchmarkPagination(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = i % 100
	}
}

func BenchmarkAggregationQuery(b *testing.B) {
	query := "SELECT COUNT(*) FROM events WHERE src_ip = '192.168.1.100' GROUP BY hour(timestamp)"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser := NewParser(query)
		_, _ = parser.Parse()
	}
}

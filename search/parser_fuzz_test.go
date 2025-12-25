package search

import (
	"testing"
)

func FuzzParser(f *testing.F) {
	seedCases := []string{
		"src_ip = '192.168.1.100'",
		"src_ip = '192.168.1.100' AND dst_port > 1024",
		"event_type = 'login' OR event_type = 'logout'",
		"NOT (src_ip = '10.0.0.1')",
		"timestamp > '2025-01-01' AND timestamp < '2025-12-31'",
	}

	for _, seed := range seedCases {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 10000 {
			return
		}
		parser := NewParser(query)
		ast, err := parser.Parse()
		if err != nil {
			return
		}
		if ast == nil {
			t.Fatal("AST is nil but no error")
		}
	})
}

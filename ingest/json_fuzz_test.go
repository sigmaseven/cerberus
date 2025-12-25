package ingest

import (
	"testing"
)

func FuzzJSONParser(f *testing.F) {
	seedCases := []string{
		`{"event_type":"login","user":"test"}`,
		`{"event":{"type":"login","user":"test"}}`,
		`{"nested":{"deep":{"value":123}}}`,
		`{"array":[1,2,3]}`,
	}

	for _, seed := range seedCases {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 10*1024*1024 {
			return
		}
		_, _ = ParseJSON(data)
	})
}

package detect

import (
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

func FuzzRegexEngine(f *testing.F) {
	seedCases := []string{
		"^admin$",
		".*password.*",
		"192\\.168\\.1\\.[0-9]+",
		"test|example",
		"[a-zA-Z0-9]+",
	}

	for _, seed := range seedCases {
		f.Add(seed, "test input")
	}

	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 1000 || len(input) > 10000 {
			return
		}

		re, err := regexp2.Compile(pattern, 0)
		if err != nil {
			return
		}

		re.MatchTimeout = 500 * time.Millisecond
		_, _ = re.MatchString(input)
	})
}

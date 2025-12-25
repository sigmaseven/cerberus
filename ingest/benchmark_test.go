package ingest

import (
	"testing"

	"cerberus/core"

	"go.uber.org/zap"
)

func BenchmarkSyslogParser(b *testing.B) {
	data := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSyslog(data)
	}
}

func BenchmarkCEFParser(b *testing.B) {
	data := "CEF:0|Test|Test|1.0|100|Test Event|10|src=192.168.1.1 suser=admin"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseCEF(data)
	}
}

func BenchmarkJSONParser(b *testing.B) {
	data := `{"event_type":"user_login","fields":{"status":"failure","user":"testuser"}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseJSON(data)
	}
}

func BenchmarkConcurrentIngestion(b *testing.B) {
	logger := zap.NewNop().Sugar()
	eventCh := make(chan *core.Event, 1000)

	listener := NewSyslogListener("0.0.0.0", 514, 10000, eventCh, logger)
	_ = listener.Start()
	defer listener.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			data := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
			event, _ := ParseSyslog(data)
			select {
			case eventCh <- event:
			default:
			}
		}
	})
}

func BenchmarkLargePayloadParsing(b *testing.B) {
	largeData := make([]byte, 100*1024) // 100KB
	for i := range largeData {
		largeData[i] = 'A'
	}
	data := string(largeData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSyslog(data)
	}
}

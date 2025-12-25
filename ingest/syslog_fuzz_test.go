package ingest

import (
	"testing"
)

func FuzzSyslogParser(f *testing.F) {
	seedCases := []string{
		"<34>Oct 11 22:14:15 mymachine su: 'su root' failed",
		"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry...",
		"<0>test message",
		"<191>Jan 1 00:00:00 host app: test",
	}

	for _, seed := range seedCases {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 65535 {
			return
		}
		_, _ = ParseSyslog(data)
	})
}

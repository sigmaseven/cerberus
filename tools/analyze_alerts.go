//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

type AlertResponse struct {
	Items []struct {
		EventID  string `json:"event_id"`
		RuleName string `json:"rule_name"`
	} `json:"items"`
	Total int `json:"total"`
}

func main() {
	resp, err := http.Get("http://localhost:8080/api/v1/alerts?limit=100")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var data AlertResponse
	json.Unmarshal(body, &data)

	fmt.Printf("Total alerts: %d\n\n", data.Total)

	// Group by event ID
	eventRules := make(map[string][]string)
	for _, alert := range data.Items {
		eventRules[alert.EventID] = append(eventRules[alert.EventID], alert.RuleName)
	}

	fmt.Printf("Unique events that generated alerts: %d\n\n", len(eventRules))

	// Find events with multiple rules
	type eventCount struct {
		id    string
		rules []string
	}
	var multiMatch []eventCount
	for id, rules := range eventRules {
		if len(rules) > 1 {
			multiMatch = append(multiMatch, eventCount{id, rules})
		}
	}

	sort.Slice(multiMatch, func(i, j int) bool {
		return len(multiMatch[i].rules) > len(multiMatch[j].rules)
	})

	if len(multiMatch) > 0 {
		fmt.Println("Events matching multiple rules:")
		for _, e := range multiMatch {
			fmt.Printf("  Event %s... matched %d rules:\n", e.id[:8], len(e.rules))
			for _, r := range e.rules {
				fmt.Printf("    - %s\n", r)
			}
		}
	} else {
		fmt.Println("No events matched multiple rules.")
	}
}

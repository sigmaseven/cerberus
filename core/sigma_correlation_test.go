package core

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestSigmaCorrelation_YAML_Parsing tests YAML parsing of all 7 correlation types
func TestSigmaCorrelation_YAML_Parsing(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "event_count correlation",
			yaml: `
type: event_count
group_by:
  - source_ip
  - username
timespan: 5m
condition:
  operator: ">="
  value: 5
`,
			wantErr: false,
		},
		{
			name: "value_count correlation",
			yaml: `
type: value_count
distinct_field: username
group_by:
  - source_ip
timespan: 10m
condition:
  operator: ">="
  value: 10
`,
			wantErr: false,
		},
		{
			name: "sequence correlation ordered",
			yaml: `
type: sequence
timespan: 1h
ordered: true
events:
  - login_attempt
  - privilege_escalation
  - lateral_movement
group_by:
  - username
`,
			wantErr: false,
		},
		{
			name: "sequence correlation unordered",
			yaml: `
type: sequence
timespan: 30m
ordered: false
events:
  - dns_query
  - network_connection
group_by:
  - process_id
`,
			wantErr: false,
		},
		{
			name: "rare correlation",
			yaml: `
type: rare
baseline_window: 7d
distinct_field: process_name
timespan: 1h
condition:
  operator: "<"
  value: 3
`,
			wantErr: false,
		},
		{
			name: "statistical correlation",
			yaml: `
type: statistical
baseline_window: 30d
timespan: 1h
std_dev_threshold: 3.0
group_by:
  - source_ip
`,
			wantErr: false,
		},
		{
			name: "chain correlation",
			yaml: `
type: chain
max_duration: 24h
min_stages: 2
group_by:
  - source_ip
  - dest_ip
stages:
  - name: reconnaissance
    detection_ref: sigma_rule_recon_001
    timeout: 1h
  - name: exploitation
    detection_ref: sigma_rule_exploit_001
    timeout: 30m
  - name: privilege_escalation
    detection_ref: sigma_rule_privesc_001
    timeout: 15m
`,
			wantErr: false,
		},
		{
			name: "cross_entity correlation",
			yaml: `
type: cross_entity
track_field: username
count_distinct: dest_host
timespan: 15m
group_by:
  - source_network
condition:
  operator: ">="
  value: 5
`,
			wantErr: false,
		},
		{
			name: "temporal correlation",
			yaml: `
type: temporal
timespan: 2h
events:
  - event_a
  - event_b
  - event_c
group_by:
  - entity_id
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sc SigmaCorrelation
			err := yaml.Unmarshal([]byte(tt.yaml), &sc)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Validate parsed structure
				if err := sc.Validate(); err != nil {
					t.Errorf("Validate() error = %v", err)
				}
			}
		})
	}
}

// TestSigmaCorrelation_Validate tests validation of correlation types
func TestSigmaCorrelation_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid event_count",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "5m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name: "event_count missing condition",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "5m",
			},
			wantErr: true,
			errMsg:  "requires condition",
		},
		{
			name: "event_count missing timespan",
			sc: &SigmaCorrelation{
				Type: "event_count",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "requires timespan",
		},
		{
			name: "valid value_count",
			sc: &SigmaCorrelation{
				Type:          "value_count",
				DistinctField: "username",
				Timespan:      "10m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    10,
				},
			},
			wantErr: false,
		},
		{
			name: "value_count missing distinct_field",
			sc: &SigmaCorrelation{
				Type:     "value_count",
				Timespan: "10m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    10,
				},
			},
			wantErr: true,
			errMsg:  "requires distinct_field",
		},
		{
			name: "valid sequence",
			sc: &SigmaCorrelation{
				Type:     "sequence",
				Timespan: "1h",
				Events:   []string{"event1", "event2"},
			},
			wantErr: false,
		},
		{
			name: "sequence missing events",
			sc: &SigmaCorrelation{
				Type:     "sequence",
				Timespan: "1h",
			},
			wantErr: true,
			errMsg:  "requires at least one event",
		},
		{
			name: "valid rare",
			sc: &SigmaCorrelation{
				Type:           "rare",
				BaselineWindow: "7d",
				Condition: &CorrelationCondition{
					Operator: "<",
					Value:    3,
				},
			},
			wantErr: false,
		},
		{
			name: "rare missing baseline_window",
			sc: &SigmaCorrelation{
				Type: "rare",
				Condition: &CorrelationCondition{
					Operator: "<",
					Value:    3,
				},
			},
			wantErr: true,
			errMsg:  "requires baseline_window",
		},
		{
			name: "valid statistical",
			sc: &SigmaCorrelation{
				Type:            "statistical",
				BaselineWindow:  "30d",
				Timespan:        "1h",
				StdDevThreshold: 3.0,
			},
			wantErr: false,
		},
		{
			name: "statistical missing baseline_window",
			sc: &SigmaCorrelation{
				Type:            "statistical",
				Timespan:        "1h",
				StdDevThreshold: 3.0,
			},
			wantErr: true,
			errMsg:  "requires baseline_window",
		},
		{
			name: "statistical zero std_dev_threshold",
			sc: &SigmaCorrelation{
				Type:            "statistical",
				BaselineWindow:  "30d",
				Timespan:        "1h",
				StdDevThreshold: 0,
			},
			wantErr: true,
			errMsg:  "positive std_dev_threshold",
		},
		{
			name: "valid chain",
			sc: &SigmaCorrelation{
				Type:        "chain",
				MaxDuration: "24h",
				Stages: []SigmaChainStage{
					{Name: "stage1", DetectionRef: "rule1"},
				},
			},
			wantErr: false,
		},
		{
			name: "chain missing stages",
			sc: &SigmaCorrelation{
				Type:        "chain",
				MaxDuration: "24h",
			},
			wantErr: true,
			errMsg:  "requires at least one stage",
		},
		{
			name: "chain missing max_duration",
			sc: &SigmaCorrelation{
				Type: "chain",
				Stages: []SigmaChainStage{
					{Name: "stage1", DetectionRef: "rule1"},
				},
			},
			wantErr: true,
			errMsg:  "requires max_duration",
		},
		{
			name: "valid cross_entity",
			sc: &SigmaCorrelation{
				Type:          "cross_entity",
				TrackField:    "username",
				CountDistinct: "dest_host",
				Timespan:      "15m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name: "cross_entity missing track_field",
			sc: &SigmaCorrelation{
				Type:          "cross_entity",
				CountDistinct: "dest_host",
				Timespan:      "15m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "requires track_field",
		},
		{
			name:    "nil correlation",
			sc:      nil,
			wantErr: true,
			errMsg:  "cannot be nil",
		},
		{
			name: "invalid duration format",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "invalid",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "invalid timespan",
		},
		{
			name: "unsupported type",
			sc: &SigmaCorrelation{
				Type: "unknown_type",
			},
			wantErr: true,
			errMsg:  "unsupported correlation type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sc.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestCorrelationCondition_Validate tests condition validation
func TestCorrelationCondition_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cond    *CorrelationCondition
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid condition with >=",
			cond: &CorrelationCondition{
				Operator: ">=",
				Value:    5,
			},
			wantErr: false,
		},
		{
			name: "valid condition with std_dev",
			cond: &CorrelationCondition{
				Operator: "std_dev",
				Value:    3.0,
			},
			wantErr: false,
		},
		{
			name: "invalid operator",
			cond: &CorrelationCondition{
				Operator: "invalid",
				Value:    5,
			},
			wantErr: true,
			errMsg:  "invalid operator",
		},
		{
			name: "missing value",
			cond: &CorrelationCondition{
				Operator: ">=",
			},
			wantErr: true,
			errMsg:  "value is required",
		},
		{
			name:    "nil condition",
			cond:    nil,
			wantErr: true,
			errMsg:  "cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cond.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ParseDuration tests duration parsing
func TestSigmaCorrelation_ParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "5 minutes",
			duration: "5m",
			want:     5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "1 hour",
			duration: "1h",
			want:     1 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "24 hours",
			duration: "24h",
			want:     24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "7 days",
			duration: "168h", // 7 * 24
			want:     168 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			duration: "invalid",
			wantErr:  true,
		},
		{
			name:     "negative duration",
			duration: "-5m",
			wantErr:  true,
		},
		{
			name:     "empty string",
			duration: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigmaCorrelation{}
			got, err := sc.ParseDuration(tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCorrelationCondition_ToThreshold tests conversion to Threshold
func TestCorrelationCondition_ToThreshold(t *testing.T) {
	tests := []struct {
		name    string
		cond    *CorrelationCondition
		want    Threshold
		wantErr bool
	}{
		{
			name: "int value",
			cond: &CorrelationCondition{
				Operator: ">=",
				Value:    5,
			},
			want: Threshold{
				Operator: ThresholdOpGreaterEqual,
				Value:    5.0,
			},
			wantErr: false,
		},
		{
			name: "float64 value",
			cond: &CorrelationCondition{
				Operator: "std_dev",
				Value:    3.0,
			},
			want: Threshold{
				Operator: ThresholdOpStdDev,
				Value:    3.0,
			},
			wantErr: false,
		},
		{
			name: "int64 value",
			cond: &CorrelationCondition{
				Operator: ">",
				Value:    int64(100),
			},
			want: Threshold{
				Operator: ThresholdOpGreater,
				Value:    100.0,
			},
			wantErr: false,
		},
		{
			name: "float32 value",
			cond: &CorrelationCondition{
				Operator: "<",
				Value:    float32(2.5),
			},
			want: Threshold{
				Operator: ThresholdOpLess,
				Value:    2.5,
			},
			wantErr: false,
		},
		{
			name: "unsupported value type",
			cond: &CorrelationCondition{
				Operator: ">=",
				Value:    "string",
			},
			wantErr: true,
		},
		{
			name:    "nil condition",
			cond:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cond.ToThreshold()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToThreshold() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Operator != tt.want.Operator {
					t.Errorf("ToThreshold() operator = %v, want %v", got.Operator, tt.want.Operator)
				}
				if got.Value != tt.want.Value {
					t.Errorf("ToThreshold() value = %v, want %v", got.Value, tt.want.Value)
				}
			}
		})
	}
}

// TestSigmaCorrelation_RoundTrip tests YAML serialization round-trip
func TestSigmaCorrelation_RoundTrip(t *testing.T) {
	original := &SigmaCorrelation{
		Type:     "event_count",
		GroupBy:  []string{"source_ip", "username"},
		Timespan: "5m",
		Condition: &CorrelationCondition{
			Operator: ">=",
			Value:    5,
		},
	}

	// Marshal to YAML
	yamlBytes, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error = %v", err)
	}

	// Unmarshal back
	parsed, err := ParseYAML(yamlBytes)
	if err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}

	// Compare
	if parsed.Type != original.Type {
		t.Errorf("Type = %v, want %v", parsed.Type, original.Type)
	}
	if len(parsed.GroupBy) != len(original.GroupBy) {
		t.Errorf("GroupBy length = %v, want %v", len(parsed.GroupBy), len(original.GroupBy))
	}
	if parsed.Timespan != original.Timespan {
		t.Errorf("Timespan = %v, want %v", parsed.Timespan, original.Timespan)
	}
	if parsed.Condition.Operator != original.Condition.Operator {
		t.Errorf("Condition.Operator = %v, want %v", parsed.Condition.Operator, original.Condition.Operator)
	}
}

// TestParseYAML tests YAML parsing with security limits
func TestParseYAML(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid YAML",
			data: []byte(`
type: event_count
timespan: 5m
condition:
  operator: ">="
  value: 5
`),
			wantErr: false,
		},
		{
			name:    "oversized YAML",
			data:    make([]byte, 2*1024*1024), // 2MB
			wantErr: true,
			errMsg:  "exceeds maximum size",
		},
		{
			name:    "malformed YAML",
			data:    []byte("invalid: [yaml"),
			wantErr: true,
			errMsg:  "failed to parse YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseYAML() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestRule_ParsedCorrelation tests Rule.ParsedCorrelation method
func TestRule_ParsedCorrelation(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid correlation",
			rule: &Rule{
				Correlation: map[string]interface{}{
					"type":     "event_count",
					"timespan": "5m",
					"condition": map[string]interface{}{
						"operator": ">=",
						"value":    5,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nil rule",
			rule:    nil,
			wantErr: true,
			errMsg:  "nil rule",
		},
		{
			name: "empty correlation",
			rule: &Rule{
				Correlation: nil,
			},
			wantErr: true,
			errMsg:  "empty or nil",
		},
		{
			name: "invalid correlation type",
			rule: &Rule{
				Correlation: map[string]interface{}{
					"type": "invalid_type",
				},
			},
			wantErr: true,
			errMsg:  "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.rule.ParsedCorrelation()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsedCorrelation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParsedCorrelation() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

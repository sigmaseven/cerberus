package core

import (
	"strings"
	"testing"
	"time"
)

// TestSigmaCorrelation_ToCountCorrelationRule tests conversion to CountCorrelationRule
func TestSigmaCorrelation_ToCountCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_count_rule",
		Type:     CorrelationTypeCount,
		Name:     "Test Count Rule",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "login_failed",
	}

	actions := []Action{
		{ID: "action1", Type: "webhook"},
	}

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
				GroupBy:  []string{"source_ip"},
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name: "valid count type",
			sc: &SigmaCorrelation{
				Type:     "count",
				Timespan: "10m",
				GroupBy:  []string{"username"},
				Condition: &CorrelationCondition{
					Operator: ">",
					Value:    10,
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:     "value_count",
				Timespan: "5m",
			},
			wantErr: true,
			errMsg:  "must be event_count or count",
		},
		{
			name:    "nil correlation",
			sc:      nil,
			wantErr: true,
			errMsg:  "correlation is nil",
		},
		{
			name: "invalid timespan",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "invalid",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: true,
			errMsg:  "failed to parse timespan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToCountCorrelationRule(base, selection, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToCountCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToCountCorrelationRule() returned nil")
				}
				if got.ID != base.ID {
					t.Errorf("ID = %v, want %v", got.ID, base.ID)
				}
				if got.Window == 0 {
					t.Error("Window should not be zero")
				}
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToValueCountCorrelationRule tests conversion to ValueCountCorrelationRule
func TestSigmaCorrelation_ToValueCountCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_value_count_rule",
		Type:     CorrelationTypeValueCount,
		Name:     "Test Value Count Rule",
		Severity: "Medium",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "authentication",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid value_count",
			sc: &SigmaCorrelation{
				Type:          "value_count",
				Timespan:      "10m",
				DistinctField: "username",
				GroupBy:       []string{"source_ip"},
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    10,
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:          "event_count",
				Timespan:      "10m",
				DistinctField: "username",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToValueCountCorrelationRule(base, selection, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToValueCountCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToValueCountCorrelationRule() returned nil")
				}
				if got.CountField != tt.sc.DistinctField {
					t.Errorf("CountField = %v, want %v", got.CountField, tt.sc.DistinctField)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToSequenceCorrelationRule tests conversion to SequenceCorrelationRule
func TestSigmaCorrelation_ToSequenceCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_sequence_rule",
		Type:     CorrelationTypeSequence,
		Name:     "Test Sequence Rule",
		Severity: "High",
		Enabled:  true,
	}

	stages := []SequenceStage{
		{Name: "stage1", Selection: map[string]interface{}{"event": "login"}},
		{Name: "stage2", Selection: map[string]interface{}{"event": "privilege_escalation"}},
	}

	actions := []Action{
		{ID: "action1", Type: "block"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid ordered sequence",
			sc: &SigmaCorrelation{
				Type:     "sequence",
				Timespan: "1h",
				Events:   []string{"event1", "event2"},
				Ordered:  true,
				GroupBy:  []string{"username"},
			},
			wantErr: false,
		},
		{
			name: "valid unordered sequence",
			sc: &SigmaCorrelation{
				Type:     "sequence",
				Timespan: "30m",
				Events:   []string{"event1", "event2", "event3"},
				Ordered:  false,
			},
			wantErr: false,
		},
		{
			name: "with max_duration",
			sc: &SigmaCorrelation{
				Type:        "sequence",
				Timespan:    "2h",
				Events:      []string{"event1", "event2"},
				MaxDuration: "1h",
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "1h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToSequenceCorrelationRule(base, stages, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToSequenceCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToSequenceCorrelationRule() returned nil")
				}
				if got.Ordered != tt.sc.Ordered {
					t.Errorf("Ordered = %v, want %v", got.Ordered, tt.sc.Ordered)
				}
				if tt.sc.MaxDuration != "" && got.MaxSpan == 0 {
					t.Error("MaxSpan should not be zero when max_duration is set")
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToRareCorrelationRule tests conversion to RareCorrelationRule
func TestSigmaCorrelation_ToRareCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_rare_rule",
		Type:     CorrelationTypeRare,
		Name:     "Test Rare Rule",
		Severity: "Medium",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"category": "process_creation",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid rare with distinct_field",
			sc: &SigmaCorrelation{
				Type:           "rare",
				BaselineWindow: "7d",
				DistinctField:  "process_name",
				Condition: &CorrelationCondition{
					Operator: "<",
					Value:    3,
				},
			},
			wantErr: false,
		},
		{
			name: "valid rare without distinct_field",
			sc: &SigmaCorrelation{
				Type:           "rare",
				BaselineWindow: "30d",
				Condition: &CorrelationCondition{
					Operator: "<=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:           "event_count",
				BaselineWindow: "7d",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToRareCorrelationRule(base, selection, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToRareCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToRareCorrelationRule() returned nil")
				}
				if got.CountField == "" {
					t.Error("CountField should not be empty")
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToStatisticalCorrelationRule tests conversion to StatisticalCorrelationRule
func TestSigmaCorrelation_ToStatisticalCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_statistical_rule",
		Type:     CorrelationTypeStatistical,
		Name:     "Test Statistical Rule",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"category": "network",
	}

	actions := []Action{
		{ID: "action1", Type: "investigate"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid statistical",
			sc: &SigmaCorrelation{
				Type:            "statistical",
				Timespan:        "1h",
				BaselineWindow:  "30d",
				StdDevThreshold: 3.0,
				GroupBy:         []string{"source_ip"},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:            "event_count",
				Timespan:        "1h",
				BaselineWindow:  "30d",
				StdDevThreshold: 3.0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToStatisticalCorrelationRule(base, selection, "bytes_sent", actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToStatisticalCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToStatisticalCorrelationRule() returned nil")
				}
				if got.Threshold.Operator != ThresholdOpStdDev {
					t.Errorf("Threshold.Operator = %v, want %v", got.Threshold.Operator, ThresholdOpStdDev)
				}
				if got.Threshold.Value != tt.sc.StdDevThreshold {
					t.Errorf("Threshold.Value = %v, want %v", got.Threshold.Value, tt.sc.StdDevThreshold)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToChainCorrelationRule tests conversion to ChainCorrelationRule
func TestSigmaCorrelation_ToChainCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_chain_rule",
		Type:     CorrelationTypeChain,
		Name:     "Test Chain Rule",
		Severity: "Critical",
		Enabled:  true,
	}

	actions := []Action{
		{ID: "action1", Type: "block"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid chain",
			sc: &SigmaCorrelation{
				Type:        "chain",
				MaxDuration: "24h",
				MinStages:   2,
				GroupBy:     []string{"source_ip"},
				Stages: []SigmaChainStage{
					{Name: "recon", DetectionRef: "rule_recon_001"},
					{Name: "exploit", DetectionRef: "rule_exploit_001"},
					{Name: "escalate", DetectionRef: "rule_privesc_001"},
				},
			},
			wantErr: false,
		},
		{
			name: "chain with stage timeouts",
			sc: &SigmaCorrelation{
				Type:        "chain",
				MaxDuration: "12h",
				Stages: []SigmaChainStage{
					{Name: "stage1", DetectionRef: "rule1", Timeout: "1h"},
					{Name: "stage2", DetectionRef: "rule2", Timeout: "30m"},
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:        "event_count",
				MaxDuration: "24h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToChainCorrelationRule(base, nil, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToChainCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToChainCorrelationRule() returned nil")
				}
				if len(got.Stages) != len(tt.sc.Stages) {
					t.Errorf("len(Stages) = %v, want %v", len(got.Stages), len(tt.sc.Stages))
				}
				if tt.sc.MinStages != 0 && got.MinStages != tt.sc.MinStages {
					t.Errorf("MinStages = %v, want %v", got.MinStages, tt.sc.MinStages)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToCrossEntityCorrelationRule tests conversion to CrossEntityCorrelationRule
func TestSigmaCorrelation_ToCrossEntityCorrelationRule(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_cross_entity_rule",
		Type:     CorrelationTypeCrossEntity,
		Name:     "Test Cross Entity Rule",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "network_connection",
	}

	actions := []Action{
		{ID: "action1", Type: "quarantine"},
	}

	tests := []struct {
		name    string
		sc      *SigmaCorrelation
		wantErr bool
	}{
		{
			name: "valid cross_entity",
			sc: &SigmaCorrelation{
				Type:          "cross_entity",
				Timespan:      "15m",
				TrackField:    "username",
				CountDistinct: "dest_host",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			sc: &SigmaCorrelation{
				Type:          "event_count",
				Timespan:      "15m",
				TrackField:    "username",
				CountDistinct: "dest_host",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToCrossEntityCorrelationRule(base, selection, actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToCrossEntityCorrelationRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToCrossEntityCorrelationRule() returned nil")
				}
				if got.TrackField != tt.sc.TrackField {
					t.Errorf("TrackField = %v, want %v", got.TrackField, tt.sc.TrackField)
				}
				if got.CountDistinct != tt.sc.CountDistinct {
					t.Errorf("CountDistinct = %v, want %v", got.CountDistinct, tt.sc.CountDistinct)
				}
			}
		})
	}
}

// TestSigmaCorrelation_ToEnhancedCorrelation tests the dispatcher method
func TestSigmaCorrelation_ToEnhancedCorrelation(t *testing.T) {
	base := EnhancedCorrelationRule{
		ID:       "test_enhanced_rule",
		Type:     CorrelationTypeCount,
		Name:     "Test Enhanced Rule",
		Severity: "High",
		Enabled:  true,
	}

	selection := map[string]interface{}{
		"event_type": "test_event",
	}

	actions := []Action{
		{ID: "action1", Type: "alert"},
	}

	tests := []struct {
		name        string
		sc          *SigmaCorrelation
		expectType  string
		wantErr     bool
	}{
		{
			name: "dispatch to event_count",
			sc: &SigmaCorrelation{
				Type:     "event_count",
				Timespan: "5m",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			expectType: "*core.CountCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to value_count",
			sc: &SigmaCorrelation{
				Type:          "value_count",
				Timespan:      "10m",
				DistinctField: "username",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    10,
				},
			},
			expectType: "*core.ValueCountCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to sequence",
			sc: &SigmaCorrelation{
				Type:     "sequence",
				Timespan: "1h",
				Events:   []string{"event1", "event2"},
			},
			expectType: "*core.SequenceCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to rare",
			sc: &SigmaCorrelation{
				Type:           "rare",
				BaselineWindow: "7d",
				Condition: &CorrelationCondition{
					Operator: "<",
					Value:    3,
				},
			},
			expectType: "*core.RareCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to statistical",
			sc: &SigmaCorrelation{
				Type:            "statistical",
				Timespan:        "1h",
				BaselineWindow:  "30d",
				StdDevThreshold: 3.0,
			},
			expectType: "*core.StatisticalCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to chain",
			sc: &SigmaCorrelation{
				Type:        "chain",
				MaxDuration: "24h",
				Stages: []SigmaChainStage{
					{Name: "stage1", DetectionRef: "rule1"},
				},
			},
			expectType: "*core.ChainCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to cross_entity",
			sc: &SigmaCorrelation{
				Type:          "cross_entity",
				Timespan:      "15m",
				TrackField:    "username",
				CountDistinct: "dest_host",
				Condition: &CorrelationCondition{
					Operator: ">=",
					Value:    5,
				},
			},
			expectType: "*core.CrossEntityCorrelationRule",
			wantErr:    false,
		},
		{
			name: "dispatch to temporal (maps to sequence)",
			sc: &SigmaCorrelation{
				Type:     "temporal",
				Timespan: "2h",
				Events:   []string{"event1", "event2"},
			},
			expectType: "*core.SequenceCorrelationRule",
			wantErr:    false,
		},
		{
			name:    "nil correlation",
			sc:      nil,
			wantErr: true,
		},
		{
			name: "invalid type (missing required fields)",
			sc: &SigmaCorrelation{
				Type: "event_count",
				// Missing timespan and condition
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sc.ToEnhancedCorrelation(base, selection, "metric_field", actions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToEnhancedCorrelation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got == nil {
					t.Fatal("ToEnhancedCorrelation() returned nil")
				}
				// Type assertion check
				typeName := getTypeName(got)
				if typeName != tt.expectType {
					t.Errorf("ToEnhancedCorrelation() type = %v, want %v", typeName, tt.expectType)
				}
			}
		})
	}
}

// TestParseDuration tests the internal parseDuration function
func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		want     time.Duration
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid 5 minutes",
			duration: "5m",
			want:     5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "valid 1 hour",
			duration: "1h",
			want:     1 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "valid 7 days",
			duration: "168h",
			want:     168 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "7 days with d suffix",
			duration: "7d",
			want:     168 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "30 days with d suffix",
			duration: "30d",
			want:     720 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "1 day with d suffix",
			duration: "1d",
			want:     24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "negative duration",
			duration: "-5m",
			wantErr:  true,
			errMsg:   "cannot be negative",
		},
		{
			name:     "negative days with d suffix",
			duration: "-7d",
			wantErr:  true,
			errMsg:   "cannot be negative",
		},
		{
			name:     "exceeds maximum",
			duration: "9000h", // More than 1 year
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "exceeds maximum with d suffix",
			duration: "400d", // More than 1 year
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "overflow protection with d suffix",
			duration: "999999999999d",
			wantErr:  true,
			errMsg:   "exceeds maximum",
		},
		{
			name:     "invalid format no suffix",
			duration: "invalid",
			wantErr:  true,
		},
		{
			name:     "invalid days format with d suffix",
			duration: "abcd",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got != tt.want {
					t.Errorf("parseDuration() = %v, want %v", got, tt.want)
				}
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

// getTypeName returns the type name of an interface value
func getTypeName(v interface{}) string {
	switch v.(type) {
	case *CountCorrelationRule:
		return "*core.CountCorrelationRule"
	case *ValueCountCorrelationRule:
		return "*core.ValueCountCorrelationRule"
	case *SequenceCorrelationRule:
		return "*core.SequenceCorrelationRule"
	case *RareCorrelationRule:
		return "*core.RareCorrelationRule"
	case *StatisticalCorrelationRule:
		return "*core.StatisticalCorrelationRule"
	case *ChainCorrelationRule:
		return "*core.ChainCorrelationRule"
	case *CrossEntityCorrelationRule:
		return "*core.CrossEntityCorrelationRule"
	default:
		return "unknown"
	}
}

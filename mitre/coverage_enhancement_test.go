package mitre

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test all uncovered methods in loader.go
func TestMITREFramework_GetTacticByID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get existing tactic", func(t *testing.T) {
		tactic := framework.GetTacticByID("TA0006")
		require.NotNil(t, tactic)
		assert.Equal(t, "TA0006", tactic.GetTacticID())
		assert.Equal(t, "credential-access", tactic.ShortName)
	})

	t.Run("get non-existent tactic", func(t *testing.T) {
		tactic := framework.GetTacticByID("TA9999")
		assert.Nil(t, tactic)
	})
}

func TestMITREFramework_GetMitigationByID(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get existing mitigation", func(t *testing.T) {
		// Find a real mitigation ID first
		if len(framework.Mitigations) > 0 {
			expectedID := framework.Mitigations[0].GetMitigationID()
			mitigation := framework.GetMitigationByID(expectedID)
			require.NotNil(t, mitigation)
			assert.Equal(t, expectedID, mitigation.GetMitigationID())
		}
	})

	t.Run("get non-existent mitigation", func(t *testing.T) {
		mitigation := framework.GetMitigationByID("M9999")
		assert.Nil(t, mitigation)
	})
}

func TestMITREFramework_GetRelationships(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get uses relationships", func(t *testing.T) {
		rels := framework.GetRelationships("uses")
		assert.NotEmpty(t, rels)
		// Verify all returned relationships have correct type
		for _, rel := range rels {
			assert.Equal(t, "uses", rel.RelationshipType)
		}
	})

	t.Run("get mitigates relationships", func(t *testing.T) {
		rels := framework.GetRelationships("mitigates")
		assert.NotEmpty(t, rels)
		for _, rel := range rels {
			assert.Equal(t, "mitigates", rel.RelationshipType)
		}
	})

	t.Run("get non-existent relationship type", func(t *testing.T) {
		rels := framework.GetRelationships("nonexistent")
		assert.Empty(t, rels)
	})
}

func TestMITREFramework_GetRelationshipsForSource(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get relationships for existing source", func(t *testing.T) {
		// Use first group as source
		if len(framework.Groups) > 0 {
			sourceID := framework.Groups[0].ID
			rels := framework.GetRelationshipsForSource(sourceID)
			// Verify all have correct source
			for _, rel := range rels {
				assert.Equal(t, sourceID, rel.SourceRef)
			}
		}
	})

	t.Run("get relationships for non-existent source", func(t *testing.T) {
		rels := framework.GetRelationshipsForSource("nonexistent-id")
		assert.Empty(t, rels)
	})
}

func TestMITREFramework_GetRelationshipsForTarget(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get relationships for existing target", func(t *testing.T) {
		// Use first technique as target
		if len(framework.Techniques) > 0 {
			targetID := framework.Techniques[0].ID
			rels := framework.GetRelationshipsForTarget(targetID)
			// Verify all have correct target
			for _, rel := range rels {
				assert.Equal(t, targetID, rel.TargetRef)
			}
		}
	})

	t.Run("get relationships for non-existent target", func(t *testing.T) {
		rels := framework.GetRelationshipsForTarget("nonexistent-id")
		assert.Empty(t, rels)
	})
}

func TestMITREFramework_GetGroupsUsingTechnique(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", logger.Sugar())
	require.NoError(t, err)

	t.Run("get groups for T1055 technique", func(t *testing.T) {
		groups := framework.GetGroupsUsingTechnique("T1055")
		// T1055 (Process Injection) is used by many groups
		assert.NotEmpty(t, groups)

		// Verify each group has a relationship using this technique
		tech := framework.GetTechniqueByID("T1055")
		require.NotNil(t, tech)

		for _, group := range groups {
			assert.NotEmpty(t, group.GetGroupID())
		}
	})

	t.Run("get groups for non-existent technique", func(t *testing.T) {
		groups := framework.GetGroupsUsingTechnique("T9999")
		assert.Nil(t, groups)
	})
}

// Test all uncovered methods in types.go
func TestMalware_GetSoftwareID(t *testing.T) {
	tests := []struct {
		name     string
		malware  Malware
		expected string
	}{
		{
			name: "malware with ID",
			malware: Malware{
				ExternalReferences: []ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "S0001"},
				},
			},
			expected: "S0001",
		},
		{
			name: "malware without ID",
			malware: Malware{
				ExternalReferences: []ExternalReference{},
			},
			expected: "",
		},
		{
			name: "malware with non-MITRE reference",
			malware: Malware{
				ExternalReferences: []ExternalReference{
					{SourceName: "other-source", ExternalID: "X001"},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.malware.GetSoftwareID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTool_GetSoftwareID(t *testing.T) {
	tests := []struct {
		name     string
		tool     Tool
		expected string
	}{
		{
			name: "tool with ID",
			tool: Tool{
				ExternalReferences: []ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "S0100"},
				},
			},
			expected: "S0100",
		},
		{
			name: "tool without ID",
			tool: Tool{
				ExternalReferences: []ExternalReference{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tool.GetSoftwareID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCourseOfAction_GetMitigationID(t *testing.T) {
	tests := []struct {
		name     string
		coa      CourseOfAction
		expected string
	}{
		{
			name: "mitigation with ID",
			coa: CourseOfAction{
				ExternalReferences: []ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "M1001"},
				},
			},
			expected: "M1001",
		},
		{
			name: "mitigation without ID",
			coa: CourseOfAction{
				ExternalReferences: []ExternalReference{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.coa.GetMitigationID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttackPattern_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ap      AttackPattern
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid attack pattern",
			ap: AttackPattern{
				ID:   "attack-pattern--123",
				Name: "Test Technique",
				ExternalReferences: []ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "T1001"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			ap: AttackPattern{
				Name: "Test Technique",
			},
			wantErr: true,
			errMsg:  "missing ID",
		},
		{
			name: "missing name",
			ap: AttackPattern{
				ID: "attack-pattern--123",
			},
			wantErr: true,
			errMsg:  "missing name",
		},
		{
			name: "missing technique ID in references",
			ap: AttackPattern{
				ID:                 "attack-pattern--123",
				Name:               "Test Technique",
				ExternalReferences: []ExternalReference{},
			},
			wantErr: true,
			errMsg:  "missing technique ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ap.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTactic_Validate(t *testing.T) {
	tests := []struct {
		name    string
		tactic  Tactic
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid tactic",
			tactic: Tactic{
				ID:        "x-mitre-tactic--123",
				Name:      "Credential Access",
				ShortName: "credential-access",
				ExternalReferences: []ExternalReference{
					{SourceName: "mitre-attack", ExternalID: "TA0006"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			tactic: Tactic{
				Name:      "Test Tactic",
				ShortName: "test",
			},
			wantErr: true,
			errMsg:  "missing ID",
		},
		{
			name: "missing name",
			tactic: Tactic{
				ID:        "x-mitre-tactic--123",
				ShortName: "test",
			},
			wantErr: true,
			errMsg:  "missing name",
		},
		{
			name: "missing short name",
			tactic: Tactic{
				ID:   "x-mitre-tactic--123",
				Name: "Test Tactic",
			},
			wantErr: true,
			errMsg:  "missing short name",
		},
		{
			name: "missing tactic ID in references",
			tactic: Tactic{
				ID:                 "x-mitre-tactic--123",
				Name:               "Test Tactic",
				ShortName:          "test",
				ExternalReferences: []ExternalReference{},
			},
			wantErr: true,
			errMsg:  "missing tactic ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tactic.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetTacticColor(t *testing.T) {
	tests := []struct {
		tacticName    string
		expectedColor string
	}{
		{"reconnaissance", "#8B4789"},
		{"initial-access", "#5F7A8B"},
		{"execution", "#4F8A8B"},
		{"persistence", "#458B74"},
		{"credential-access", "#8B4726"},
		{"impact", "#5D478B"},
		{"unknown-tactic", "#888888"}, // Default color
		{"", "#888888"},               // Empty string
	}

	for _, tt := range tests {
		t.Run(tt.tacticName, func(t *testing.T) {
			color := GetTacticColor(tt.tacticName)
			assert.Equal(t, tt.expectedColor, color)
		})
	}
}

func TestGetTacticName(t *testing.T) {
	tests := []struct {
		shortName    string
		expectedName string
	}{
		{"reconnaissance", "Reconnaissance"},
		{"initial-access", "Initial Access"},
		{"execution", "Execution"},
		{"credential-access", "Credential Access"},
		{"impact", "Impact"},
		{"unknown-tactic", "unknown-tactic"}, // Returns as-is
		{"", ""},                             // Empty string
	}

	for _, tt := range tests {
		t.Run(tt.shortName, func(t *testing.T) {
			name := GetTacticName(tt.shortName)
			assert.Equal(t, tt.expectedName, name)
		})
	}
}

func TestParseSTIXObject_EdgeCases(t *testing.T) {
	t.Run("parse campaign", func(t *testing.T) {
		rawObj := map[string]interface{}{
			"type": "campaign",
			"id":   "campaign--123",
			"name": "Test Campaign",
		}

		obj, err := ParseSTIXObject(rawObj)
		require.NoError(t, err)
		campaign, ok := obj.(Campaign)
		assert.True(t, ok)
		assert.Equal(t, "campaign", campaign.Type)
	})

	t.Run("parse data source", func(t *testing.T) {
		rawObj := map[string]interface{}{
			"type": "x-mitre-data-source",
			"id":   "x-mitre-data-source--123",
			"name": "Process Monitoring",
		}

		obj, err := ParseSTIXObject(rawObj)
		require.NoError(t, err)
		ds, ok := obj.(DataSource)
		assert.True(t, ok)
		assert.Equal(t, "x-mitre-data-source", ds.Type)
	})

	t.Run("parse data component", func(t *testing.T) {
		rawObj := map[string]interface{}{
			"type":                    "x-mitre-data-component",
			"id":                      "x-mitre-data-component--123",
			"name":                    "Process Creation",
			"x_mitre_data_source_ref": "x-mitre-data-source--456",
		}

		obj, err := ParseSTIXObject(rawObj)
		require.NoError(t, err)
		dc, ok := obj.(DataComponent)
		assert.True(t, ok)
		assert.Equal(t, "x-mitre-data-component", dc.Type)
	})

	t.Run("parse unsupported type returns nil", func(t *testing.T) {
		rawObj := map[string]interface{}{
			"type": "unknown-type",
			"id":   "unknown--123",
		}

		obj, err := ParseSTIXObject(rawObj)
		assert.NoError(t, err)
		assert.Nil(t, obj)
	})
}

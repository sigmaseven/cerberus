package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.6: Comprehensive Investigation Lifecycle Tests
// Tests cover: investigation creation, status transitions, priority management,
// verdict handling, notes, alert/event linking, closure requirements, validation

// TestNewInvestigation tests investigation creation
func TestNewInvestigation(t *testing.T) {
	now := time.Now()
	investigation := NewInvestigation(
		"Test Investigation",
		"Test description",
		InvestigationPriorityHigh,
		"user123",
	)

	assert.NotEmpty(t, investigation.InvestigationID, "Investigation should have ID")
	assert.Equal(t, "Test Investigation", investigation.Title)
	assert.Equal(t, "Test description", investigation.Description)
	assert.Equal(t, InvestigationPriorityHigh, investigation.Priority)
	assert.Equal(t, InvestigationStatusOpen, investigation.Status)
	assert.Equal(t, "user123", investigation.CreatedBy)
	assert.Equal(t, "user123", investigation.AssigneeID, "Assignee should default to creator")
	assert.NotZero(t, investigation.CreatedAt)
	assert.NotZero(t, investigation.UpdatedAt)
	assert.Empty(t, investigation.AlertIDs)
	assert.Empty(t, investigation.EventIDs)
	assert.Empty(t, investigation.Notes)
	assert.Empty(t, investigation.MitreTactics)
	assert.Empty(t, investigation.MitreTechniques)
	assert.True(t, investigation.CreatedAt.After(now.Add(-1*time.Second)))
}

// TestInvestigation_Validate_ValidInvestigation tests validation of valid investigation
func TestInvestigation_Validate_ValidInvestigation(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-1",
		Title:           "Valid Investigation",
		Description:     "Test description",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
		AssigneeID:      "user123",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	err := investigation.Validate()
	assert.NoError(t, err, "Valid investigation should pass validation")
}

// TestInvestigation_Validate_MissingTitle tests validation error for missing title
func TestInvestigation_Validate_MissingTitle(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-2",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation without title should fail validation")
	assert.Contains(t, err.Error(), "title is required")
}

// TestInvestigation_Validate_TitleTooLong tests validation error for title too long
func TestInvestigation_Validate_TitleTooLong(t *testing.T) {
	longTitle := make([]byte, 201)
	for i := range longTitle {
		longTitle[i] = 'A'
	}

	investigation := &Investigation{
		InvestigationID: "INV-TEST-3",
		Title:           string(longTitle), // 201 characters
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with title > 200 chars should fail validation")
	assert.Contains(t, err.Error(), "title too long")
}

// TestInvestigation_Validate_InvalidStatus tests validation error for invalid status
func TestInvestigation_Validate_InvalidStatus(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-4",
		Title:           "Test Investigation",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatus("invalid"), // Invalid status
		CreatedBy:       "user123",
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with invalid status should fail validation")
	assert.Contains(t, err.Error(), "invalid investigation status")
}

// TestInvestigation_Validate_InvalidPriority tests validation error for invalid priority
func TestInvestigation_Validate_InvalidPriority(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-5",
		Title:           "Test Investigation",
		Priority:        InvestigationPriority("invalid"), // Invalid priority
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with invalid priority should fail validation")
	assert.Contains(t, err.Error(), "invalid investigation priority")
}

// TestInvestigation_Validate_InvalidVerdict tests validation error for invalid verdict
func TestInvestigation_Validate_InvalidVerdict(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-6",
		Title:           "Test Investigation",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusClosed,
		CreatedBy:       "user123",
		Verdict:         InvestigationVerdict("invalid"), // Invalid verdict
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with invalid verdict should fail validation")
	assert.Contains(t, err.Error(), "invalid investigation verdict")
}

// TestInvestigation_Validate_DescriptionTooLong tests validation error for description too long
func TestInvestigation_Validate_DescriptionTooLong(t *testing.T) {
	longDesc := make([]byte, 2001)
	for i := range longDesc {
		longDesc[i] = 'A'
	}

	investigation := &Investigation{
		InvestigationID: "INV-TEST-7",
		Title:           "Test Investigation",
		Description:     string(longDesc), // 2001 characters
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with description > 2000 chars should fail validation")
	assert.Contains(t, err.Error(), "description too long")
}

// TestInvestigation_Validate_SummaryTooLong tests validation error for summary too long
func TestInvestigation_Validate_SummaryTooLong(t *testing.T) {
	longSummary := make([]byte, 5001)
	for i := range longSummary {
		longSummary[i] = 'A'
	}

	investigation := &Investigation{
		InvestigationID: "INV-TEST-8",
		Title:           "Test Investigation",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusClosed,
		CreatedBy:       "user123",
		Summary:         string(longSummary), // 5001 characters
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with summary > 5000 chars should fail validation")
	assert.Contains(t, err.Error(), "summary too long")
}

// TestInvestigation_Validate_MLFeedback_InvalidRating tests validation error for invalid ML rating
func TestInvestigation_Validate_MLFeedback_InvalidRating(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-TEST-9",
		Title:           "Test Investigation",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
		MLFeedback: &MLFeedback{
			MLQualityRating: 6, // Invalid (must be 1-5)
		},
	}

	err := investigation.Validate()
	require.Error(t, err, "Investigation with invalid ML rating should fail validation")
	assert.Contains(t, err.Error(), "ML quality rating must be between 1 and 5")
}

// TestInvestigation_Validate_MLFeedback_ValidRatings tests all valid ML ratings
func TestInvestigation_Validate_MLFeedback_ValidRatings(t *testing.T) {
	for rating := 1; rating <= 5; rating++ {
		t.Run(string(rune('0'+rating)), func(t *testing.T) {
			investigation := &Investigation{
				InvestigationID: "INV-TEST-ML-" + string(rune('0'+rating)),
				Title:           "Test Investigation",
				Priority:        InvestigationPriorityHigh,
				Status:          InvestigationStatusOpen,
				CreatedBy:       "user123",
				MLFeedback: &MLFeedback{
					MLQualityRating: rating,
				},
			}

			err := investigation.Validate()
			assert.NoError(t, err, "ML rating %d should be valid", rating)
		})
	}
}

// TestInvestigationStatus_IsValid tests investigation status validation
func TestInvestigationStatus_IsValid(t *testing.T) {
	validStatuses := []InvestigationStatus{
		InvestigationStatusOpen,
		InvestigationStatusInProgress,
		InvestigationStatusInvestigating,
		InvestigationStatusAwaitingReview,
		InvestigationStatusClosed,
		InvestigationStatusResolved,
		InvestigationStatusFalsePositive,
	}

	for _, status := range validStatuses {
		t.Run(string(status), func(t *testing.T) {
			assert.True(t, status.IsValid(), "Status %s should be valid", status)
		})
	}

	// Invalid status
	invalidStatus := InvestigationStatus("invalid")
	assert.False(t, invalidStatus.IsValid(), "Invalid status should return false")
}

// TestInvestigationPriority_IsValid tests investigation priority validation
func TestInvestigationPriority_IsValid(t *testing.T) {
	validPriorities := []InvestigationPriority{
		InvestigationPriorityCritical,
		InvestigationPriorityHigh,
		InvestigationPriorityMedium,
		InvestigationPriorityLow,
	}

	for _, priority := range validPriorities {
		t.Run(string(priority), func(t *testing.T) {
			assert.True(t, priority.IsValid(), "Priority %s should be valid", priority)
		})
	}

	// Invalid priority
	invalidPriority := InvestigationPriority("invalid")
	assert.False(t, invalidPriority.IsValid(), "Invalid priority should return false")
}

// TestInvestigationVerdict_IsValid tests investigation verdict validation
func TestInvestigationVerdict_IsValid(t *testing.T) {
	validVerdicts := []InvestigationVerdict{
		InvestigationVerdictTruePositive,
		InvestigationVerdictFalsePositive,
		InvestigationVerdictInconclusive,
	}

	for _, verdict := range validVerdicts {
		t.Run(string(verdict), func(t *testing.T) {
			assert.True(t, verdict.IsValid(), "Verdict %s should be valid", verdict)
		})
	}

	// Invalid verdict
	invalidVerdict := InvestigationVerdict("invalid")
	assert.False(t, invalidVerdict.IsValid(), "Invalid verdict should return false")
}

// TestInvestigation_Structure tests Investigation structure and fields
func TestInvestigation_Structure(t *testing.T) {
	now := time.Now()
	closedAt := now.Add(1 * time.Hour)

	investigation := &Investigation{
		InvestigationID: "INV-STRUCTURE-TEST",
		Title:           "Structure Test Investigation",
		Description:     "Test description",
		Priority:        InvestigationPriorityCritical,
		Status:          InvestigationStatusInProgress,
		AssigneeID:      "user456",
		CreatedBy:       "user123",
		CreatedAt:       now,
		UpdatedAt:       now,
		ClosedAt:        &closedAt,
		AlertIDs:        []string{"alert-1", "alert-2"},
		EventIDs:        []string{"event-1", "event-2"},
		MitreTactics:    []string{"TA0001", "TA0006"},
		MitreTechniques: []string{"T1078", "T1110"},
		Artifacts: InvestigationArtifacts{
			IPs:   []string{"192.168.1.100"},
			Hosts: []string{"host1.example.com"},
			Users: []string{"testuser"},
		},
		Notes: []InvestigationNote{
			{
				ID:        "note-1",
				AnalystID: "user123",
				Content:   "Test note",
				CreatedAt: now,
			},
		},
		Verdict:            InvestigationVerdictTruePositive,
		ResolutionCategory: "incident_contained",
		Summary:            "Test summary",
		AffectedAssets:     []string{"asset1", "asset2"},
		MLFeedback: &MLFeedback{
			UseForTraining:  true,
			MLQualityRating: 5,
			MLHelpfulness:   "very_helpful",
		},
		Tags: []string{"test", "critical"},
	}

	assert.Equal(t, "INV-STRUCTURE-TEST", investigation.InvestigationID)
	assert.Equal(t, "Structure Test Investigation", investigation.Title)
	assert.Equal(t, InvestigationPriorityCritical, investigation.Priority)
	assert.Equal(t, InvestigationStatusInProgress, investigation.Status)
	assert.Equal(t, "user456", investigation.AssigneeID)
	assert.Len(t, investigation.AlertIDs, 2)
	assert.Len(t, investigation.EventIDs, 2)
	assert.Len(t, investigation.MitreTactics, 2)
	assert.Len(t, investigation.MitreTechniques, 2)
	assert.NotNil(t, investigation.ClosedAt)
	assert.Equal(t, InvestigationVerdictTruePositive, investigation.Verdict)
	assert.Len(t, investigation.Notes, 1)
	assert.Len(t, investigation.Tags, 2)
	assert.NotNil(t, investigation.MLFeedback)
}

// TestInvestigation_Close tests investigation closure
func TestInvestigation_Close(t *testing.T) {
	baseTime := time.Now().UTC().Add(-1 * time.Second) // Ensure ClosedAt will be after CreatedAt
	investigation := &Investigation{
		InvestigationID: "INV-CLOSE-TEST",
		Title:           "Close Test Investigation",
		Priority:        InvestigationPriorityHigh,
		Status:          InvestigationStatusInProgress,
		CreatedBy:       "user123",
		CreatedAt:       baseTime,
		UpdatedAt:       baseTime,
	}

	mlFeedback := &MLFeedback{
		UseForTraining:  true,
		MLQualityRating: 4,
		MLHelpfulness:   "somewhat",
	}
	affectedAssets := []string{"asset1", "asset2"}

	err := investigation.Close(
		InvestigationVerdictTruePositive,
		"incident_contained",
		"Test summary",
		affectedAssets,
		mlFeedback,
	)

	require.NoError(t, err, "Should close investigation successfully")
	assert.Equal(t, InvestigationStatusClosed, investigation.Status)
	assert.Equal(t, InvestigationVerdictTruePositive, investigation.Verdict)
	assert.Equal(t, "incident_contained", investigation.ResolutionCategory)
	assert.Equal(t, "Test summary", investigation.Summary)
	assert.Equal(t, affectedAssets, investigation.AffectedAssets)
	assert.NotNil(t, investigation.MLFeedback)
	assert.NotNil(t, investigation.ClosedAt)
	assert.True(t, investigation.ClosedAt.After(investigation.CreatedAt))
}

// TestInvestigation_Close_AllVerdicts tests closure with all verdict types
func TestInvestigation_Close_AllVerdicts(t *testing.T) {
	verdicts := []InvestigationVerdict{
		InvestigationVerdictTruePositive,
		InvestigationVerdictFalsePositive,
		InvestigationVerdictInconclusive,
	}

	for _, verdict := range verdicts {
		t.Run(string(verdict), func(t *testing.T) {
			investigation := &Investigation{
				InvestigationID: "INV-CLOSE-" + string(verdict),
				Title:           "Close Test",
				Priority:        InvestigationPriorityHigh,
				Status:          InvestigationStatusInProgress,
				CreatedBy:       "user123",
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}

			err := investigation.Close(verdict, "category", "summary", []string{}, nil)
			require.NoError(t, err, "Should close with verdict %s", verdict)
			assert.Equal(t, InvestigationStatusClosed, investigation.Status)
			assert.Equal(t, verdict, investigation.Verdict)
		})
	}
}

// TestInvestigationNote_Structure tests InvestigationNote structure
func TestInvestigationNote_Structure(t *testing.T) {
	now := time.Now()
	note := InvestigationNote{
		ID:        "note-1",
		AnalystID: "user123",
		Content:   "Test note content",
		CreatedAt: now,
	}

	assert.Equal(t, "note-1", note.ID)
	assert.Equal(t, "user123", note.AnalystID)
	assert.Equal(t, "Test note content", note.Content)
	assert.Equal(t, now.Unix(), note.CreatedAt.Unix())
}

// TestInvestigationArtifacts_Structure tests InvestigationArtifacts structure
func TestInvestigationArtifacts_Structure(t *testing.T) {
	artifacts := InvestigationArtifacts{
		IPs:       []string{"192.168.1.100", "10.0.0.1"},
		Hosts:     []string{"host1.example.com", "host2.example.com"},
		Users:     []string{"user1", "user2"},
		Files:     []string{"/etc/passwd", "/tmp/file"},
		Hashes:    []string{"abc123", "def456"},
		Processes: []string{"cmd.exe", "powershell.exe"},
	}

	assert.Len(t, artifacts.IPs, 2)
	assert.Len(t, artifacts.Hosts, 2)
	assert.Len(t, artifacts.Users, 2)
	assert.Len(t, artifacts.Files, 2)
	assert.Len(t, artifacts.Hashes, 2)
	assert.Len(t, artifacts.Processes, 2)
}

// TestMLFeedback_Structure tests MLFeedback structure
func TestMLFeedback_Structure(t *testing.T) {
	feedback := MLFeedback{
		UseForTraining:  true,
		MLQualityRating: 5,
		MLHelpfulness:   "very_helpful",
	}

	assert.True(t, feedback.UseForTraining)
	assert.Equal(t, 5, feedback.MLQualityRating)
	assert.Equal(t, "very_helpful", feedback.MLHelpfulness)
}

// TestInvestigation_Serialization tests JSON serialization/deserialization
func TestInvestigation_Serialization(t *testing.T) {
	now := time.Now()
	closedAt := now.Add(1 * time.Hour)

	investigation := &Investigation{
		InvestigationID:    "INV-SERIALIZATION-TEST",
		Title:              "Serialization Test",
		Description:        "Test description",
		Priority:           InvestigationPriorityHigh,
		Status:             InvestigationStatusClosed,
		AssigneeID:         "user456",
		CreatedBy:          "user123",
		CreatedAt:          now,
		UpdatedAt:          now,
		ClosedAt:           &closedAt,
		AlertIDs:           []string{"alert-1"},
		EventIDs:           []string{"event-1"},
		MitreTactics:       []string{"TA0001"},
		MitreTechniques:    []string{"T1078"},
		Verdict:            InvestigationVerdictTruePositive,
		ResolutionCategory: "incident_contained",
		Summary:            "Test summary",
		AffectedAssets:     []string{"asset1"},
		Tags:               []string{"test"},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(investigation)
	require.NoError(t, err, "Should serialize Investigation to JSON")
	assert.NotEmpty(t, jsonData)

	// Deserialize from JSON
	var deserializedInvestigation Investigation
	err = json.Unmarshal(jsonData, &deserializedInvestigation)
	require.NoError(t, err, "Should deserialize Investigation from JSON")

	assert.Equal(t, investigation.InvestigationID, deserializedInvestigation.InvestigationID)
	assert.Equal(t, investigation.Title, deserializedInvestigation.Title)
	assert.Equal(t, investigation.Priority, deserializedInvestigation.Priority)
	assert.Equal(t, investigation.Status, deserializedInvestigation.Status)
	assert.Equal(t, investigation.Verdict, deserializedInvestigation.Verdict)
	assert.Equal(t, investigation.AlertIDs, deserializedInvestigation.AlertIDs)
}

// TestInvestigation_Serialization_WithoutOptionalFields tests serialization without optional fields
func TestInvestigation_Serialization_WithoutOptionalFields(t *testing.T) {
	investigation := &Investigation{
		InvestigationID: "INV-MINIMAL-TEST",
		Title:           "Minimal Test",
		Priority:        InvestigationPriorityMedium,
		Status:          InvestigationStatusOpen,
		CreatedBy:       "user123",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		// All other fields are empty/default
	}

	jsonData, err := json.Marshal(investigation)
	require.NoError(t, err, "Should serialize minimal investigation")

	var deserializedInvestigation Investigation
	err = json.Unmarshal(jsonData, &deserializedInvestigation)
	require.NoError(t, err, "Should deserialize minimal investigation")
	assert.Nil(t, deserializedInvestigation.ClosedAt)
	assert.Empty(t, deserializedInvestigation.Verdict)
	assert.Empty(t, deserializedInvestigation.ResolutionCategory)
	assert.Empty(t, deserializedInvestigation.Summary)
	assert.Nil(t, deserializedInvestigation.MLFeedback)
}

// TestInvestigation_IsValidStatus tests IsValidStatus method
func TestInvestigation_IsValidStatus(t *testing.T) {
	investigation := &Investigation{
		Status: InvestigationStatusOpen,
	}
	assert.True(t, investigation.IsValidStatus())

	investigation.Status = InvestigationStatus("invalid")
	assert.False(t, investigation.IsValidStatus())
}

// TestInvestigation_IsValidPriority tests IsValidPriority method
func TestInvestigation_IsValidPriority(t *testing.T) {
	investigation := &Investigation{
		Priority: InvestigationPriorityHigh,
	}
	assert.True(t, investigation.IsValidPriority())

	investigation.Priority = InvestigationPriority("invalid")
	assert.False(t, investigation.IsValidPriority())
}

// TestInvestigation_IsValidVerdict tests IsValidVerdict method
func TestInvestigation_IsValidVerdict(t *testing.T) {
	// Empty verdict should be valid (optional until closure)
	investigation := &Investigation{
		Verdict: "",
	}
	assert.True(t, investigation.IsValidVerdict())

	// Valid verdict
	investigation.Verdict = InvestigationVerdictTruePositive
	assert.True(t, investigation.IsValidVerdict())

	// Invalid verdict
	investigation.Verdict = InvestigationVerdict("invalid")
	assert.False(t, investigation.IsValidVerdict())
}

// TestInvestigation_StatusConstants tests investigation status constants
func TestInvestigation_StatusConstants(t *testing.T) {
	assert.Equal(t, InvestigationStatus("open"), InvestigationStatusOpen)
	assert.Equal(t, InvestigationStatus("in_progress"), InvestigationStatusInProgress)
	assert.Equal(t, InvestigationStatus("in_progress"), InvestigationStatusInvestigating) // Alias
	assert.Equal(t, InvestigationStatus("awaiting_review"), InvestigationStatusAwaitingReview)
	assert.Equal(t, InvestigationStatus("closed"), InvestigationStatusClosed)
	assert.Equal(t, InvestigationStatus("resolved"), InvestigationStatusResolved)
	assert.Equal(t, InvestigationStatus("false_positive"), InvestigationStatusFalsePositive)
}

// TestInvestigation_PriorityConstants tests investigation priority constants
func TestInvestigation_PriorityConstants(t *testing.T) {
	assert.Equal(t, InvestigationPriority("critical"), InvestigationPriorityCritical)
	assert.Equal(t, InvestigationPriority("high"), InvestigationPriorityHigh)
	assert.Equal(t, InvestigationPriority("medium"), InvestigationPriorityMedium)
	assert.Equal(t, InvestigationPriority("low"), InvestigationPriorityLow)
}

// TestInvestigation_VerdictConstants tests investigation verdict constants
func TestInvestigation_VerdictConstants(t *testing.T) {
	assert.Equal(t, InvestigationVerdict("true_positive"), InvestigationVerdictTruePositive)
	assert.Equal(t, InvestigationVerdict("false_positive"), InvestigationVerdictFalsePositive)
	assert.Equal(t, InvestigationVerdict("inconclusive"), InvestigationVerdictInconclusive)
}

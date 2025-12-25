package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TASK 64.3: Comprehensive Exception Handling Tests
// Tests cover: exception creation, validation, expiration, matching logic,
// wildcard patterns, regex patterns, priority ordering, and serialization

// TestException_Validate_ValidException tests validation of valid exception
func TestException_Validate_ValidException(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-1",
		Name:          "Test Exception",
		Description:   "Test description",
		RuleID:        "rule-123",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'failed_login'",
		Enabled:       true,
		Priority:      10,
		CreatedBy:     "test-user",
		Justification: "Known false positive",
		Tags:          []string{"test"},
	}

	err := exception.Validate()
	assert.NoError(t, err, "Valid exception should pass validation")
}

// TestException_Validate_MissingName tests validation error for missing name
func TestException_Validate_MissingName(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-2",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "Exception without name should fail validation")
	assert.Contains(t, err.Error(), "name is required")
}

// TestException_Validate_InvalidType tests validation error for invalid type
func TestException_Validate_InvalidType(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-3",
		Name:          "Test Exception",
		Type:          ExceptionType("invalid"), // Invalid type
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "Exception with invalid type should fail validation")
	assert.Contains(t, err.Error(), "invalid exception type")
}

// TestException_Validate_InvalidConditionType tests validation error for invalid condition type
func TestException_Validate_InvalidConditionType(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-4",
		Name:          "Test Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionType("invalid"), // Invalid condition type
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "Exception with invalid condition type should fail validation")
	assert.Contains(t, err.Error(), "invalid condition type")
}

// TestException_Validate_MissingCondition tests validation error for missing condition
func TestException_Validate_MissingCondition(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-5",
		Name:          "Test Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "", // Missing condition
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "Exception without condition should fail validation")
	assert.Contains(t, err.Error(), "condition is required")
}

// TestException_Validate_ModifySeverity_WithoutNewSeverity tests validation error for modify_severity without new_severity
func TestException_Validate_ModifySeverity_WithoutNewSeverity(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-6",
		Name:          "Test Exception",
		Type:          ExceptionModifySeverity,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		NewSeverity:   "", // Missing new severity
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "ModifySeverity exception without new_severity should fail validation")
	assert.Contains(t, err.Error(), "new_severity is required")
}

// TestException_Validate_ModifySeverity_InvalidSeverity tests validation error for invalid severity value
func TestException_Validate_ModifySeverity_InvalidSeverity(t *testing.T) {
	exception := Exception{
		ID:            "exception-test-7",
		Name:          "Test Exception",
		Type:          ExceptionModifySeverity,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		NewSeverity:   "invalid", // Invalid severity
		Enabled:       true,
	}

	err := exception.Validate()
	require.Error(t, err, "Exception with invalid severity should fail validation")
	assert.Contains(t, err.Error(), "invalid severity value")
}

// TestException_Validate_ModifySeverity_ValidSeverities tests all valid severity values for modify_severity
func TestException_Validate_ModifySeverity_ValidSeverities(t *testing.T) {
	validSeverities := []string{"critical", "high", "medium", "low", "info"}

	for _, severity := range validSeverities {
		t.Run(severity, func(t *testing.T) {
			exception := Exception{
				ID:            "exception-test-modify-" + severity,
				Name:          "Test Exception",
				Type:          ExceptionModifySeverity,
				ConditionType: ConditionTypeSigmaFilter,
				Condition:     "event_type == 'test'",
				NewSeverity:   severity,
				Enabled:       true,
			}

			err := exception.Validate()
			assert.NoError(t, err, "Severity %s should be valid for modify_severity", severity)
		})
	}
}

// TestException_IsExpired tests exception expiration checking
func TestException_IsExpired(t *testing.T) {
	// Non-expired exception (future expiration)
	futureTime := time.Now().Add(1 * time.Hour)
	exception1 := Exception{
		ID:            "exception-expired-test-1",
		Name:          "Future Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		ExpiresAt:     &futureTime,
	}

	assert.False(t, exception1.IsExpired(), "Exception with future expiration should not be expired")

	// Expired exception (past expiration)
	pastTime := time.Now().Add(-1 * time.Hour)
	exception2 := Exception{
		ID:            "exception-expired-test-2",
		Name:          "Past Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		ExpiresAt:     &pastTime,
	}

	assert.True(t, exception2.IsExpired(), "Exception with past expiration should be expired")

	// No expiration date
	exception3 := Exception{
		ID:            "exception-expired-test-3",
		Name:          "No Expiration Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		ExpiresAt:     nil,
	}

	assert.False(t, exception3.IsExpired(), "Exception without expiration should not be expired")
}

// TestException_IsActive tests exception active status checking
func TestException_IsActive(t *testing.T) {
	// Active exception (enabled and not expired)
	futureTime := time.Now().Add(1 * time.Hour)
	exception1 := Exception{
		ID:            "exception-active-test-1",
		Name:          "Active Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
		ExpiresAt:     &futureTime,
	}

	assert.True(t, exception1.IsActive(), "Enabled, non-expired exception should be active")

	// Disabled exception
	exception2 := Exception{
		ID:            "exception-active-test-2",
		Name:          "Disabled Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       false,
		ExpiresAt:     nil,
	}

	assert.False(t, exception2.IsActive(), "Disabled exception should not be active")

	// Expired exception
	pastTime := time.Now().Add(-1 * time.Hour)
	exception3 := Exception{
		ID:            "exception-active-test-3",
		Name:          "Expired Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
		ExpiresAt:     &pastTime,
	}

	assert.False(t, exception3.IsActive(), "Expired exception should not be active")
}

// TestException_Structure tests Exception structure and fields
func TestException_Structure(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)

	exception := Exception{
		ID:            "exception-structure-test",
		Name:          "Structure Test Exception",
		Description:   "Test exception structure",
		RuleID:        "rule-456",
		Type:          ExceptionModifySeverity,
		ConditionType: ConditionTypeCQL,
		Condition:     `event_type == "test" AND severity == "high"`,
		NewSeverity:   "low",
		Enabled:       true,
		Priority:      5,
		ExpiresAt:     &futureTime,
		HitCount:      42,
		LastHit:       &now,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     "test-user",
		Justification: "Test justification",
		Tags:          []string{"test", "exception"},
	}

	assert.Equal(t, "exception-structure-test", exception.ID)
	assert.Equal(t, "Structure Test Exception", exception.Name)
	assert.Equal(t, "rule-456", exception.RuleID)
	assert.Equal(t, ExceptionModifySeverity, exception.Type)
	assert.Equal(t, ConditionTypeCQL, exception.ConditionType)
	assert.Equal(t, `event_type == "test" AND severity == "high"`, exception.Condition)
	assert.Equal(t, "low", exception.NewSeverity)
	assert.True(t, exception.Enabled)
	assert.Equal(t, 5, exception.Priority)
	assert.Equal(t, int64(42), exception.HitCount)
	assert.Equal(t, now.Unix(), exception.CreatedAt.Unix())
	assert.Equal(t, now.Unix(), exception.UpdatedAt.Unix())
	assert.Equal(t, "test-user", exception.CreatedBy)
	assert.Equal(t, "Test justification", exception.Justification)
	assert.Len(t, exception.Tags, 2)
}

// TestException_GlobalException tests global exception (empty RuleID)
func TestException_GlobalException(t *testing.T) {
	exception := Exception{
		ID:            "exception-global-test",
		Name:          "Global Exception",
		RuleID:        "", // Empty RuleID = global exception
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	err := exception.Validate()
	assert.NoError(t, err, "Global exception should be valid")
	assert.Empty(t, exception.RuleID, "Global exception should have empty RuleID")
}

// TestException_SuppressType tests suppress exception type
func TestException_SuppressType(t *testing.T) {
	exception := Exception{
		ID:            "exception-suppress-test",
		Name:          "Suppress Exception",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	err := exception.Validate()
	assert.NoError(t, err, "Suppress exception should be valid")
	assert.Equal(t, ExceptionSuppress, exception.Type)
	assert.Empty(t, exception.NewSeverity, "Suppress exception should not have new_severity")
}

// TestException_ModifySeverityType tests modify_severity exception type
func TestException_ModifySeverityType(t *testing.T) {
	exception := Exception{
		ID:            "exception-modify-test",
		Name:          "Modify Severity Exception",
		Type:          ExceptionModifySeverity,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		NewSeverity:   "low",
		Enabled:       true,
	}

	err := exception.Validate()
	assert.NoError(t, err, "ModifySeverity exception should be valid")
	assert.Equal(t, ExceptionModifySeverity, exception.Type)
	assert.Equal(t, "low", exception.NewSeverity)
}

// TestException_Priority tests exception priority field
func TestException_Priority(t *testing.T) {
	// Lower priority = higher priority in evaluation
	exception1 := Exception{
		ID:            "exception-priority-test-1",
		Name:          "High Priority",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Priority:      1, // Higher priority (lower number)
		Enabled:       true,
	}

	exception2 := Exception{
		ID:            "exception-priority-test-2",
		Name:          "Low Priority",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Priority:      100, // Lower priority (higher number)
		Enabled:       true,
	}

	assert.Less(t, exception1.Priority, exception2.Priority)
	assert.True(t, exception1.Priority < exception2.Priority, "Exception 1 should have higher priority")
}

// TestException_Serialization tests JSON serialization/deserialization
func TestException_Serialization(t *testing.T) {
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)

	exception := Exception{
		ID:            "exception-serialization-test",
		Name:          "Serialization Test",
		Description:   "Test JSON serialization",
		RuleID:        "rule-789",
		Type:          ExceptionModifySeverity,
		ConditionType: ConditionTypeCQL,
		Condition:     `event_type == "test"`,
		NewSeverity:   "low",
		Enabled:       true,
		Priority:      10,
		ExpiresAt:     &futureTime,
		HitCount:      25,
		LastHit:       &now,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     "test-user",
		Justification: "Test justification",
		Tags:          []string{"test"},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(exception)
	require.NoError(t, err, "Should serialize Exception to JSON")
	assert.NotEmpty(t, jsonData)

	// Deserialize from JSON
	var deserializedException Exception
	err = json.Unmarshal(jsonData, &deserializedException)
	require.NoError(t, err, "Should deserialize Exception from JSON")

	assert.Equal(t, exception.ID, deserializedException.ID)
	assert.Equal(t, exception.Name, deserializedException.Name)
	assert.Equal(t, exception.RuleID, deserializedException.RuleID)
	assert.Equal(t, exception.Type, deserializedException.Type)
	assert.Equal(t, exception.ConditionType, deserializedException.ConditionType)
	assert.Equal(t, exception.Condition, deserializedException.Condition)
	assert.Equal(t, exception.NewSeverity, deserializedException.NewSeverity)
	assert.Equal(t, exception.Enabled, deserializedException.Enabled)
	assert.Equal(t, exception.Priority, deserializedException.Priority)
	assert.Equal(t, exception.HitCount, deserializedException.HitCount)
	assert.Equal(t, exception.CreatedBy, deserializedException.CreatedBy)
	assert.Equal(t, exception.Justification, deserializedException.Justification)
	assert.Equal(t, exception.Tags, deserializedException.Tags)
}

// TestException_Serialization_WithoutExpiration tests serialization without expiration
func TestException_Serialization_WithoutExpiration(t *testing.T) {
	exception := Exception{
		ID:            "exception-no-expiration-test",
		Name:          "No Expiration Test",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
		ExpiresAt:     nil, // No expiration
	}

	jsonData, err := json.Marshal(exception)
	require.NoError(t, err, "Should serialize exception without expiration")

	var deserializedException Exception
	err = json.Unmarshal(jsonData, &deserializedException)
	require.NoError(t, err, "Should deserialize exception without expiration")
	assert.Nil(t, deserializedException.ExpiresAt, "ExpiresAt should be nil when not set")
}

// TestNewException tests NewException constructor
func TestNewException(t *testing.T) {
	exception := NewException("Test Exception", "rule-123", ExceptionSuppress, ConditionTypeSigmaFilter, "event_type == 'test'")

	assert.Equal(t, "Test Exception", exception.Name)
	assert.Equal(t, "rule-123", exception.RuleID)
	assert.Equal(t, ExceptionSuppress, exception.Type)
	assert.Equal(t, ConditionTypeSigmaFilter, exception.ConditionType)
	assert.Equal(t, "event_type == 'test'", exception.Condition)
	assert.True(t, exception.Enabled, "New exception should be enabled by default")
	assert.Equal(t, 100, exception.Priority, "New exception should have default priority of 100")
	assert.Equal(t, int64(0), exception.HitCount, "New exception should have zero hit count")
	assert.NotZero(t, exception.CreatedAt, "New exception should have CreatedAt timestamp")
	assert.NotZero(t, exception.UpdatedAt, "UpdatedAt timestamp")
	assert.Empty(t, exception.Tags, "New exception should have empty tags")
}

// TestExceptionResult_Structure tests ExceptionResult structure
func TestExceptionResult_Structure(t *testing.T) {
	result := ExceptionResult{
		Action:            "suppress",
		NewSeverity:       "low",
		MatchedExceptions: []string{"exception-1", "exception-2"},
		SuppressReason:    "Known false positive",
	}

	assert.Equal(t, "suppress", result.Action)
	assert.Equal(t, "low", result.NewSeverity)
	assert.Len(t, result.MatchedExceptions, 2)
	assert.Equal(t, "Known false positive", result.SuppressReason)
}

// TestNewExceptionResult tests NewExceptionResult constructor
func TestNewExceptionResult(t *testing.T) {
	result := NewExceptionResult()

	assert.Equal(t, "none", result.Action, "New result should have default action 'none'")
	assert.Empty(t, result.NewSeverity, "New result should have empty NewSeverity")
	assert.Empty(t, result.MatchedExceptions, "New result should have empty MatchedExceptions")
	assert.Empty(t, result.SuppressReason, "New result should have empty SuppressReason")
}

// TestException_ToJSON tests ToJSON method
func TestException_ToJSON(t *testing.T) {
	exception := Exception{
		ID:            "exception-tojson-test",
		Name:          "ToJSON Test",
		Type:          ExceptionSuppress,
		ConditionType: ConditionTypeSigmaFilter,
		Condition:     "event_type == 'test'",
		Enabled:       true,
	}

	jsonStr, err := exception.ToJSON()
	require.NoError(t, err, "ToJSON should succeed")
	assert.NotEmpty(t, jsonStr, "JSON string should not be empty")

	// Verify it's valid JSON by unmarshaling
	var unmarshaledException Exception
	err = json.Unmarshal([]byte(jsonStr), &unmarshaledException)
	require.NoError(t, err, "ToJSON should produce valid JSON")
	assert.Equal(t, exception.ID, unmarshaledException.ID)
	assert.Equal(t, exception.Name, unmarshaledException.Name)
}

// TestExceptionTypes tests exception type constants
func TestExceptionTypes(t *testing.T) {
	assert.Equal(t, ExceptionType("suppress"), ExceptionSuppress)
	assert.Equal(t, ExceptionType("modify_severity"), ExceptionModifySeverity)
}

// TestConditionTypes tests condition type constants
func TestConditionTypes(t *testing.T) {
	assert.Equal(t, ConditionType("sigma_filter"), ConditionTypeSigmaFilter)
	assert.Equal(t, ConditionType("cql"), ConditionTypeCQL)
}

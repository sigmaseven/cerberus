package storage

import "errors"

// Storage error constants
var (
	// ErrRuleNotFound is returned when a rule is not found
	ErrRuleNotFound = errors.New("rule not found")

	// ErrActionNotFound is returned when an action is not found
	ErrActionNotFound = errors.New("action not found")

	// ErrCorrelationRuleNotFound is returned when a correlation rule is not found
	ErrCorrelationRuleNotFound = errors.New("correlation rule not found")

	// ErrAlertNotFound is returned when an alert is not found
	ErrAlertNotFound = errors.New("alert not found")

	// ErrAlertAlreadyLinked is returned when an alert is already linked to an investigation
	// TASK 106: Used for optimistic locking to prevent race conditions
	ErrAlertAlreadyLinked = errors.New("alert is already linked to an investigation")

	// ErrEventNotFound is returned when an event is not found
	ErrEventNotFound = errors.New("event not found")

	// ErrInvestigationNotFound is returned when an investigation is not found
	ErrInvestigationNotFound = errors.New("investigation not found")

	// ErrListenerNotFound is returned when a listener is not found
	ErrListenerNotFound = errors.New("listener not found")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrExceptionNotFound is returned when an exception is not found
	ErrExceptionNotFound = errors.New("exception not found")

	// ErrFieldMappingNotFound is returned when a field mapping is not found
	ErrFieldMappingNotFound = errors.New("field mapping not found")

	// ErrSavedSearchNotFound is returned when a saved search is not found
	ErrSavedSearchNotFound = errors.New("saved search not found")

	// ErrPlaybookNotFound is returned when a playbook is not found
	ErrPlaybookNotFound = errors.New("playbook not found")

	// ErrPlaybookNameExists is returned when a playbook with the same name already exists
	ErrPlaybookNameExists = errors.New("playbook with this name already exists")

	// ErrPlaybookExecutionNotFound is returned when a playbook execution is not found
	ErrPlaybookExecutionNotFound = errors.New("playbook execution not found")

	// Generic storage errors

	// ErrNotFound is a generic "not found" error
	ErrNotFound = errors.New("not found")

	// ErrDuplicateRule is returned when attempting to create a rule that already exists
	ErrDuplicateRule = errors.New("rule already exists")

	// ErrInvalidRule is returned when a rule validation fails
	ErrInvalidRule = errors.New("invalid rule")

	// ErrDatabaseClosed is returned when attempting to use a closed database connection
	ErrDatabaseClosed = errors.New("database is closed")

	// ErrConstraintViolation is returned when a database constraint is violated
	ErrConstraintViolation = errors.New("constraint violation")

	// ErrNotImplemented is returned when a method is not implemented
	ErrNotImplemented = errors.New("not implemented")
)

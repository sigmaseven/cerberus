package soar

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"cerberus/core"
	"cerberus/metrics"

	"go.uber.org/zap"
)

// AuditMetadata contains user context for audit logging
// TASK 36.5: Metadata extracted from request context for audit trail
type AuditMetadata struct {
	UserID    string
	UserEmail string
	SourceIP  string
	UserAgent string
}

// getAuditMetadataFromContext extracts audit metadata from context
// TASK 36.5: Helper to extract user info from HTTP request context
func getAuditMetadataFromContext(ctx context.Context) AuditMetadata {
	metadata := AuditMetadata{}

	// Extract username/user ID from context (set by JWT middleware)
	if username, ok := ctx.Value("username").(string); ok {
		metadata.UserID = username
	}

	// Extract source IP from context (set by middleware)
	if sourceIP, ok := ctx.Value("source_ip").(string); ok {
		metadata.SourceIP = sourceIP
	}

	// Extract user agent from request context (set by middleware)
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		metadata.UserAgent = userAgent
	}

	// Extract user email from context (set by middleware if available)
	if userEmail, ok := ctx.Value("user_email").(string); ok {
		metadata.UserEmail = userEmail
	}

	// Try to extract from HTTP request if context has request
	if req, ok := ctx.Value("http_request").(*http.Request); ok {
		if metadata.SourceIP == "" {
			metadata.SourceIP = req.RemoteAddr
		}
		if metadata.UserAgent == "" {
			metadata.UserAgent = req.Header.Get("User-Agent")
		}
	}

	return metadata
}

// Executor executes playbooks for alerts
// TASK 25: SOAR playbook execution engine
type Executor struct {
	actions       map[ActionType]Action
	actionsMu     sync.RWMutex
	maxConcurrent int
	semaphore     chan struct{} // TASK 25.5: Concurrency control semaphore
	activeCount   int           // TASK 25.5: Track active executions for metrics
	activeMu      sync.Mutex
	logger        *zap.SugaredLogger
	auditLogger   AuditLogger // TASK 36.5: Audit logger for playbook execution events
}

// NewExecutor creates a new playbook executor
// TASK 25.1: Initialize executor with concurrency control (default: 10 concurrent executions)
// TASK 36.5: Accept optional AuditLogger for audit trail
func NewExecutor(maxConcurrent int, logger *zap.SugaredLogger, auditLogger AuditLogger) *Executor {
	if maxConcurrent <= 0 {
		maxConcurrent = 10 // Default: 10 concurrent executions
	}
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if auditLogger == nil {
		auditLogger = &NoOpAuditLogger{} // Fallback to no-op if not provided
	}

	return &Executor{
		actions:       make(map[ActionType]Action),
		maxConcurrent: maxConcurrent,
		semaphore:     make(chan struct{}, maxConcurrent),
		logger:        logger,
		auditLogger:   auditLogger,
	}
}

// RegisterAction registers an action type
// TASK 25: Register action handlers for playbook execution
func (e *Executor) RegisterAction(action Action) {
	e.actionsMu.Lock()
	defer e.actionsMu.Unlock()
	e.actions[action.Type()] = action
	e.logger.Infof("Registered SOAR action: %s (%s)", action.Name(), action.Type())
}

// GetAction retrieves a registered action by type
func (e *Executor) GetAction(actionType ActionType) (Action, error) {
	e.actionsMu.RLock()
	defer e.actionsMu.RUnlock()

	action, exists := e.actions[actionType]
	if !exists {
		return nil, fmt.Errorf("action type %s not registered", actionType)
	}
	return action, nil
}

// ExecutePlaybook executes a playbook for an alert
// TASK 25.1: Sequential step execution with conditional logic, error handling, and timeouts
func (e *Executor) ExecutePlaybook(ctx context.Context, playbook *Playbook, alert *core.Alert) (*PlaybookExecution, error) {
	// Check if playbook is enabled
	if !playbook.Enabled {
		return nil, fmt.Errorf("playbook %s is disabled", playbook.ID)
	}

	// Acquire semaphore for concurrency control
	// TASK 25.5: Limit concurrent playbook executions
	select {
	case e.semaphore <- struct{}{}:
		// TASK 25.5: Track active executions for metrics
		e.activeMu.Lock()
		e.activeCount++
		queueDepth := e.maxConcurrent - e.activeCount
		e.activeMu.Unlock()
		metrics.PlaybookQueueDepth.Set(float64(queueDepth))

		defer func() {
			<-e.semaphore
			// TASK 25.5: Update active count and queue depth metric
			e.activeMu.Lock()
			e.activeCount--
			queueDepth := e.maxConcurrent - e.activeCount
			e.activeMu.Unlock()
			metrics.PlaybookQueueDepth.Set(float64(queueDepth))
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Queue is full - reject execution
		e.activeMu.Lock()
		queueDepth := e.maxConcurrent - e.activeCount
		e.activeMu.Unlock()
		metrics.PlaybookQueueDepth.Set(float64(queueDepth))
		e.logger.Warnf("Playbook execution queue full, rejecting execution for playbook %s", playbook.ID)
		return nil, fmt.Errorf("playbook execution queue full (max: %d)", e.maxConcurrent)
	}

	execution := &PlaybookExecution{
		ID:           fmt.Sprintf("exec-%d", time.Now().UnixNano()),
		PlaybookID:   playbook.ID,
		PlaybookName: playbook.Name,
		AlertID:      alert.AlertID,
		Status:       ActionStatusRunning,
		StartedAt:    time.Now(),
		StepResults:  make(map[string]*ActionResult),
		Metadata:     make(map[string]interface{}),
	}

	// TASK 25.5: Emit metrics for playbook execution start
	metrics.PlaybookExecutionsTotal.WithLabelValues(playbook.ID, "running").Inc()

	e.logger.Infow("Starting playbook execution",
		"playbook_id", playbook.ID,
		"playbook_name", playbook.Name,
		"alert_id", alert.AlertID,
		"execution_id", execution.ID)

	// TASK 36.5: Log playbook start audit event
	auditMetadata := getAuditMetadataFromContext(ctx)
	e.auditLogger.Log(ctx, &AuditEvent{
		EventType:           "playbook_started",
		PlaybookID:          playbook.ID,
		PlaybookExecutionID: execution.ID,
		AlertID:             alert.AlertID,
		UserID:              auditMetadata.UserID,
		UserEmail:           auditMetadata.UserEmail,
		SourceIP:            auditMetadata.SourceIP,
		UserAgent:           auditMetadata.UserAgent,
		Result:              "started",
	})

	// Execute steps sequentially
	// TASK 25.1: Sequential for loop over playbook.Steps
	for _, step := range playbook.Steps {
		stepStartTime := time.Now()

		// TASK 25.2: Evaluate step conditions before execution
		if len(step.Conditions) > 0 {
			conditionsMet, err := e.evaluateConditions(step.Conditions, alert)
			if err != nil {
				e.logger.Warnf("Failed to evaluate conditions for step %s: %v", step.ID, err)
				continue // Skip step on condition evaluation error
			}
			if !conditionsMet {
				e.logger.Debugf("Step %s conditions not met, skipping", step.ID)
				execution.StepResults[step.ID] = &ActionResult{
					ActionType:  step.ActionType,
					Status:      ActionStatusSkipped,
					Message:     "Step conditions not met",
					StartedAt:   stepStartTime,
					CompletedAt: stepStartTime,
					Duration:    0,
				}
				continue
			}
		}

		// Get action handler for step
		action, err := e.GetAction(step.ActionType)
		if err != nil {
			e.logger.Errorf("Action type %s not found for step %s: %v", step.ActionType, step.ID, err)
			execution.StepResults[step.ID] = &ActionResult{
				ActionType:  step.ActionType,
				Status:      ActionStatusFailed,
				Message:     fmt.Sprintf("Action type %s not registered", step.ActionType),
				Error:       err.Error(),
				StartedAt:   stepStartTime,
				CompletedAt: time.Now(),
				Duration:    time.Since(stepStartTime),
			}

			// TASK 25.3: Check continue_on_error flag
			if !step.ContinueOnError {
				execution.Status = ActionStatusFailed
				execution.Error = fmt.Sprintf("Step %s failed: %v", step.ID, err)
				execution.CompletedAt = time.Now()
				execution.Duration = time.Since(execution.StartedAt)

				// TASK 36.5: Log playbook failure audit event
				playbookDurationMs := uint32(execution.Duration.Milliseconds())
				if playbookDurationMs == 0 && execution.Duration > 0 {
					playbookDurationMs = 1
				}
				e.auditLogger.Log(ctx, &AuditEvent{
					EventType:           "playbook_completed",
					PlaybookID:          playbook.ID,
					PlaybookExecutionID: execution.ID,
					AlertID:             alert.AlertID,
					Result:              "failure",
					ErrorMessage:        execution.Error,
					DurationMs:          playbookDurationMs,
					UserID:              auditMetadata.UserID,
					UserEmail:           auditMetadata.UserEmail,
					SourceIP:            auditMetadata.SourceIP,
					UserAgent:           auditMetadata.UserAgent,
				})

				return execution, fmt.Errorf("playbook execution failed at step %s: %w", step.ID, err)
			}

			continue // Continue to next step
		}

		// Validate step parameters
		if err := action.ValidateParams(step.Parameters); err != nil {
			e.logger.Errorf("Invalid parameters for step %s: %v", step.ID, err)
			execution.StepResults[step.ID] = &ActionResult{
				ActionType:  step.ActionType,
				Status:      ActionStatusFailed,
				Message:     "Invalid parameters",
				Error:       err.Error(),
				StartedAt:   stepStartTime,
				CompletedAt: time.Now(),
				Duration:    time.Since(stepStartTime),
			}

			if !step.ContinueOnError {
				execution.Status = ActionStatusFailed
				execution.Error = fmt.Sprintf("Step %s parameter validation failed: %v", step.ID, err)
				execution.CompletedAt = time.Now()
				execution.Duration = time.Since(execution.StartedAt)

				// TASK 36.5: Log playbook failure audit event
				playbookDurationMs := uint32(execution.Duration.Milliseconds())
				if playbookDurationMs == 0 && execution.Duration > 0 {
					playbookDurationMs = 1
				}
				e.auditLogger.Log(ctx, &AuditEvent{
					EventType:           "playbook_completed",
					PlaybookID:          playbook.ID,
					PlaybookExecutionID: execution.ID,
					AlertID:             alert.AlertID,
					Result:              "failure",
					ErrorMessage:        execution.Error,
					DurationMs:          playbookDurationMs,
					UserID:              auditMetadata.UserID,
					UserEmail:           auditMetadata.UserEmail,
					SourceIP:            auditMetadata.SourceIP,
					UserAgent:           auditMetadata.UserAgent,
				})

				return execution, fmt.Errorf("playbook execution failed at step %s: %w", step.ID, err)
			}

			continue
		}

		// TASK 25.1: Create context with timeout for step execution
		stepTimeout := step.Timeout
		if stepTimeout == 0 {
			stepTimeout = 30 * time.Second // Default timeout: 30 seconds
		}

		stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()

		// TASK 35.3: Interpolate variables in step parameters
		interpolatedParams := e.interpolateVariables(step.Parameters, map[string]interface{}{
			"alert":          alert,
			"event":          alert.Event,
			"previous_steps": execution.StepResults,
		}).(map[string]interface{})

		// Execute step action
		e.logger.Infow("Executing playbook step",
			"playbook_id", playbook.ID,
			"step_id", step.ID,
			"step_name", step.Name,
			"action_type", step.ActionType,
			"timeout", stepTimeout)

		result, err := action.Execute(stepCtx, alert, interpolatedParams)

		// Handle step execution result
		if err != nil {
			e.logger.Warnf("Step %s execution failed: %v", step.ID, err)
			result = &ActionResult{
				ActionType:  step.ActionType,
				Status:      ActionStatusFailed,
				Message:     "Step execution failed",
				Error:       err.Error(),
				StartedAt:   stepStartTime,
				CompletedAt: time.Now(),
				Duration:    time.Since(stepStartTime),
			}

			// Check for timeout
			if stepCtx.Err() == context.DeadlineExceeded {
				result.Error = fmt.Sprintf("Step timeout after %v", stepTimeout)
				e.logger.Warnf("Step %s timed out after %v", step.ID, stepTimeout)
			}

			// TASK 25.5: Emit metrics for step failure
			metrics.PlaybookStepFailures.WithLabelValues(playbook.ID, step.ID, string(step.ActionType)).Inc()

			// TASK 25.3: Check continue_on_error flag
			if !step.ContinueOnError {
				execution.Status = ActionStatusFailed
				execution.Error = fmt.Sprintf("Step %s failed: %v", step.ID, err)
				execution.CompletedAt = time.Now()
				execution.Duration = time.Since(execution.StartedAt)
				execution.StepResults[step.ID] = result

				// TASK 25.5: Emit metrics for failed playbook
				metrics.PlaybookExecutionsTotal.WithLabelValues(playbook.ID, "failed").Inc()
				metrics.PlaybookExecutionDuration.WithLabelValues(playbook.ID).Observe(execution.Duration.Seconds())
				e.activeMu.Lock()
				queueDepth := e.maxConcurrent - e.activeCount
				e.activeMu.Unlock()
				metrics.PlaybookQueueDepth.Set(float64(queueDepth))

				// TASK 36.5: Log playbook failure audit event
				playbookDurationMs := uint32(execution.Duration.Milliseconds())
				if playbookDurationMs == 0 && execution.Duration > 0 {
					playbookDurationMs = 1
				}
				e.auditLogger.Log(ctx, &AuditEvent{
					EventType:           "playbook_completed",
					PlaybookID:          playbook.ID,
					PlaybookExecutionID: execution.ID,
					AlertID:             alert.AlertID,
					Result:              "failure",
					ErrorMessage:        execution.Error,
					DurationMs:          playbookDurationMs,
					UserID:              auditMetadata.UserID,
					UserEmail:           auditMetadata.UserEmail,
					SourceIP:            auditMetadata.SourceIP,
					UserAgent:           auditMetadata.UserAgent,
				})

				return execution, fmt.Errorf("playbook execution failed at step %s: %w", step.ID, err)
			}
		}

		// Store step result
		if result == nil {
			result = &ActionResult{
				ActionType:  step.ActionType,
				Status:      ActionStatusCompleted,
				Message:     "Step completed successfully",
				StartedAt:   stepStartTime,
				CompletedAt: time.Now(),
				Duration:    time.Since(stepStartTime),
			}
		}

		execution.StepResults[step.ID] = result

		// TASK 25.5: Emit metrics and log step execution for audit trail
		if result.Status == ActionStatusFailed {
			metrics.PlaybookStepFailures.WithLabelValues(playbook.ID, step.ID, string(step.ActionType)).Inc()
		}

		e.logger.Infow("Playbook step executed",
			"playbook_id", playbook.ID,
			"step_id", step.ID,
			"step_name", step.Name,
			"status", result.Status,
			"duration", result.Duration,
			"error", result.Error)

		// TASK 36.5: Log step execution audit event
		resultStr := "success"
		if result.Status == ActionStatusFailed {
			resultStr = "failure"
		} else if result.Status == ActionStatusSkipped {
			resultStr = "skipped"
		}

		stepDurationMs := uint32(result.Duration.Milliseconds())
		if stepDurationMs == 0 && result.Duration > 0 {
			stepDurationMs = 1 // Ensure at least 1ms if duration > 0
		}

		e.auditLogger.Log(ctx, &AuditEvent{
			EventType:           "step_executed",
			PlaybookID:          playbook.ID,
			PlaybookExecutionID: execution.ID,
			StepName:            step.Name,
			ActionType:          string(step.ActionType),
			AlertID:             alert.AlertID,
			Parameters:          step.Parameters,
			Result:              resultStr,
			ErrorMessage:        result.Error,
			DurationMs:          stepDurationMs,
			UserID:              auditMetadata.UserID,
			UserEmail:           auditMetadata.UserEmail,
			SourceIP:            auditMetadata.SourceIP,
			UserAgent:           auditMetadata.UserAgent,
		})
	}

	// All steps completed successfully
	execution.Status = ActionStatusCompleted
	execution.CompletedAt = time.Now()
	execution.Duration = time.Since(execution.StartedAt)

	// TASK 25.5: Emit metrics for playbook completion
	metrics.PlaybookExecutionsTotal.WithLabelValues(playbook.ID, string(execution.Status)).Inc()
	metrics.PlaybookExecutionDuration.WithLabelValues(playbook.ID).Observe(execution.Duration.Seconds())
	e.activeMu.Lock()
	queueDepth := e.maxConcurrent - e.activeCount
	e.activeMu.Unlock()
	metrics.PlaybookQueueDepth.Set(float64(queueDepth)) // Current queue depth

	e.logger.Infow("Playbook execution completed",
		"playbook_id", playbook.ID,
		"alert_id", alert.AlertID,
		"execution_id", execution.ID,
		"status", execution.Status,
		"duration", execution.Duration,
		"steps_executed", len(execution.StepResults))

	// TASK 36.5: Log playbook completion audit event
	resultStr := "success"
	if execution.Status == ActionStatusFailed {
		resultStr = "failure"
	}
	playbookDurationMs := uint32(execution.Duration.Milliseconds())
	if playbookDurationMs == 0 && execution.Duration > 0 {
		playbookDurationMs = 1 // Ensure at least 1ms if duration > 0
	}

	e.auditLogger.Log(ctx, &AuditEvent{
		EventType:           "playbook_completed",
		PlaybookID:          playbook.ID,
		PlaybookExecutionID: execution.ID,
		AlertID:             alert.AlertID,
		Result:              resultStr,
		ErrorMessage:        execution.Error,
		DurationMs:          playbookDurationMs,
		UserID:              auditMetadata.UserID,
		UserEmail:           auditMetadata.UserEmail,
		SourceIP:            auditMetadata.SourceIP,
		UserAgent:           auditMetadata.UserAgent,
	})

	return execution, nil
}

// ShouldTrigger checks if a playbook should be triggered for an alert
// TASK 25.2: Evaluate playbook trigger conditions
func (e *Executor) ShouldTrigger(playbook *Playbook, alert *core.Alert) bool {
	if !playbook.Enabled {
		return false
	}

	// Check all triggers
	for _, trigger := range playbook.Triggers {
		switch trigger.Type {
		case "alert":
			// Always trigger on alert
			if len(trigger.Conditions) == 0 {
				return true
			}
			// Evaluate trigger conditions
			conditionsMet, err := e.evaluateConditions(trigger.Conditions, alert)
			if err != nil {
				e.logger.Warnf("Failed to evaluate trigger conditions for playbook %s: %v", playbook.ID, err)
				continue
			}
			if conditionsMet {
				return true
			}
		case "severity":
			// Check if alert severity matches
			if len(trigger.Conditions) > 0 {
				conditionsMet, err := e.evaluateConditions(trigger.Conditions, alert)
				if err != nil {
					continue
				}
				if conditionsMet {
					return true
				}
			}
		case "rule_id":
			// Check if alert rule ID matches
			if len(trigger.Conditions) > 0 {
				conditionsMet, err := e.evaluateConditions(trigger.Conditions, alert)
				if err != nil {
					continue
				}
				if conditionsMet {
					return true
				}
			}
		}
	}

	return false
}

// evaluateConditions evaluates step or trigger conditions against alert data
// TASK 25.2: Condition evaluator supporting comparison and logical operators
func (e *Executor) evaluateConditions(conditions []PlaybookCondition, alert *core.Alert) (bool, error) {
	if len(conditions) == 0 {
		return true, nil // No conditions = always true
	}

	// Evaluate all conditions with AND logic (all must be true)
	for _, condition := range conditions {
		fieldValue := e.getAlertField(alert, condition.Field)
		if fieldValue == nil {
			return false, fmt.Errorf("field %s not found in alert", condition.Field)
		}

		match, err := e.evaluateCondition(condition, fieldValue)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition: %w", err)
		}

		if !match {
			return false, nil // Any condition fails = overall false
		}
	}

	return true, nil
}

// evaluateCondition evaluates a single condition
// TASK 25.2: Support operators: equals, not_equals, contains, greater_than, less_than
func (e *Executor) evaluateCondition(condition PlaybookCondition, fieldValue interface{}) (bool, error) {
	switch condition.Operator {
	case "equals", "eq":
		return e.compareValues(fieldValue, condition.Value, "=="), nil
	case "not_equals", "ne":
		return !e.compareValues(fieldValue, condition.Value, "=="), nil
	case "contains":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		valueStr := fmt.Sprintf("%v", condition.Value)
		return contains(fieldStr, valueStr), nil
	case "greater_than", "gt":
		return e.compareValues(fieldValue, condition.Value, ">"), nil
	case "less_than", "lt":
		return e.compareValues(fieldValue, condition.Value, "<"), nil
	case "greater_than_or_equal", "gte":
		return e.compareValues(fieldValue, condition.Value, ">="), nil
	case "less_than_or_equal", "lte":
		return e.compareValues(fieldValue, condition.Value, "<="), nil
	case "in":
		// TASK 35.2: Support IN operator for value in array
		return e.evaluateInOperator(fieldValue, condition.Value), nil
	case "matches":
		// TASK 35.2: Support regex matching with timeout protection
		return e.evaluateMatchesOperator(fieldValue, condition.Value)
	default:
		return false, fmt.Errorf("unsupported operator: %s", condition.Operator)
	}
}

// evaluateInOperator checks if fieldValue is in the value array
// TASK 35.2: Support IN operator for array membership
func (e *Executor) evaluateInOperator(fieldValue interface{}, value interface{}) bool {
	// Value should be an array
	valueArr, ok := value.([]interface{})
	if !ok {
		// Try to convert to array if it's a single value
		valueArr = []interface{}{value}
	}

	// Check if fieldValue is in the array
	fieldStr := fmt.Sprintf("%v", fieldValue)
	for _, v := range valueArr {
		valStr := fmt.Sprintf("%v", v)
		if fieldStr == valStr {
			return true
		}
	}
	return false
}

// evaluateMatchesOperator performs regex matching with timeout protection
// TASK 35.2: Support regex matching with ReDoS protection
func (e *Executor) evaluateMatchesOperator(fieldValue interface{}, pattern interface{}) (bool, error) {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	patternStr := fmt.Sprintf("%v", pattern)

	if patternStr == "" {
		return false, fmt.Errorf("regex pattern cannot be empty")
	}

	// Use regexp.MatchString for basic regex matching with timeout context
	// TASK 35.2: Basic regex matching (for production, use detect.EvaluateRegexPatternWithTimeout for ReDoS protection)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Execute regex in goroutine to enforce timeout
	type result struct {
		matched bool
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		matched, err := regexp.MatchString(patternStr, fieldStr)
		resultCh <- result{matched: matched, err: err}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return false, fmt.Errorf("invalid regex pattern: %w", res.err)
		}
		return res.matched, nil
	case <-ctx.Done():
		return false, fmt.Errorf("regex timeout after %v", 500*time.Millisecond)
	}
}

// interpolateVariables replaces {{variable}} placeholders in string values
// TASK 35.3: Variable interpolation for context references
func (e *Executor) interpolateVariables(value interface{}, context map[string]interface{}) interface{} {
	switch v := value.(type) {
	case string:
		// Replace {{field.path}} patterns
		result := v
		// Simple regex to find {{...}} patterns
		re := regexp.MustCompile(`\{\{([^}]+)\}\}`)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			// Extract field path (remove {{ and }})
			fieldPath := match[2 : len(match)-2]
			fieldPath = strings.TrimSpace(fieldPath)

			// Resolve field path from context
			value := e.resolveFieldPath(fieldPath, context)
			if value == nil {
				return match // Keep original if not found
			}
			return fmt.Sprintf("%v", value)
		})
		return result
	case map[string]interface{}:
		// Recursively interpolate map values
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = e.interpolateVariables(val, context)
		}
		return result
	case []interface{}:
		// Recursively interpolate array values
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = e.interpolateVariables(val, context)
		}
		return result
	default:
		return value
	}
}

// resolveFieldPath resolves a dot-notation path from context (e.g., "alert.severity", "event.source_ip")
// TASK 35.3: Support nested field access from execution context
func (e *Executor) resolveFieldPath(path string, context map[string]interface{}) interface{} {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil
	}

	current := context
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		val, ok := current[part]
		if !ok {
			return nil
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return val
		}

		// Otherwise, continue traversing
		nextMap, ok := val.(map[string]interface{})
		if !ok {
			// Try to extract from struct-like objects (alert, event)
			if part == "alert" {
				if alert, ok := val.(*core.Alert); ok {
					return e.getAlertField(alert, strings.Join(parts[i+1:], "."))
				}
			} else if part == "event" {
				if event, ok := val.(*core.Event); ok {
					return e.getEventField(event, strings.Join(parts[i+1:], "."))
				}
			}
			return nil
		}

		current = nextMap
	}

	return nil
}

// compareValues compares two values with the given operator
func (e *Executor) compareValues(a, b interface{}, op string) bool {
	// Convert to comparable types
	aFloat := toFloat(a)
	bFloat := toFloat(b)

	if aFloat != nil && bFloat != nil {
		switch op {
		case "==":
			return *aFloat == *bFloat
		case ">":
			return *aFloat > *bFloat
		case "<":
			return *aFloat < *bFloat
		case ">=":
			return *aFloat >= *bFloat
		case "<=":
			return *aFloat <= *bFloat
		}
	}

	// Fallback to string comparison
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)

	switch op {
	case "==":
		return aStr == bStr
	case ">":
		return aStr > bStr
	case "<":
		return aStr < bStr
	case ">=":
		return aStr >= bStr
	case "<=":
		return aStr <= bStr
	}

	return false
}

// toFloat converts a value to float64 if possible
func toFloat(v interface{}) *float64 {
	switch val := v.(type) {
	case float64:
		return &val
	case float32:
		f := float64(val)
		return &f
	case int:
		f := float64(val)
		return &f
	case int64:
		f := float64(val)
		return &f
	case int32:
		f := float64(val)
		return &f
	default:
		return nil
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOfSubstring(s, substr) >= 0)
}

// indexOfSubstring finds the index of a substring (simple implementation)
func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// getAlertField extracts a field value from an alert
func (e *Executor) getAlertField(alert *core.Alert, field string) interface{} {
	switch field {
	case "alert_id":
		return alert.AlertID
	case "rule_id":
		return alert.RuleID
	case "event_id":
		return alert.EventID
	case "severity":
		return alert.Severity
	case "status":
		return string(alert.Status)
	case "timestamp":
		return alert.Timestamp
	case "rule_name":
		return alert.RuleName
	case "rule_type":
		return alert.RuleType
	case "assigned_to":
		return alert.AssignedTo
	default:
		// Try nested field access (e.g., "event.source_ip")
		if len(field) > 6 && field[:6] == "event." {
			if alert.Event != nil {
				eventField := field[6:]
				return e.getEventField(alert.Event, eventField)
			}
		}
		return nil
	}
}

// getEventField extracts a field value from an event
func (e *Executor) getEventField(event *core.Event, field string) interface{} {
	if event == nil {
		return nil
	}

	switch field {
	case "event_id":
		return event.EventID
	case "timestamp":
		return event.Timestamp
	case "event_type":
		return event.EventType
	case "severity":
		return event.Severity
	case "source_ip":
		return event.SourceIP
	case "source_format":
		return event.SourceFormat
	default:
		// Try to get from Fields map
		if event.Fields != nil {
			if val, ok := event.Fields[field]; ok {
				return val
			}
		}
		return nil
	}
}

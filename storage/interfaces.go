package storage

import (
	"context"
	"time"

	"cerberus/core"
	"cerberus/mitre"
	"cerberus/soar"
)

// RuleStorageInterface defines the interface for rule storage (supports both SIGMA and CQL rules)
type RuleStorageInterface interface {
	GetRules(limit int, offset int) ([]core.Rule, error)
	GetAllRules() ([]core.Rule, error)
	GetRulesByType(ruleType string, limit int, offset int) ([]core.Rule, error)
	GetEnabledRules() ([]core.Rule, error)
	GetRuleCount() (int64, error)
	GetRule(id string) (*core.Rule, error)
	CreateRule(rule *core.Rule) error
	UpdateRule(id string, rule *core.Rule) error
	DeleteRule(id string) error
	DeleteAllRules(ruleType string) (int64, error) // Delete all rules, optionally filtered by type
	EnableRule(id string) error
	DisableRule(id string) error
	SearchRules(query string) ([]core.Rule, error)
	// Advanced filtering
	GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error)
	GetRuleFilterMetadata() (*core.RuleFilterMetadata, error)
	EnsureIndexes() error
}

// ActionStorageInterface defines the interface for action storage
type ActionStorageInterface interface {
	GetActions() ([]core.Action, error)
	GetAction(id string) (*core.Action, error)
	CreateAction(action *core.Action) error
	UpdateAction(id string, action *core.Action) error
	DeleteAction(id string) error
	EnsureIndexes() error
}

// CorrelationRuleStorageInterface defines the interface for correlation rule storage
type CorrelationRuleStorageInterface interface {
	GetCorrelationRules(limit int, offset int) ([]core.CorrelationRule, error)
	GetAllCorrelationRules() ([]core.CorrelationRule, error)
	GetCorrelationRuleCount() (int64, error)
	GetCorrelationRule(id string) (*core.CorrelationRule, error)
	CreateCorrelationRule(rule *core.CorrelationRule) error
	UpdateCorrelationRule(id string, rule *core.CorrelationRule) error
	DeleteCorrelationRule(id string) error
	SearchCorrelationRules(query string, limit, offset int) ([]core.CorrelationRule, int64, error)
	EnsureIndexes() error
}

// InvestigationStorageInterface defines the interface for investigation storage
type InvestigationStorageInterface interface {
	GetInvestigations(limit int, offset int, filters map[string]interface{}) ([]core.Investigation, error)
	GetInvestigationCount(filters map[string]interface{}) (int64, error)
	GetInvestigation(id string) (*core.Investigation, error)
	CreateInvestigation(investigation *core.Investigation) error
	UpdateInvestigation(id string, investigation *core.Investigation) error
	DeleteInvestigation(id string) error
	CloseInvestigation(id string, verdict core.InvestigationVerdict, resolutionCategory, summary string, affectedAssets []string, mlFeedback *core.MLFeedback) error
	AddNote(investigationID, analystID, content string) error
	AddAlert(investigationID, alertID string) error
	GetInvestigationsByAlertID(alertID string) ([]core.Investigation, error)
	GetInvestigationsByAssignee(assigneeID string, limit int, offset int) ([]core.Investigation, error)
	// TASK 28: Investigation lifecycle management methods
	AssociateAlert(ctx context.Context, investigationID, alertID, userID string) error
	DissociateAlert(ctx context.Context, investigationID, alertID string) error
	GetAlertsForInvestigation(ctx context.Context, investigationID string) ([]*core.Alert, error)
	GetInvestigationsForAlert(ctx context.Context, alertID string) ([]*core.Investigation, error)
	GenerateTimeline(ctx context.Context, investigationID string, limit, offset int) ([]TimelineEntry, int64, error)
	CalculateStatistics(ctx context.Context, investigationID string) (*InvestigationDetailedStatistics, error)
	ValidateClosureRequirements(investigation *core.Investigation) error
	EnsureIndexes() error
}

// MitreStorageInterface defines the interface for MITRE ATT&CK data storage
type MitreStorageInterface interface {
	GetTactics() ([]mitre.Tactic, error)
	GetTactic(id string) (*mitre.Tactic, error)
	GetTacticByShortName(shortName string) (*mitre.Tactic, error)
	GetTechniques(limit int, offset int, tacticID string) ([]mitre.Technique, error)
	GetTechniqueCount() (int64, error)
	GetTechnique(id string) (*mitre.Technique, error)
	GetSubTechniques(parentTechniqueID string) ([]mitre.Technique, error) // TASK 9.1: Sub-technique support
	GetTacticsForTechnique(techniqueID string) ([]mitre.Tactic, error)
	SearchTechniques(query string, limit int) ([]mitre.Technique, error)
	CreateTactic(tactic *mitre.Tactic) error
	CreateTechnique(technique *mitre.Technique) error
	CreateTechniqueTacticMapping(techniqueID, tacticID string) error // TASK 9.1: Many-to-many mapping
	UpdateTactic(id string, tactic *mitre.Tactic) error
	UpdateTechnique(id string, technique *mitre.Technique) error
	DeleteAllTactics() error
	DeleteAllTechniques() error
	GetTacticCoverage() ([]mitre.TacticCoverage, error)
	GetTechniqueCoverage() ([]mitre.TechniqueCoverage, error)
	// TASK 9.1: Data source methods
	CreateDataSource(dataSource *mitre.DataSource) error
	GetDataSources() ([]mitre.DataSource, error)
	CreateTechniqueDataSourceMapping(techniqueID, dataSourceID string) error
	EnsureIndexes() error
}

// DynamicListenerStorageInterface defines the interface for dynamic listener storage
type DynamicListenerStorageInterface interface {
	CreateListener(listener *DynamicListener) error
	GetListener(id string) (*DynamicListener, error)
	GetAllListeners() ([]*DynamicListener, error)
	GetListenersByStatus(status string) ([]*DynamicListener, error)
	UpdateListener(id string, listener *DynamicListener) error
	UpdateListenerStatus(id string, status string) error
	UpdateStatistics(id string, stats *ListenerStats) error
	IncrementEventCount(id string) error
	IncrementErrorCount(id string) error
	SetStartedAt(id string, startedAt time.Time) error
	SetStoppedAt(id string, stoppedAt time.Time) error
	DeleteListener(id string) error
	CheckPortConflict(host string, port int, protocol string, excludeID string) (bool, error)
}

// ExceptionStorageInterface defines the interface for exception storage
type ExceptionStorageInterface interface {
	// CRUD operations
	CreateException(exception *core.Exception) error
	GetException(id string) (*core.Exception, error)
	GetAllExceptions(filters *core.ExceptionFilters) ([]core.Exception, int64, error)
	GetExceptionsByRuleID(ruleID string) ([]core.Exception, error)
	GetGlobalExceptions() ([]core.Exception, error)
	GetActiveExceptions() ([]core.Exception, error)
	UpdateException(id string, exception *core.Exception) error
	DeleteException(id string) error

	// Hit tracking
	IncrementHitCount(id string) error
	UpdateLastHit(id string, timestamp time.Time) error

	// Utility
	EnsureIndexes() error
}

// MLModelStorageInterface defines the interface for ML model storage
// TASK 26: ML model persistence interface
type MLModelStorageInterface interface {
	SaveModel(ctx context.Context, name, version, modelType string, modelData []byte, config, metrics string) error
	LoadModel(ctx context.Context, name, version string) (string, []byte, error)
	LoadLatestModel(ctx context.Context, name string) (string, string, []byte, error)
	ListVersions(ctx context.Context, name string) ([]string, error)
	ListModels(ctx context.Context, name string) ([]ModelMetadata, error)
	GetLatestVersion(modelName string) (string, error) // For versioning interface
	DeployModel(ctx context.Context, name, version, deployedBy string) error
	GetActiveModel(ctx context.Context, name string) (string, string, []byte, error)
	GetDeploymentHistory(ctx context.Context, name string, limit int) ([]DeploymentRecord, error)
}

// MLModelMetricsStorageInterface defines the interface for ML model performance metrics storage
// TASK 29: ML feedback loop metrics storage
type MLModelMetricsStorageInterface interface {
	RecordFeedback(ctx context.Context, alertID, investigationID string, predictedScore float64, predictedAnomaly, actualAnomaly bool, confusionEntry string, timestamp time.Time) error
	GetConfusionMatrix(ctx context.Context, modelName string, windowDuration time.Duration) (*ConfusionMatrix, error)
	GetAverageMetrics(ctx context.Context, modelName string, windowDuration, aggregationPeriod time.Duration) (*ModelMetricsSummary, error)
	StoreMetrics(ctx context.Context, metrics *ModelMetrics) error
}

// ConfusionMatrix represents a confusion matrix for model evaluation
type ConfusionMatrix struct {
	TP int64 // True Positives
	TN int64 // True Negatives
	FP int64 // False Positives
	FN int64 // False Negatives
}

// ModelMetricsSummary represents summarized metrics for a time window
type ModelMetricsSummary struct {
	Precision float64
	Recall    float64
	F1Score   float64
	Accuracy  float64
}

// ModelMetrics represents detailed model performance metrics
// Defined in ml/feedback_loop.go
type ModelMetrics struct {
	ModelID           string
	Timestamp         time.Time
	WindowDuration    time.Duration
	TruePositives     int64
	TrueNegatives     int64
	FalsePositives    int64
	FalseNegatives    int64
	Precision         float64
	Recall            float64
	F1Score           float64
	FalsePositiveRate float64
	FalseNegativeRate float64
	Accuracy          float64
	DriftScore        float64
	DriftDetected     bool
}

// PlaybookStorageInterface defines the interface for playbook storage.
// Implementations must be safe for concurrent access.
// All getter methods return ErrPlaybookNotFound when the playbook does not exist.
// IDs are caller-generated UUIDs.
type PlaybookStorageInterface interface {
	// CRUD operations
	CreatePlaybook(playbook *soar.Playbook) error
	GetPlaybook(id string) (*soar.Playbook, error)
	GetPlaybooks(limit, offset int) ([]soar.Playbook, error)
	GetAllPlaybooks() ([]soar.Playbook, error)
	GetPlaybookCount() (int64, error)
	UpdatePlaybook(id string, playbook *soar.Playbook) error
	DeletePlaybook(id string) error

	// Enable/Disable operations
	EnablePlaybook(id string) error
	DisablePlaybook(id string) error

	// Filtering and search
	GetPlaybooksByStatus(enabled bool) ([]soar.Playbook, error)
	GetPlaybooksByTag(tag string) ([]soar.Playbook, error)
	SearchPlaybooks(query string) ([]soar.Playbook, error)

	// Validation helpers
	PlaybookNameExists(name string, excludeID string) (bool, error)

	// Statistics - playbook counts only; execution stats are in PlaybookExecutionStorageInterface
	GetPlaybookStats() (*PlaybookStats, error)

	// Indexing
	EnsureIndexes() error
}

// PlaybookStats represents aggregated statistics for playbooks.
// Execution-related statistics are provided by PlaybookExecutionStorageInterface.
type PlaybookStats struct {
	TotalPlaybooks    int64 `json:"total_playbooks"`
	EnabledPlaybooks  int64 `json:"enabled_playbooks"`
	DisabledPlaybooks int64 `json:"disabled_playbooks"`
}

// PlaybookExecutionSummary represents a summary of playbook execution statistics.
// Used by PlaybookExecutionStorageInterface for execution reporting.
type PlaybookExecutionSummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ExecutionCount int64  `json:"execution_count"`
}

// RulePerformanceStorageInterface defines the interface for rule performance tracking
// TASK 171: Track rule evaluation metrics for performance monitoring
type RulePerformanceStorageInterface interface {
	// GetPerformance retrieves performance metrics for a rule
	GetPerformance(ruleID string) (*RulePerformance, error)
	// UpdatePerformance updates or inserts performance metrics for a rule
	UpdatePerformance(stats *RulePerformance) error
	// BatchUpdatePerformance updates multiple rule performance records atomically
	BatchUpdatePerformance(stats []*RulePerformance) error
	// GetSlowRules retrieves rules exceeding evaluation time threshold
	GetSlowRules(thresholdMs float64, limit int) ([]*RulePerformance, error)
	// ReportFalsePositive increments false positive count for a rule
	ReportFalsePositive(ruleID string) error
	// DeletePerformance removes performance metrics for a rule
	DeletePerformance(ruleID string) error
}

// Package api Cerberus SIEM API
//
//	@title			Cerberus SIEM API
//	@version		1.0
//	@description	API for managing Cerberus SIEM events, alerts, rules, and configuration
//	@termsOfService	http://swagger.io/terms/
//
// @license.name	MIT
// @license.url	https://opensource.org/licenses/MIT
//
// @host		localhost:8081
// @BasePath	/
// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @description				Enter your API key
package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/ingest"
	"cerberus/service"
	"cerberus/soar"
	"cerberus/storage"
	"cerberus/threat/feeds"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// Request size limits to prevent DoS attacks
	maxRequestBodySize = 10 * 1024 * 1024 // 10 MB
	maxHeaderBytes     = 1 * 1024 * 1024  // 1 MB
)

// limitRequestBody middleware limits the size of request bodies to prevent DoS
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		next.ServeHTTP(w, r)
	})
}

// rateLimiterEntry holds a rate limiter with last seen time
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// authFailureEntry holds auth failure count and last failure time
// Used by detectSuspiciousLoginActivity for tracking login patterns
type authFailureEntry struct {
	// TASK 138: count field is unused, but lastFail is used
	lastFail time.Time
}

// EventStorer interface for event storage
type EventStorer interface {
	GetEvents(ctx context.Context, limit int, offset int) ([]core.Event, error)
	GetEventCount(ctx context.Context) (int64, error)
	GetEventCountsByMonth(ctx context.Context) ([]map[string]interface{}, error)
}

// AlertStorer interface for alert storage
type AlertStorer interface {
	GetAlerts(ctx context.Context, limit int, offset int) ([]core.Alert, error)
	GetAlert(ctx context.Context, id string) (*core.Alert, error)
	GetAlertCount(ctx context.Context) (int64, error)
	GetAlertCountsByMonth(ctx context.Context) ([]map[string]interface{}, error)
	AcknowledgeAlert(ctx context.Context, id string) error
	DismissAlert(ctx context.Context, id string) error
	UpdateAlertStatus(ctx context.Context, id string, status core.AlertStatus) error
	AssignAlert(ctx context.Context, id string, assignedTo string) error
	DeleteAlert(ctx context.Context, id string) error
	InsertAlert(ctx context.Context, alert *core.Alert) error // TASK 145.2: Added for AlertService integration
	// TASK 51.3: GetAlertsFiltered retrieves alerts with filtering by severity and status
	GetAlertsFiltered(ctx context.Context, limit, offset int, severity, status string) ([]*core.Alert, error)
	// TASK 104: UpdateAlertDisposition updates alert disposition with analyst verdict
	// TASK 111: Returns previous disposition for audit logging
	// TASK 111 FIX: Accepts context for request cancellation support (BLOCKING-5)
	UpdateAlertDisposition(ctx context.Context, alertID string, disposition core.AlertDisposition, reason, userID string) (previousDisposition string, err error)
	// TASK 105: UpdateAlertAssignee updates alert assignee with nullable support for unassign
	UpdateAlertAssignee(ctx context.Context, alertID string, assigneeID *string) error
	// TASK 105: GetAlertByID retrieves an alert by ID (for getting previous assignee)
	GetAlertByID(ctx context.Context, alertID string) (*core.Alert, error)
	// TASK 106: UpdateAlertInvestigation links or unlinks an alert to/from an investigation
	UpdateAlertInvestigation(ctx context.Context, alertID, investigationID string) error
	// TASK 110: GetAlertsWithFilters retrieves alerts with comprehensive filtering including dispositions
	// Returns alerts, total count, and error
	GetAlertsWithFilters(ctx context.Context, filters *core.AlertFilters) ([]*core.Alert, int64, error)
	// Alert status history methods for timeline display
	// RecordStatusChange records a status change in the alert's history
	RecordStatusChange(ctx context.Context, change *core.StatusChange) error
	// GetAlertHistory retrieves the status change history for an alert
	GetAlertHistory(ctx context.Context, alertID string) ([]*core.StatusChange, error)
}

// RuleStorer interface for rule storage
// TASK 173 BLOCKER-4: Legacy Design Note
// This interface does NOT use context.Context parameters. This is a legacy design choice
// from the original implementation. While newer interfaces (EventStorer, AlertStorer) use
// context for cancellation support, RuleStorer predates this pattern. The storage
// implementations (SQLiteRuleStorage) also do not accept context.
// This is documented as a known limitation, not a bug. Future refactoring could add context
// support, but would require breaking changes to both the interface and all implementations.
type RuleStorer interface {
	GetRules(limit int, offset int) ([]core.Rule, error)
	GetAllRules() ([]core.Rule, error)
	GetRuleCount() (int64, error)
	GetRule(id string) (*core.Rule, error)
	CreateRule(rule *core.Rule) error
	UpdateRule(id string, rule *core.Rule) error
	DeleteRule(id string) error
	DeleteAllRules(ruleType string) (int64, error)                      // Delete all rules, optionally by type
	GetRulesWithFilters(filters *core.RuleFilters) ([]core.Rule, int64, error) // Filter rules by search term, etc.
}

// ActionStorer interface for action storage
type ActionStorer interface {
	GetActions() ([]core.Action, error)
	GetAction(id string) (*core.Action, error)
	CreateAction(action *core.Action) error
	UpdateAction(id string, action *core.Action) error
	DeleteAction(id string) error
}

// CorrelationRuleStorer interface for correlation rule storage
// TASK 173 BLOCKER-4: Legacy Design Note (same as RuleStorer)
// This interface does NOT use context.Context parameters. This is a legacy design choice.
// See RuleStorer comment above for full explanation.
type CorrelationRuleStorer interface {
	GetCorrelationRules(limit int, offset int) ([]core.CorrelationRule, error)
	GetAllCorrelationRules() ([]core.CorrelationRule, error)
	GetCorrelationRuleCount() (int64, error)
	GetCorrelationRule(id string) (*core.CorrelationRule, error)
	CreateCorrelationRule(rule *core.CorrelationRule) error
	UpdateCorrelationRule(id string, rule *core.CorrelationRule) error
	DeleteCorrelationRule(id string) error
	SearchCorrelationRules(query string, limit, offset int) ([]core.CorrelationRule, int64, error)
}

// DetectorInterface defines the interface for detector operations
// This allows the API to trigger rule reloads without tight coupling
// PRODUCTION: Methods return errors to enable proper error handling in API handlers
type DetectorInterface interface {
	ReloadRules(rules []core.Rule) error
	ReloadCorrelationRules(rules []core.CorrelationRule) error
}

// API holds the API server
type API struct {
	router                 *mux.Router
	server                 *http.Server
	eventStorage           EventStorer
	alertStorage           AlertStorer
	rawAlertStorage        AlertStorer // Same as alertStorage for compatibility
	ruleStorage            RuleStorer
	actionStorage          ActionStorer
	correlationRuleStorage CorrelationRuleStorer
	investigationStorage   InvestigationStorer
	userStorage            storage.UserStorage
	roleStorage            storage.RoleStorage // RBAC: Role storage for permission management
	savedSearchStorage     *storage.SQLiteSavedSearchStorage
	listenerManager        *ingest.ListenerManager // TASK 81: Dynamic listener manager
	detector               DetectorInterface       // PRODUCTION FIX: Detector for hot-reload of rules
	mlManager              *MLManager
	mlSystem               MLAnomalyDetector // For health checks
	config                 *config.Config
	logger                 *zap.SugaredLogger
	rateLimiters           map[string]*rateLimiterEntry
	rateLimitersMu         sync.Mutex
	multiTierRateLimiter   *MultiTierRateLimiter // TASK 24: Multi-tier rate limiting
	// TASK 138: Removed unused authFailures and authFailuresMu fields (now in AuthManager)
	authManager              *AuthManager
	stopCh                   chan struct{}
	clickhouseConn           driver.Conn                             // TASK 4.7: ClickHouse connection for query execution
	clickhouse               *storage.ClickHouse                     // Health checks: ClickHouse wrapper
	sqlite                   *storage.SQLite                         // Health checks: SQLite wrapper
	startTime                time.Time                               // Health checks: Service start time
	dlq                      *ingest.DLQ                             // TASK 7.4: DLQ for malformed events
	mitreStorage             storage.MitreStorageInterface           // TASK 9.6: MITRE storage for techniques and data sources
	playbookExecutor         *soar.Executor                          // TASK 35: SOAR playbook executor
	playbookExecutionStorage *storage.SQLitePlaybookExecutionStorage // TASK 35: Playbook execution state storage
	playbookStorage          storage.PlaybookStorageInterface        // TASK 96: Playbook CRUD storage
	passwordPolicyManager    *PasswordPolicyManager                  // TASK 38: Password policy enforcement
	mlModelStorage           *storage.MLModelStorage                 // TASK 37: ML model persistence storage
	fieldMappingStorage      storage.FieldMappingStorage             // Field mapping storage for SIGMA field normalization
	evidenceStorage          core.EvidenceStorage                    // Evidence file attachment storage
	alertLinkStorage         core.AlertLinkStorage                   // Alert linking storage for bi-directional alert relationships
	alertService             core.AlertService                       // TASK 145.2: Alert service for business logic
	feedManager              FeedManagerInterface                    // TASK 154: Feed management for SIGMA rule feeds
	wsHub                    *Hub                                    // TASK 158: WebSocket hub for real-time event broadcasting
	lifecycleAuditStorage         *storage.SQLiteLifecycleAuditStorage         // TASK 169: Rule lifecycle audit trail storage
	fieldMappingAuditStorage      *storage.SQLiteFieldMappingAuditStorage      // TASK 185: Field mapping lifecycle audit trail storage
	detectorReloadMu              sync.Mutex                                   // TASK 173 BLOCKER-2: Mutex for safe detector reload operations
	approvalStorage               storage.ApprovalStorageInterface             // Approval workflow storage for playbook step approvals
	iocStorage                    core.IOCStorage                              // IOC lifecycle management storage
	iocFeedManager                feeds.IOCFeedManager                         // IOC feed management for threat intelligence feeds
}

// NewAPI creates a new API server
// PRODUCTION: Now accepts detector for hot-reload capability and roleStorage for RBAC
// TASK 7.4: Now accepts DLQ for malformed event management
// TASK 9.6: Now accepts mitreStorage for MITRE ATT&CK integration
// TASK 35: Now accepts playbook executor and execution storage for SOAR
// TASK 38: Now accepts password history storage for password policy enforcement
// TASK 37: Now accepts ML model storage for model persistence and lifecycle management
// TASK 81: Now accepts listenerManager for dynamic listener management
// TASK 99: Now accepts playbookStorage for playbook CRUD operations
// TASK 169: Now accepts lifecycleAuditStorage for rule lifecycle management
// TASK 185: Now accepts fieldMappingAuditStorage for field mapping lifecycle management
// Also accepts fieldMappingStorage for SIGMA field normalization
// Also accepts evidenceStorage for alert evidence file attachments
// Also accepts alertLinkStorage for bi-directional alert relationships
func NewAPI(eventStorage EventStorer, alertStorage AlertStorer, ruleStorage RuleStorer, actionStorage ActionStorer, correlationRuleStorage CorrelationRuleStorer, investigationStorage InvestigationStorer, userStorage storage.UserStorage, roleStorage storage.RoleStorage, savedSearchStorage *storage.SQLiteSavedSearchStorage, detector DetectorInterface, mlDetector MLAnomalyDetector, config *config.Config, logger *zap.SugaredLogger, dlq *ingest.DLQ, mitreStorage storage.MitreStorageInterface, playbookExecutor *soar.Executor, playbookExecutionStorage *storage.SQLitePlaybookExecutionStorage, passwordHistoryStorage *storage.SQLitePasswordHistoryStorage, mlModelStorage *storage.MLModelStorage, fieldMappingStorage storage.FieldMappingStorage, listenerManager *ingest.ListenerManager, playbookStorage storage.PlaybookStorageInterface, evidenceStorage core.EvidenceStorage, alertLinkStorage core.AlertLinkStorage, lifecycleAuditStorage *storage.SQLiteLifecycleAuditStorage, fieldMappingAuditStorage *storage.SQLiteFieldMappingAuditStorage) *API {
	api := &API{
		router:                 mux.NewRouter(),
		eventStorage:           eventStorage,
		alertStorage:           alertStorage,
		rawAlertStorage:        alertStorage,
		ruleStorage:            ruleStorage,
		actionStorage:          actionStorage,
		correlationRuleStorage: correlationRuleStorage,
		investigationStorage:   investigationStorage,
		userStorage:            userStorage,
		roleStorage:            roleStorage, // RBAC: Store role storage reference
		savedSearchStorage:     savedSearchStorage,
		listenerManager:        listenerManager, // TASK 81: Store listener manager reference
		detector:               detector,        // PRODUCTION FIX: Store detector reference for rule reloading
		mlManager:              NewMLManager(mlDetector, logger),
		mlSystem:               mlDetector, // For health checks
		config:                 config,
		logger:                 logger,
		rateLimiters:           make(map[string]*rateLimiterEntry),
		// TASK 138: Removed authFailures initialization (now in AuthManager)
		authManager:              NewAuthManager(),
		stopCh:                   make(chan struct{}),
		startTime:                time.Now(),                                                       // Health checks: track service start time
		dlq:                      dlq,                                                              // TASK 7.4: Store DLQ reference
		mitreStorage:             mitreStorage,                                                     // TASK 9.6: Store MITRE storage reference
		playbookExecutor:         playbookExecutor,                                                 // TASK 35: Store playbook executor reference
		playbookExecutionStorage: playbookExecutionStorage,                                         // TASK 35: Store playbook execution storage reference
		passwordPolicyManager:    NewPasswordPolicyManager(config, passwordHistoryStorage, logger), // TASK 38: Initialize password policy manager
		mlModelStorage:           mlModelStorage,                                                   // TASK 37: Store ML model storage reference
		fieldMappingStorage:      fieldMappingStorage,                                              // Store field mapping storage reference
		playbookStorage:          playbookStorage,                                                  // TASK 99: Store playbook CRUD storage reference
		evidenceStorage:          evidenceStorage,                                                  // Evidence file attachment storage
		alertLinkStorage:         alertLinkStorage,                                                 // Alert linking storage for bi-directional relationships
		lifecycleAuditStorage:    lifecycleAuditStorage,                                            // TASK 169: Rule lifecycle audit trail storage
		fieldMappingAuditStorage: fieldMappingAuditStorage,                                         // TASK 185: Field mapping lifecycle audit trail storage
	}

	// TASK 145.2: Initialize alert service for business logic separation
	// Note: alertStorage and ruleStorage are type-compatible with service.AlertStorage and service.RuleStorage
	api.alertService = service.NewAlertService(alertStorage, ruleStorage, userStorage, investigationStorage, logger)

	// TASK 24: Initialize multi-tier rate limiter
	var redisCache *core.RedisCache = nil
	if config.API.RateLimit.Redis.Enabled {
		redisCache = core.NewRedisCache(
			config.API.RateLimit.Redis.Addr,
			config.API.RateLimit.Redis.Password,
			config.API.RateLimit.Redis.DB,
			config.API.RateLimit.Redis.PoolSize,
			logger,
		)
		// Test Redis connection
		if err := redisCache.Ping(context.Background()); err != nil {
			logger.Warnf("Redis connection failed, falling back to in-memory rate limiting: %v", err)
			redisCache = nil
		}
	}

	loginConfig := &RateLimiterConfig{
		Limit:  config.API.RateLimit.Login.Limit,
		Window: config.API.RateLimit.Login.Window,
		Burst:  config.API.RateLimit.Login.Burst,
	}
	apiConfig := &RateLimiterConfig{
		Limit:  config.API.RateLimit.API.Limit,
		Window: config.API.RateLimit.API.Window,
		Burst:  config.API.RateLimit.API.Burst,
	}
	globalConfig := &RateLimiterConfig{
		Limit:  config.API.RateLimit.Global.Limit,
		Window: config.API.RateLimit.Global.Window,
		Burst:  config.API.RateLimit.Global.Burst,
	}

	api.multiTierRateLimiter = NewMultiTierRateLimiter(
		loginConfig,
		apiConfig,
		globalConfig,
		config.API.RateLimit.ExemptIPs,
		redisCache,
		logger,
	)

	// TASK 158: Initialize WebSocket hub for real-time events
	api.wsHub = NewHub(logger, context.Background())

	api.setupRoutes()
	go api.cleanupRateLimiters()
	// SECURITY FIX: Start JWT token blacklist cleanup goroutine
	go api.cleanupTokenBlacklist()
	// TASK 158: Start WebSocket hub
	go api.wsHub.Start()
	return api
}

// SetHealthCheckDependencies sets the storage connections needed for health checks
// This should be called after the API is created if ClickHouse/SQLite aren't available at creation time
func (a *API) SetHealthCheckDependencies(clickhouse *storage.ClickHouse, sqlite *storage.SQLite) {
	a.clickhouse = clickhouse
	a.sqlite = sqlite
	// Also set clickhouseConn for query execution
	if clickhouse != nil {
		a.clickhouseConn = clickhouse.Conn
	}
}

// SetFeedManager sets the feed manager for SIGMA rule feed management
// TASK 154: This should be called after the API is created when feedManager is available
func (a *API) SetFeedManager(feedManager FeedManagerInterface) {
	a.feedManager = feedManager
}

// SetIOCStorage sets the IOC storage for indicator of compromise lifecycle management
// IOC Lifecycle: This should be called after the API is created when IOC storage is available
func (a *API) SetIOCStorage(iocStorage core.IOCStorage) {
	a.iocStorage = iocStorage
}

// SetIOCFeedManager sets the IOC feed manager for threat intelligence feed management
// IOC Feeds: This should be called after the API is created when IOC feed manager is available
func (a *API) SetIOCFeedManager(iocFeedManager feeds.IOCFeedManager) {
	a.iocFeedManager = iocFeedManager
}

// setupRoutes sets up the API routes
func (a *API) setupRoutes() {
	// Global middlewares - applied to all routes
	// TASK 152: Request ID middleware MUST be first for proper correlation
	a.router.Use(a.requestIDMiddleware) // TASK 152: Request tracing and correlation IDs
	a.router.Use(a.corsMiddleware)
	a.router.Use(a.globalRateLimitMiddleware) // TASK 24: Global rate limit first
	a.router.Use(a.rateLimitMiddleware)       // Legacy rate limiting (for backwards compatibility)
	a.router.Use(limitRequestBody)
	a.router.Use(a.contentSecurityPolicyMiddleware) // SECURITY: Add CSP headers
	a.router.Use(a.errorRecoveryMiddleware)         // SECURITY: Panic recovery
	a.router.Use(a.errorSanitizationMiddleware)     // SECURITY: Sanitize error responses

	// Public routes (no auth required)
	// AUTH: Public authentication endpoints (not versioned for compatibility)
	a.router.HandleFunc("/api/auth/config", a.getAuthConfig).Methods("GET")
	// TASK 24: Login endpoint uses login-tier rate limiting
	loginHandler := a.loginRateLimitMiddleware(http.HandlerFunc(a.login))
	a.router.Handle("/api/auth/login", loginHandler).Methods("POST")
	a.router.HandleFunc("/api/auth/logout", a.logout).Methods("POST")
	a.router.HandleFunc("/api/auth/status", a.authStatus).Methods("GET")

	// CSRF token endpoint - requires JWT auth but NOT CSRF protection (chicken-and-egg problem)
	if a.config.Auth.Enabled {
		csrfTokenHandler := a.jwtAuthMiddleware(http.HandlerFunc(a.getCSRFToken))
		a.router.Handle("/api/v1/auth/csrf-token", csrfTokenHandler).Methods("GET")
	}

	// TASK 8.3: MFA endpoints (require authentication)
	if a.config.Auth.Enabled {
		authRequired := a.router.PathPrefix("/api/v1/auth/mfa").Subrouter()
		authRequired.Use(a.jwtAuthMiddleware)
		authRequired.Use(a.csrfProtectionMiddleware)
		authRequired.HandleFunc("/enable", a.enableMFA).Methods("POST")
		authRequired.HandleFunc("/verify", a.verifyMFA).Methods("POST")
		authRequired.HandleFunc("/disable", a.disableMFA).Methods("POST")
	}

	// Health check endpoints (unauthenticated for orchestrator probes)
	a.router.HandleFunc("/health", a.healthCheck).Methods("GET")
	a.router.HandleFunc("/health/live", a.healthLive).Methods("GET")         // Liveness probe
	a.router.HandleFunc("/health/ready", a.healthReady).Methods("GET")       // Readiness probe
	a.router.HandleFunc("/health/detailed", a.healthDetailed).Methods("GET") // Detailed diagnostics
	a.router.Handle("/metrics", promhttp.Handler())

	// TASK 160.1: System endpoints (first-run check is unauthenticated for frontend detection)
	a.router.HandleFunc("/api/v1/system/first-run", a.getFirstRun).Methods("GET")

	// Swagger UI
	a.router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// TASK 158: WebSocket endpoint for real-time event streaming
	// Note: WebSocket upgrades must happen BEFORE other middlewares that write responses
	a.router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(a.wsHub, a.logger, w, r)
	}).Methods("GET")

	// Protected routes (require auth)
	if a.config.Auth.Enabled {
		protected := a.router.PathPrefix("/api/v1").Subrouter()
		protected.Use(a.jwtAuthMiddleware)
		protected.Use(a.apiRateLimitMiddleware)   // TASK 24: API-tier rate limiting for authenticated endpoints
		protected.Use(a.csrfProtectionMiddleware) // SECURITY: Add CSRF protection to all protected routes

		// RBAC: Events endpoints (read:events permission required)
		protected.Handle("/events", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getEvents))).Methods("GET")

		// RBAC: Alerts endpoints (read:alerts for read, write would need different permission)
		protected.Handle("/alerts", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getAlerts))).Methods("GET")
		protected.Handle("/alerts/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getAlertByID))).Methods("GET")
		protected.Handle("/alerts/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.deleteAlert))).Methods("DELETE")
		protected.Handle("/alerts/{id}/acknowledge", a.RequirePermission(storage.PermAcknowledgeAlerts)(http.HandlerFunc(a.acknowledgeAlert))).Methods("POST") // TASK 31: Use specific acknowledge permission
		protected.Handle("/alerts/{id}/dismiss", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.dismissAlert))).Methods("POST")
		protected.Handle("/alerts/{id}/status", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.updateAlertStatus))).Methods("PUT")
		protected.Handle("/alerts/{id}/assign", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.assignAlert))).Methods("PUT")
		protected.Handle("/alerts/{id}/history", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getAlertHistory))).Methods("GET")
		// TASK 104: Alert disposition endpoint (requires disposition permission)
		protected.Handle("/alerts/{id}/disposition", a.RequirePermission(storage.PermDispositionAlerts)(http.HandlerFunc(a.updateAlertDisposition))).Methods("PATCH")
		// TASK 105: Alert assignee endpoint (requires dedicated assignment permission)
		protected.Handle("/alerts/{id}/assignee", a.RequirePermission(storage.PermAssignAlerts)(http.HandlerFunc(a.updateAlertAssignee))).Methods("PATCH")
		// TASK 106: Create investigation from alert endpoint (requires investigation creation permission)
		protected.Handle("/alerts/{id}/investigation", a.RequirePermission(storage.PermCreateInvestigations)(http.HandlerFunc(a.createInvestigationFromAlert))).Methods("POST")
		// TASK 107: Link alert to existing investigation endpoint (requires investigation creation permission)
		protected.Handle("/alerts/{id}/investigation", a.RequirePermission(storage.PermCreateInvestigations)(http.HandlerFunc(a.linkAlertToInvestigation))).Methods("PATCH")

		// Evidence endpoints for alert attachments
		protected.Handle("/alerts/{id}/evidence", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.listEvidence))).Methods("GET")
		protected.Handle("/alerts/{id}/evidence", a.RequirePermission(storage.PermAcknowledgeAlerts)(http.HandlerFunc(a.uploadEvidence))).Methods("POST")
		protected.Handle("/alerts/{id}/evidence/{evidence_id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getEvidence))).Methods("GET")
		protected.Handle("/alerts/{id}/evidence/{evidence_id}/download", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.downloadEvidence))).Methods("GET")
		protected.Handle("/alerts/{id}/evidence/{evidence_id}", a.RequirePermission(storage.PermAcknowledgeAlerts)(http.HandlerFunc(a.deleteEvidence))).Methods("DELETE")

		// Alert linking endpoints for bi-directional alert relationships
		protected.Handle("/alerts/{id}/related", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.listRelatedAlerts))).Methods("GET")
		protected.Handle("/alerts/{id}/related", a.RequirePermission(storage.PermAcknowledgeAlerts)(http.HandlerFunc(a.linkAlerts))).Methods("POST")
		protected.Handle("/alerts/{id}/related/{related_id}", a.RequirePermission(storage.PermAcknowledgeAlerts)(http.HandlerFunc(a.unlinkAlerts))).Methods("DELETE")

		// TASK 173: Unified Rules endpoints (detection + correlation)
		// Static routes MUST be registered BEFORE parameterized routes to ensure proper matching
		protected.Handle("/rules/validate", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleValidateRule))).Methods("POST")
		protected.Handle("/rules/import", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleImportRules))).Methods("POST")
		protected.Handle("/rules/export", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleExportRules))).Methods("GET")
		protected.Handle("/rules/bulk-enable", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleBulkEnable))).Methods("POST")
		protected.Handle("/rules/bulk-disable", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleBulkDisable))).Methods("POST")
		protected.Handle("/rules/bulk-delete", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleBulkDelete))).Methods("POST")
		protected.Handle("/rules/clear-all", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.handleClearAllRules))).Methods("POST")

		// TASK 170: Rule testing endpoints with RBAC
		protected.Handle("/rules/test", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.TestRule))).Methods("POST")
		protected.Handle("/rules/sample-events", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.UploadSampleEvents))).Methods("POST")

		// TASK 171: Rule performance tracking static endpoints
		protected.Handle("/rules/performance/slow", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetSlowRules))).Methods("GET")

		// RBAC: Unified Rules endpoints (support both detection and correlation)
		// Note: handleGetRules is the new unified handler, getRules is the legacy handler
		protected.Handle("/rules", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetRules))).Methods("GET")
		protected.Handle("/rules", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleCreateRule))).Methods("POST")
		protected.Handle("/rules/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetRule))).Methods("GET")
		protected.Handle("/rules/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleUpdateRule))).Methods("PUT", "PATCH") // TASK 48: PATCH support for partial updates
		protected.Handle("/rules/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleDeleteRule))).Methods("DELETE")

		// TASK 169: Rule lifecycle management endpoints with RBAC
		protected.Handle("/rules/{id}/lifecycle", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleRuleLifecycle))).Methods("POST")
		protected.Handle("/rules/{id}/lifecycle-history", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetLifecycleHistory))).Methods("GET")

		// TASK 170: Rule testing endpoints with rule ID
		protected.Handle("/rules/{id}/test-batch", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.BatchTestRule))).Methods("POST")

		// TASK 171: Rule performance tracking per-rule endpoints
		protected.Handle("/rules/{id}/performance", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetRulePerformance))).Methods("GET")
		protected.Handle("/rules/{id}/performance/false-positive", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleReportFalsePositive))).Methods("POST")

		// RBAC: Actions endpoints
		protected.Handle("/actions", a.RequirePermission(storage.PermReadActions)(http.HandlerFunc(a.getActions))).Methods("GET")
		protected.Handle("/actions", a.RequirePermission(storage.PermWriteActions)(http.HandlerFunc(a.createAction))).Methods("POST")
		protected.Handle("/actions/{id}", a.RequirePermission(storage.PermReadActions)(http.HandlerFunc(a.getAction))).Methods("GET")
		protected.Handle("/actions/{id}", a.RequirePermission(storage.PermWriteActions)(http.HandlerFunc(a.updateAction))).Methods("PUT", "PATCH") // TASK 48: PATCH support for partial updates
		protected.Handle("/actions/{id}", a.RequirePermission(storage.PermWriteActions)(http.HandlerFunc(a.deleteAction))).Methods("DELETE")

		// TASK 173: DEPRECATED - Correlation Rules endpoints
		// These endpoints are deprecated in favor of unified /api/v1/rules?category=correlation
		// They return 410 Gone with migration guidance
		protected.PathPrefix("/correlation-rules").Handler(http.HandlerFunc(a.handleDeprecatedEndpoint))

		// Visual Correlation Builder endpoints (VISUAL_BUILDER_BACKEND_INTEGRATION.md)
		// These endpoints support the visual correlation rule builder in the frontend
		protected.Handle("/correlations", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.createVisualCorrelation))).Methods("POST")
		protected.Handle("/correlations", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.listVisualCorrelations))).Methods("GET")
		protected.Handle("/correlations/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getVisualCorrelation))).Methods("GET")
		protected.Handle("/correlations/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.updateVisualCorrelation))).Methods("PUT")
		protected.Handle("/correlations/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.deleteVisualCorrelation))).Methods("DELETE")

		// RBAC: Investigations endpoints (read:alerts permission for now)
		protected.Handle("/investigations", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getInvestigations))).Methods("GET")
		protected.Handle("/investigations", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.createInvestigation))).Methods("POST")
		protected.Handle("/investigations/statistics", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getInvestigationStatistics))).Methods("GET")
		protected.Handle("/investigations/stats", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getInvestigationStatistics))).Methods("GET") // Alias for frontend compatibility
		protected.Handle("/investigations/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getInvestigation))).Methods("GET")
		protected.Handle("/investigations/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.updateInvestigation))).Methods("PUT", "PATCH") // TASK 48: PATCH support for partial updates (updateInvestigation already supports partial updates via pointer fields)
		protected.Handle("/investigations/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.deleteInvestigation))).Methods("DELETE")
		protected.Handle("/investigations/{id}/close", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.closeInvestigation))).Methods("POST")
		protected.Handle("/investigations/{id}/notes", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.addInvestigationNote))).Methods("POST")
		protected.Handle("/investigations/{id}/alerts", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.addInvestigationAlert))).Methods("POST")
		protected.Handle("/investigations/{id}/timeline", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getInvestigationTimeline))).Methods("GET")

		// Investigation Evidence endpoints - uses investigation-specific permissions
		protected.Handle("/investigations/{id}/evidence", a.RequirePermission(storage.PermReadInvestigations)(http.HandlerFunc(a.listInvestigationEvidence))).Methods("GET")
		protected.Handle("/investigations/{id}/evidence", a.RequirePermission(storage.PermWriteInvestigations)(http.HandlerFunc(a.uploadInvestigationEvidence))).Methods("POST")
		protected.Handle("/investigations/{id}/evidence/{evidence_id}", a.RequirePermission(storage.PermReadInvestigations)(http.HandlerFunc(a.getInvestigationEvidence))).Methods("GET")
		protected.Handle("/investigations/{id}/evidence/{evidence_id}/download", a.RequirePermission(storage.PermReadInvestigations)(http.HandlerFunc(a.downloadInvestigationEvidence))).Methods("GET")
		protected.Handle("/investigations/{id}/evidence/{evidence_id}", a.RequirePermission(storage.PermWriteInvestigations)(http.HandlerFunc(a.deleteInvestigationEvidence))).Methods("DELETE")

		// RBAC: Dynamic Listeners CRUD endpoints
		protected.Handle("/listeners", a.RequirePermission(storage.PermReadListeners)(http.HandlerFunc(a.listDynamicListeners))).Methods("GET")
		protected.Handle("/listeners", a.RequirePermission(storage.PermWriteListeners)(http.HandlerFunc(a.createDynamicListener))).Methods("POST")
		protected.Handle("/listeners/{id}", a.RequirePermission(storage.PermReadListeners)(http.HandlerFunc(a.getDynamicListener))).Methods("GET")
		protected.Handle("/listeners/{id}", a.RequirePermission(storage.PermWriteListeners)(http.HandlerFunc(a.updateDynamicListener))).Methods("PUT", "PATCH")
		protected.Handle("/listeners/{id}", a.RequirePermission(storage.PermWriteListeners)(http.HandlerFunc(a.deleteDynamicListener))).Methods("DELETE")

		// RBAC: Listener Control endpoints (require admin:system for runtime socket changes)
		protected.Handle("/listeners/{id}/start", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.startDynamicListener))).Methods("POST")
		protected.Handle("/listeners/{id}/stop", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.stopDynamicListener))).Methods("POST")
		protected.Handle("/listeners/{id}/restart", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.restartDynamicListener))).Methods("POST")
		protected.Handle("/listeners/{id}/stats", a.RequirePermission(storage.PermReadListeners)(http.HandlerFunc(a.getDynamicListenerStats))).Methods("GET")

		// RBAC: Listener Templates endpoints
		protected.Handle("/listener-templates", a.RequirePermission(storage.PermReadListeners)(http.HandlerFunc(a.getListenerTemplates))).Methods("GET")
		protected.Handle("/listener-templates/{id}", a.RequirePermission(storage.PermReadListeners)(http.HandlerFunc(a.getListenerTemplate))).Methods("GET")
		protected.Handle("/listeners/from-template/{templateId}", a.RequirePermission(storage.PermWriteListeners)(http.HandlerFunc(a.createListenerFromTemplate))).Methods("POST")

		// RBAC: Per-listener DLQ endpoints (read:events for viewing, admin:system for replay/discard)
		protected.Handle("/listeners/{id}/dlq", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.listListenerDLQEvents))).Methods("GET")
		protected.Handle("/listeners/{id}/dlq/{eventId}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getListenerDLQEvent))).Methods("GET")
		protected.Handle("/listeners/{id}/dlq/{eventId}/replay", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.replayListenerDLQEvent))).Methods("POST")
		protected.Handle("/listeners/{id}/dlq/{eventId}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.discardListenerDLQEvent))).Methods("DELETE")

		// RBAC: Dashboard endpoints (read:events permission)
		protected.Handle("/dashboard", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getDashboardStats))).Methods("GET")
		protected.Handle("/dashboard/chart", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getDashboardChart))).Methods("GET")

		// TASK 160.1: System setup endpoints (admin permission required)
		protected.Handle("/system/complete-setup", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.completeSetup))).Methods("POST")

		// RBAC: MITRE ATT&CK coverage endpoints (read:rules permission)
		protected.Handle("/mitre/coverage", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getMITRECoverage))).Methods("GET")
		protected.Handle("/mitre/coverage/matrix", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getMITRECoverageMatrix))).Methods("GET")
		protected.Handle("/mitre/coverage/data-sources", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getDataSourceCoverage))).Methods("GET")

		// TASK 9.6: MITRE import and management endpoints (write:rules permission)
		protected.Handle("/mitre/import", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.importMITREBundle))).Methods("POST")
		protected.Handle("/mitre/update", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.updateMITREBundle))).Methods("POST")
		protected.Handle("/mitre/techniques/{id}/subtechniques", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getSubTechniques))).Methods("GET")
		protected.Handle("/mitre/data-sources", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getDataSources))).Methods("GET")

		// Event search endpoints (temporarily disabled)
		// TASK 4.7: Event search endpoints with RBAC
		protected.Handle("/events/search", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.searchEvents))).Methods("POST")
		protected.Handle("/events/search/validate", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.validateQuery))).Methods("POST")
		// protected.Handle("/events/export", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.exportEvents))).Methods("POST")
		protected.Handle("/events/search/fields", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getSearchFields))).Methods("GET")
		protected.Handle("/events/search/operators", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getSearchOperators))).Methods("GET")

		// RBAC: Saved searches endpoints (read:events for read, write:events for modify)
		protected.Handle("/saved-searches", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getSavedSearches))).Methods("GET")
		protected.Handle("/saved-searches", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.createSavedSearch))).Methods("POST")
		protected.Handle("/saved-searches/{id}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getSavedSearch))).Methods("GET")
		protected.Handle("/saved-searches/{id}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.updateSavedSearch))).Methods("PUT")
		protected.Handle("/saved-searches/{id}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.deleteSavedSearch))).Methods("DELETE")

		// RBAC: ML endpoints (admin:system for config changes, read:events for status)
		protected.Handle("/ml/status", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLStatus))).Methods("GET")
		protected.Handle("/ml/health", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLHealth))).Methods("GET")
		protected.Handle("/ml/performance", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLPerformanceHistory))).Methods("GET")
		protected.Handle("/ml/train", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.forceTraining))).Methods("POST")
		protected.Handle("/ml/config", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLConfig))).Methods("GET")
		protected.Handle("/ml/config", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.updateMLConfig))).Methods("PUT")

		// TASK 37.5: ML Model Lifecycle Management endpoints
		protected.Handle("/ml/models", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLModels))).Methods("GET")
		protected.Handle("/ml/models/{name}/{version}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getMLModel))).Methods("GET")
		protected.Handle("/ml/models/{name}/{version}/activate", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.activateMLModel))).Methods("POST")
		protected.Handle("/ml/models/{name}/{version}/rollback", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.rollbackMLModel))).Methods("POST")
		protected.Handle("/ml/models/{name}/{version}/status", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.updateMLModelStatus))).Methods("PUT")
		protected.Handle("/ml/models/{name}/prune", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.pruneMLModelVersions))).Methods("POST")

		// RBAC: User Management API endpoints
		// TASK 3.6: /users/me endpoint for current user info (requires authentication only)
		protected.Handle("/users/me", a.RequireAnyPermission()(http.HandlerFunc(a.getCurrentUser))).Methods("GET")
		// TASK 108: Assignable users endpoint for alert assignment dropdown (requires alert:assign permission)
		// NOTE: Must be registered BEFORE /users/{username} to avoid route conflict
		protected.Handle("/users/assignable", a.RequirePermission(storage.PermAssignAlerts)(http.HandlerFunc(a.getAssignableUsers))).Methods("GET")
		// Other user endpoints require specific permissions
		protected.Handle("/users", a.RequirePermission(storage.PermReadUsers)(http.HandlerFunc(a.listUsers))).Methods("GET")
		protected.Handle("/users", a.RequirePermission(storage.PermWriteUsers)(http.HandlerFunc(a.createUser))).Methods("POST")
		protected.Handle("/users/{username}", a.RequirePermission(storage.PermReadUsers)(http.HandlerFunc(a.getUser))).Methods("GET")
		protected.Handle("/users/{username}", a.RequirePermission(storage.PermWriteUsers)(http.HandlerFunc(a.updateUser))).Methods("PUT", "PATCH") // TASK 48: PATCH support for partial updates
		protected.Handle("/users/{username}", a.RequirePermission(storage.PermWriteUsers)(http.HandlerFunc(a.deleteUser))).Methods("DELETE")
		protected.Handle("/users/{username}/role", a.RequirePermission(storage.PermWriteUsers)(http.HandlerFunc(a.updateUserRole))).Methods("PUT")
		// TASK 39: Admin unlock endpoint (requires admin:system permission)
		protected.Handle("/users/{username}/unlock", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.unlockUser))).Methods("POST")

		// RBAC: Role Management API endpoints (require admin:system permission)
		protected.Handle("/roles", a.RequirePermission(storage.PermReadUsers)(http.HandlerFunc(a.listRoles))).Methods("GET")
		protected.Handle("/roles/{id}", a.RequirePermission(storage.PermReadUsers)(http.HandlerFunc(a.getRole))).Methods("GET")

		// RBAC: DLQ endpoints (read:events for viewing, admin:system for replay/discard)
		protected.Handle("/dlq", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.listDLQEvents))).Methods("GET")
		protected.Handle("/dlq/{id}", a.RequirePermission(storage.PermReadEvents)(http.HandlerFunc(a.getDLQEvent))).Methods("GET")
		protected.Handle("/dlq/{id}/replay", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.replayDLQEvent))).Methods("POST")
		protected.Handle("/dlq/{id}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.discardDLQEvent))).Methods("DELETE")
		protected.Handle("/dlq/replay-all", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.replayAllDLQEvents))).Methods("POST")

		// TASK 35: SOAR playbook execution endpoints (require execute_playbooks permission)
		// Note: execute_playbooks permission not yet defined, using PermReadAlerts for now
		protected.Handle("/playbooks/{id}/execute", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.executePlaybook))).Methods("POST")
		protected.Handle("/playbook-executions/{id}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getPlaybookExecution))).Methods("GET")
		protected.Handle("/playbook-executions", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.listPlaybookExecutions))).Methods("GET")
		protected.Handle("/approvals/stats", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getApprovalStats))).Methods("GET")

		// TASK 96-99: Playbook CRUD endpoints
		// TASK 96: Base route structure and handlers (create, read, update, delete, list)
		// TASK 97: Additional endpoints (enable, disable, duplicate, validate)
		// TASK 98: Stats endpoint
		// TASK 99: Storage initialization (main.go) and API integration
		// IMPORTANT: Static paths (/playbooks/stats, /playbooks/validate) MUST be registered
		// BEFORE parameterized paths (/playbooks/{id}) to ensure proper routing
		protected.Handle("/playbooks", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.listPlaybooks))).Methods("GET")
		protected.Handle("/playbooks", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.createPlaybook))).Methods("POST")
		protected.Handle("/playbooks/stats", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getPlaybookStats))).Methods("GET")            // TASK 98
		protected.Handle("/playbooks/validate", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.validatePlaybookHandler))).Methods("POST") // TASK 97
		protected.Handle("/playbooks/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getPlaybook))).Methods("GET")
		protected.Handle("/playbooks/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.updatePlaybook))).Methods("PUT")
		protected.Handle("/playbooks/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.deletePlaybook))).Methods("DELETE")
		protected.Handle("/playbooks/{id}/enable", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.enablePlaybook))).Methods("POST")       // TASK 97
		protected.Handle("/playbooks/{id}/disable", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.disablePlaybook))).Methods("POST")     // TASK 97
		protected.Handle("/playbooks/{id}/duplicate", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.duplicatePlaybook))).Methods("POST") // TASK 97

		// ALRT-006: One-Click Remediation Actions
		// Remediation endpoints require admin:system permission for security-critical operations
		protected.Handle("/remediation/block-ip", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.blockIP))).Methods("POST")
		protected.Handle("/remediation/unblock-ip", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.unblockIP))).Methods("POST")
		protected.Handle("/remediation/actions/{alertId}", a.RequirePermission(storage.PermReadAlerts)(http.HandlerFunc(a.getRemediationActions))).Methods("GET")
		protected.Handle("/hunt/iocs", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.huntIOCs))).Methods("POST")

		// Playbook Execution Approval Workflow endpoints (legacy - execution-level)
		protected.Handle("/playbooks/executions/{executionId}/approve", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.approvePlaybookExecution))).Methods("POST")
		protected.Handle("/playbooks/executions/{executionId}/reject", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.rejectPlaybookExecution))).Methods("POST")

		// Step-Level Approval Workflow endpoints (new - for playbook step approvals)
		// NOTE: Static paths (/approvals/stats, /approvals/pending, /approvals/expire) MUST be before /{id}
		protected.Handle("/approvals", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.listApprovals))).Methods("GET")
		protected.Handle("/approvals/stats", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getApprovalStatsHandler))).Methods("GET")
		protected.Handle("/approvals/pending", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getPendingApprovalsForUser))).Methods("GET")
		protected.Handle("/approvals/expire", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.expireApprovals))).Methods("POST")
		protected.Handle("/approvals/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getApproval))).Methods("GET")
		protected.Handle("/approvals/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.processApproval))).Methods("PATCH")
		protected.Handle("/approvals/{id}", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.cancelApproval))).Methods("DELETE")
		protected.Handle("/approvals/{id}/actions", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getApprovalActions))).Methods("GET")

		// Rule Clone and Version Management endpoints
		protected.Handle("/rules/{id}/clone", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.cloneRule))).Methods("POST")
		protected.Handle("/rules/{id}/versions", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getRuleVersions))).Methods("GET")
		protected.Handle("/rules/{id}/restore", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.restoreRule))).Methods("POST")

		// Field Mapping endpoints for SIGMA field normalization (admin:system for modifications)
		protected.Handle("/settings/field-mappings", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFieldMappings))).Methods("GET")
		protected.Handle("/settings/field-mappings", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.createFieldMapping))).Methods("POST")
		protected.Handle("/settings/field-mappings/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFieldMapping))).Methods("GET")
		protected.Handle("/settings/field-mappings/{id}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.updateFieldMapping))).Methods("PUT")
		protected.Handle("/settings/field-mappings/{id}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.deleteFieldMapping))).Methods("DELETE")
		protected.Handle("/settings/field-mappings/reload", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.reloadFieldMappings))).Methods("POST")
		protected.Handle("/settings/field-mappings/test", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.testFieldMapping))).Methods("POST")
		protected.Handle("/settings/field-mappings/discover", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.discoverFields))).Methods("POST")

		// TASK 185: Field Mapping Lifecycle Management endpoints
		protected.Handle("/settings/field-mappings/{id}/lifecycle", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.handleFieldMappingLifecycle))).Methods("POST")
		protected.Handle("/settings/field-mappings/{id}/lifecycle-history", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetFieldMappingLifecycleHistory))).Methods("GET")
		protected.Handle("/settings/field-mappings/{id}/usage", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetFieldMappingUsage))).Methods("GET")

		// TASK 172: CQL to SIGMA migration endpoint (requires write:rules permission)
		protected.Handle("/rules/migrate-cql", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.migrateCQLHandler))).Methods("POST")

		// IOC Lifecycle Management endpoints
		// IMPORTANT: Static paths (/iocs/stats, /iocs/bulk) MUST be registered BEFORE parameterized paths ({id})
		protected.Handle("/iocs", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCs))).Methods("GET")
		protected.Handle("/iocs", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.createIOC))).Methods("POST")
		protected.Handle("/iocs/stats", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCStats))).Methods("GET")
		protected.Handle("/iocs/bulk", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.bulkImportIOCs))).Methods("POST")
		protected.Handle("/iocs/bulk/status", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.bulkUpdateIOCStatus))).Methods("PUT")
		protected.Handle("/iocs/{id}", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOC))).Methods("GET")
		protected.Handle("/iocs/{id}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.updateIOC))).Methods("PUT", "PATCH")
		protected.Handle("/iocs/{id}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.deleteIOC))).Methods("DELETE")
		protected.Handle("/iocs/{id}/matches", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCMatches))).Methods("GET")
		protected.Handle("/iocs/{id}/investigations/{investigationId}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.linkIOCToInvestigation))).Methods("POST")
		protected.Handle("/iocs/{id}/investigations/{investigationId}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.unlinkIOCFromInvestigation))).Methods("DELETE")

		// Threat Hunt endpoints (search for IOCs in historical logs)
		protected.Handle("/hunts", a.RequirePermission(storage.PermReadHunts)(http.HandlerFunc(a.getHunts))).Methods("GET")
		protected.Handle("/hunts", a.RequirePermission(storage.PermWriteHunts)(http.HandlerFunc(a.createHunt))).Methods("POST")
		protected.Handle("/hunts/{id}", a.RequirePermission(storage.PermReadHunts)(http.HandlerFunc(a.getHunt))).Methods("GET")
		protected.Handle("/hunts/{id}/matches", a.RequirePermission(storage.PermReadHunts)(http.HandlerFunc(a.getHuntMatches))).Methods("GET")
		protected.Handle("/hunts/{id}/cancel", a.RequirePermission(storage.PermWriteHunts)(http.HandlerFunc(a.cancelHunt))).Methods("POST")

		// TASK 154: SIGMA Feed Management endpoints
		// Uses read:rules for read operations and admin:system for modifications (like field-mappings)
		// NOTE: Static paths (templates, sync-all, summary) MUST be registered BEFORE parameterized paths ({id})
		protected.Handle("/feeds", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.listFeeds))).Methods("GET")
		protected.Handle("/feeds", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.createFeed))).Methods("POST")
		protected.Handle("/feeds/summary", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFeedsSummary))).Methods("GET") // TASK 157.1
		protected.Handle("/feeds/templates", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFeedTemplates))).Methods("GET")
		protected.Handle("/feeds/sync-all", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.syncAllFeeds))).Methods("POST")
		protected.Handle("/feeds/{id}", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFeedByID))).Methods("GET")
		protected.Handle("/feeds/{id}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.updateFeed))).Methods("PUT", "PATCH")
		protected.Handle("/feeds/{id}", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.deleteFeed))).Methods("DELETE")
		protected.Handle("/feeds/{id}/sync", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.syncFeed))).Methods("POST")
		protected.Handle("/feeds/{id}/stats", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFeedStats))).Methods("GET")
		protected.Handle("/feeds/{id}/history", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.getFeedHistory))).Methods("GET")
		protected.Handle("/feeds/{id}/test", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.testFeed))).Methods("POST")
		protected.Handle("/feeds/{id}/enable", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.enableFeed))).Methods("POST")
		protected.Handle("/feeds/{id}/disable", a.RequirePermission(storage.PermAdminSystem)(http.HandlerFunc(a.disableFeed))).Methods("POST")

		// IOC Feed Management endpoints (Threat Intelligence Feeds)
		// Uses read:iocs for read operations and write:iocs for modifications
		// NOTE: Static paths (templates, summary) MUST be registered BEFORE parameterized paths ({id})
		protected.Handle("/ioc-feeds", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCFeeds))).Methods("GET")
		protected.Handle("/ioc-feeds", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.createIOCFeed))).Methods("POST")
		protected.Handle("/ioc-feeds/summary", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCFeedsSummary))).Methods("GET")
		protected.Handle("/ioc-feeds/templates", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCFeedTemplates))).Methods("GET")
		protected.Handle("/ioc-feeds/{id}", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCFeed))).Methods("GET")
		protected.Handle("/ioc-feeds/{id}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.updateIOCFeed))).Methods("PUT", "PATCH")
		protected.Handle("/ioc-feeds/{id}", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.deleteIOCFeed))).Methods("DELETE")
		protected.Handle("/ioc-feeds/{id}/sync", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.syncIOCFeed))).Methods("POST")
		protected.Handle("/ioc-feeds/{id}/test", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.testIOCFeed))).Methods("POST")
		protected.Handle("/ioc-feeds/{id}/history", a.RequirePermission(storage.PermReadIOCs)(http.HandlerFunc(a.getIOCFeedSyncHistory))).Methods("GET")
		protected.Handle("/ioc-feeds/{id}/enable", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.enableIOCFeed))).Methods("POST")
		protected.Handle("/ioc-feeds/{id}/disable", a.RequirePermission(storage.PermWriteIOCs)(http.HandlerFunc(a.disableIOCFeed))).Methods("POST")
	} else {
		// If auth is disabled, all routes are public
		a.router.HandleFunc("/api/v1/events", a.getEvents).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts", a.getAlerts).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}", a.getAlertByID).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}", a.deleteAlert).Methods("DELETE")
		a.router.HandleFunc("/api/v1/alerts/{id}/acknowledge", a.acknowledgeAlert).Methods("POST")
		a.router.HandleFunc("/api/v1/alerts/{id}/dismiss", a.dismissAlert).Methods("POST")
		a.router.HandleFunc("/api/v1/alerts/{id}/status", a.updateAlertStatus).Methods("PUT")
		a.router.HandleFunc("/api/v1/alerts/{id}/assign", a.assignAlert).Methods("PUT")
		a.router.HandleFunc("/api/v1/alerts/{id}/history", a.getAlertHistory).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}/disposition", a.updateAlertDisposition).Methods("PATCH")        // TASK 104
		a.router.HandleFunc("/api/v1/alerts/{id}/assignee", a.updateAlertAssignee).Methods("PATCH")              // TASK 105
		a.router.HandleFunc("/api/v1/alerts/{id}/investigation", a.createInvestigationFromAlert).Methods("POST") // TASK 106
		// NOTE: TASK 107 PATCH /alerts/{id}/investigation intentionally NOT exposed in auth-disabled mode
		// This endpoint modifies security investigation data and requires authenticated RBAC enforcement

		// Evidence endpoints for alert attachments
		a.router.HandleFunc("/api/v1/alerts/{id}/evidence", a.listEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}/evidence", a.uploadEvidence).Methods("POST")
		a.router.HandleFunc("/api/v1/alerts/{id}/evidence/{evidence_id}", a.getEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}/evidence/{evidence_id}/download", a.downloadEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}/evidence/{evidence_id}", a.deleteEvidence).Methods("DELETE")

		// Alert linking endpoints for bi-directional alert relationships
		a.router.HandleFunc("/api/v1/alerts/{id}/related", a.listRelatedAlerts).Methods("GET")
		a.router.HandleFunc("/api/v1/alerts/{id}/related", a.linkAlerts).Methods("POST")
		a.router.HandleFunc("/api/v1/alerts/{id}/related/{related_id}", a.unlinkAlerts).Methods("DELETE")

		a.router.HandleFunc("/api/v1/rules", a.getRules).Methods("GET")
		a.router.HandleFunc("/api/v1/rules", a.createRule).Methods("POST")
		// a.router.HandleFunc("/api/v1/rules/export", a.exportRules).Methods("GET")
		// a.router.HandleFunc("/api/v1/rules/import", a.importRules).Methods("POST")
		a.router.HandleFunc("/api/v1/rules/clear-all", a.handleClearAllRules).Methods("POST") // Clear all rules
		a.router.HandleFunc("/api/v1/rules/{id}", a.getRule).Methods("GET")
		a.router.HandleFunc("/api/v1/rules/{id}", a.updateRule).Methods("PUT")
		a.router.HandleFunc("/api/v1/rules/{id}", a.deleteRule).Methods("DELETE")
		a.router.HandleFunc("/api/v1/actions", a.getActions).Methods("GET")
		a.router.HandleFunc("/api/v1/actions", a.createAction).Methods("POST")
		a.router.HandleFunc("/api/v1/actions/{id}", a.getAction).Methods("GET")
		a.router.HandleFunc("/api/v1/actions/{id}", a.updateAction).Methods("PUT")
		a.router.HandleFunc("/api/v1/actions/{id}", a.deleteAction).Methods("DELETE")
		a.router.HandleFunc("/api/v1/correlation-rules", a.getCorrelationRules).Methods("GET")
		a.router.HandleFunc("/api/v1/correlation-rules", a.createCorrelationRule).Methods("POST")
		// a.router.HandleFunc("/api/v1/correlation-rules/export", a.exportCorrelationRules).Methods("GET")
		// a.router.HandleFunc("/api/v1/correlation-rules/import", a.importCorrelationRules).Methods("POST")
		a.router.HandleFunc("/api/v1/correlation-rules/{id}", a.getCorrelationRule).Methods("GET")
		a.router.HandleFunc("/api/v1/correlation-rules/{id}", a.updateCorrelationRule).Methods("PUT")
		a.router.HandleFunc("/api/v1/correlation-rules/{id}", a.deleteCorrelationRule).Methods("DELETE")

		// Visual Correlation Builder endpoints (auth disabled mode)
		a.router.HandleFunc("/api/v1/correlations", a.listVisualCorrelations).Methods("GET")
		a.router.HandleFunc("/api/v1/correlations", a.createVisualCorrelation).Methods("POST")
		a.router.HandleFunc("/api/v1/correlations/{id}", a.getVisualCorrelation).Methods("GET")
		a.router.HandleFunc("/api/v1/correlations/{id}", a.updateVisualCorrelation).Methods("PUT")
		a.router.HandleFunc("/api/v1/correlations/{id}", a.deleteVisualCorrelation).Methods("DELETE")

		a.router.HandleFunc("/api/v1/investigations", a.getInvestigations).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations", a.createInvestigation).Methods("POST")
		a.router.HandleFunc("/api/v1/investigations/statistics", a.getInvestigationStatistics).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations/stats", a.getInvestigationStatistics).Methods("GET") // Alias for frontend compatibility
		a.router.HandleFunc("/api/v1/investigations/{id}", a.getInvestigation).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations/{id}", a.updateInvestigation).Methods("PUT")
		a.router.HandleFunc("/api/v1/investigations/{id}", a.deleteInvestigation).Methods("DELETE")
		a.router.HandleFunc("/api/v1/investigations/{id}/close", a.closeInvestigation).Methods("POST")
		a.router.HandleFunc("/api/v1/investigations/{id}/notes", a.addInvestigationNote).Methods("POST")
		a.router.HandleFunc("/api/v1/investigations/{id}/alerts", a.addInvestigationAlert).Methods("POST")
		a.router.HandleFunc("/api/v1/investigations/{id}/timeline", a.getInvestigationTimeline).Methods("GET")

		// Investigation Evidence endpoints (auth disabled mode)
		a.router.HandleFunc("/api/v1/investigations/{id}/evidence", a.listInvestigationEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations/{id}/evidence", a.uploadInvestigationEvidence).Methods("POST")
		a.router.HandleFunc("/api/v1/investigations/{id}/evidence/{evidence_id}", a.getInvestigationEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations/{id}/evidence/{evidence_id}/download", a.downloadInvestigationEvidence).Methods("GET")
		a.router.HandleFunc("/api/v1/investigations/{id}/evidence/{evidence_id}", a.deleteInvestigationEvidence).Methods("DELETE")

		// Dynamic Listeners CRUD endpoints (auth disabled mode)
		a.router.HandleFunc("/api/v1/listeners", a.listDynamicListeners).Methods("GET")
		a.router.HandleFunc("/api/v1/listeners", a.createDynamicListener).Methods("POST")
		a.router.HandleFunc("/api/v1/listeners/{id}", a.getDynamicListener).Methods("GET")
		a.router.HandleFunc("/api/v1/listeners/{id}", a.updateDynamicListener).Methods("PUT", "PATCH")
		a.router.HandleFunc("/api/v1/listeners/{id}", a.deleteDynamicListener).Methods("DELETE")

		// Listener Control endpoints (auth disabled mode)
		a.router.HandleFunc("/api/v1/listeners/{id}/start", a.startDynamicListener).Methods("POST")
		a.router.HandleFunc("/api/v1/listeners/{id}/stop", a.stopDynamicListener).Methods("POST")
		a.router.HandleFunc("/api/v1/listeners/{id}/restart", a.restartDynamicListener).Methods("POST")
		a.router.HandleFunc("/api/v1/listeners/{id}/stats", a.getDynamicListenerStats).Methods("GET")

		// Listener Templates endpoints (auth disabled mode)
		a.router.HandleFunc("/api/v1/listener-templates", a.getListenerTemplates).Methods("GET")
		a.router.HandleFunc("/api/v1/listener-templates/{id}", a.getListenerTemplate).Methods("GET")
		a.router.HandleFunc("/api/v1/listeners/from-template/{templateId}", a.createListenerFromTemplate).Methods("POST")

		// Per-listener DLQ endpoints
		a.router.HandleFunc("/api/v1/listeners/{id}/dlq", a.listListenerDLQEvents).Methods("GET")
		a.router.HandleFunc("/api/v1/listeners/{id}/dlq/{eventId}", a.getListenerDLQEvent).Methods("GET")
		a.router.HandleFunc("/api/v1/listeners/{id}/dlq/{eventId}/replay", a.replayListenerDLQEvent).Methods("POST")
		a.router.HandleFunc("/api/v1/listeners/{id}/dlq/{eventId}", a.discardListenerDLQEvent).Methods("DELETE")

		a.router.HandleFunc("/api/v1/dashboard", a.getDashboardStats).Methods("GET")
		a.router.HandleFunc("/api/v1/dashboard/chart", a.getDashboardChart).Methods("GET")

		// SOAR/Playbook endpoints
		a.router.HandleFunc("/api/v1/approvals/stats", a.getApprovalStats).Methods("GET")
		// Note: Playbook CRUD routes are in protected section only (lines 448-453) to enforce RBAC

		// ALRT-006: One-Click Remediation Actions (auth-disabled mode)
		a.router.HandleFunc("/api/v1/remediation/block-ip", a.blockIP).Methods("POST")
		a.router.HandleFunc("/api/v1/remediation/unblock-ip", a.unblockIP).Methods("POST")
		a.router.HandleFunc("/api/v1/remediation/actions/{alertId}", a.getRemediationActions).Methods("GET")
		a.router.HandleFunc("/api/v1/hunt/iocs", a.huntIOCs).Methods("POST")

		// Playbook CRUD and management endpoints (auth-disabled mode)
		// IMPORTANT: Static paths (/playbooks/stats, /playbooks/validate) MUST be registered
		// BEFORE parameterized paths (/playbooks/{id}) to ensure proper routing
		a.router.HandleFunc("/api/v1/playbooks", a.listPlaybooks).Methods("GET")
		a.router.HandleFunc("/api/v1/playbooks", a.createPlaybook).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/stats", a.getPlaybookStats).Methods("GET")
		a.router.HandleFunc("/api/v1/playbooks/validate", a.validatePlaybookHandler).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/{id}", a.getPlaybook).Methods("GET")
		a.router.HandleFunc("/api/v1/playbooks/{id}", a.updatePlaybook).Methods("PUT")
		a.router.HandleFunc("/api/v1/playbooks/{id}", a.deletePlaybook).Methods("DELETE")
		a.router.HandleFunc("/api/v1/playbooks/{id}/enable", a.enablePlaybook).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/{id}/disable", a.disablePlaybook).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/{id}/duplicate", a.duplicatePlaybook).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/{id}/execute", a.executePlaybook).Methods("POST")

		// Playbook Execution Approval Workflow endpoints (auth-disabled mode)
		a.router.HandleFunc("/api/v1/playbooks/executions/{executionId}/approve", a.approvePlaybookExecution).Methods("POST")
		a.router.HandleFunc("/api/v1/playbooks/executions/{executionId}/reject", a.rejectPlaybookExecution).Methods("POST")

		// Rule Clone and Version Management endpoints (auth-disabled mode)
		a.router.HandleFunc("/api/v1/rules/{id}/clone", a.cloneRule).Methods("POST")
		a.router.HandleFunc("/api/v1/rules/{id}/versions", a.getRuleVersions).Methods("GET")
		a.router.HandleFunc("/api/v1/rules/{id}/restore", a.restoreRule).Methods("POST")

		// MITRE ATT&CK endpoints
		a.router.HandleFunc("/api/v1/mitre/statistics", a.getMITREStatistics).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/tactics", a.getTactics).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/tactics/{id}", a.getTactic).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/techniques", a.getTechniques).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/techniques/{id}", a.getTechnique).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/coverage", a.getMITRECoverage).Methods("GET")
		a.router.HandleFunc("/api/v1/mitre/coverage/matrix", a.getMITRECoverageMatrix).Methods("GET")

		// TASK 160.1: System setup endpoint (auth-disabled mode)
		a.router.HandleFunc("/api/v1/system/complete-setup", a.completeSetup).Methods("POST")

		// TASK 4.7: Event search endpoints (enabled with executor implementation)
		a.router.HandleFunc("/api/v1/events/search", a.searchEvents).Methods("POST")
		a.router.HandleFunc("/api/v1/events/search/validate", a.validateQuery).Methods("POST")
		// a.router.HandleFunc("/api/v1/events/export", a.exportEvents).Methods("POST")
		a.router.HandleFunc("/api/v1/events/search/fields", a.getSearchFields).Methods("GET")
		a.router.HandleFunc("/api/v1/events/search/operators", a.getSearchOperators).Methods("GET")

		// Saved searches endpoints
		a.router.HandleFunc("/api/v1/saved-searches", a.getSavedSearches).Methods("GET")
		a.router.HandleFunc("/api/v1/saved-searches", a.createSavedSearch).Methods("POST")
		a.router.HandleFunc("/api/v1/saved-searches/{id}", a.getSavedSearch).Methods("GET")
		a.router.HandleFunc("/api/v1/saved-searches/{id}", a.updateSavedSearch).Methods("PUT")
		a.router.HandleFunc("/api/v1/saved-searches/{id}", a.deleteSavedSearch).Methods("DELETE")

		// ML endpoints
		a.router.HandleFunc("/api/v1/ml/status", a.getMLStatus).Methods("GET")
		a.router.HandleFunc("/api/v1/ml/health", a.getMLHealth).Methods("GET")
		a.router.HandleFunc("/api/v1/ml/performance", a.getMLPerformanceHistory).Methods("GET")
		a.router.HandleFunc("/api/v1/ml/train", a.forceTraining).Methods("POST")
		a.router.HandleFunc("/api/v1/ml/config", a.getMLConfig).Methods("GET")
		a.router.HandleFunc("/api/v1/ml/config", a.updateMLConfig).Methods("PUT")

		// TASK 7.4: DLQ endpoints for malformed event management
		a.router.HandleFunc("/api/v1/dlq", a.listDLQEvents).Methods("GET")
		a.router.HandleFunc("/api/v1/dlq/{id}", a.getDLQEvent).Methods("GET")
		a.router.HandleFunc("/api/v1/dlq/{id}/replay", a.replayDLQEvent).Methods("POST")
		a.router.HandleFunc("/api/v1/dlq/{id}", a.discardDLQEvent).Methods("DELETE")
		a.router.HandleFunc("/api/v1/dlq/replay-all", a.replayAllDLQEvents).Methods("POST")

		// Field Mapping endpoints for SIGMA field normalization
		a.router.HandleFunc("/api/v1/settings/field-mappings", a.getFieldMappings).Methods("GET")
		a.router.HandleFunc("/api/v1/settings/field-mappings", a.createFieldMapping).Methods("POST")
		a.router.HandleFunc("/api/v1/settings/field-mappings/reload", a.reloadFieldMappings).Methods("POST")
		a.router.HandleFunc("/api/v1/settings/field-mappings/test", a.testFieldMapping).Methods("POST")
		a.router.HandleFunc("/api/v1/settings/field-mappings/discover", a.discoverFields).Methods("POST")
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}", a.getFieldMapping).Methods("GET")
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}", a.updateFieldMapping).Methods("PUT")
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}", a.deleteFieldMapping).Methods("DELETE")

		// TASK 185: Field Mapping Lifecycle Management endpoints (auth-disabled mode)
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}/lifecycle", a.handleFieldMappingLifecycle).Methods("POST")
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}/lifecycle-history", a.handleGetFieldMappingLifecycleHistory).Methods("GET")
		a.router.HandleFunc("/api/v1/settings/field-mappings/{id}/usage", a.handleGetFieldMappingUsage).Methods("GET")

		// TASK 154: SIGMA Feed Management endpoints (auth-disabled mode)
		// NOTE: Static paths (templates, sync-all, summary) MUST be registered BEFORE parameterized paths ({id})
		a.router.HandleFunc("/api/v1/feeds", a.listFeeds).Methods("GET")
		a.router.HandleFunc("/api/v1/feeds", a.createFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/feeds/summary", a.getFeedsSummary).Methods("GET") // TASK 157.1
		a.router.HandleFunc("/api/v1/feeds/templates", a.getFeedTemplates).Methods("GET")
		a.router.HandleFunc("/api/v1/feeds/sync-all", a.syncAllFeeds).Methods("POST")
		a.router.HandleFunc("/api/v1/feeds/{id}", a.getFeedByID).Methods("GET")
		a.router.HandleFunc("/api/v1/feeds/{id}", a.updateFeed).Methods("PUT", "PATCH")
		a.router.HandleFunc("/api/v1/feeds/{id}", a.deleteFeed).Methods("DELETE")
		a.router.HandleFunc("/api/v1/feeds/{id}/sync", a.syncFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/feeds/{id}/stats", a.getFeedStats).Methods("GET")
		a.router.HandleFunc("/api/v1/feeds/{id}/history", a.getFeedHistory).Methods("GET")
		a.router.HandleFunc("/api/v1/feeds/{id}/test", a.testFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/feeds/{id}/enable", a.enableFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/feeds/{id}/disable", a.disableFeed).Methods("POST")

		// IOC Lifecycle Management endpoints - auth-disabled mode
		// IMPORTANT: Static paths (/iocs/stats, /iocs/bulk) MUST be registered BEFORE parameterized paths ({id})
		a.router.HandleFunc("/api/v1/iocs", a.getIOCs).Methods("GET")
		a.router.HandleFunc("/api/v1/iocs", a.createIOC).Methods("POST")
		a.router.HandleFunc("/api/v1/iocs/stats", a.getIOCStats).Methods("GET")
		a.router.HandleFunc("/api/v1/iocs/bulk", a.bulkImportIOCs).Methods("POST")
		a.router.HandleFunc("/api/v1/iocs/bulk/status", a.bulkUpdateIOCStatus).Methods("PUT")
		a.router.HandleFunc("/api/v1/iocs/{id}", a.getIOC).Methods("GET")
		a.router.HandleFunc("/api/v1/iocs/{id}", a.updateIOC).Methods("PUT", "PATCH")
		a.router.HandleFunc("/api/v1/iocs/{id}", a.deleteIOC).Methods("DELETE")
		a.router.HandleFunc("/api/v1/iocs/{id}/matches", a.getIOCMatches).Methods("GET")
		a.router.HandleFunc("/api/v1/iocs/{id}/investigations/{investigationId}", a.linkIOCToInvestigation).Methods("POST")
		a.router.HandleFunc("/api/v1/iocs/{id}/investigations/{investigationId}", a.unlinkIOCFromInvestigation).Methods("DELETE")

		// IOC Feed Management endpoints (Threat Intelligence Feeds) - auth-disabled mode
		// NOTE: Static paths (templates, summary) MUST be registered BEFORE parameterized paths ({id})
		a.router.HandleFunc("/api/v1/ioc-feeds", a.getIOCFeeds).Methods("GET")
		a.router.HandleFunc("/api/v1/ioc-feeds", a.createIOCFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/ioc-feeds/summary", a.getIOCFeedsSummary).Methods("GET")
		a.router.HandleFunc("/api/v1/ioc-feeds/templates", a.getIOCFeedTemplates).Methods("GET")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}", a.getIOCFeed).Methods("GET")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}", a.updateIOCFeed).Methods("PUT", "PATCH")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}", a.deleteIOCFeed).Methods("DELETE")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}/sync", a.syncIOCFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}/test", a.testIOCFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}/history", a.getIOCFeedSyncHistory).Methods("GET")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}/enable", a.enableIOCFeed).Methods("POST")
		a.router.HandleFunc("/api/v1/ioc-feeds/{id}/disable", a.disableIOCFeed).Methods("POST")
	}
}

// Start starts the API server
func (a *API) Start(port string) error {
	a.server = &http.Server{
		Addr:              port,
		Handler:           a.router,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return a.server.ListenAndServe()
}

// StartTLS starts the API server with TLS
func (a *API) StartTLS(port, certFile, keyFile string) error {
	a.server = &http.Server{
		Addr:              port,
		Handler:           a.router,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return a.server.ListenAndServeTLS(certFile, keyFile)
}

// Stop stops the API server
func (a *API) Stop(ctx context.Context) error {
	close(a.stopCh)
	// TASK 158: Gracefully shutdown WebSocket hub
	if a.wsHub != nil {
		a.wsHub.Stop()
	}
	if a.server != nil {
		return a.server.Shutdown(ctx)
	}
	return nil
}

// BroadcastFeedEvent broadcasts a feed synchronization event to all WebSocket clients.
// TASK 158: Real-time feed sync progress notifications.
// PRODUCTION: Non-blocking, safe for concurrent use, with error logging.
func (a *API) BroadcastFeedEvent(event *FeedSyncEvent) {
	if a.wsHub == nil {
		// WebSocket hub not initialized, skip broadcast
		return
	}

	// Ensure timestamp is set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Broadcast the feed event
	if err := a.wsHub.BroadcastMessage("feed_sync", event); err != nil {
		a.logger.Warnw("Failed to broadcast feed sync event",
			"feed_id", event.FeedID,
			"type", event.Type,
			"error", err)
	}
}

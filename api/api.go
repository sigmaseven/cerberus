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
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/swaggo/http-swagger"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// rateLimiterEntry holds a rate limiter with last seen time
type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// authFailureEntry holds auth failure count and last failure time
type authFailureEntry struct {
	count    int
	lastFail time.Time
}

// EventStorer interface for event storage
type EventStorer interface {
	GetEvents(limit int) ([]core.Event, error)
	GetEventCount() (int64, error)
	GetEventCountsByMonth() ([]map[string]interface{}, error)
}

// AlertStorer interface for alert storage
type AlertStorer interface {
	GetAlerts(limit int) ([]core.Alert, error)
	GetAlertCount() (int64, error)
	GetAlertCountsByMonth() ([]map[string]interface{}, error)
	AcknowledgeAlert(id string) error
	DismissAlert(id string) error
}

// RuleStorer interface for rule storage
type RuleStorer interface {
	GetRules() ([]core.Rule, error)
	GetRule(id string) (*core.Rule, error)
	CreateRule(rule *core.Rule) error
	UpdateRule(id string, rule *core.Rule) error
	DeleteRule(id string) error
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
type CorrelationRuleStorer interface {
	GetCorrelationRules() ([]core.CorrelationRule, error)
	GetCorrelationRule(id string) (*core.CorrelationRule, error)
	CreateCorrelationRule(rule *core.CorrelationRule) error
	UpdateCorrelationRule(id string, rule *core.CorrelationRule) error
	DeleteCorrelationRule(id string) error
}

// API holds the API server
type API struct {
	router                 *mux.Router
	server                 *http.Server
	eventStorage           EventStorer
	alertStorage           AlertStorer
	ruleStorage            RuleStorer
	actionStorage          ActionStorer
	correlationRuleStorage CorrelationRuleStorer
	config                 *config.Config
	logger                 *zap.SugaredLogger
	rateLimiters           map[string]*rateLimiterEntry
	rateLimitersMu         sync.Mutex
	authFailures           map[string]*authFailureEntry
	authFailuresMu         sync.Mutex
	stopCh                 chan struct{}
}

// NewAPI creates a new API server
func NewAPI(eventStorage EventStorer, alertStorage AlertStorer, ruleStorage RuleStorer, actionStorage ActionStorer, correlationRuleStorage CorrelationRuleStorer, config *config.Config, logger *zap.SugaredLogger) *API {
	api := &API{
		router:                 mux.NewRouter(),
		eventStorage:           eventStorage,
		alertStorage:           alertStorage,
		ruleStorage:            ruleStorage,
		actionStorage:          actionStorage,
		correlationRuleStorage: correlationRuleStorage,
		config:                 config,
		logger:                 logger,
		rateLimiters:           make(map[string]*rateLimiterEntry),
		authFailures:           make(map[string]*authFailureEntry),
		stopCh:                 make(chan struct{}),
	}
	api.setupRoutes()
	go api.cleanupRateLimiters()
	return api
}

// setupRoutes sets up the API routes
func (a *API) setupRoutes() {
	a.router.Use(a.corsMiddleware)
	a.router.Use(a.rateLimitMiddleware)
	if a.config.Auth.Enabled {
		a.router.Use(a.basicAuthMiddleware)
	}
	a.router.HandleFunc("/api/events", a.getEvents).Methods("GET")
	a.router.HandleFunc("/api/alerts", a.getAlerts).Methods("GET")
	a.router.HandleFunc("/api/alerts/{id}/acknowledge", a.acknowledgeAlert).Methods("POST")
	a.router.HandleFunc("/api/alerts/{id}/dismiss", a.dismissAlert).Methods("POST")
	a.router.HandleFunc("/api/rules", a.getRules).Methods("GET")
	a.router.HandleFunc("/api/rules", a.createRule).Methods("POST")
	a.router.HandleFunc("/api/rules/{id}", a.getRule).Methods("GET")
	a.router.HandleFunc("/api/rules/{id}", a.updateRule).Methods("PUT")
	a.router.HandleFunc("/api/rules/{id}", a.deleteRule).Methods("DELETE")
	a.router.HandleFunc("/api/actions", a.getActions).Methods("GET")
	a.router.HandleFunc("/api/actions", a.createAction).Methods("POST")
	a.router.HandleFunc("/api/actions/{id}", a.getAction).Methods("GET")
	a.router.HandleFunc("/api/actions/{id}", a.updateAction).Methods("PUT")
	a.router.HandleFunc("/api/actions/{id}", a.deleteAction).Methods("DELETE")
	a.router.HandleFunc("/api/correlation-rules", a.getCorrelationRules).Methods("GET")
	a.router.HandleFunc("/api/correlation-rules", a.createCorrelationRule).Methods("POST")
	a.router.HandleFunc("/api/correlation-rules/{id}", a.getCorrelationRule).Methods("GET")
	a.router.HandleFunc("/api/correlation-rules/{id}", a.updateCorrelationRule).Methods("PUT")
	a.router.HandleFunc("/api/correlation-rules/{id}", a.deleteCorrelationRule).Methods("DELETE")
	a.router.HandleFunc("/api/listeners", a.getListeners).Methods("GET")
	a.router.HandleFunc("/api/dashboard", a.getDashboardStats).Methods("GET")
	a.router.HandleFunc("/api/dashboard/chart", a.getDashboardChart).Methods("GET")
	a.router.HandleFunc("/health", a.healthCheck).Methods("GET")
	a.router.Handle("/metrics", promhttp.Handler())

	// Swagger UI
	a.router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)
}

// Start starts the API server
func (a *API) Start(port string) error {
	a.server = &http.Server{
		Addr:    port,
		Handler: a.router,
	}
	return a.server.ListenAndServe()
}

// StartTLS starts the API server with TLS
func (a *API) StartTLS(port, certFile, keyFile string) error {
	a.server = &http.Server{
		Addr:    port,
		Handler: a.router,
	}
	return a.server.ListenAndServeTLS(certFile, keyFile)
}

// Stop stops the API server
func (a *API) Stop(ctx context.Context) error {
	close(a.stopCh)
	if a.server != nil {
		return a.server.Shutdown(ctx)
	}
	return nil
}

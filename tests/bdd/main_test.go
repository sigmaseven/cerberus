// Package bdd provides BDD tests for Cerberus SIEM using Godog
//
// This package contains Behavior-Driven Development tests that verify
// Cerberus meets all requirements defined in docs/requirements/.
//
// Requirements Coverage:
// - SEC-001 through SEC-016: Security (authentication, authorization, SQL injection, etc.)
// - DATA-001 through DATA-003: Data integrity (ACID, referential integrity, durability)
// - SIGMA-002, SIGMA-005: SIGMA compliance (operators, field paths)
// - API-001 through API-013: API contracts
// - PERF-001, PERF-002: Performance SLAs
// - FR-CORR-001 through FR-CORR-014: Correlation rules
// - FR-ING-001 through FR-ING-014: Data ingestion
//
// Architecture:
// - Feature files: tests/bdd/features/**/*.feature (Gherkin scenarios)
// - Step definitions: tests/bdd/steps/*_steps.go (Go implementations)
// - Test contexts: Per-domain context structs for state isolation
//
// Running Tests:
//
//	# Run all BDD tests
//	go test -v ./tests/bdd
//
//	# Run specific tag
//	go test -v ./tests/bdd -godog.tags="@security"
//
//	# Run with specific format
//	go test -v ./tests/bdd -godog.format=pretty
//
// Requirements Traceability:
// Every scenario references its requirement ID in comments for full traceability.
package bdd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"

	"cerberus/tests/bdd/steps"
)

// TestMain is the entry point for Godog BDD tests
// It configures the test suite and runs all scenarios
func TestMain(m *testing.M) {
	opts := godog.Options{
		Output: colors.Colored(os.Stdout),
		Format: "pretty", // Options: pretty, cucumber, junit, progress
		Paths:  []string{"features"},
		Tags:   "", // Run all scenarios by default, can be overridden with -godog.tags
	}

	// Parse command-line flags for godog
	godog.BindCommandLineFlags("godog.", &opts)

	status := godog.TestSuite{
		Name:                 "cerberus-bdd",
		TestSuiteInitializer: InitializeTestSuite,
		ScenarioInitializer:  InitializeScenario,
		Options:              &opts,
	}.Run()

	os.Exit(status)
}

// InitializeTestSuite sets up suite-level hooks
// This runs once before all scenarios
func InitializeTestSuite(ctx *godog.TestSuiteContext) {
	ctx.BeforeSuite(func() {
		fmt.Println("==============================================")
		fmt.Println("Cerberus SIEM BDD Test Suite")
		fmt.Println("==============================================")
		fmt.Println("Testing comprehensive requirements compliance")
		fmt.Println("Feature files: tests/bdd/features/")
		fmt.Println("Step definitions: tests/bdd/steps/")
		fmt.Println("==============================================")

		// Pre-suite setup could go here:
		// - Start Cerberus in test mode
		// - Initialize test database
		// - Set up test data fixtures
		// Currently assuming Cerberus is already running
	})

	ctx.AfterSuite(func() {
		fmt.Println("==============================================")
		fmt.Println("BDD Test Suite Completed")
		fmt.Println("==============================================")

		// Post-suite cleanup could go here:
		// - Stop Cerberus test instance
		// - Clean up test database
		// - Generate coverage reports
	})
}

// InitializeScenario registers all step definitions for each scenario
// This runs before each individual scenario to ensure isolation
//
// Design Pattern: Context Per Domain
// - SecurityContext: Security tests (authentication, SQL injection, RBAC)
// - DataContext: Data integrity tests (ACID, transactions)
// - DetectionContext: Detection engine tests (SIGMA, correlation)
// - APIContext: API contract tests
// - PerformanceContext: Performance and throughput tests
//
// Each context maintains isolated state to prevent test contamination.
func InitializeScenario(ctx *godog.ScenarioContext) {
	// Initialize context objects for each test domain
	// All domains are now implemented per requirements
	securityCtx := steps.NewSecurityContext()

	// Register step definitions by domain
	apiCtx := &steps.APIContext{
		baseURL:    "http://localhost:8080",
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	steps.RegisterSecuritySteps(ctx, securityCtx)
	steps.InitializeAuthenticationContext(ctx)
	steps.InitializeAuthorizationContext(ctx)
	steps.InitializeACIDContext(ctx)
	steps.InitializeSIGMAContext(ctx)
	steps.InitializeCorrelationContext(ctx)
	steps.InitializeAPIContext(ctx)
	steps.InitializePerformanceContext(ctx)
	steps.InitializeAlertContext(ctx, apiCtx)
	steps.InitializeInvestigationContext(ctx, apiCtx)
	steps.InitializeSearchContext(ctx, apiCtx)
	steps.InitializeNotificationContext(ctx, apiCtx)
	steps.InitializeBackupContext(ctx, apiCtx)

	// Scenario-level hooks for setup and teardown
	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		// Before each scenario:
		// - Reset context state
		// - Log scenario start
		fmt.Printf("\n--- Scenario: %s ---\n", sc.Name)

		// Tag-specific setup
		for _, tag := range sc.Tags {
			switch tag.Name {
			case "@critical":
				fmt.Println("    [CRITICAL TEST - Full validation required]")
			case "@security":
				fmt.Println("    [SECURITY TEST - Attack vector validation]")
			case "@performance":
				fmt.Println("    [PERFORMANCE TEST - SLA validation required]")
			}
		}

		return ctx, nil
	})

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		// After each scenario:
		// - Log scenario result
		// - Clean up test data
		// - Report failures

		if err != nil {
			fmt.Printf("    [FAILED] %s: %v\n", sc.Name, err)

			// Tag-specific failure handling
			for _, tag := range sc.Tags {
				if tag.Name == "@critical" {
					fmt.Println("    [CRITICAL FAILURE - BLOCKER]")
				}
			}
		} else {
			fmt.Printf("    [PASSED] %s\n", sc.Name)
		}

		return ctx, nil
	})
}

// TestFeatures runs the BDD tests with the testing package
// This allows integration with standard Go testing tools
func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t, // Integrate with Go testing
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

// Package main is the entry point for the Cerberus SIEM system.
package main

import (
	"context"
	"fmt"
	"os"

	"cerberus/bootstrap"
	"cerberus/cmd"
	_ "cerberus/docs"
)

// checkSecurityViolations ensures test mode cannot be enabled in production.
// FR-SOAR-018 CRITICAL-002: Test mode bypasses ALL SSRF protection.
func checkSecurityViolations() {
	if os.Getenv("CERBERUS_TEST_MODE") == "1" {
		environment := os.Getenv("ENVIRONMENT")
		cerberusEnv := os.Getenv("CERBERUS_ENV")

		// Check for production environment
		if environment == "production" || environment == "prod" || cerberusEnv == "production" {
			fmt.Fprintf(os.Stderr, "FATAL SECURITY VIOLATION: CERBERUS_TEST_MODE cannot be enabled in production environment\n")
			fmt.Fprintf(os.Stderr, "Test mode disables critical security controls including SSRF protection\n")
			fmt.Fprintf(os.Stderr, "Current environment: ENVIRONMENT=%s, CERBERUS_ENV=%s\n", environment, cerberusEnv)
			fmt.Fprintf(os.Stderr, "To fix: Unset CERBERUS_TEST_MODE environment variable\n")
			os.Exit(1)
		}

		// Warning for non-production environments
		fmt.Fprintf(os.Stderr, "WARNING: Running in TEST MODE - SSRF protection and other security controls are DISABLED\n")
		fmt.Fprintf(os.Stderr, "This mode is ONLY for testing and MUST NOT be used in production\n")
		fmt.Fprintf(os.Stderr, "Current environment: ENVIRONMENT=%s, CERBERUS_ENV=%s\n", environment, cerberusEnv)
	}
}

// run initializes and starts the Cerberus SIEM system.
func run() error {
	ctx := context.Background()

	// Create and initialize application
	app, err := bootstrap.NewApp(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}

	// Start all services
	if err := app.Start(ctx); err != nil {
		app.Shutdown()
		return fmt.Errorf("failed to start application: %w", err)
	}

	// Wait for shutdown signal
	app.WaitForShutdown()

	// Graceful shutdown
	app.Shutdown()

	return nil
}

// main is the entry point.
func main() {
	checkSecurityViolations()

	// Check if running as CLI command
	if len(os.Args) > 1 && os.Args[1] == "feeds" {
		// Execute feeds CLI command
		// Strip "feeds" from os.Args since the command already knows it's the feeds command
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

		feedsCmd := cmd.NewFeedsCmd()
		if err := feedsCmd.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Otherwise run as normal server
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

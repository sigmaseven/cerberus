// Package bootstrap provides application initialization and lifecycle management.
// It extracts the initialization logic from main.go into testable, composable components.
//
// Usage:
//
//	app, err := bootstrap.NewApp(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer app.Shutdown()
//
//	if err := app.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Wait for shutdown signal
//	app.WaitForShutdown()
package bootstrap

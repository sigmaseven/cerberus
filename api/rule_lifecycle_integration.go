package api

// This file contains the API struct updates and route registration for rule lifecycle management
// TASK 169: Rule Lifecycle Management API

// The following updates need to be made to api.go:

// 1. Add to API struct (around line 186):
//    lifecycleAuditStorage *storage.SQLiteLifecycleAuditStorage // TASK 169: Lifecycle audit trail
//    lifecycleManager      *storage.LifecycleManager             // TASK 169: Background sunset enforcement

// 2. Add to NewAPI parameters (around line 200):
//    lifecycleAuditStorage *storage.SQLiteLifecycleAuditStorage,
//    lifecycleManager *storage.LifecycleManager,

// 3. Set fields in NewAPI (around line 235):
//    lifecycleAuditStorage: lifecycleAuditStorage, // TASK 169
//    lifecycleManager:      lifecycleManager,      // TASK 169

// 4. Add routes to setupRoutes (after line 412):
//    // TASK 169: Rule lifecycle management endpoints
//    protected.Handle("/rules/{id}/lifecycle", a.RequirePermission(storage.PermWriteRules)(http.HandlerFunc(a.handleRuleLifecycle))).Methods("POST")
//    protected.Handle("/rules/{id}/lifecycle-history", a.RequirePermission(storage.PermReadRules)(http.HandlerFunc(a.handleGetLifecycleHistory))).Methods("GET")

// 5. Add lifecycle manager start/stop to Start() and Stop() methods:
//    In Start() after line ~290:
//      if a.lifecycleManager != nil {
//          a.lifecycleManager.Start()
//      }
//
//    In Stop() before line ~305:
//      if a.lifecycleManager != nil {
//          a.lifecycleManager.Stop()
//      }

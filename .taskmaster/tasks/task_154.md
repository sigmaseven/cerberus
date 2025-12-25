# Task ID: 154

**Title:** Implement Feed Management API Endpoints

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Create REST API handlers for SIGMA feed CRUD operations, sync triggers, and status management in the API layer

**Details:**

Create api/feed_handlers.go to expose the existing sigma/feeds/manager.go functionality via HTTP endpoints.

Required endpoints:
- GET /api/v1/feeds - List all feeds with stats
- POST /api/v1/feeds - Create new feed with validation
- GET /api/v1/feeds/{id} - Get feed details
- PUT /api/v1/feeds/{id} - Update feed configuration
- DELETE /api/v1/feeds/{id} - Delete feed
- POST /api/v1/feeds/{id}/sync - Trigger manual sync
- POST /api/v1/feeds/sync-all - Sync all enabled feeds
- GET /api/v1/feeds/{id}/history - Get sync history with pagination
- GET /api/v1/feeds/{id}/stats - Get feed statistics
- GET /api/v1/feeds/templates - List available feed templates from sigma_feeds/config/feed_templates.yaml
- POST /api/v1/feeds/{id}/test - Test feed connectivity
- POST /api/v1/feeds/{id}/enable - Enable feed
- POST /api/v1/feeds/{id}/disable - Disable feed

Implementation:
1. Wire feedManager to API struct in api.go NewAPI()
2. Create handler functions using existing feedManager methods
3. Add RBAC middleware with permissions: feeds:read, feeds:write, feeds:delete
4. Add request validation using existing api/validation.go patterns
5. Return JSON responses matching PRD schemas
6. Add error handling with proper HTTP status codes
7. Register routes in api.go setupRoutes()
8. Add Swagger documentation annotations

Security:
- Validate all inputs to prevent injection
- Require authentication for all endpoints
- Use RBAC permissions for authorization
- Rate limit sync operations to prevent abuse

**Test Strategy:**

Unit tests: Test each handler with valid/invalid inputs, mock feedManager responses, verify RBAC enforcement. Integration tests: Call endpoints via HTTP, verify database changes, test sync operations with real git repos, verify error handling and status codes.

## Subtasks

### 154.1. Create api/feed_handlers.go with basic CRUD endpoints

**Status:** done  
**Dependencies:** None  

Implement core CRUD handlers for feed management: GET /api/v1/feeds (list all), POST /api/v1/feeds (create), GET /api/v1/feeds/{id} (get details), PUT /api/v1/feeds/{id} (update), and DELETE /api/v1/feeds/{id} (delete). Wire feedManager to API struct in api.go NewAPI() function.

**Details:**

Create new file api/feed_handlers.go. Add feedManager field to API struct in api.go. In NewAPI(), initialize feedManager from existing sigma/feeds/manager.go. Implement handler functions: handleListFeeds() for GET /feeds, handleCreateFeed() for POST /feeds with JSON body validation, handleGetFeed() for GET /feeds/{id} with ID parameter extraction, handleUpdateFeed() for PUT /feeds/{id}, and handleDeleteFeed() for DELETE /feeds/{id}. Each handler should call corresponding feedManager methods (ListFeeds, CreateFeed, GetFeed, UpdateFeed, DeleteFeed). Return JSON responses with appropriate HTTP status codes (200, 201, 404, 500). Follow existing patterns from api/handlers.go for request parsing, error handling, and response formatting.

### 154.2. Implement sync operation endpoints with concurrency control

**Status:** done  
**Dependencies:** 154.1  

Add feed synchronization endpoints: POST /api/v1/feeds/{id}/sync (trigger single feed sync), POST /api/v1/feeds/sync-all (sync all enabled feeds), and GET /api/v1/feeds/{id}/history (get sync history with pagination). Implement proper locking to prevent concurrent syncs of the same feed.

**Details:**

In api/feed_handlers.go, implement handleSyncFeed() for POST /feeds/{id}/sync that calls feedManager.SyncFeed(id). Implement handleSyncAllFeeds() for POST /feeds/sync-all that iterates enabled feeds and calls SyncFeed for each. Add sync history handler handleGetFeedHistory() for GET /feeds/{id}/history with query parameters for pagination (page, limit). Use sync.Mutex or feedManager's existing locking to prevent concurrent syncs of same feed. Return sync job status immediately (202 Accepted) for async operations. For history endpoint, return paginated list of sync events with timestamps, status, rules_synced count, and errors. Handle edge cases: feed not found, feed disabled, sync already in progress. Follow api/handlers.go error handling patterns.

### 154.3. Add validation, RBAC middleware, and comprehensive error handling

**Status:** done  
**Dependencies:** 154.1, 154.2  

Implement input validation for all feed endpoints, add RBAC middleware with permissions (feeds:read, feeds:write, feeds:delete), and comprehensive error handling with proper HTTP status codes following existing api/validation.go and api/middleware.go patterns.

**Details:**

Add request validation using api/validation.go patterns: validate feed creation/update payloads (required fields: name, url, feed_type; optional: enabled, sync_interval, auth config), validate URL format and reachability, validate sync_interval ranges. Apply RBAC middleware to routes: feeds:read for GET endpoints, feeds:write for POST/PUT, feeds:delete for DELETE. Use existing ContextKeyUsername and ContextKeyRoles from api/context_keys.go. Implement comprehensive error handling: 400 for validation errors, 401 for unauthenticated, 403 for unauthorized, 404 for feed not found, 409 for conflicts (duplicate name, concurrent sync), 422 for invalid feed configuration, 429 for rate limiting, 500 for server errors. Return structured JSON error responses with error codes and messages. Add rate limiting for sync endpoints to prevent abuse (max 1 sync per feed per minute).

### 154.4. Add remaining utility endpoints, Swagger docs, and route registration

**Status:** done  
**Dependencies:** 154.1, 154.2, 154.3  

Implement remaining endpoints (templates, test, enable/disable, stats), add comprehensive Swagger annotations to all handlers, and register all routes in api.go setupRoutes() with proper middleware chain.

**Details:**

In api/feed_handlers.go, implement remaining handlers: handleGetFeedTemplates() for GET /feeds/templates (read from sigma_feeds/config/feed_templates.yaml), handleTestFeed() for POST /feeds/{id}/test (test git connectivity), handleGetFeedStats() for GET /feeds/{id}/stats (return rules count, last sync time, success rate), handleEnableFeed() for POST /feeds/{id}/enable, handleDisableFeed() for POST /feeds/{id}/disable. Add Swagger annotations to all handlers using existing patterns from api/handlers.go (add @Summary, @Description, @Tags, @Accept, @Produce, @Param, @Success, @Failure, @Router, @Security). In api.go setupRoutes(), register all feed routes under /api/v1/feeds with proper middleware chain: authentication -> RBAC -> rate limiting -> handler. Group routes logically: CRUD routes, sync routes, utility routes. Ensure route ordering prevents conflicts (specific routes before parameterized routes).

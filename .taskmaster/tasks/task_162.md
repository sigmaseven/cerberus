# Task ID: 162

**Title:** Add Swagger/OpenAPI Documentation for Feed Endpoints

**Status:** done

**Dependencies:** 154 ✓

**Priority:** low

**Description:** Document all feed management API endpoints with request/response schemas and examples

**Details:**

Update docs/swagger.yaml and auto-generated docs/docs.go:

Add endpoint documentation with swag annotations in api/feed_handlers.go:

For each endpoint, document:
1. Summary and description
2. Parameters (path, query, body)
3. Request body schema with examples
4. Response schemas (200, 400, 401, 403, 404, 500)
5. Security requirements (JWT token)
6. Tags (group under "Feeds")

Example annotation:
// GetFeeds retrieves all feeds
// @Summary List all SIGMA feeds
// @Description Get all configured SIGMA rule feeds with statistics
// @Tags Feeds
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {array} feeds.RuleFeed "List of feeds"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /feeds [get]

Schemas to define:
- RuleFeed (from PRD Feed Response)
- FeedCreateRequest (from PRD Feed Create)
- FeedUpdateRequest (partial RuleFeed)
- FeedSyncResult (from PRD Sync Result)
- FeedStats (embedded in RuleFeed)
- FeedTemplate
- ErrorResponse (standard error format)

Add examples:
- Valid feed creation with Git source
- Valid feed creation with filesystem source
- Sync result success
- Sync result with errors
- Error responses for validation failures

Generate updated docs:
- Run: swag init -g main.go
- Verify at http://localhost:8081/swagger/index.html
- Test "Try it out" functionality

Add to API documentation section:
- Link from README.md
- Update API versioning notes
- Add changelog entry

**Test Strategy:**

Manual verification: Load Swagger UI, verify all endpoints documented, test example requests, verify schemas match actual responses. Automated: Swagger validator to check spec validity.

## Subtasks

### 162.1. Add Swagger annotations to all feed endpoints in api/feed_handlers.go

**Status:** pending  
**Dependencies:** None  

Add comprehensive Swagger/OpenAPI annotations to all feed management endpoints including GET /feeds, POST /feeds, GET /feeds/{id}, PUT /feeds/{id}, DELETE /feeds/{id}, POST /feeds/{id}/sync, POST /feeds/sync-all, GET /feeds/templates, and GET /feeds/stats

**Details:**

For each endpoint in api/feed_handlers.go (created in task 154), add swag annotations following this pattern:

1. Summary - concise endpoint description
2. Description - detailed explanation of functionality
3. Tags - all under "Feeds" tag
4. Accept/Produce - application/json
5. Security - ApiKeyAuth (JWT token)
6. Parameters - document path params (id), query params (enabled, type), body params
7. Success responses - 200/201 with schema references
8. Error responses - 400 (validation), 401 (unauthorized), 403 (forbidden), 404 (not found), 500 (server error)

Use @Param for parameters, @Success/@Failure for responses, @Router for endpoint paths. Reference schema types defined in subtask 2. Include examples in annotations where applicable (e.g., feed ID formats, sync operation responses).

### 162.2. Define Swagger schemas, generate documentation, and update project documentation

**Status:** pending  
**Dependencies:** 162.1  

Define all required Swagger schema models for feeds (RuleFeed, FeedCreateRequest, FeedUpdateRequest, FeedSyncResult, FeedStats, FeedTemplate, ErrorResponse) with field documentation and examples, then generate OpenAPI documentation and integrate into project

**Details:**

1. Define Swagger schemas as Go structs with swag comments or in docs/swagger.yaml:
   - RuleFeed: id, name, type, source, enabled, include_patterns, exclude_patterns, tags, schedule, last_sync, stats, created_at, updated_at
   - FeedCreateRequest: name, type (git/filesystem), source (URL/path), include_patterns, exclude_patterns, tags, schedule
   - FeedUpdateRequest: partial RuleFeed fields (name, enabled, patterns, schedule)
   - FeedSyncResult: feed_id, success, rules_added, rules_updated, rules_removed, errors, sync_duration
   - FeedStats: total_rules, enabled_rules, last_sync_status, last_error
   - FeedTemplate: name, type, description, example_source, default_patterns
   - ErrorResponse: error, message, details

2. Add realistic examples for each schema (Git feed with github.com/SigmaHQ/sigma, filesystem feed, sync results)

3. Run 'swag init -g main.go' to generate docs/docs.go and docs/swagger.yaml

4. Verify Swagger UI at http://localhost:8081/swagger/index.html - test 'Try it out' functionality with example requests

5. Update README.md: Add API documentation section linking to /swagger/index.html, note API version, add changelog entry for feed endpoints

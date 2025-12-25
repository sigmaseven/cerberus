# Task ID: 173

**Title:** Unify Rules API Endpoints

**Status:** done

**Dependencies:** 167 ✓, 168 ✓

**Priority:** high

**Description:** Consolidate detection and correlation rule endpoints into unified /api/v1/rules with category filtering, deprecate old endpoints

**Details:**

Implementation: Modify api/handlers.go:

1. Enhance GET /api/v1/rules:
   - Add ?category=detection|correlation|all parameter
   - Add ?lifecycle_status filter
   - Support filtering by logsource fields
   - Return unified response format

2. CRUD operations work for both categories:
   POST /api/v1/rules (auto-detect category from correlation field)
   GET /api/v1/rules/{id} (returns detection or correlation)
   PUT /api/v1/rules/{id} (validates category consistency)
   DELETE /api/v1/rules/{id} (cascade deletes correlation state)

3. Add bulk operations:
   POST /api/v1/rules/bulk-enable {rule_ids: []}
   POST /api/v1/rules/bulk-disable
   POST /api/v1/rules/bulk-delete

4. Import/Export:
   POST /api/v1/rules/import (SIGMA YAML multipart upload)
   GET /api/v1/rules/export?format=sigma&category=all (ZIP of YAML files)

5. Validation:
   POST /api/v1/rules/validate (validate SIGMA YAML before creation)

6. Deprecate old endpoints:
   /api/v1/correlation-rules/* -> 410 Gone with redirect header
   Log deprecation warnings for 6 months

7. Update Swagger docs

**Test Strategy:**

Create api/unified_rules_api_test.go:
1. Test GET with category filtering
2. Test POST auto-detects category
3. Test PUT validates category consistency
4. Test bulk operations on mixed categories
5. Test import/export round-trip
6. Test old endpoint redirects
7. Test API contract backward compatibility
8. Run existing rule CRUD tests against new API

## Subtasks

### 173.1. Enhance GET /api/v1/rules with category and filtering parameters

**Status:** pending  
**Dependencies:** None  

Extend the GET /api/v1/rules endpoint to support category filtering (detection|correlation|all), lifecycle_status filter, and logsource field filtering with unified response format

**Details:**

Implementation in api/handlers.go:
1. Add query parameter parsing for 'category' (detection|correlation|all, default='all')
2. Add 'lifecycle_status' query parameter support (draft|testing|stable|deprecated)
3. Add logsource filtering support (product, service, category fields)
4. Modify database query to filter by rule_category field
5. Return unified response format with rule metadata including category
6. Ensure pagination and sorting work across both rule types
7. Add proper error handling for invalid filter values

### 173.2. Implement category auto-detection in POST /api/v1/rules handler

**Status:** pending  
**Dependencies:** 173.1  

Add logic to POST handler that automatically detects whether a rule is detection or correlation type based on the presence of correlation configuration fields

**Details:**

Implementation in api/handlers.go:
1. Parse incoming rule JSON/YAML in POST handler
2. Check for presence of 'correlation' field or 'sequence' field
3. If correlation fields present, set rule_category='correlation'
4. If correlation fields absent, set rule_category='detection'
5. Validate correlation config structure if category='correlation'
6. Validate SIGMA detection logic if category='detection'
7. Set appropriate default lifecycle_status based on category
8. Return created rule with assigned category in response
9. Add comprehensive error messages for ambiguous rule types

### 173.3. Add category consistency validation in PUT /api/v1/rules/{id}

**Status:** pending  
**Dependencies:** 173.2  

Implement validation logic in the PUT handler to ensure rule category cannot be changed and updates maintain category-specific field consistency

**Details:**

Implementation in api/handlers.go:
1. Retrieve existing rule from database by ID
2. Compare existing rule_category with category implied by update payload
3. Reject update if category field changed explicitly (return 400 Bad Request)
4. Reject if correlation fields added to detection rule or vice versa
5. Validate correlation config structure for correlation rules
6. Validate SIGMA detection fields for detection rules
7. Allow lifecycle_status transitions according to rules
8. Preserve rule_category in database on successful update
9. Return detailed validation error messages

### 173.4. Implement bulk operations endpoints with transaction safety

**Status:** pending  
**Dependencies:** 173.3  

Create three new bulk operation endpoints (bulk-enable, bulk-disable, bulk-delete) that operate on multiple rules atomically with proper error handling and rollback

**Details:**

Implementation in api/handlers.go:
1. POST /api/v1/rules/bulk-enable: accept {rule_ids: []} JSON body
2. POST /api/v1/rules/bulk-disable: accept {rule_ids: []} JSON body
3. POST /api/v1/rules/bulk-delete: accept {rule_ids: []} JSON body
4. Wrap operations in database transaction for atomicity
5. Validate all rule_ids exist before applying changes
6. For bulk-delete on correlation rules, cascade delete correlation state
7. Return success count, failure count, and detailed error list
8. Rollback transaction if any operation fails (all-or-nothing)
9. Add audit logging for bulk operations
10. Implement rate limiting for bulk endpoints

### 173.5. Create import/export functionality for SIGMA YAML rules

**Status:** pending  
**Dependencies:** 173.4  

Implement POST /api/v1/rules/import for multipart YAML upload and GET /api/v1/rules/export to download rules as ZIP archive of SIGMA YAML files

**Details:**

Implementation in api/handlers.go:
1. POST /api/v1/rules/import:
   - Accept multipart/form-data with YAML files
   - Parse each YAML file as SIGMA rule
   - Auto-detect category using logic from subtask 2
   - Validate each rule before import
   - Return import summary (success count, failures with reasons)
   - Support batch import in transaction
2. GET /api/v1/rules/export:
   - Accept ?format=sigma&category=detection|correlation|all parameters
   - Query rules based on category filter
   - Convert each rule to SIGMA YAML format
   - Create ZIP archive with organized folder structure
   - Stream ZIP response with appropriate headers
   - Include metadata.json in ZIP with export timestamp

### 173.6. Add endpoint deprecation and update Swagger documentation

**Status:** pending  
**Dependencies:** 173.5  

Implement 410 Gone responses for deprecated correlation-rules endpoints with redirect headers, add deprecation warnings to logs, and update all Swagger API documentation

**Details:**

Implementation across multiple files:
1. api/handlers.go - Add middleware/handlers for /api/v1/correlation-rules/*:
   - Return 410 Gone status
   - Add 'Location' header pointing to new /api/v1/rules endpoint
   - Add 'Sunset' header with deprecation date (6 months)
   - Log deprecation warning with caller IP and endpoint
2. docs/docs.go and docs/swagger.yaml:
   - Document all new unified /api/v1/rules endpoints
   - Add category, lifecycle_status, logsource parameters
   - Document bulk operation endpoints with request/response schemas
   - Document import/export endpoints with multipart and ZIP formats
   - Mark old /api/v1/correlation-rules/* as deprecated with migration notes
3. Add deprecation metrics for monitoring migration progress

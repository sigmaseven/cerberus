# Task ID: 142

**Title:** Convert TODO Comments to Tracked Issues

**Status:** done

**Dependencies:** None

**Priority:** low

**Description:** Document and track 77 TODO/FIXME/HACK comments as GitHub issues with resolution timelines

**Details:**

**TECHNICAL DEBT MANAGEMENT**

Found 77 TODO/FIXME/HACK comments across 23 files.

Critical TODOs to prioritize:
1. `api/handlers.go:76` - "TODO: Get actual total count from storage"
2. `api/handlers.go:79` - "TODO: Calculate based on actual total"
3. `storage/clickhouse_events.go` - Performance optimization TODO
4. `detect/engine.go` - Rule evaluation optimization TODO

Implementation process:

**Phase 1: Audit (1-2 hours)**
```bash
grep -rn "TODO\|FIXME\|HACK" --include='*.go' . > todo_audit.txt
```
Categorize:
- CRITICAL: Affects functionality or security
- HIGH: Performance or user experience impact  
- MEDIUM: Code quality improvements
- LOW: Nice-to-have refactorings
- INVALID: Already done, remove comment

**Phase 2: Create issues**
For each TODO:
1. Create GitHub issue with:
   - Title from TODO comment
   - File and line reference
   - Context (why it matters)
   - Estimated effort
   - Priority label
2. Replace TODO with issue reference:
   ```go
   // TODO: Get actual total count from storage
   // Issue #XXX: Implement accurate pagination total count
   ```

**Phase 3: Resolution plan**
- CRITICAL: Sprint 1-2
- HIGH: Quarter 1
- MEDIUM: Backlog with deadline
- LOW: Nice-to-have
- INVALID: Remove immediately

**Phase 4: Prevent new TODOs**
Add pre-commit hook or CI check:
```bash
if git diff --cached | grep -q '// TODO'; then
    echo "ERROR: New TODO comments require GitHub issue"
    exit 1
fi
```

Allow TODOs with issue reference:
```go
// TODO(#123): Description
```

**Test Strategy:**

1. Audit completeness: Verify all TODOs captured
2. Issue tracking: Confirm all issues created in GitHub
3. Code review: Verify TODO comments updated with issue refs
4. CI integration: Test pre-commit hook blocks raw TODOs
5. Documentation: Update CONTRIBUTING.md with TODO policy
6. Periodic review: Schedule quarterly TODO audit
7. Metrics: Track TODO resolution rate

## Subtasks

### 142.1. Run comprehensive audit to find and categorize all TODO/FIXME/HACK comments

**Status:** done  
**Dependencies:** None  

Execute grep search across Go codebase to find all TODO/FIXME/HACK comments, categorize by priority (CRITICAL/HIGH/MEDIUM/LOW/INVALID), and filter out comments in vendored/external code like sigma rules data

**Details:**

Run `grep -rn 'TODO\|FIXME\|HACK' --include='*.go' . > todo_audit.txt` to capture all instances. Review each comment in context to determine: (1) Whether it's in production code vs vendored/sigma rules data, (2) Priority level based on impact to functionality/security/performance/code quality, (3) Whether the TODO is still valid or already resolved. Create a categorized spreadsheet or markdown file with columns: file path, line number, comment text, category (CRITICAL/HIGH/MEDIUM/LOW/INVALID), estimated effort, and notes on context. Focus on the ~77 production code TODOs, excluding sigma rules data which shouldn't be tracked.
<info added on 2025-12-14T21:31:03.404Z>
Based on the codebase analysis and the audit completion report, here is the new information to append to the subtask details:

Audit completed successfully. Analyzed entire Go codebase and identified 26 untracked TODO/FIXME/HACK comments in production code (separate from 787 existing TASK references which are already tracked). 

Priority breakdown:
- CRITICAL (5 items): Pagination total count calculation (api/handlers.go:76,79), version information endpoint, admin permission check, field mapping validation check
- HIGH (2 items): Configurable timeout values for external integrations
- MEDIUM (5 items): Performance counters, monitoring/observability improvements, workflow enhancements  
- LOW (14 items): ML feature extractors, sandbox mode features, minor optimizations

Key findings: Most TODOs represent future feature enhancements rather than bugs or technical debt. Existing codebase demonstrates strong discipline with TASK comment system for tracking work items. The 26 untracked TODOs were likely added during rapid development phases and represent legitimate gaps in the tracking system. Critical items focus on API completeness (pagination accuracy, version endpoints) and security validation. Sigma rules directory excluded from audit as those files are external/vendored data not part of application codebase.
</info added on 2025-12-14T21:31:03.404Z>

### 142.2. Create GitHub issues for CRITICAL and HIGH priority TODOs with proper context

**Status:** done  
**Dependencies:** 142.1  

Generate GitHub issues for all CRITICAL and HIGH priority TODO comments identified in audit, including file references, technical context, effort estimates, and appropriate labels

**Details:**

For each CRITICAL and HIGH priority TODO from the audit: (1) Create a GitHub issue with title derived from TODO comment, (2) Add issue body containing: file path and line number, full TODO comment text, explanation of why it matters (functionality/security/performance impact), code context (surrounding function/feature), estimated effort (hours/days), and suggested implementation approach, (3) Apply labels: priority level (critical/high), category (bug/performance/refactor/security), and area (api/storage/detect/etc). Prioritize the known critical items: api/handlers.go pagination TODOs, storage/clickhouse_events.go performance optimization, detect/engine.go rule evaluation optimization. Track issue numbers for use in next subtask.

### 142.3. Update codebase comments to reference GitHub issue numbers and remove invalid TODOs

**Status:** done  
**Dependencies:** 142.1, 142.2  

Replace TODO comments with GitHub issue references, remove comments marked as INVALID during audit, and standardize format across codebase

**Details:**

For each TODO with a created GitHub issue: (1) Replace the comment format from `// TODO: description` to `// TODO(#XXX): description` or `// Issue #XXX: description` where XXX is the GitHub issue number, (2) Ensure the updated comment retains enough context for developers, (3) For INVALID TODOs identified in audit (already completed or no longer relevant), remove the comment entirely and verify the code works as expected. For MEDIUM/LOW priority TODOs without issues yet, leave as-is for now. Create a summary document listing all changes: file path, old comment, new comment/removed, and issue number. This ensures traceability and makes code review easier.

### 142.4. Implement pre-commit hook for TODO policy and update CONTRIBUTING.md documentation

**Status:** done  
**Dependencies:** 142.1, 142.2, 142.3  

Create pre-commit hook that prevents raw TODO comments without issue references, and document the TODO policy in CONTRIBUTING.md for team adoption

**Details:**

Create `.git/hooks/pre-commit` script that: (1) Checks staged Go files for new TODO/FIXME/HACK comments using `git diff --cached`, (2) Allows TODOs with issue reference format `TODO(#123)` or `Issue #123`, (3) Rejects commits with raw TODO comments and displays error message explaining policy, (4) Provides example of correct format. Make hook executable with `chmod +x`. Update CONTRIBUTING.md with new section on Technical Debt Policy: (1) Explain that all TODOs must reference GitHub issues, (2) Provide examples of acceptable formats, (3) Document the categorization system (CRITICAL/HIGH/MEDIUM/LOW), (4) Explain when to create issues vs fix immediately, (5) Reference the pre-commit hook. Optional: Add GitHub Actions CI check as backup to pre-commit hook for enforcement.

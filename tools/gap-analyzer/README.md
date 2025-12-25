# Requirements-to-Test-Coverage Gap Analyzer

**Version**: 1.0.0
**Author**: Golang Architect
**Purpose**: Automated requirements-to-test-coverage gap analysis tool for continuous quality assurance

---

## Overview

The Gap Analyzer is a production-quality Go tool that automatically maps requirements documents to test files, calculates coverage percentages, identifies gaps, and generates comprehensive reports. This tool eliminates the manual effort of tracking requirements coverage and enables continuous gap analysis in CI/CD pipelines.

## Features

### Requirements Parsing
- Automatically extracts requirement IDs from markdown documents
- Supports multiple ID patterns: `FR-XXX-NNN`, `NFR-XXX-NNN`, `REQ-XXX`, `XXX-NNN`
- Identifies requirement types: MUST/SHALL, SHOULD, MAY (RFC 2119)
- Determines priority levels: P0 (Critical), P1 (High), P2 (Medium), P3 (Low)
- Extracts keywords for intelligent test matching

### Test Discovery
- Recursively scans for `*_test.go` files
- Identifies disabled tests (`.go.disabled` extension)
- Parses test function names and comments
- Extracts explicit coverage comments (`// Covers: FR-XXX-NNN`)
- Derives test keywords from function names

### Coverage Mapping
- **High Confidence**: Explicit coverage comments in test code
- **Medium Confidence**: Strong keyword match + file path correlation
- **Low Confidence**: Weak keyword matches
- Calculates coverage percentages per requirement and category
- Identifies gaps (requirements with no test coverage)

### Report Generation
- **Markdown**: Human-readable comprehensive report
- **JSON**: Machine-readable for programmatic analysis
- **YAML**: Alternative structured format
- **Badge**: Shields.io compatible coverage badge
- **History**: Tracks coverage trends over time

### CI/CD Integration
- Exit code 0 if coverage meets threshold, 1 if below
- Configurable minimum coverage percentage
- Fail on P0 gaps option
- Fail on new gaps option (compared to baseline)

---

## Installation

```bash
# From the Cerberus project root
cd /path/to/cerberus

# Build the tool
go build -o gap-analyzer tools/gap-analyzer

# Or build and install
go install ./tools/gap-analyzer
```

---

## Configuration

The tool uses a YAML configuration file (`config.yaml`) located in `tools/gap-analyzer/`:

```yaml
requirements:
  directory: "docs/requirements"
  patterns:
    - "*.md"
  id_patterns:
    - "FR-[A-Z]+-[0-9]+"
    - "NFR-[A-Z]+-[0-9]+"
    - "REQ-[A-Z0-9]+"
    - "[A-Z]+-[0-9]+"
  priority_keywords:
    P0: ["CRITICAL", "SECURITY", "BLOCKING", "MUST", "SHALL"]
    P1: ["HIGH", "SHOULD", "IMPORTANT"]
    P2: ["MEDIUM", "MAY", "RECOMMENDED"]
    P3: ["LOW", "NICE TO HAVE", "OPTIONAL"]

tests:
  directories:
    - "."
  patterns:
    - "*_test.go"
    - "*_test.go.disabled"
  coverage_comment_patterns:
    - "// Covers: "
    - "// Tests: "
    - "// Validates: "
    - "// REQUIREMENT: "

coverage:
  minimum_percentage: 80
  fail_on_p0_gaps: true
  fail_on_new_gaps: false

output:
  markdown: "REQUIREMENTS_GAP_ANALYSIS.md"
  json: "gap-analysis.json"
  yaml: "gap-analysis.yaml"
  badge: "coverage-badge.json"
  history: ".gap-analysis-history"
```

---

## Usage

### Basic Usage

```bash
# Run with default configuration
./gap-analyzer

# Run with custom config
./gap-analyzer -config path/to/config.yaml

# Verbose output
./gap-analyzer -verbose

# Summary mode (compact reports < 5 MB, recommended for CI/CD)
./gap-analyzer -summary
```

### Output Format Options

```bash
# Generate only markdown report
./gap-analyzer -format markdown -output report.md

# Generate only JSON report
./gap-analyzer -format json -output analysis.json

# Generate only YAML report
./gap-analyzer -format yaml -output analysis.yaml

# Generate only coverage badge
./gap-analyzer -format badge -output badge.json

# Generate all formats (default)
./gap-analyzer -format all
```

### CI/CD Check Mode

```bash
# Check if coverage meets 80% threshold (from config)
./gap-analyzer -check

# Check with custom threshold
./gap-analyzer -check -threshold 90

# Exit codes:
# 0 = Coverage meets threshold
# 1 = Coverage below threshold OR P0 gaps exist
```

### Version Information

```bash
./gap-analyzer -version
```

---

## Adding Explicit Coverage Comments to Tests

To improve traceability and ensure high-confidence mappings, add explicit coverage comments to your test functions:

### Recommended Format

```go
package api

import "testing"

// REQUIREMENT: FR-API-001 - RESTful API Design
// Covers: FR-API-001, FR-API-002, FR-API-003
// This test validates that all API endpoints follow RESTful design principles
func TestAPIRestfulDesign(t *testing.T) {
    // test implementation
}
```

### Supported Comment Patterns

The following patterns are recognized (configurable in `config.yaml`):

- `// Covers: FR-XXX-NNN, FR-YYY-NNN`
- `// Tests: FR-XXX-NNN`
- `// Validates: FR-XXX-NNN`
- `// Verifies: FR-XXX-NNN`
- `// REQUIREMENT: FR-XXX-NNN`

### Best Practices

1. **Place coverage comments immediately before test function**
2. **Use requirement IDs exactly as they appear in requirement documents**
3. **List all requirements tested by the function** (comma-separated)
4. **Add description of what the test validates**
5. **Update comments when test scope changes**

---

## Report Structure

### Executive Summary
- Overall coverage percentage
- Coverage breakdown (Covered/Partial/Missing)
- Priority distribution of gaps (P0/P1/P2/P3)

### Coverage by Category
- Per-category coverage statistics
- Sorted by coverage percentage (lowest first) to highlight problem areas

### Critical Gaps
- P0 (Critical) gaps requiring immediate attention
- P1 (High) MUST requirements with missing/weak coverage
- Detailed information for each gap

### Detailed Coverage by Category
- Requirement-by-requirement breakdown
- Tests covering each requirement
- Confidence level of the mapping
- Disabled test indicators

### Recommendations
- Actionable suggestions based on analysis
- Category-specific improvement areas
- Disabled test review reminders

### Traceability Matrix
- Complete requirements-to-tests mapping table
- Quick lookup of coverage status

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Requirements Coverage Analysis

on:
  pull_request:
  push:
    branches: [main]

jobs:
  gap-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Build Gap Analyzer
        run: go build -o gap-analyzer ./tools/gap-analyzer

      - name: Run Gap Analysis
        run: |
          ./gap-analyzer -verbose -check -threshold 80

      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: gap-analysis-reports
          path: |
            REQUIREMENTS_GAP_ANALYSIS.md
            gap-analysis.json
            coverage-badge.json

      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('REQUIREMENTS_GAP_ANALYSIS.md', 'utf8');
            const summary = report.split('## Coverage by Category')[0];

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## Requirements Coverage Analysis\n\n' + summary
            });
```

### GitLab CI Example

```yaml
gap-analysis:
  stage: test
  script:
    - go build -o gap-analyzer ./tools/gap-analyzer
    - ./gap-analyzer -check -threshold 80
  artifacts:
    when: always
    paths:
      - REQUIREMENTS_GAP_ANALYSIS.md
      - gap-analysis.json
      - coverage-badge.json
    reports:
      coverage_report:
        coverage_format: cobertura
        path: gap-analysis.json
```

---

## Interpreting Results

### Coverage Status

| Status | Meaning | Criteria |
|--------|---------|----------|
| ✅ **COVERED** | Comprehensive test coverage | High confidence: 2+ tests OR Medium confidence: 3+ tests |
| ⚠️ **PARTIAL** | Some test coverage, but incomplete | Medium confidence: 1-2 tests OR Low confidence: multiple tests |
| ❌ **MISSING** | No test coverage | No tests found or all tests disabled |

### Confidence Levels

| Confidence | Meaning | How Determined |
|------------|---------|----------------|
| **HIGH** | Explicit requirement ID in test comment | `// Covers: FR-XXX-NNN` found in test |
| **MEDIUM** | Strong correlation between requirement and test | File path correlation + 2+ keyword matches |
| **LOW** | Weak keyword match only | 1+ keyword match, no file correlation |

### Priority Levels

| Priority | Severity | Action Required |
|----------|----------|-----------------|
| **P0** | Critical - Production Blocker | Immediate action required, blocks release |
| **P1** | High - Important Feature | Should be addressed before release |
| **P2** | Medium - Desired Feature | Address in current sprint/milestone |
| **P3** | Low - Nice to Have | Address when capacity allows |

---

## Troubleshooting

### Issue: Requirements not detected

**Solution**: Check requirement ID patterns in `config.yaml`. Ensure your requirement IDs match one of the configured regex patterns.

```yaml
requirements:
  id_patterns:
    - "YOUR-PATTERN-HERE"
```

### Issue: Tests not found

**Solution**: Verify test file patterns and directories:

```yaml
tests:
  directories:
    - "."  # Current directory
    - "pkg"  # Additional directories
  patterns:
    - "*_test.go"
```

### Issue: Low confidence mappings

**Solution**: Add explicit coverage comments to your tests:

```go
// Covers: FR-API-001, FR-API-002
func TestAPIEndpoints(t *testing.T) { ... }
```

### Issue: Incorrect priority assignment

**Solution**: Ensure requirements use RFC 2119 keywords (MUST, SHOULD, MAY) and/or configure priority keywords:

```yaml
requirements:
  priority_keywords:
    P0: ["CRITICAL", "SECURITY", "MUST"]
```

---

## Development

### Project Structure

```
tools/gap-analyzer/
├── main.go                 # CLI entry point
├── types.go                # Core data structures
├── config.yaml             # Default configuration
├── parser/
│   ├── requirements.go     # Requirements document parser
│   ├── tests.go           # Test file parser
│   ├── matcher.go         # Requirements-to-tests matcher
│   ├── requirements_test.go
│   └── tests_test.go
├── analyzer/
│   └── analyzer.go        # Coverage calculation and gap analysis
├── reporter/
│   ├── markdown.go        # Markdown report generator
│   ├── json.go            # JSON/YAML/Badge generators
└── README.md              # This file
```

### Running Tests

```bash
# Run all tests
go test ./tools/gap-analyzer/...

# Run with coverage
go test -cover ./tools/gap-analyzer/...

# Run specific package
go test ./tools/gap-analyzer/parser
```

### Building

```bash
# Build for current platform
go build -o gap-analyzer ./tools/gap-analyzer

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o gap-analyzer-linux ./tools/gap-analyzer
GOOS=windows GOARCH=amd64 go build -o gap-analyzer.exe ./tools/gap-analyzer
GOOS=darwin GOARCH=amd64 go build -o gap-analyzer-darwin ./tools/gap-analyzer
```

---

## Performance

- **Execution Time**:
  - Full mode: < 15 seconds (380 requirements, 1392 tests)
  - Summary mode: < 5 seconds (faster, recommended for CI/CD)
- **Memory Usage**: ~100MB peak during analysis
- **Scalability**: Linear O(n*m) where n=requirements, m=tests

### Output File Sizes

| Mode | JSON | YAML | Markdown |
|------|------|------|----------|
| **Full** | 81 MB | 69 MB | 14 MB |
| **Summary** | 4.4 MB | 3.8 MB | 12 KB |
| **Reduction** | 94.6% | 94.5% | 99.9% |

**Recommendation**: Use `--summary` mode for CI/CD and version control. Summary mode includes:
- Executive summary and statistics
- Category breakdowns
- P0 and P1 gaps only (critical requirements)
- Actionable recommendations

Note: Actual execution time varies by system. Use `-verbose` flag to see timing for your environment.

---

## Limitations

1. **Keyword Matching**: Low/medium confidence mappings rely on keyword matching, which may produce false positives
2. **Natural Language**: Cannot parse complex requirement logic or dependencies
3. **Test Quality**: Cannot assess whether tests adequately validate requirements (only presence)
4. **Language Specific**: Currently only supports Go test files (`*_test.go`)

---

## Roadmap

Future enhancements:

- [ ] Support for other test frameworks (pytest, Jest, JUnit)
- [ ] Baseline comparison for trend analysis
- [ ] Integration with test coverage tools (go test -cover)
- [ ] Machine learning for improved requirement-test matching
- [ ] Visual coverage dashboards (HTML report)
- [ ] Requirements traceability graph visualization

---

## Support

For issues, questions, or contributions:

1. Check this README for common solutions
2. Review existing issues in project tracker
3. Open a new issue with detailed reproduction steps
4. For security issues, contact the security team directly

---

## License

Copyright 2025 Cerberus SIEM Project. All rights reserved.

# Gap Analyzer - Quick Start Guide

## Installation

```bash
cd /path/to/cerberus
go build -o gap-analyzer tools/gap-analyzer
```

## Usage

### Run Analysis
```bash
./gap-analyzer -verbose
```

### Check Mode (for CI/CD)
```bash
./gap-analyzer -check -threshold 80
# Exit 0 if coverage >= 80%, exit 1 otherwise
```

### Custom Output
```bash
# Markdown only
./gap-analyzer -format markdown -output report.md

# JSON only
./gap-analyzer -format json -output analysis.json
```

## Adding Coverage Comments to Tests

```go
// REQUIREMENT: FR-API-001 - RESTful API Design
// Covers: FR-API-001, FR-API-002
func TestAPIDesign(t *testing.T) {
    // your test code
}
```

## Output Files

- `REQUIREMENTS_GAP_ANALYSIS.md` - Human-readable report
- `gap-analysis.json` - Machine-readable analysis
- `gap-analysis.yaml` - Alternative format
- `coverage-badge.json` - Coverage badge for README

## Understanding Results

| Icon | Status | Meaning |
|------|--------|---------|
| ✅ | COVERED | Comprehensive test coverage |
| ⚠️ | PARTIAL | Some tests but incomplete |
| ❌ | MISSING | No tests found |

**Confidence Levels**:
- HIGH: Explicit `// Covers: FR-XXX` comment
- MEDIUM: File correlation + keyword match
- LOW: Keyword match only

## CI/CD Integration

See `.github/workflows/gap-analysis.yml` for GitHub Actions example.

```yaml
- name: Run Gap Analysis
  run: ./gap-analyzer -check -threshold 80
```

## Configuration

Edit `tools/gap-analyzer/config.yaml`:
- Requirement ID patterns
- Test file patterns
- Coverage thresholds
- Output paths

## Common Issues

**Requirements not found?**
→ Check `id_patterns` in config.yaml

**Tests not detected?**
→ Verify `patterns` and `directories` in config.yaml

**Low confidence mappings?**
→ Add explicit `// Covers: FR-XXX` comments

## Full Documentation

See `tools/gap-analyzer/README.md` for complete documentation.

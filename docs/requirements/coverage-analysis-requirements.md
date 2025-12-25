# Coverage Analysis and Tools Requirements

**Document Owner**: Detection Engineering Team + Security Operations Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Security Team Review
**Last Updated**: 2025-11-16
**Version**: 1.0
**Priority**: P1 (High Priority for Detection Effectiveness)
**Authoritative Sources**:
- MITRE ATT&CK Coverage Framework
- NIST Cybersecurity Framework (CSF) v2.0
- Center for Threat-Informed Defense - "ATT&CK Evaluations"
- "Threat-Informed Defense with ATT&CK" - SANS Institute
- Gartner Security Operations Maturity Model

---

## 1. Executive Summary

### 1.1 Purpose

This document defines comprehensive requirements for coverage analysis capabilities within the Cerberus SIEM system. Coverage analysis evaluates the effectiveness of security detections across multiple dimensions (MITRE ATT&CK, data sources, platforms, asset types) to identify blind spots and guide detection engineering priorities.

**Critical Business Drivers**:
- **Risk Reduction**: Identify and close detection gaps before they are exploited
- **Resource Optimization**: Focus detection engineering on high-value gaps
- **Compliance**: Demonstrate due diligence in security monitoring (SOC 2, ISO 27001)
- **Executive Reporting**: Communicate security posture with data-driven metrics
- **Continuous Improvement**: Track detection coverage trends over time

### 1.2 Scope

**In Scope**:
- Detection coverage analysis (rules, ML models, manual detections)
- Data source coverage and visibility assessment
- Platform coverage (Windows, Linux, macOS, cloud)
- Asset-based coverage (critical assets vs. general population)
- Coverage heatmap and matrix visualization
- Gap prioritization and recommendation engine
- Coverage trending and forecasting
- Benchmark comparison (industry standards)
- Custom coverage dimensions and groupings

**Out of Scope** (Future Enhancements):
- Automated penetration testing for coverage validation - Phase 2
- Purple team exercise management - Phase 3
- Integration with vulnerability management - Phase 2
- Threat simulation and emulation - Phase 3

### 1.3 Current Implementation Analysis

**Existing Coverage Components** (as of 2025-11-16):

| Component | File | Status | Coverage |
|-----------|------|--------|----------|
| MITRE Coverage API | `api/mitre_coverage.go` | ✅ Implemented | Basic technique coverage |
| Coverage Heatmap | `frontend/src/pages/MitreCoverage/components/CoverageHeatMap.tsx` | ✅ Implemented | Visual heatmap |
| Gap Analysis | `frontend/src/pages/MitreCoverage/components/GapAnalysisTable.tsx` | ✅ Implemented | Gap list |
| Coverage Matrix | `frontend/src/pages/MitreCoverage/components/CoverageMatrix.tsx` | ✅ Implemented | Full matrix view |

**Current Coverage Calculation** (from `api/mitre_coverage.go`):
```go
// Calculate coverage by tactic
for tacticID, tacticData := range mitreTactics {
    tacticTotal := len(tacticData.Techniques)
    tacticCovered := 0

    for _, tech := range tacticData.Techniques {
        ruleCount := coveredTechniques[tech.ID]
        if ruleCount > 0 {
            tacticCovered++
        }
    }

    coveragePercent = (float64(tacticCovered) / float64(tacticTotal)) * 100
}
```

**Coverage Metrics Currently Tracked**:
- Total techniques: 60 (hardcoded subset)
- Covered techniques: Count of techniques with ≥1 rule
- Coverage percentage: (Covered / Total) * 100
- Per-tactic coverage
- Gaps (uncovered techniques)
- Rule count per technique

**Implementation Gaps Identified**:
1. ❌ **No Data Source Coverage**: Visibility into log sources not assessed
2. ❌ **No Platform-Specific Coverage**: Can't analyze Windows vs. Linux coverage separately
3. ❌ **No Asset-Based Coverage**: Critical assets may have different coverage than general population
4. ❌ **Binary Coverage (Covered/Not Covered)**: No quality scoring (1 rule = same as 10 rules)
5. ❌ **No Confidence Weighting**: High-confidence rules not distinguished from low-confidence
6. ❌ **No Coverage Trends**: Historical coverage not tracked
7. ❌ **No Benchmark Comparison**: Can't compare to industry standards
8. ❌ **Limited Gap Prioritization**: Gaps not prioritized by threat intelligence or business impact
9. ❌ **No Coverage Forecasting**: Can't predict coverage at current rate of improvement
10. ⚠️ **Hardcoded Technique List**: Only 60 techniques tracked (ATT&CK Enterprise has 640+)

**Coverage Dashboard Highlights**:
- ✅ Visual heatmap with color-coding
- ✅ Per-tactic breakdown charts
- ✅ Gap table with technique details
- ✅ Overall coverage percentage
- ❌ No drill-down to sub-techniques
- ❌ No filter by platform or data source
- ❌ No coverage trend charts

---

## 2. Functional Requirements

### 2.1 Detection Coverage Analysis

#### FR-COV-001: Multi-Dimensional Coverage Calculation

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (Only MITRE technique coverage)
**Owner**: Detection Engineering Team

**Requirement Statement**:
System MUST calculate detection coverage across multiple dimensions including MITRE ATT&CK techniques, data sources, platforms, asset types, and detection methods with quality scoring and confidence weighting.

**Rationale**:
- Single-dimensional coverage (e.g., only MITRE) provides incomplete picture
- Quality matters: 10 high-quality rules better than 1 low-quality rule
- Coverage varies by platform (Windows typically better covered than Linux)
- Critical assets require higher coverage than general population

**Coverage Dimensions**:

| Dimension | Description | Current Status | Priority |
|-----------|-------------|----------------|----------|
| **MITRE Technique** | Coverage by ATT&CK technique | ✅ Partial | P0 |
| **Data Source** | Coverage by log source type | ❌ Not Implemented | P0 |
| **Platform** | Coverage by OS/platform | ❌ Not Implemented | P0 |
| **Asset Type** | Coverage by asset criticality | ❌ Not Implemented | P1 |
| **Detection Method** | Coverage by rule type (signature, anomaly, ML) | ❌ Not Implemented | P1 |
| **Threat Actor** | Coverage by threat group TTPs | ❌ Not Implemented | P2 |
| **Industry** | Coverage by industry-specific threats | ❌ Not Implemented | P2 |

**Specification**:

**1. MITRE Technique Coverage** (Enhanced):
```go
type TechniqueCoverage struct {
    TechniqueID       string   `json:"technique_id"`
    TechniqueName     string   `json:"technique_name"`
    Platforms         []string `json:"platforms"`

    // Coverage Metrics
    TotalRules        int      `json:"total_rules"`
    HighConfRules     int      `json:"high_conf_rules"`
    MediumConfRules   int      `json:"medium_conf_rules"`
    LowConfRules      int      `json:"low_conf_rules"`
    MLModels          int      `json:"ml_models"`

    // Quality Score (0-100)
    CoverageQuality   float64  `json:"coverage_quality"`

    // Weighted Coverage (confidence-weighted)
    WeightedCoverage  float64  `json:"weighted_coverage"`

    // Detection Depth (how many variants covered)
    SubTechniquesCovered int   `json:"subtechniques_covered"`
    SubTechniquesTotal   int   `json:"subtechniques_total"`

    // Alert Activity
    AlertCount30d     int      `json:"alert_count_30d"`
    LastAlertTime     time.Time `json:"last_alert_time,omitempty"`
}

// Calculate coverage quality score
func calculateCoverageQuality(coverage *TechniqueCoverage) float64 {
    score := 0.0

    // Factor 1: Rule count (max 40 points)
    // Diminishing returns: 1 rule=20pts, 2=30pts, 3=35pts, 4+=40pts
    if coverage.TotalRules == 0 {
        return 0.0
    } else if coverage.TotalRules == 1 {
        score += 20.0
    } else if coverage.TotalRules == 2 {
        score += 30.0
    } else if coverage.TotalRules == 3 {
        score += 35.0
    } else {
        score += 40.0
    }

    // Factor 2: Confidence distribution (max 30 points)
    highConfWeight := float64(coverage.HighConfRules) * 10.0   // 10 pts per high-conf rule
    mediumConfWeight := float64(coverage.MediumConfRules) * 5.0 // 5 pts per medium-conf rule
    lowConfWeight := float64(coverage.LowConfRules) * 2.0       // 2 pts per low-conf rule
    confidenceScore := min(highConfWeight+mediumConfWeight+lowConfWeight, 30.0)
    score += confidenceScore

    // Factor 3: Sub-technique coverage (max 20 points)
    if coverage.SubTechniquesTotal > 0 {
        subTechPercent := float64(coverage.SubTechniquesCovered) / float64(coverage.SubTechniquesTotal)
        score += subTechPercent * 20.0
    } else {
        score += 20.0 // No sub-techniques = full credit
    }

    // Factor 4: Detection method diversity (max 10 points)
    if coverage.MLModels > 0 {
        score += 10.0 // Hybrid rule+ML detection is best
    } else if coverage.TotalRules >= 2 {
        score += 5.0 // Multiple rules provide redundancy
    }

    return score
}
```

**2. Data Source Coverage**:
```go
type DataSourceCoverage struct {
    DataSourceName    string   `json:"data_source_name"` // "Windows Event Logs", "Linux Auditd"
    DataSourceType    string   `json:"data_source_type"` // "Host", "Network", "Cloud", "Application"

    // Visibility Metrics
    IsCollected       bool     `json:"is_collected"` // Are we collecting this data source?
    EventsPerDay      int64    `json:"events_per_day"`
    HostsCoverage     int      `json:"hosts_coverage"` // How many hosts sending this data

    // Detection Metrics
    TechniquesDetectable int    `json:"techniques_detectable"` // How many techniques this source can detect
    TechniquesCovered    int    `json:"techniques_covered"` // How many we have rules for
    RulesUsing          int     `json:"rules_using"` // Rules leveraging this data source

    // Quality Metrics
    DataQuality         float64 `json:"data_quality"` // 0-100 (completeness, accuracy)
    NoiseLvl            string  `json:"noise_level"` // "high", "medium", "low"
    RetentionDays       int     `json:"retention_days"`

    // Gaps
    MissingTechniques   []string `json:"missing_techniques"` // Techniques we could detect but don't
}

// Calculate data source coverage
func calculateDataSourceCoverage(dataSource *DataSourceCoverage) float64 {
    if !dataSource.IsCollected {
        return 0.0
    }

    if dataSource.TechniquesDetectable == 0 {
        return 100.0 // No techniques rely on this source
    }

    // Base coverage: techniques covered / detectable
    coveragePercent := (float64(dataSource.TechniquesCovered) / float64(dataSource.TechniquesDetectable)) * 100

    // Adjust for data quality
    qualityMultiplier := dataSource.DataQuality / 100.0
    adjustedCoverage := coveragePercent * qualityMultiplier

    return adjustedCoverage
}
```

**3. Platform Coverage**:
```go
type PlatformCoverage struct {
    Platform          string   `json:"platform"` // "Windows", "Linux", "macOS", "Cloud"

    // Detection Metrics
    TotalTechniques   int      `json:"total_techniques"` // Techniques applicable to this platform
    CoveredTechniques int      `json:"covered_techniques"`
    CoveragePercent   float64  `json:"coverage_percent"`

    // Asset Inventory
    TotalAssets       int      `json:"total_assets"` // Hosts running this platform
    MonitoredAssets   int      `json:"monitored_assets"` // Hosts sending logs
    MonitoringGap     int      `json:"monitoring_gap"` // Assets not monitored

    // Data Source Breakdown
    DataSources       []*DataSourceCoverage `json:"data_sources"`

    // Rules
    RuleCount         int      `json:"rule_count"`
    PlatformSpecific  int      `json:"platform_specific"` // Rules specific to this platform
    CrossPlatform     int      `json:"cross_platform"` // Rules covering multiple platforms
}
```

**4. Asset-Based Coverage**:
```go
type AssetBasedCoverage struct {
    AssetTier         string   `json:"asset_tier"` // "Critical", "High", "Medium", "Low"
    AssetCount        int      `json:"asset_count"`
    MonitoredCount    int      `json:"monitored_count"`

    // Coverage Requirements
    RequiredCoverage  float64  `json:"required_coverage"` // Minimum % for this tier
    ActualCoverage    float64  `json:"actual_coverage"`
    CoverageDeficit   float64  `json:"coverage_deficit"` // Gap from requirement

    // Technique Coverage
    TechniquesCovered int      `json:"techniques_covered"`
    TechniquesTotal   int      `json:"techniques_total"`

    // Detection Depth
    AvgRulesPerTechnique float64 `json:"avg_rules_per_technique"`
    MLCoverage        float64  `json:"ml_coverage"` // % techniques with ML detection
}

// Asset tier coverage requirements
var assetTierRequirements = map[string]float64{
    "Critical": 95.0, // Critical assets require 95% coverage
    "High":     85.0,
    "Medium":   70.0,
    "Low":      50.0,
}
```

**Acceptance Criteria**:
- [ ] Multi-dimensional coverage calculated
- [ ] Coverage quality score (0-100) per technique
- [ ] Confidence-weighted coverage
- [ ] Sub-technique coverage tracked
- [ ] Data source coverage assessed
- [ ] Platform-specific coverage calculated
- [ ] Asset-tier coverage analyzed
- [ ] Coverage API supports filtering by dimension
- [ ] Coverage dashboard displays all dimensions
- [ ] Coverage trends tracked over time

**Test Requirements**:
```go
// TEST-COV-001: Coverage quality score calculation
func TestCoverage_QualityScore(t *testing.T) {
    coverage := &TechniqueCoverage{
        TechniqueID:         "T1055",
        TotalRules:          4,
        HighConfRules:       2,
        MediumConfRules:     1,
        LowConfRules:        1,
        MLModels:            1,
        SubTechniquesCovered: 3,
        SubTechniquesTotal:  5,
    }

    quality := calculateCoverageQuality(coverage)

    // Verify score components:
    // - Rule count (4 rules): 40 points
    // - Confidence (2*10 + 1*5 + 1*2): 27 points (capped at 30)
    // - Sub-techniques (3/5): 12 points
    // - ML diversity: 10 points
    // Total: ~89 points
    assert.Greater(t, quality, 85.0)
    assert.LessOrEqual(t, quality, 100.0)
}

// TEST-COV-002: Data source coverage calculation
func TestCoverage_DataSource(t *testing.T) {
    dataSource := &DataSourceCoverage{
        DataSourceName:       "Windows Event Logs",
        IsCollected:          true,
        TechniquesDetectable: 100,
        TechniquesCovered:    80,
        DataQuality:          90.0, // 90% quality
    }

    coverage := calculateDataSourceCoverage(dataSource)

    // 80/100 = 80% base coverage
    // 80% * 0.9 (quality) = 72% adjusted coverage
    assert.InDelta(t, 72.0, coverage, 1.0)
}

// TEST-COV-003: Platform coverage calculation
func TestCoverage_Platform(t *testing.T) {
    platformCov := &PlatformCoverage{
        Platform:          "Windows",
        TotalTechniques:   400,
        CoveredTechniques: 300,
        TotalAssets:       1000,
        MonitoredAssets:   950,
    }

    // Coverage: 300/400 = 75%
    coveragePercent := (float64(platformCov.CoveredTechniques) / float64(platformCov.TotalTechniques)) * 100
    assert.InDelta(t, 75.0, coveragePercent, 0.1)

    // Monitoring gap: 1000 - 950 = 50 assets
    monitoringGap := platformCov.TotalAssets - platformCov.MonitoredAssets
    assert.Equal(t, 50, monitoringGap)
}
```

**TBDs**:
- [ ] **TBD-COV-001**: Coverage quality score weights (adjust factors?) (Owner: Detection Team, Deadline: Week 2)
- [ ] **TBD-COV-002**: Asset tier definitions and requirements (Owner: Risk Team, Deadline: Week 2)

---

#### FR-COV-002: Coverage Scoring and Grading

**Priority**: P1 (High)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Detection Engineering Team

**Requirement Statement**:
System MUST provide coverage scoring and grading (A-F scale) for individual techniques, tactics, platforms, and overall security posture to enable quick assessment and executive reporting.

**Rationale**:
- Letter grades are intuitive for non-technical stakeholders
- Scoring enables benchmarking and goal-setting
- Grades highlight areas needing immediate attention
- Trending scores show improvement or regression

**Coverage Grading Scale**:
```
A+ (95-100): Excellent - Multiple high-quality detections, ML coverage, tested
A  (90-94):  Very Good - Multiple quality detections
B  (80-89):  Good - Solid coverage with room for improvement
C  (70-79):  Fair - Basic coverage, needs enhancement
D  (60-69):  Poor - Minimal coverage, significant gaps
F  (0-59):   Failing - No or inadequate coverage
```

**Specification**:
```go
type CoverageGrade struct {
    Entity       string  `json:"entity"` // "T1055", "TA0004", "Windows", "Overall"
    EntityType   string  `json:"entity_type"` // "technique", "tactic", "platform", "overall"
    Score        float64 `json:"score"` // 0-100
    Grade        string  `json:"grade"` // "A+", "A", "B", "C", "D", "F"
    Trend        string  `json:"trend"` // "improving", "stable", "declining"
    PreviousGrade string `json:"previous_grade,omitempty"`

    // Breakdown
    Components   map[string]float64 `json:"components"` // Score breakdown
    Strengths    []string           `json:"strengths"`
    Weaknesses   []string           `json:"weaknesses"`
    Recommendations []string        `json:"recommendations"`
}

func calculateGrade(score float64) string {
    switch {
    case score >= 95:
        return "A+"
    case score >= 90:
        return "A"
    case score >= 80:
        return "B"
    case score >= 70:
        return "C"
    case score >= 60:
        return "D"
    default:
        return "F"
    }
}

func generateCoverageReportCard(metrics *CoverageMetrics) *ReportCard {
    reportCard := &ReportCard{
        OverallGrade: calculateGrade(metrics.OverallScore),
        Grades:       []*CoverageGrade{},
    }

    // Technique-level grades
    for _, techCov := range metrics.TechniqueCoverage {
        grade := &CoverageGrade{
            Entity:     techCov.TechniqueID,
            EntityType: "technique",
            Score:      techCov.CoverageQuality,
            Grade:      calculateGrade(techCov.CoverageQuality),
        }

        // Identify strengths/weaknesses
        if techCov.HighConfRules >= 2 {
            grade.Strengths = append(grade.Strengths, "Multiple high-confidence rules")
        }
        if techCov.MLModels > 0 {
            grade.Strengths = append(grade.Strengths, "ML detection available")
        }
        if techCov.SubTechniquesCovered < techCov.SubTechniquesTotal/2 {
            grade.Weaknesses = append(grade.Weaknesses, "Low sub-technique coverage")
        }
        if techCov.TotalRules == 1 {
            grade.Weaknesses = append(grade.Weaknesses, "Single point of failure (only 1 rule)")
            grade.Recommendations = append(grade.Recommendations, "Add redundant detection rule")
        }

        reportCard.Grades = append(reportCard.Grades, grade)
    }

    return reportCard
}
```

**Executive Summary Report**:
```json
{
  "report_date": "2025-01-16",
  "overall_grade": "B",
  "overall_score": 82.5,
  "trend": "improving",

  "grade_distribution": {
    "A+": 15,
    "A": 45,
    "B": 120,
    "C": 80,
    "D": 30,
    "F": 50
  },

  "highlights": {
    "highest_grade_tactics": [
      {"tactic": "Initial Access", "grade": "A"},
      {"tactic": "Execution", "grade": "A-"}
    ],
    "lowest_grade_tactics": [
      {"tactic": "Impact", "grade": "D"},
      {"tactic": "Collection", "grade": "C-"}
    ]
  },

  "key_metrics": {
    "techniques_with_a_grade": 60,
    "techniques_failing": 50,
    "coverage_improvement_30d": "+5.2%",
    "gaps_closed_30d": 12
  }
}
```

**Acceptance Criteria**:
- [ ] Coverage scored on 0-100 scale
- [ ] Letter grades assigned (A+ through F)
- [ ] Overall security posture grade calculated
- [ ] Per-tactic grades calculated
- [ ] Per-platform grades calculated
- [ ] Strengths and weaknesses identified
- [ ] Recommendations generated
- [ ] Executive summary report generated
- [ ] Trend analysis (grade changes over time)
- [ ] Report exportable to PDF

**Test Requirements**:
```go
// TEST-COV-004: Coverage grading
func TestCoverage_Grading(t *testing.T) {
    testCases := []struct {
        score float64
        expectedGrade string
    }{
        {97.0, "A+"},
        {92.0, "A"},
        {85.0, "B"},
        {75.0, "C"},
        {65.0, "D"},
        {45.0, "F"},
    }

    for _, tc := range testCases {
        grade := calculateGrade(tc.score)
        assert.Equal(t, tc.expectedGrade, grade, "Score %v should be grade %s", tc.score, tc.expectedGrade)
    }
}
```

---

### 2.2 Heatmap Visualization

#### FR-COV-003: Interactive Coverage Heatmap

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED (Basic)
**Owner**: Frontend Team

**Requirement Statement**:
System MUST provide interactive coverage heatmaps with drill-down capabilities, filtering, custom color schemes, and export functionality.

**Rationale**:
- Visual heatmaps enable rapid assessment of coverage landscape
- Interactive elements allow investigation of specific areas
- Export enables sharing with stakeholders
- Custom views support different analysis perspectives

**Current Implementation**: `frontend/src/pages/MitreCoverage/components/CoverageHeatMap.tsx`

**Enhancements Needed**:

**1. Drill-Down Capabilities**:
```typescript
// Click technique → show details modal
interface TechniqueDetailsModal {
  techniqueId: string;
  techniqueName: string;
  description: string;
  coverageScore: number;
  rulesCount: number;
  rulesList: RuleReference[];
  mlModels: MLModelReference[];
  subTechniques: SubTechniqueStatus[];
  alertActivity: AlertActivityChart; // Last 30 days
  recommendations: string[];
}

// Click tactic → filter to show only that tactic's techniques
// Shift+Click → multi-select tactics for comparison
```

**2. Advanced Filtering**:
```typescript
interface HeatmapFilters {
  platforms: string[]; // ["Windows", "Linux"]
  dataSources: string[]; // ["Windows Event Logs"]
  confidenceLevels: string[]; // ["high", "medium"]
  coverageThreshold: number; // Show only techniques with >N rules
  includeSubTechniques: boolean;
  hideDeprecated: boolean;
}
```

**3. Custom Color Schemes**:
```typescript
type ColorScheme = "default" | "red-green" | "blue-yellow" | "grayscale" | "high-contrast";

interface ColorSchemeConfig {
  noRule: string; // Color for 0 rules
  minimalCoverage: string; // 1 rule
  partialCoverage: string; // 2-3 rules
  goodCoverage: string; // 4-5 rules
  excellentCoverage: string; // 6+ rules
}

const colorSchemes: Record<ColorScheme, ColorSchemeConfig> = {
  "default": {
    noRule: "#ff0000",
    minimalCoverage: "#ff9900",
    partialCoverage: "#ffff00",
    goodCoverage: "#90ee90",
    excellentCoverage: "#00ff00",
  },
  "high-contrast": {
    noRule: "#000000",
    minimalCoverage: "#404040",
    partialCoverage: "#808080",
    goodCoverage: "#c0c0c0",
    excellentCoverage: "#ffffff",
  },
};
```

**4. Export Capabilities**:
```typescript
interface ExportOptions {
  format: "png" | "svg" | "pdf" | "navigator-layer";
  includeTooltips: boolean;
  includeLabels: boolean;
  resolution: "low" | "medium" | "high";
  orientation: "landscape" | "portrait";
}

async function exportHeatmap(options: ExportOptions): Promise<Blob> {
  if (options.format === "png" || options.format === "svg") {
    return exportAsImage(options);
  } else if (options.format === "pdf") {
    return exportAsPDF(options);
  } else if (options.format === "navigator-layer") {
    return exportAsNavigatorLayer();
  }
}
```

**Acceptance Criteria**:
- [x] Heatmap renders all techniques
- [x] Color-coded by rule count
- [ ] Click technique → details modal
- [ ] Hover → tooltip with technique info
- [ ] Filter by platform, data source, confidence
- [ ] Zoom in/out for large matrices
- [ ] Export to PNG, SVG, PDF
- [ ] Export to ATT&CK Navigator layer
- [ ] Custom color schemes selectable
- [ ] Responsive design (mobile/tablet)

---

### 2.3 Gap Prioritization

#### FR-COV-004: Intelligent Gap Prioritization

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (Gaps identified, not prioritized)
**Owner**: Threat Intelligence Team + Detection Team

**Requirement Statement**:
System MUST prioritize coverage gaps using multi-factor scoring including threat intelligence (active campaigns), asset criticality, attack likelihood, detection difficulty, and business risk.

**Rationale**:
- Not all gaps are equal: T1055 (Process Injection) used in 50% of attacks vs. rare techniques
- Resources are limited: must focus on high-impact gaps
- Prioritization requires combining technical and business factors
- Dynamic prioritization adapts to changing threat landscape

**Prioritization Factors**:

| Factor | Weight | Source | Range |
|--------|--------|--------|-------|
| **Threat Prevalence** | 30% | Threat intel feeds | 0-30 |
| **Observed in Wild** | 20% | Threat intel + IOCs | 0-20 |
| **Asset Criticality** | 20% | Asset inventory | 0-20 |
| **Detection Difficulty** | 15% | ATT&CK metadata | 0-15 |
| **Business Impact** | 15% | Risk assessment | 0-15 |

**Specification**:
```go
type GapPriority struct {
    TechniqueID       string  `json:"technique_id"`
    TechniqueName     string  `json:"technique_name"`
    PriorityScore     float64 `json:"priority_score"` // 0-100
    PriorityTier      string  `json:"priority_tier"` // "Critical", "High", "Medium", "Low"

    // Scoring Breakdown
    ThreatPrevalence  float64 `json:"threat_prevalence_score"` // 0-30
    ObservedInWild    float64 `json:"observed_in_wild_score"` // 0-20
    AssetCriticality  float64 `json:"asset_criticality_score"` // 0-20
    DetectionDifficulty float64 `json:"detection_difficulty_score"` // 0-15
    BusinessImpact    float64 `json:"business_impact_score"` // 0-15

    // Supporting Data
    ThreatGroups      []string `json:"threat_groups"` // Groups using this technique
    RecentCampaigns   int      `json:"recent_campaigns"` // Count of campaigns in last 90 days
    AffectedPlatforms []string `json:"affected_platforms"`
    AffectedAssets    int      `json:"affected_assets"` // Count of assets vulnerable

    // Remediation
    EstimatedEffort   string   `json:"estimated_effort"` // "Low", "Medium", "High"
    RecommendedRules  []string `json:"recommended_rules"` // Suggested rule templates
    RecommendedDataSources []string `json:"recommended_data_sources"`
    ExpectedROI       string   `json:"expected_roi"` // Return on investment
}

type GapPrioritizer struct {
    attackStorage   ATTACKStorage
    threatIntel     ThreatIntelFeed
    assetInventory  AssetInventory
    riskModel       RiskModel
}

func (gp *GapPrioritizer) PrioritizeGap(gap *CoverageGap) (*GapPriority, error) {
    priority := &GapPriority{
        TechniqueID:   gap.TechniqueID,
        TechniqueName: gap.TechniqueName,
    }

    technique, _ := gp.attackStorage.GetTechniqueByID(gap.TechniqueID)

    // Factor 1: Threat Prevalence (0-30 points)
    prevalence := gp.threatIntel.GetTechniquePrevalence(gap.TechniqueID)
    priority.ThreatPrevalence = prevalenceToScore(prevalence, 30.0)

    // Factor 2: Observed in Wild (0-20 points)
    campaigns := gp.threatIntel.GetRecentCampaigns(gap.TechniqueID, 90*24*time.Hour)
    priority.RecentCampaigns = len(campaigns)
    if len(campaigns) > 0 {
        priority.ObservedInWild = 20.0 // Active in last 90 days
    } else if len(campaigns) > 0 { // Historical
        priority.ObservedInWild = 10.0
    } else {
        priority.ObservedInWild = 0.0
    }

    // Factor 3: Asset Criticality (0-20 points)
    affectedAssets := gp.assetInventory.GetAssetsForPlatforms(technique.Platforms)
    priority.AffectedAssets = len(affectedAssets)
    criticalAssets := filterCriticalAssets(affectedAssets)
    if len(criticalAssets) > 0 {
        priority.AssetCriticality = 20.0 // Critical assets affected
    } else if len(affectedAssets) > 100 {
        priority.AssetCriticality = 15.0 // Many assets affected
    } else if len(affectedAssets) > 10 {
        priority.AssetCriticality = 10.0
    } else {
        priority.AssetCriticality = 5.0
    }

    // Factor 4: Detection Difficulty (0-15 points)
    // Higher difficulty = higher priority (harder gaps to close)
    difficulty := estimateDetectionDifficulty(technique)
    priority.DetectionDifficulty = difficultyToScore(difficulty, 15.0)

    // Factor 5: Business Impact (0-15 points)
    impact := gp.riskModel.EstimateImpact(technique)
    priority.BusinessImpact = impactToScore(impact, 15.0)

    // Calculate total priority score
    priority.PriorityScore = priority.ThreatPrevalence +
                              priority.ObservedInWild +
                              priority.AssetCriticality +
                              priority.DetectionDifficulty +
                              priority.BusinessImpact

    // Assign priority tier
    priority.PriorityTier = scoreToPriorityTier(priority.PriorityScore)

    return priority, nil
}

func scoreToPriorityTier(score float64) string {
    if score >= 80 {
        return "Critical"
    } else if score >= 60 {
        return "High"
    } else if score >= 40 {
        return "Medium"
    } else {
        return "Low"
    }
}
```

**Acceptance Criteria**:
- [ ] Gaps prioritized using multi-factor scoring
- [ ] Priority score (0-100) calculated
- [ ] Priority tier assigned (Critical/High/Medium/Low)
- [ ] Threat intelligence integrated (prevalence, campaigns)
- [ ] Asset criticality factored into score
- [ ] Detection difficulty considered
- [ ] Business impact assessed
- [ ] Scoring factors configurable (weights adjustable)
- [ ] Top 20 priority gaps dashboard
- [ ] Priority re-calculated daily (threat landscape changes)

**Test Requirements**:
```go
// TEST-COV-005: Gap prioritization scoring
func TestGapPrioritization_Scoring(t *testing.T) {
    prioritizer := NewGapPrioritizer(attackStorage, threatIntel, assetInventory, riskModel)

    // Gap 1: Process Injection (high prevalence, active campaigns)
    gap1 := &CoverageGap{TechniqueID: "T1055", TechniqueName: "Process Injection"}
    threatIntel.SetPrevalence("T1055", "very_high") // 30 points
    threatIntel.SetRecentCampaigns("T1055", 5) // 20 points (observed in wild)
    assetInventory.SetCriticalAssets("T1055", 10) // 20 points (critical assets)

    priority1, _ := prioritizer.PrioritizeGap(gap1)
    assert.Equal(t, "Critical", priority1.PriorityTier)
    assert.Greater(t, priority1.PriorityScore, 80.0)

    // Gap 2: Rare technique, no recent activity
    gap2 := &CoverageGap{TechniqueID: "T9999", TechniqueName: "Rare Technique"}
    threatIntel.SetPrevalence("T9999", "low") // 10 points
    threatIntel.SetRecentCampaigns("T9999", 0) // 0 points

    priority2, _ := prioritizer.PrioritizeGap(gap2)
    assert.Equal(t, "Low", priority2.PriorityTier)
    assert.Less(t, priority2.PriorityScore, 40.0)
}
```

**TBDs**:
- [ ] **TBD-COV-003**: Threat intel feed integration (Owner: Threat Intel Team, Deadline: Week 3)
- [ ] **TBD-COV-004**: Asset criticality classification (Owner: Risk Team, Deadline: Week 2)
- [ ] **TBD-COV-005**: Priority score weight calibration (Owner: Detection Team, Deadline: Week 3)

---

### 2.4 Coverage Recommendations

#### FR-COV-005: Automated Detection Recommendations

**Priority**: P1 (High)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Detection Engineering Team

**Requirement Statement**:
System MUST provide automated recommendations for closing coverage gaps including suggested rules, data sources, configuration changes, and expected return on investment.

**Rationale**:
- Accelerates detection engineering workflow
- Reduces time from gap identification to remediation
- Provides actionable guidance for junior analysts
- Prioritizes recommendations by expected ROI

**Recommendation Types**:

| Type | Description | Priority |
|------|-------------|----------|
| **Rule Templates** | Pre-built rule suggestions | P0 |
| **Data Source Enablement** | Suggest enabling new log sources | P0 |
| **Rule Tuning** | Improve existing low-quality rules | P1 |
| **ML Model Deployment** | Suggest ML-based detection | P1 |
| **Integration** | Third-party tool integration | P2 |

**Specification**:
```go
type DetectionRecommendation struct {
    RecommendationID  string  `json:"recommendation_id"`
    Type              string  `json:"type"` // "rule", "data_source", "tuning", "ml_model"
    Priority          string  `json:"priority"` // "critical", "high", "medium", "low"
    EstimatedEffort   string  `json:"estimated_effort"` // "1 hour", "1 day", "1 week"
    EstimatedROI      float64 `json:"estimated_roi"` // Gap closure impact (0-100)

    // Gap Context
    TargetTechnique   string  `json:"target_technique"`
    CurrentCoverage   float64 `json:"current_coverage"`
    ExpectedCoverage  float64 `json:"expected_coverage"` // After implementing recommendation

    // Recommendation Details
    Title             string  `json:"title"`
    Description       string  `json:"description"`
    Implementation    string  `json:"implementation"` // Step-by-step guide
    Prerequisites     []string `json:"prerequisites"`

    // Resources
    RuleTemplate      *RuleTemplate `json:"rule_template,omitempty"`
    DataSourceConfig  *DataSourceConfig `json:"data_source_config,omitempty"`
    ExternalLinks     []string `json:"external_links"` // Documentation, blogs

    // Validation
    TestPlan          string  `json:"test_plan"`
    SuccessCriteria   []string `json:"success_criteria"`
}

type RecommendationEngine struct {
    attackStorage  ATTACKStorage
    ruleStorage    RuleStorage
    dataSourceRepo DataSourceRepository
    templateRepo   RuleTemplateRepository
}

func (re *RecommendationEngine) GenerateRecommendations(gap *GapPriority) ([]*DetectionRecommendation, error) {
    recommendations := []*DetectionRecommendation{}

    technique, _ := re.attackStorage.GetTechniqueByID(gap.TechniqueID)

    // Recommendation 1: Check for rule templates
    templates := re.templateRepo.FindTemplatesForTechnique(gap.TechniqueID)
    for _, template := range templates {
        rec := &DetectionRecommendation{
            RecommendationID: generateID(),
            Type:             "rule",
            Priority:         gap.PriorityTier,
            EstimatedEffort:  "2 hours", // Time to adapt template
            EstimatedROI:     calculateTemplateROI(template, gap),
            TargetTechnique:  gap.TechniqueID,
            Title:            fmt.Sprintf("Deploy %s rule template", template.Name),
            Description:      template.Description,
            RuleTemplate:     template,
            Implementation:   generateImplementationGuide(template),
            TestPlan:         generateTestPlan(template),
        }
        recommendations = append(recommendations, rec)
    }

    // Recommendation 2: Check if required data sources are enabled
    requiredDataSources := technique.DataSources
    enabledDataSources := re.dataSourceRepo.GetEnabledDataSources()
    for _, required := range requiredDataSources {
        if !contains(enabledDataSources, required) {
            rec := &DetectionRecommendation{
                RecommendationID: generateID(),
                Type:             "data_source",
                Priority:         "high",
                EstimatedEffort:  "1 day",
                EstimatedROI:     calculateDataSourceROI(required, gap),
                TargetTechnique:  gap.TechniqueID,
                Title:            fmt.Sprintf("Enable %s data source", required),
                Description:      fmt.Sprintf("Technique %s requires %s for detection", gap.TechniqueID, required),
                DataSourceConfig: re.dataSourceRepo.GetConfigGuide(required),
            }
            recommendations = append(recommendations, rec)
        }
    }

    // Recommendation 3: ML model suggestions
    if gap.PriorityTier == "Critical" || gap.PriorityTier == "High" {
        rec := &DetectionRecommendation{
            RecommendationID: generateID(),
            Type:             "ml_model",
            Priority:         "medium",
            EstimatedEffort:  "1 week",
            EstimatedROI:     calculateMLROI(gap),
            TargetTechnique:  gap.TechniqueID,
            Title:            "Train ML model for anomaly detection",
            Description:      "ML can detect novel variants of this technique",
        }
        recommendations = append(recommendations, rec)
    }

    // Sort by ROI (highest first)
    sort.Slice(recommendations, func(i, j int) bool {
        return recommendations[i].EstimatedROI > recommendations[j].EstimatedROI
    })

    return recommendations, nil
}
```

**Rule Template Repository**:
```go
type RuleTemplate struct {
    ID               string            `json:"id"`
    Name             string            `json:"name"`
    Description      string            `json:"description"`
    TechniqueID      string            `json:"technique_id"`
    Platform         string            `json:"platform"`
    DataSources      []string          `json:"data_sources"`
    Severity         string            `json:"severity"`
    Confidence       string            `json:"confidence"`
    RuleLogic        string            `json:"rule_logic"` // SIGMA, CQL, or custom format
    Variables        map[string]string `json:"variables"` // Customizable parameters
    TestCases        []TestCase        `json:"test_cases"`
    AuthorInfo       string            `json:"author_info"`
    References       []string          `json:"references"`
}

// Example template for T1055 (Process Injection)
var processInjectionTemplate = &RuleTemplate{
    ID:          "template-t1055",
    Name:        "Process Injection Detection",
    Description: "Detects common process injection techniques including DLL injection, PE injection, and thread hijacking",
    TechniqueID: "T1055",
    Platform:    "Windows",
    DataSources: []string{"Process: Process Creation", "Process: Process Modification"},
    Severity:    "high",
    Confidence:  "high",
    RuleLogic: `
detection:
  selection:
    EventID: 10 # Sysmon Process Access
    GrantedAccess:
      - "0x1F0FFF"
      - "0x1F1FFF"
    TargetImage|endswith:
      - '\explorer.exe'
      - '\svchost.exe'
  condition: selection
`,
    Variables: map[string]string{
        "monitored_processes": "explorer.exe,svchost.exe",
        "suspicious_access_rights": "0x1F0FFF,0x1F1FFF",
    },
}
```

**Acceptance Criteria**:
- [ ] Recommendations generated for each gap
- [ ] Rule templates suggested when available
- [ ] Data source recommendations included
- [ ] Estimated effort provided (hours/days/weeks)
- [ ] Estimated ROI calculated
- [ ] Recommendations sorted by ROI
- [ ] Implementation guides included
- [ ] Test plans provided
- [ ] Recommendations exportable to task list
- [ ] Recommendations trackable (marked complete when implemented)

**Test Requirements**:
```go
// TEST-COV-006: Recommendation generation
func TestRecommendations_Generation(t *testing.T) {
    engine := NewRecommendationEngine(attackStorage, ruleStorage, dataSourceRepo, templateRepo)

    gap := &GapPriority{
        TechniqueID:  "T1055",
        PriorityTier: "Critical",
    }

    // Mock template repository
    templateRepo.AddTemplate(&RuleTemplate{
        ID:          "template-t1055",
        TechniqueID: "T1055",
        Name:        "Process Injection Detection",
    })

    // Generate recommendations
    recommendations, err := engine.GenerateRecommendations(gap)
    require.NoError(t, err)

    // Verify rule template recommendation
    assert.NotEmpty(t, recommendations)
    ruleRec := findRecommendationType(recommendations, "rule")
    require.NotNil(t, ruleRec)
    assert.Equal(t, "T1055", ruleRec.TargetTechnique)
    assert.NotNil(t, ruleRec.RuleTemplate)
}
```

---

### 2.5 Coverage Trending and Forecasting

#### FR-COV-006: Coverage Trend Analysis

**Priority**: P1 (High)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Analytics Team

**Requirement Statement**:
System MUST track coverage metrics over time, calculate trend rates, and forecast future coverage to enable data-driven planning and demonstrate continuous improvement.

**Rationale**:
- Historical trends show whether security posture is improving or degrading
- Forecasting enables goal-setting (e.g., "90% coverage by Q3")
- Trending identifies anomalies (sudden coverage drop may indicate rule deletion)
- Compliance reporting often requires demonstrating continuous improvement

**Specification**:
```go
type CoverageTrend struct {
    MetricName        string    `json:"metric_name"` // "overall_coverage", "tactic_TA0004"
    Datapoints        []CoverageDatapoint `json:"datapoints"`
    TrendDirection    string    `json:"trend_direction"` // "improving", "stable", "declining"
    TrendRate         float64   `json:"trend_rate"` // % change per month
    ConfidenceInterval float64  `json:"confidence_interval"` // Statistical confidence (0-1)

    // Forecasting
    Forecast30d       float64   `json:"forecast_30d"` // Predicted coverage in 30 days
    Forecast90d       float64   `json:"forecast_90d"` // Predicted coverage in 90 days
    ForecastModel     string    `json:"forecast_model"` // "linear", "exponential", "moving_average"
}

type CoverageDatapoint struct {
    Timestamp         time.Time `json:"timestamp"`
    CoveragePercent   float64   `json:"coverage_percent"`
    TotalTechniques   int       `json:"total_techniques"`
    CoveredTechniques int       `json:"covered_techniques"`
    RuleCount         int       `json:"rule_count"`
}

type TrendAnalyzer struct {
    storage CoverageHistoryStorage
}

func (ta *TrendAnalyzer) AnalyzeTrend(metricName string, lookbackDays int) (*CoverageTrend, error) {
    // Fetch historical datapoints
    datapoints, err := ta.storage.GetCoverageHistory(metricName, lookbackDays)
    if err != nil {
        return nil, err
    }

    if len(datapoints) < 2 {
        return nil, fmt.Errorf("insufficient data for trend analysis (need at least 2 datapoints)")
    }

    trend := &CoverageTrend{
        MetricName: metricName,
        Datapoints: datapoints,
    }

    // Calculate trend direction
    firstValue := datapoints[0].CoveragePercent
    lastValue := datapoints[len(datapoints)-1].CoveragePercent
    changePercent := ((lastValue - firstValue) / firstValue) * 100

    if changePercent > 5 {
        trend.TrendDirection = "improving"
    } else if changePercent < -5 {
        trend.TrendDirection = "declining"
    } else {
        trend.TrendDirection = "stable"
    }

    // Calculate trend rate (% change per month)
    durationDays := datapoints[len(datapoints)-1].Timestamp.Sub(datapoints[0].Timestamp).Hours() / 24
    durationMonths := durationDays / 30
    if durationMonths > 0 {
        trend.TrendRate = changePercent / durationMonths
    }

    // Linear regression for forecasting
    trend.Forecast30d = forecastLinear(datapoints, 30)
    trend.Forecast90d = forecastLinear(datapoints, 90)
    trend.ForecastModel = "linear"

    return trend, nil
}

func forecastLinear(datapoints []CoverageDatapoint, forecastDays int) float64 {
    // Simple linear regression
    n := len(datapoints)
    var sumX, sumY, sumXY, sumX2 float64

    for i, dp := range datapoints {
        x := float64(i)
        y := dp.CoveragePercent
        sumX += x
        sumY += y
        sumXY += x * y
        sumX2 += x * x
    }

    // Calculate slope and intercept
    slope := (float64(n)*sumXY - sumX*sumY) / (float64(n)*sumX2 - sumX*sumX)
    intercept := (sumY - slope*sumX) / float64(n)

    // Forecast
    xFuture := float64(n) + (float64(forecastDays) / 7.0) // Assume weekly datapoints
    forecast := slope*xFuture + intercept

    // Clamp to 0-100 range
    if forecast < 0 {
        return 0
    } else if forecast > 100 {
        return 100
    }
    return forecast
}
```

**Coverage History Storage**:
```sql
CREATE TABLE IF NOT EXISTS coverage_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    metric_name TEXT NOT NULL,
    coverage_percent REAL NOT NULL,
    total_techniques INTEGER,
    covered_techniques INTEGER,
    rule_count INTEGER,
    UNIQUE(timestamp, metric_name)
);

CREATE INDEX idx_coverage_history_metric_time ON coverage_history(metric_name, timestamp);
```

**Periodic Coverage Snapshot** (Cronjob):
```go
// Run daily at midnight
func (cs *CoverageSnapshot) CaptureSnapshot() error {
    // Calculate current coverage
    coverage := calculateCurrentCoverage()

    // Store snapshot
    for metricName, value := range coverage {
        datapoint := &CoverageDatapoint{
            Timestamp:         time.Now(),
            CoveragePercent:   value.Percent,
            TotalTechniques:   value.Total,
            CoveredTechniques: value.Covered,
            RuleCount:         value.RuleCount,
        }
        cs.storage.SaveDatapoint(metricName, datapoint)
    }

    return nil
}
```

**Acceptance Criteria**:
- [ ] Coverage snapshots captured daily
- [ ] Coverage history retained for 1 year
- [ ] Trend analysis calculates direction and rate
- [ ] Linear regression forecasting implemented
- [ ] Forecasts for 30, 60, 90 days
- [ ] Trend charts displayed in dashboard
- [ ] Anomaly detection (sudden coverage drops)
- [ ] Alert if coverage regresses >5% in 7 days
- [ ] Trend comparison (this month vs. last month)

**Test Requirements**:
```go
// TEST-COV-007: Trend analysis
func TestTrend_Analysis(t *testing.T) {
    analyzer := NewTrendAnalyzer(coverageHistoryStorage)

    // Mock historical data: improving coverage
    datapoints := []CoverageDatapoint{
        {Timestamp: time.Now().AddDate(0, -3, 0), CoveragePercent: 60.0},
        {Timestamp: time.Now().AddDate(0, -2, 0), CoveragePercent: 65.0},
        {Timestamp: time.Now().AddDate(0, -1, 0), CoveragePercent: 70.0},
        {Timestamp: time.Now(), CoveragePercent: 75.0},
    }
    coverageHistoryStorage.SaveBulk("overall_coverage", datapoints)

    // Analyze trend
    trend, err := analyzer.AnalyzeTrend("overall_coverage", 90)
    require.NoError(t, err)

    // Verify improving trend
    assert.Equal(t, "improving", trend.TrendDirection)
    assert.Greater(t, trend.TrendRate, 0.0)

    // Verify forecast
    assert.Greater(t, trend.Forecast30d, 75.0) // Should forecast higher
    assert.InDelta(t, 80.0, trend.Forecast30d, 5.0) // Approx 80% in 30 days
}
```

---

### 2.6 Benchmark Comparison

#### FR-COV-007: Industry Benchmark Comparison

**Priority**: P2 (Medium)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System SHOULD support comparison of organizational coverage against industry benchmarks and peer organizations to contextualize security posture.

**Rationale**:
- Benchmarks provide context: "Is 75% coverage good or bad?"
- Peer comparison identifies areas where organization lags
- Industry-specific benchmarks account for vertical differences
- Enables data-driven goal-setting

**Specification**:
```go
type IndustryBenchmark struct {
    IndustryVertical  string  `json:"industry_vertical"` // "Finance", "Healthcare", "Technology"
    OrganizationSize  string  `json:"organization_size"` // "Small", "Medium", "Large", "Enterprise"
    BenchmarkSource   string  `json:"benchmark_source"` // "Gartner", "SANS", "MITRE", "Internal"
    LastUpdated       time.Time `json:"last_updated"`

    // Benchmark Data
    AverageCoverage   float64 `json:"average_coverage"` // Industry average
    Percentile25      float64 `json:"percentile_25"` // 25th percentile (low performers)
    Percentile50      float64 `json:"percentile_50"` // Median
    Percentile75      float64 `json:"percentile_75"` // 75th percentile (high performers)
    Percentile90      float64 `json:"percentile_90"` // 90th percentile (best in class)

    // Tactic-Specific Benchmarks
    TacticBenchmarks  map[string]float64 `json:"tactic_benchmarks"` // Per-tactic averages
}

type BenchmarkComparison struct {
    OrganizationCoverage float64           `json:"organization_coverage"`
    Benchmark            *IndustryBenchmark `json:"benchmark"`
    Percentile           float64           `json:"percentile"` // Where org ranks (0-100)
    PerformanceCategory  string            `json:"performance_category"` // "Below Average", "Average", "Above Average", "Best in Class"
    Gap                  float64           `json:"gap"` // Difference from median
    Recommendation       string            `json:"recommendation"`
}

func compareToBenchmark(orgCoverage float64, benchmark *IndustryBenchmark) *BenchmarkComparison {
    comparison := &BenchmarkComparison{
        OrganizationCoverage: orgCoverage,
        Benchmark:            benchmark,
    }

    // Determine percentile
    if orgCoverage >= benchmark.Percentile90 {
        comparison.Percentile = 90
        comparison.PerformanceCategory = "Best in Class"
        comparison.Recommendation = "Maintain current coverage and focus on quality improvement"
    } else if orgCoverage >= benchmark.Percentile75 {
        comparison.Percentile = 75
        comparison.PerformanceCategory = "Above Average"
        comparison.Recommendation = "Good coverage. Consider targeting 90th percentile"
    } else if orgCoverage >= benchmark.Percentile50 {
        comparison.Percentile = 50
        comparison.PerformanceCategory = "Average"
        comparison.Recommendation = "Focus on closing high-priority gaps to reach 75th percentile"
    } else if orgCoverage >= benchmark.Percentile25 {
        comparison.Percentile = 25
        comparison.PerformanceCategory = "Below Average"
        comparison.Recommendation = "CRITICAL: Coverage below industry average. Immediate action required"
    } else {
        comparison.Percentile = 10
        comparison.PerformanceCategory = "Significantly Below Average"
        comparison.Recommendation = "URGENT: Coverage in bottom 25%. Prioritize detection engineering resources"
    }

    comparison.Gap = orgCoverage - benchmark.Percentile50

    return comparison
}
```

**Benchmark Data Sources**:
- **MITRE ATT&CK Evaluations**: Public evaluation results
- **Gartner Research**: Industry survey data
- **SANS Institute**: Threat detection metrics
- **Internal**: Historical organizational data

**Acceptance Criteria**:
- [ ] Benchmark data imported from external sources
- [ ] Benchmark data stored and versioned
- [ ] Comparison to industry vertical
- [ ] Comparison to organization size
- [ ] Percentile ranking calculated
- [ ] Performance category assigned
- [ ] Gap from median displayed
- [ ] Recommendations generated
- [ ] Benchmark comparison dashboard

---

## 3. Non-Functional Requirements

### 3.1 Performance

#### NFR-COV-001: Coverage Calculation Performance

**Priority**: P0 (Critical)
**Requirement**: Multi-dimensional coverage calculation MUST complete within 5 seconds for 1,000 rules and 640 techniques.

**Acceptance Criteria**:
- [ ] Coverage API responds in <5s (p95)
- [ ] Incremental updates when rules change
- [ ] Caching of calculated coverage (5-minute TTL)

---

#### NFR-COV-002: Heatmap Rendering Performance

**Priority**: P1 (High)
**Requirement**: Heatmap MUST render within 2 seconds for full 640-technique matrix.

**Acceptance Criteria**:
- [ ] Heatmap loads in <2s
- [ ] Smooth interactions (hover, click)
- [ ] Responsive on mobile devices

---

### 3.2 Data Retention

#### NFR-COV-003: Coverage History Retention

**Priority**: P1 (High)
**Requirement**: Coverage history MUST be retained for at least 1 year.

**Acceptance Criteria**:
- [ ] Daily snapshots for 1 year
- [ ] Hourly snapshots for last 7 days
- [ ] Automated cleanup of data >1 year old

---

## 4. Data Models

### 4.1 Coverage Schemas

See FR-COV-001 for detailed coverage data models.

---

## 5. API Specification

### 5.1 Coverage APIs

#### GET /api/v1/coverage
Get overall coverage summary.

**Response**: `200 OK`
```json
{
  "overall_coverage": 75.5,
  "overall_grade": "B",
  "total_techniques": 640,
  "covered_techniques": 483,
  "high_quality_coverage": 320,
  "gaps": 157
}
```

---

#### GET /api/v1/coverage/dimensions
Get multi-dimensional coverage breakdown.

**Query Params**:
- `dimension`: "technique", "data_source", "platform", "asset_tier"
- `filter`: Platform, confidence, etc.

**Response**: `200 OK`
```json
{
  "dimension": "platform",
  "breakdown": [
    {
      "platform": "Windows",
      "coverage_percent": 82.3,
      "techniques_covered": 350,
      "techniques_total": 425
    },
    {
      "platform": "Linux",
      "coverage_percent": 65.8,
      "techniques_covered": 131,
      "techniques_total": 199
    }
  ]
}
```

---

#### GET /api/v1/coverage/gaps
Get prioritized coverage gaps.

**Query Params**:
- `priority`: "critical", "high", "medium", "low"
- `limit`: Number of gaps to return (default: 20)

**Response**: `200 OK`
```json
{
  "gaps": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "priority_score": 92.5,
      "priority_tier": "Critical",
      "threat_prevalence": "very_high",
      "recent_campaigns": 5
    }
  ]
}
```

---

#### GET /api/v1/coverage/recommendations
Get detection recommendations for gaps.

**Query Params**:
- `gap_id`: Specific gap to get recommendations for
- `limit`: Number of recommendations

**Response**: `200 OK`
```json
{
  "recommendations": [
    {
      "recommendation_id": "rec-12345",
      "type": "rule",
      "title": "Deploy Process Injection Detection Rule",
      "estimated_effort": "2 hours",
      "estimated_roi": 85.0,
      "rule_template": {...}
    }
  ]
}
```

---

#### GET /api/v1/coverage/trends
Get coverage trends over time.

**Query Params**:
- `metric`: Metric name ("overall_coverage", "tactic_TA0004")
- `lookback_days`: Historical window (30, 60, 90, 365)

**Response**: `200 OK`
```json
{
  "metric_name": "overall_coverage",
  "trend_direction": "improving",
  "trend_rate": 2.5,
  "forecast_30d": 77.8,
  "datapoints": [...]
}
```

---

## 6. UI Requirements

### 6.1 Coverage Dashboard

**Components**:
- Overall coverage gauge (0-100%)
- Coverage grade badge (A+ through F)
- Trend chart (last 90 days)
- Top 10 priority gaps
- Coverage by dimension tabs (MITRE, Data Source, Platform)
- Recommendations widget

---

### 6.2 Gap Analysis Page

**Components**:
- Filterable gap table (priority, technique, platform)
- Gap details modal
- Recommendation panel
- Bulk actions (mark as accepted risk, assign to analyst)

---

## 7. Testing Requirements

### 7.1 Unit Tests

**Coverage Target**: ≥80%

**Critical Test Cases**:
- [ ] Coverage calculation (multi-dimensional)
- [ ] Coverage quality scoring
- [ ] Gap prioritization
- [ ] Trend analysis and forecasting
- [ ] Recommendation generation

---

### 7.2 Integration Tests

**Test Scenarios**:
- [ ] End-to-end: Rule creation → Coverage update → Gap closure
- [ ] Benchmark comparison
- [ ] Trend tracking over time

---

## 8. TBD Tracker

| ID | Description | Owner | Deadline | Priority | Status |
|----|-------------|-------|----------|----------|--------|
| TBD-COV-001 | Coverage quality score weights | Detection Team | Week 2 | P0 | OPEN |
| TBD-COV-002 | Asset tier definitions | Risk Team | Week 2 | P1 | OPEN |
| TBD-COV-003 | Threat intel feed integration | Threat Intel Team | Week 3 | P1 | OPEN |
| TBD-COV-004 | Asset criticality classification | Risk Team | Week 2 | P1 | OPEN |
| TBD-COV-005 | Priority score weight calibration | Detection Team | Week 3 | P1 | OPEN |

---

## 9. Compliance Verification Checklist

### Coverage Analysis
- [ ] Multi-dimensional coverage (MITRE, data source, platform, asset)
- [ ] Coverage quality scoring
- [ ] Coverage grading (A-F)
- [ ] Confidence weighting

### Gaps
- [x] Gap identification
- [ ] Gap prioritization (threat intel, asset criticality)
- [ ] Recommendations generation
- [ ] Rule templates

### Trending
- [ ] Historical tracking (1 year)
- [ ] Trend analysis (direction, rate)
- [ ] Forecasting (30/60/90 days)
- [ ] Anomaly detection

---

## 10. References

### Industry Standards
- MITRE ATT&CK Framework
- NIST Cybersecurity Framework v2.0
- Center for Threat-Informed Defense

### Internal Documents
- `docs/requirements/mitre-attack-requirements.md`
- `docs/requirements/alert-requirements.md`

### Related Code
- `api/mitre_coverage.go`
- `frontend/src/pages/MitreCoverage/`

---

## 11. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-16 | Blueprint Architect | Initial comprehensive coverage analysis requirements |

---

**Document Status**: DRAFT - Pending Security Team Review
**Next Review Date**: 2025-11-23
**Approvers**: Detection Engineering Lead, Security Operations Lead, Architect
**Classification**: INTERNAL

---

**End of Coverage Analysis and Tools Requirements Document**

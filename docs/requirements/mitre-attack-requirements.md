# MITRE ATT&CK Integration Requirements

**Document Owner**: Threat Intelligence Team + Detection Engineering Team
**Created**: 2025-11-16
**Status**: DRAFT - Pending Threat Intel Review
**Last Updated**: 2025-11-16
**Version**: 1.0
**Priority**: P0 (Critical for Threat Context and Coverage Analysis)
**Authoritative Sources**:
- MITRE ATT&CK Framework v14.1 (https://attack.mitre.org/)
- MITRE ATT&CK STIX 2.1 Specification
- ATT&CK Navigator Project (https://mitre-attack.github.io/attack-navigator/)
- "Operationalizing Threat Intelligence" - Mandiant
- Gartner Threat Intelligence Platform Market Guide

---

## 1. Executive Summary

### 1.1 Purpose

This document defines comprehensive requirements for integrating the MITRE ATT&CK® framework into the Cerberus SIEM system. ATT&CK provides a globally-accessible knowledge base of adversary tactics, techniques, and procedures based on real-world observations, enabling threat-informed defense.

**Critical Business Drivers**:
- **Common Threat Language**: Industry-standard vocabulary for describing threats
- **Coverage Gap Analysis**: Identify blind spots in detection capabilities
- **Threat Intelligence Mapping**: Link alerts to adversary behaviors
- **Executive Reporting**: Communicate security posture to stakeholders
- **Regulatory Compliance**: Many frameworks now reference ATT&CK (NIST CSF 2.0, etc.)

### 1.2 Scope

**In Scope**:
- ATT&CK data import and version management (STIX 2.1 format)
- Tactic, technique, sub-technique storage and querying
- Mapping rules and alerts to ATT&CK techniques
- Coverage matrix visualization (heatmaps, navigator layers)
- Gap analysis and prioritization
- Threat group and campaign tracking
- Mitigation recommendations
- Integration with rule creation workflow

**Out of Scope** (Future Enhancements):
- Custom technique creation for organization-specific TTPs - Phase 2
- ATT&CK data source mapping automation - Phase 2
- Automated technique suggestion from ML patterns - Phase 3
- Integration with external threat intel feeds - Phase 2

### 1.3 Current Implementation Analysis

**Existing MITRE Components** (as of 2025-11-16):

| Component | File | Status | Coverage |
|-----------|------|--------|----------|
| ATT&CK Data Types | `mitre/types.go` | ✅ Complete | Comprehensive STIX 2.1 types |
| ATT&CK Loader | `mitre/loader.go` | ✅ Implemented | Parses STIX bundles |
| Coverage API | `api/mitre_coverage.go` | ✅ Implemented | Coverage report and matrix |
| Frontend Coverage | `frontend/src/pages/MitreCoverage/` | ✅ Implemented | Heatmap, gaps, dashboard |
| Frontend Matrix | `frontend/src/pages/MitreMatrix/` | ✅ Implemented | Full matrix visualization |
| Frontend Knowledge Base | `frontend/src/pages/MitreKnowledgeBase/` | ✅ Implemented | Technique browsing |
| Technique Detail | `frontend/src/pages/MitreTechniqueDetail/` | ✅ Implemented | Detailed technique view |

**Implementation Highlights**:

**MITRE Data Structures** (`mitre/types.go`):
```go
type AttackPattern struct { // Techniques
    ID                   string
    Name                 string
    Description          string
    KillChainPhases      []KillChainPhase
    Platforms            []string
    DataSources          []string
    Detection            string
    Mitigations          []string
    XMitreIsSubTechnique bool
}

type Tactic struct {
    ID          string
    Name        string
    ShortName   string
    Description string
}

type IntrusionSet struct { // Threat Groups
    Name    string
    Aliases []string
}

type Relationship struct { // Links techniques to tactics, groups, etc.
    SourceRef string
    TargetRef string
    RelationshipType string
}
```

**Coverage Calculation** (`api/mitre_coverage.go:333-443`):
```go
func (a *API) getMITRECoverage(w http.ResponseWriter, r *http.Request) {
    // Get all enabled rules
    rules, _ := a.ruleStorage.GetAllRules()

    // Build map of covered techniques
    coveredTechniques := make(map[string]int)
    for _, rule := range rules {
        for _, techID := range rule.MitreTechniques {
            coveredTechniques[techID]++
        }
    }

    // Also scan Sigma feed rules
    sigmaRuleCoverage, _, _ := scanSigmaFeedRules("./data/feeds")
    for techID, count := range sigmaRuleCoverage {
        coveredTechniques[techID] += count
    }

    // Calculate coverage by tactic
    for tacticID, tacticData := range mitreTactics {
        tacticCovered := 0
        for _, tech := range tacticData.Techniques {
            if coveredTechniques[tech.ID] > 0 {
                tacticCovered++
            }
        }
        coveragePercent = (tacticCovered / tacticTotal) * 100
    }
}
```

**Current ATT&CK Tactics (Hardcoded)**: 12 tactics with 60 techniques
- Initial Access (TA0001)
- Execution (TA0002)
- Persistence (TA0003)
- Privilege Escalation (TA0004)
- Defense Evasion (TA0005)
- Credential Access (TA0006)
- Discovery (TA0007)
- Lateral Movement (TA0008)
- Collection (TA0009)
- Exfiltration (TA0010)
- Command and Control (TA0011)
- Impact (TA0040)

**Implementation Gaps Identified**:
1. ❌ **No Dynamic ATT&CK Data Import**: Tactics/techniques hardcoded, not loaded from STIX
2. ❌ **No Sub-Technique Support**: Only parent techniques tracked
3. ❌ **No Data Source Mapping**: Detection data sources not linked to techniques
4. ❌ **Limited Mitigation Tracking**: Mitigations not stored or displayed
5. ❌ **No Threat Group Tracking**: Groups/campaigns not integrated with alerts
6. ❌ **No ATT&CK Version Management**: Cannot track ATT&CK framework updates
7. ⚠️ **Sigma Feed Scanning**: Path traversal vulnerability fixed, but inefficient
8. ❌ **No Navigator Layer Export**: Cannot export to ATT&CK Navigator tool

---

## 2. Functional Requirements

### 2.1 ATT&CK Data Import and Management

#### FR-MITRE-001: STIX 2.1 Bundle Import

**Priority**: P0 (Critical)
**Status**: ⚠️ PARTIAL (Loader exists, not integrated)
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System MUST import MITRE ATT&CK framework data from official STIX 2.1 bundles including tactics, techniques, sub-techniques, groups, software, mitigations, and relationships.

**Rationale**:
- ATT&CK framework updates quarterly (4 versions/year)
- Manual updates are error-prone and time-consuming
- STIX 2.1 is the official ATT&CK data format
- Relationships critical for mapping techniques → tactics → groups

**STIX 2.1 Bundle Structure**:
```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {
      "type": "attack-pattern",
      "id": "attack-pattern--<uuid>",
      "name": "Process Injection",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1055",
          "url": "https://attack.mitre.org/techniques/T1055"
        }
      ],
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "privilege-escalation"
        }
      ],
      "x_mitre_is_subtechnique": false,
      "x_mitre_platforms": ["Windows", "Linux", "macOS"],
      "x_mitre_data_sources": ["Process: Process Creation", "Process: Process Modification"],
      "x_mitre_detection": "Detection methods...",
      "x_mitre_version": "2.4"
    },
    {
      "type": "x-mitre-tactic",
      "id": "x-mitre-tactic--<uuid>",
      "name": "Privilege Escalation",
      "x_mitre_shortname": "privilege-escalation",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0004"
        }
      ]
    },
    {
      "type": "relationship",
      "source_ref": "attack-pattern--<uuid>",
      "target_ref": "x-mitre-tactic--<uuid>",
      "relationship_type": "uses"
    }
  ]
}
```

**Official ATT&CK Data Sources**:
- Enterprise: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
- Mobile: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json
- ICS: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json

**Specification**:

**Import Workflow**:
```
1. Download STIX bundle from official source
   - HTTP GET with User-Agent header
   - Verify HTTPS certificate
   - 30-second timeout

2. Validate bundle structure
   - Check JSON schema validity
   - Verify STIX version (2.0 or 2.1)
   - Validate required fields

3. Parse STIX objects by type
   - attack-pattern → Techniques
   - x-mitre-tactic → Tactics
   - intrusion-set → Threat Groups
   - malware, tool → Software
   - course-of-action → Mitigations
   - x-mitre-data-source → Data Sources
   - relationship → Links

4. Build relationship graph
   - Technique → Tactic (kill chain phases)
   - Group → Technique (uses)
   - Technique → Mitigation (mitigates)
   - Technique → Data Source (detects)

5. Store in database (SQLite)
   - Upsert (update if exists, insert if new)
   - Track ATT&CK version and import timestamp
   - Preserve historical versions

6. Update coverage calculations
   - Re-map rules to new technique IDs
   - Flag deprecated techniques
   - Notify if rules reference removed techniques
```

**Current Implementation**: `mitre/loader.go:20-230`
```go
type Loader struct {
    logger *zap.SugaredLogger
}

func (l *Loader) LoadFromFile(filePath string) (*MITREFramework, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    var bundle STIXBundle
    if err := json.Unmarshal(data, &bundle); err != nil {
        return nil, err
    }

    framework := &MITREFramework{}

    // Parse each object in bundle
    for _, rawObj := range bundle.Objects {
        obj, err := ParseSTIXObject(rawObj)
        if err != nil {
            l.logger.Warnf("Failed to parse object: %v", err)
            continue
        }

        // Type switch to categorize objects
        switch v := obj.(type) {
        case AttackPattern:
            framework.Techniques = append(framework.Techniques, v)
        case Tactic:
            framework.Tactics = append(framework.Tactics, v)
        case IntrusionSet:
            framework.Groups = append(framework.Groups, v)
        // ... other types
        }
    }

    return framework, nil
}
```

**Gaps**:
- ✅ STIX parsing implemented
- ❌ Not called from anywhere (orphaned code)
- ❌ No HTTP download capability
- ❌ No database storage
- ❌ No relationship graph building
- ❌ No version tracking
- ❌ No automated updates

**Enhanced Implementation Needed**:
```go
type ATTACKImporter struct {
    storage    ATTACKStorage // Database interface
    httpClient *http.Client
    logger     *zap.SugaredLogger
}

type ATTACKStorage interface {
    // Tactics
    UpsertTactic(tactic *Tactic) error
    GetTacticByID(tacticID string) (*Tactic, error)
    ListTactics(domain string) ([]*Tactic, error)

    // Techniques
    UpsertTechnique(technique *AttackPattern) error
    GetTechniqueByID(techniqueID string) (*AttackPattern, error)
    ListTechniques(filter TechniqueFilter) ([]*AttackPattern, error)
    GetSubTechniques(parentID string) ([]*AttackPattern, error)

    // Groups
    UpsertGroup(group *IntrusionSet) error
    GetGroupByID(groupID string) (*IntrusionSet, error)
    ListGroups() ([]*IntrusionSet, error)

    // Relationships
    UpsertRelationship(rel *Relationship) error
    GetRelationships(sourceRef string) ([]*Relationship, error)

    // Versioning
    GetATTACKVersion() (string, error)
    SetATTACKVersion(version, domain string, timestamp time.Time) error
}

func (ai *ATTACKImporter) ImportFromURL(url string) (*ImportResult, error) {
    // Download bundle
    resp, err := ai.httpClient.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to download ATT&CK data: %w", err)
    }
    defer resp.Body.Close()

    // Parse STIX bundle
    var bundle STIXBundle
    if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
        return nil, fmt.Errorf("failed to parse STIX bundle: %w", err)
    }

    // Import objects
    result := &ImportResult{}
    for _, rawObj := range bundle.Objects {
        obj, err := ParseSTIXObject(rawObj)
        if err != nil {
            ai.logger.Warnf("Failed to parse object: %v", err)
            result.Errors = append(result.Errors, err.Error())
            continue
        }

        switch v := obj.(type) {
        case Tactic:
            if err := ai.storage.UpsertTactic(&v); err != nil {
                result.Errors = append(result.Errors, err.Error())
            } else {
                result.TacticsImported++
            }
        case AttackPattern:
            if err := ai.storage.UpsertTechnique(&v); err != nil {
                result.Errors = append(result.Errors, err.Error())
            } else {
                result.TechniquesImported++
            }
        // ... other types
        }
    }

    // Record import metadata
    ai.storage.SetATTACKVersion(extractVersion(bundle), "enterprise", time.Now())

    return result, nil
}

type ImportResult struct {
    TacticsImported     int
    TechniquesImported  int
    GroupsImported      int
    MitigationsImported int
    RelationshipsImported int
    Errors              []string
    Duration            time.Duration
}
```

**Acceptance Criteria**:
- [ ] STIX 2.1 bundles downloaded from official URLs
- [ ] All STIX object types parsed correctly
- [ ] Techniques, tactics, groups, mitigations stored in database
- [ ] Sub-techniques linked to parent techniques
- [ ] Relationships preserved (technique → tactic, group → technique)
- [ ] ATT&CK version tracked and displayed in UI
- [ ] Import idempotent (can re-run without duplicates)
- [ ] Import errors logged and reported
- [ ] Import completes in <60 seconds for full Enterprise framework
- [ ] Deprecated techniques flagged (revoked field)

**Test Requirements**:
```go
// TEST-MITRE-001: STIX bundle import
func TestATTACKImporter_ImportFromFile(t *testing.T) {
    storage := NewMockATTACKStorage()
    importer := NewATTACKImporter(storage, nil, logger)

    // Import from test STIX file
    result, err := importer.ImportFromFile("testdata/enterprise-attack-sample.json")
    require.NoError(t, err)

    // Verify tactics imported
    assert.Greater(t, result.TacticsImported, 0)
    tactics, _ := storage.ListTactics("enterprise")
    assert.NotEmpty(t, tactics)

    // Verify techniques imported
    assert.Greater(t, result.TechniquesImported, 0)
    techniques, _ := storage.ListTechniques(TechniqueFilter{})
    assert.NotEmpty(t, techniques)

    // Verify sub-techniques linked
    subTechniques, _ := storage.GetSubTechniques("T1055") // Process Injection
    assert.NotEmpty(t, subTechniques)
    for _, sub := range subTechniques {
        assert.True(t, sub.IsSubTechnique())
        assert.Equal(t, "T1055", sub.GetParentTechniqueID())
    }
}

// TEST-MITRE-002: Import idempotency
func TestATTACKImporter_Idempotency(t *testing.T) {
    storage := NewMockATTACKStorage()
    importer := NewATTACKImporter(storage, nil, logger)

    // First import
    result1, _ := importer.ImportFromFile("testdata/enterprise-attack-sample.json")

    // Second import (should update, not duplicate)
    result2, _ := importer.ImportFromFile("testdata/enterprise-attack-sample.json")

    // Verify counts match (no duplicates)
    assert.Equal(t, result1.TechniquesImported, result2.TechniquesImported)

    // Verify database count matches import count
    techniques, _ := storage.ListTechniques(TechniqueFilter{})
    assert.Len(t, techniques, result1.TechniquesImported)
}

// TEST-MITRE-003: Relationship graph construction
func TestATTACKImporter_Relationships(t *testing.T) {
    storage := NewMockATTACKStorage()
    importer := NewATTACKImporter(storage, nil, logger)

    importer.ImportFromFile("testdata/enterprise-attack-sample.json")

    // Verify technique → tactic relationship
    technique, _ := storage.GetTechniqueByID("T1055") // Process Injection
    assert.NotEmpty(t, technique.GetTacticNames())
    assert.Contains(t, technique.GetTacticNames(), "privilege-escalation")

    // Verify group → technique relationship
    relationships, _ := storage.GetRelationships("intrusion-set--<group-uuid>")
    assert.NotEmpty(t, relationships)

    // Verify technique → mitigation relationship
    mitigations := filterRelationshipsByType(relationships, "mitigates")
    assert.NotEmpty(t, mitigations)
}
```

**TBDs**:
- [ ] **TBD-MITRE-001**: Auto-update schedule (weekly? monthly?) (Owner: Threat Intel Team, Deadline: Week 2)
- [ ] **TBD-MITRE-002**: Support multiple ATT&CK domains (Enterprise, Mobile, ICS) (Owner: Threat Intel Team, Deadline: Week 3)
- [ ] **TBD-MITRE-003**: Import strategy for large bundles (>50MB) - streaming parser? (Owner: Dev Team, Deadline: Week 3)

---

#### FR-MITRE-002: ATT&CK Version Management

**Priority**: P0 (Critical)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System MUST track ATT&CK framework versions, detect updates, notify administrators, and support rollback to previous versions.

**Rationale**:
- ATT&CK updates can introduce breaking changes (technique IDs change, deprecations)
- Rules mapped to deprecated techniques need review
- Auditing requires tracking which ATT&CK version was active when
- Rollback needed if new version causes issues

**Specification**:

**Version Metadata**:
```go
type ATTACKVersion struct {
    Domain      string    `json:"domain"` // "enterprise", "mobile", "ics"
    Version     string    `json:"version"` // "14.1"
    ReleaseDate time.Time `json:"release_date"`
    ImportedAt  time.Time `json:"imported_at"`
    ImportedBy  string    `json:"imported_by"`
    IsCurrent   bool      `json:"is_current"`
    SourceURL   string    `json:"source_url"`
    Checksum    string    `json:"checksum"` // SHA256 of bundle
}
```

**Version Detection Workflow**:
```
1. Query GitHub API for latest release
   - URL: https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest
   - Extract version from tag name (e.g., "ATT&CK-v14.1")

2. Compare with current version in database
   - If version differs → new version available

3. Notify administrators
   - Email notification
   - Dashboard banner
   - Webhook to Slack/Teams

4. Optionally auto-import
   - If auto_update enabled in config
   - Run import in background
   - Log results
```

**Rollback Workflow**:
```
1. List available versions
   - Query historical ATTACKVersion records

2. Select target version
   - Administrator chooses version to restore

3. Restore data
   - Load archived STIX bundle for that version
   - Clear current techniques/tactics
   - Re-import archived version
   - Update IsCurrent flag

4. Re-map rules
   - Check all rules for technique references
   - Flag rules with deprecated techniques
   - Suggest alternative techniques
```

**Acceptance Criteria**:
- [ ] ATT&CK version stored in database
- [ ] Version displayed in UI (header or settings page)
- [ ] Update detection checks daily (configurable)
- [ ] Administrators notified of new versions
- [ ] Manual import triggered from UI
- [ ] Historical versions retained (at least 3 previous)
- [ ] Rollback to previous version supported
- [ ] Changelog displayed (what changed between versions)

**Test Requirements**:
```go
// TEST-MITRE-004: Version tracking
func TestATTACKVersion_Tracking(t *testing.T) {
    storage := NewATTACKStorage()

    // Import version 14.0
    importer := NewATTACKImporter(storage, nil, logger)
    importer.ImportFromURL("https://example.com/attack-v14.0.json")

    version140, _ := storage.GetCurrentATTACKVersion("enterprise")
    assert.Equal(t, "14.0", version140.Version)
    assert.True(t, version140.IsCurrent)

    // Import version 14.1
    importer.ImportFromURL("https://example.com/attack-v14.1.json")

    version141, _ := storage.GetCurrentATTACKVersion("enterprise")
    assert.Equal(t, "14.1", version141.Version)
    assert.True(t, version141.IsCurrent)

    // Verify 14.0 still stored but not current
    version140Updated, _ := storage.GetATTACKVersion("enterprise", "14.0")
    assert.NotNil(t, version140Updated)
    assert.False(t, version140Updated.IsCurrent)
}

// TEST-MITRE-005: Version rollback
func TestATTACKVersion_Rollback(t *testing.T) {
    storage := NewATTACKStorage()

    // Import v14.0 and v14.1
    // ... (setup code)

    // Rollback to v14.0
    err := storage.RollbackToVersion("enterprise", "14.0")
    require.NoError(t, err)

    // Verify v14.0 is current
    current, _ := storage.GetCurrentATTACKVersion("enterprise")
    assert.Equal(t, "14.0", current.Version)
    assert.True(t, current.IsCurrent)

    // Verify techniques match v14.0 snapshot
    techniques, _ := storage.ListTechniques(TechniqueFilter{})
    // Compare against known v14.0 technique count
}
```

**TBDs**:
- [ ] **TBD-MITRE-004**: Automatic update policy (auto-import or manual approval?) (Owner: Security Team, Deadline: Week 2)
- [ ] **TBD-MITRE-005**: Version retention policy (keep how many historical versions?) (Owner: Ops Team, Deadline: Week 2)

---

### 2.2 Tactic and Technique Storage

#### FR-MITRE-003: Comprehensive Technique Data Storage

**Priority**: P0 (Critical)
**Status**: ❌ NOT IMPLEMENTED (Hardcoded tactics/techniques)
**Owner**: Development Team

**Requirement Statement**:
System MUST store complete ATT&CK technique data including metadata, platforms, data sources, detection guidance, mitigations, and relationships to tactics, groups, and software.

**Rationale**:
- Hardcoded techniques cannot scale (640+ techniques in Enterprise ATT&CK)
- Rich metadata enables better detection recommendations
- Data source mapping guides log collection priorities
- Detection guidance accelerates rule creation

**Database Schema**:
```sql
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id TEXT PRIMARY KEY, -- Technique ID (T1055)
    stix_id TEXT UNIQUE NOT NULL, -- STIX UUID
    name TEXT NOT NULL,
    description TEXT,
    detection TEXT, -- Detection guidance from ATT&CK
    is_subtechnique BOOLEAN DEFAULT FALSE,
    parent_id TEXT, -- Parent technique ID (for sub-techniques)

    -- Metadata
    version TEXT, -- ATT&CK version
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    deprecated BOOLEAN DEFAULT FALSE,
    revoked BOOLEAN DEFAULT FALSE,

    -- Platforms (JSON array)
    platforms TEXT, -- ["Windows", "Linux", "macOS"]

    -- Data Sources (JSON array)
    data_sources TEXT, -- ["Process: Process Creation", "File: File Modification"]

    -- Defense Bypassed (JSON array)
    defense_bypassed TEXT,

    -- Permissions Required (JSON array)
    permissions_required TEXT,

    -- System Requirements (JSON array)
    system_requirements TEXT,

    -- ATT&CK domain
    domain TEXT DEFAULT 'enterprise', -- "enterprise", "mobile", "ics"

    FOREIGN KEY (parent_id) REFERENCES mitre_techniques(id)
);

CREATE TABLE IF NOT EXISTS mitre_tactics (
    id TEXT PRIMARY KEY, -- Tactic ID (TA0004)
    stix_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    short_name TEXT NOT NULL,
    description TEXT,

    version TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    deprecated BOOLEAN DEFAULT FALSE,

    domain TEXT DEFAULT 'enterprise'
);

CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
    technique_id TEXT NOT NULL,
    tactic_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, tactic_id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
    FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id)
);

CREATE TABLE IF NOT EXISTS mitre_groups (
    id TEXT PRIMARY KEY, -- Group ID (G0016)
    stix_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    aliases TEXT, -- JSON array
    description TEXT,

    version TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    deprecated BOOLEAN DEFAULT FALSE,

    domain TEXT DEFAULT 'enterprise'
);

CREATE TABLE IF NOT EXISTS mitre_group_techniques (
    group_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    description TEXT, -- How group uses this technique
    PRIMARY KEY (group_id, technique_id),
    FOREIGN KEY (group_id) REFERENCES mitre_groups(id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)
);

CREATE TABLE IF NOT EXISTS mitre_mitigations (
    id TEXT PRIMARY KEY, -- Mitigation ID (M1001)
    stix_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,

    version TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,
    deprecated BOOLEAN DEFAULT FALSE,

    domain TEXT DEFAULT 'enterprise'
);

CREATE TABLE IF NOT EXISTS mitre_technique_mitigations (
    technique_id TEXT NOT NULL,
    mitigation_id TEXT NOT NULL,
    description TEXT, -- How mitigation addresses technique
    PRIMARY KEY (technique_id, mitigation_id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
    FOREIGN KEY (mitigation_id) REFERENCES mitre_mitigations(id)
);

CREATE TABLE IF NOT EXISTS mitre_data_sources (
    id TEXT PRIMARY KEY, -- Data source ID
    stix_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    platforms TEXT, -- JSON array
    collection_layers TEXT, -- JSON array

    version TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,

    domain TEXT DEFAULT 'enterprise'
);

CREATE TABLE IF NOT EXISTS mitre_data_components (
    id TEXT PRIMARY KEY,
    stix_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    data_source_id TEXT NOT NULL,

    version TEXT,
    created_at TIMESTAMP,
    modified_at TIMESTAMP,

    FOREIGN KEY (data_source_id) REFERENCES mitre_data_sources(id)
);
```

**Acceptance Criteria**:
- [ ] All 640+ Enterprise techniques stored
- [ ] All 14 tactics stored
- [ ] All 140+ groups stored
- [ ] All 40+ mitigations stored
- [ ] Sub-techniques linked to parents
- [ ] Technique-tactic relationships preserved
- [ ] Group-technique usage stored
- [ ] Mitigation-technique mappings stored
- [ ] Data source-technique mappings stored
- [ ] Deprecated techniques flagged
- [ ] Efficient querying (indexed on common fields)

**Test Requirements**:
```go
// TEST-MITRE-006: Technique storage and retrieval
func TestMITREStorage_Techniques(t *testing.T) {
    storage := NewATTACKStorage()

    technique := &AttackPattern{
        ID:                   "attack-pattern--uuid",
        Name:                 "Process Injection",
        Description:          "Adversaries may inject code...",
        Platforms:            []string{"Windows", "Linux"},
        DataSources:          []string{"Process: Process Creation"},
        Detection:            "Monitor for unusual process...",
        XMitreIsSubTechnique: false,
    }
    technique.ExternalReferences = []ExternalReference{
        {SourceName: "mitre-attack", ExternalID: "T1055"},
    }

    // Store technique
    err := storage.UpsertTechnique(technique)
    require.NoError(t, err)

    // Retrieve technique
    retrieved, err := storage.GetTechniqueByID("T1055")
    require.NoError(t, err)
    assert.Equal(t, "Process Injection", retrieved.Name)
    assert.Contains(t, retrieved.Platforms, "Windows")
    assert.NotEmpty(t, retrieved.Detection)
}

// TEST-MITRE-007: Sub-technique relationships
func TestMITREStorage_SubTechniques(t *testing.T) {
    storage := NewATTACKStorage()

    // Store parent technique
    parent := createTechnique("T1055", "Process Injection", false)
    storage.UpsertTechnique(parent)

    // Store sub-techniques
    sub1 := createTechnique("T1055.001", "Dynamic-link Library Injection", true)
    storage.UpsertTechnique(sub1)

    sub2 := createTechnique("T1055.002", "Portable Executable Injection", true)
    storage.UpsertTechnique(sub2)

    // Retrieve sub-techniques
    subs, err := storage.GetSubTechniques("T1055")
    require.NoError(t, err)
    assert.Len(t, subs, 2)

    for _, sub := range subs {
        assert.True(t, sub.IsSubTechnique())
        assert.Equal(t, "T1055", sub.GetParentTechniqueID())
    }
}
```

---

### 2.3 Detection Mapping

#### FR-MITRE-004: Rule-to-Technique Mapping

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED (Basic)
**Owner**: Detection Engineering Team

**Requirement Statement**:
System MUST support mapping detection rules to one or more MITRE ATT&CK techniques with optional confidence scores and mapping metadata.

**Rationale**:
- Maps detections to adversary behaviors (threat-informed defense)
- Enables coverage gap analysis
- Supports security program metrics (coverage %)
- Required for compliance frameworks

**Current Implementation**:
```go
// core/rule.go
type Rule struct {
    ID               string   `json:"id"`
    Name             string   `json:"name"`
    MitreTechniques  []string `json:"mitre_techniques"` // ["T1055", "T1003"]
    // ... other fields
}
```

**Enhancement Needed**:
```go
type TechniqueMapping struct {
    TechniqueID string  `json:"technique_id"` // T1055.001
    Confidence  string  `json:"confidence"`   // "high", "medium", "low"
    Coverage    string  `json:"coverage"`     // "full", "partial", "context"
    Notes       string  `json:"notes"`        // Analyst notes
    MappedBy    string  `json:"mapped_by"`    // User who created mapping
    MappedAt    time.Time `json:"mapped_at"`
}

type Rule struct {
    ID                  string               `json:"id"`
    Name                string               `json:"name"`
    TechniqueMappings   []*TechniqueMapping  `json:"technique_mappings"`
    // ... other fields
}
```

**Mapping Confidence Levels**:
- **High**: Rule specifically detects this technique (direct evidence)
- **Medium**: Rule may detect this technique (indirect evidence)
- **Low**: Rule provides context related to technique (auxiliary)

**Mapping Coverage Types**:
- **Full**: Rule detects all variants of the technique
- **Partial**: Rule detects some variants (e.g., only Windows, not Linux)
- **Context**: Rule provides contextual information but doesn't directly detect

**Acceptance Criteria**:
- [x] Rules can be tagged with multiple techniques
- [ ] Technique mappings include confidence scores
- [ ] Technique mappings include coverage types
- [ ] Mappings include analyst notes
- [ ] Mappings timestamped and attributed
- [ ] UI supports technique selection (autocomplete)
- [ ] Technique validation (reject invalid technique IDs)
- [ ] Coverage matrix reflects confidence levels (color-coded)

**Test Requirements**:
```go
// TEST-MITRE-008: Technique mapping with metadata
func TestRuleMapping_TechniqueMetadata(t *testing.T) {
    rule := &core.Rule{
        ID:   "rule-001",
        Name: "Process Injection Detection",
        TechniqueMappings: []*TechniqueMapping{
            {
                TechniqueID: "T1055.001",
                Confidence:  "high",
                Coverage:    "full",
                Notes:       "Detects DLL injection via process hollowing",
                MappedBy:    "analyst@example.com",
                MappedAt:    time.Now(),
            },
            {
                TechniqueID: "T1055.002",
                Confidence:  "medium",
                Coverage:    "partial",
                Notes:       "May detect PE injection, Windows only",
                MappedBy:    "analyst@example.com",
                MappedAt:    time.Now(),
            },
        },
    }

    storage := NewRuleStorage()
    err := storage.SaveRule(rule)
    require.NoError(t, err)

    // Retrieve and verify mappings
    retrieved, _ := storage.GetRule("rule-001")
    assert.Len(t, retrieved.TechniqueMappings, 2)

    highConfMapping := retrieved.TechniqueMappings[0]
    assert.Equal(t, "T1055.001", highConfMapping.TechniqueID)
    assert.Equal(t, "high", highConfMapping.Confidence)
    assert.Equal(t, "full", highConfMapping.Coverage)
}
```

---

#### FR-MITRE-005: Alert-to-Technique Tagging

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED (Inherited from rules)
**Owner**: Detection Engineering Team

**Requirement Statement**:
System MUST automatically tag alerts with MITRE ATT&CK techniques from the triggering rule and support manual technique tagging for investigations.

**Rationale**:
- Alerts inherit techniques from rules
- Manual tagging for ML alerts or investigations
- Technique frequency analysis identifies active threats
- Threat hunting based on technique activity

**Specification**:
```go
type Alert struct {
    ID               string               `json:"id"`
    RuleID           string               `json:"rule_id"`
    Timestamp        time.Time            `json:"timestamp"`

    // Inherited from rule
    MitreTechniques  []string             `json:"mitre_techniques"`

    // Manual/analyst-added
    ManualTechniques []*TechniqueTag      `json:"manual_techniques,omitempty"`
}

type TechniqueTag struct {
    TechniqueID string    `json:"technique_id"`
    AddedBy     string    `json:"added_by"`
    AddedAt     time.Time `json:"added_at"`
    Reason      string    `json:"reason"` // Why this technique was tagged
}
```

**Acceptance Criteria**:
- [x] Alerts inherit techniques from triggering rule
- [ ] Analysts can manually add techniques to alerts
- [ ] Manual technique additions logged (audit trail)
- [ ] Alert search/filter by technique ID
- [ ] Technique frequency dashboard (top 10 techniques)
- [ ] Alert timeline by technique (show technique activity over time)

---

### 2.4 Coverage Matrix and Visualization

#### FR-MITRE-006: Coverage Matrix Generation

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED
**Owner**: Threat Intelligence Team + Frontend Team

**Requirement Statement**:
System MUST generate comprehensive coverage matrices showing detection coverage across all ATT&CK tactics and techniques with visual heatmaps, gap identification, and drill-down capabilities.

**Rationale**:
- Visualizes security posture at a glance
- Identifies coverage gaps for remediation
- Executive reporting (board-level metrics)
- Guides detection engineering priorities

**Current Implementation**: `api/mitre_coverage.go`

**Coverage Matrix Structure**:
```json
{
  "tactics": [
    {
      "tactic_id": "TA0004",
      "tactic_name": "Privilege Escalation",
      "techniques": [
        {
          "technique_id": "T1055",
          "technique_name": "Process Injection",
          "is_covered": true,
          "rule_count": 3,
          "rules": [
            {
              "rule_id": "rule-001",
              "rule_name": "Process Injection Detection",
              "rule_severity": "high",
              "source": "mongodb"
            },
            {
              "rule_id": "sigma-proc-injection",
              "rule_name": "Suspicious Process Injection",
              "rule_severity": "medium",
              "source": "sigma_feed"
            }
          ]
        },
        {
          "technique_id": "T1548",
          "technique_name": "Abuse Elevation Control Mechanism",
          "is_covered": false,
          "rule_count": 0,
          "rules": []
        }
      ]
    }
  ]
}
```

**Heatmap Visualization**:
```
Tactic → [Techniques]
Color Scale:
  Red (0 rules)       → No coverage
  Orange (1 rule)     → Minimal coverage
  Yellow (2-3 rules)  → Partial coverage
  Light Green (4-5)   → Good coverage
  Dark Green (6+)     → Excellent coverage
```

**Current Coverage Calculation**:
```go
// api/mitre_coverage.go:378-421
tacticCovered := 0
for _, tech := range tacticData.Techniques {
    ruleCount := coveredTechniques[tech.ID]
    if ruleCount > 0 {
        tacticCovered++
    }
}
coveragePercent = (tacticCovered / tacticTotal) * 100
```

**Acceptance Criteria**:
- [x] Coverage matrix generated for all tactics
- [x] Per-technique rule count displayed
- [x] Coverage percentage calculated per tactic
- [x] Overall coverage percentage calculated
- [x] Gaps identified (uncovered techniques)
- [x] Heatmap visualization in frontend
- [ ] Sub-technique coverage (currently only parent techniques)
- [ ] Confidence-weighted coverage (high confidence = more coverage)
- [ ] Data source coverage analysis
- [ ] Platform-specific coverage (Windows vs. Linux)

**Test Requirements**:
```go
// TEST-MITRE-009: Coverage matrix calculation
func TestCoverageMatrix_Calculation(t *testing.T) {
    ruleStorage := NewMockRuleStorage()

    // Create rules mapped to techniques
    rule1 := &core.Rule{
        ID:              "rule-001",
        MitreTechniques: []string{"T1055", "T1003"},
        Enabled:         true,
    }
    rule2 := &core.Rule{
        ID:              "rule-002",
        MitreTechniques: []string{"T1055"},
        Enabled:         true,
    }
    ruleStorage.SaveRule(rule1)
    ruleStorage.SaveRule(rule2)

    // Generate coverage matrix
    matrix := GenerateCoverageMatrix(ruleStorage)

    // Find Privilege Escalation tactic
    privEscTactic := findTactic(matrix, "TA0004")
    require.NotNil(t, privEscTactic)

    // Verify T1055 covered
    t1055 := findTechnique(privEscTactic, "T1055")
    assert.True(t, t1055.IsCovered)
    assert.Equal(t, 2, t1055.RuleCount) // 2 rules cover this technique
    assert.Len(t, t1055.Rules, 2)

    // Verify T1003 covered
    t1003 := findTechnique(privEscTactic, "T1003")
    assert.True(t, t1003.IsCovered)
    assert.Equal(t, 1, t1003.RuleCount)

    // Calculate coverage percentage
    coveredCount := 0
    totalCount := len(privEscTactic.Techniques)
    for _, tech := range privEscTactic.Techniques {
        if tech.IsCovered {
            coveredCount++
        }
    }
    coveragePercent := (float64(coveredCount) / float64(totalCount)) * 100
    assert.Greater(t, coveragePercent, 0.0)
}
```

---

#### FR-MITRE-007: ATT&CK Navigator Layer Export

**Priority**: P1 (High)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System MUST export coverage data as ATT&CK Navigator layer files for visualization and sharing with external tools.

**Rationale**:
- ATT&CK Navigator is the industry-standard visualization tool
- Enables sharing coverage with partners, auditors
- Supports comparison with other organizations' coverage
- Integration with threat intelligence platforms

**ATT&CK Navigator Layer Format** (JSON):
```json
{
  "name": "Cerberus SIEM Detection Coverage",
  "versions": {
    "attack": "14",
    "navigator": "4.9",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "Detection coverage as of 2025-01-16",
  "techniques": [
    {
      "techniqueID": "T1055",
      "tactic": "privilege-escalation",
      "score": 3,
      "color": "#00ff00",
      "comment": "3 rules provide coverage",
      "enabled": true,
      "metadata": [
        {"name": "Rules", "value": "rule-001, rule-002, rule-003"}
      ]
    },
    {
      "techniqueID": "T1548",
      "tactic": "privilege-escalation",
      "score": 0,
      "color": "#ff0000",
      "comment": "No coverage",
      "enabled": true
    }
  ],
  "gradient": {
    "colors": ["#ff0000", "#ffff00", "#00ff00"],
    "minValue": 0,
    "maxValue": 10
  }
}
```

**Export API**:
```go
type NavigatorLayerExporter struct {
    ruleStorage RuleStorage
    attackStorage ATTACKStorage
}

func (nle *NavigatorLayerExporter) ExportCoverageLayer() (*NavigatorLayer, error) {
    // Get all techniques
    techniques, err := nle.attackStorage.ListTechniques(TechniqueFilter{})
    if err != nil {
        return nil, err
    }

    // Get rule coverage
    rules, err := nle.ruleStorage.GetAllRules()
    if err != nil {
        return nil, err
    }

    // Build coverage map
    coverage := make(map[string]int) // techniqueID -> rule count
    for _, rule := range rules {
        if !rule.Enabled {
            continue
        }
        for _, techID := range rule.MitreTechniques {
            coverage[techID]++
        }
    }

    // Build layer
    layer := &NavigatorLayer{
        Name:        "Cerberus Detection Coverage",
        Description: fmt.Sprintf("Generated on %s", time.Now().Format(time.RFC3339)),
        Domain:      "enterprise-attack",
        Version:     "4.5",
        Techniques:  []NavigatorLayerTechnique{},
    }

    for _, tech := range techniques {
        techID := tech.GetTechniqueID()
        ruleCount := coverage[techID]

        layer.Techniques = append(layer.Techniques, NavigatorLayerTechnique{
            TechniqueID: techID,
            Score:       ruleCount,
            Color:       getColorForScore(ruleCount),
            Comment:     fmt.Sprintf("%d rules", ruleCount),
        })
    }

    return layer, nil
}

func getColorForScore(score int) string {
    if score == 0 {
        return "#ff0000" // Red - no coverage
    } else if score <= 2 {
        return "#ff9900" // Orange - minimal
    } else if score <= 5 {
        return "#ffff00" // Yellow - partial
    } else {
        return "#00ff00" // Green - good
    }
}
```

**Acceptance Criteria**:
- [ ] Export coverage as Navigator layer JSON
- [ ] Layer compatible with ATT&CK Navigator v4.x
- [ ] Score based on rule count
- [ ] Color-coded by coverage level
- [ ] Comments include rule names
- [ ] Export API endpoint: `GET /api/v1/mitre/navigator/layer`
- [ ] Download as `.json` file from UI
- [ ] Support for multiple layer types (coverage, threat group activity)

**Test Requirements**:
```go
// TEST-MITRE-010: Navigator layer export
func TestNavigatorLayer_Export(t *testing.T) {
    exporter := NewNavigatorLayerExporter(ruleStorage, attackStorage)

    layer, err := exporter.ExportCoverageLayer()
    require.NoError(t, err)

    // Verify layer structure
    assert.Equal(t, "enterprise-attack", layer.Domain)
    assert.NotEmpty(t, layer.Techniques)

    // Verify technique with coverage
    t1055 := findTechniqueInLayer(layer, "T1055")
    require.NotNil(t, t1055)
    assert.Greater(t, t1055.Score, 0)
    assert.NotEmpty(t, t1055.Color)
    assert.Contains(t, t1055.Comment, "rules")

    // Verify technique without coverage
    uncovered := findUncoveredTechnique(layer)
    require.NotNil(t, uncovered)
    assert.Equal(t, 0, uncovered.Score)
    assert.Equal(t, "#ff0000", uncovered.Color)
}
```

---

### 2.5 Gap Analysis

#### FR-MITRE-008: Coverage Gap Identification

**Priority**: P0 (Critical)
**Status**: ✅ IMPLEMENTED (Basic)
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System MUST identify and report uncovered ATT&CK techniques (gaps) with prioritization based on threat prevalence, asset criticality, and attack likelihood.

**Rationale**:
- Limited resources require prioritized gap closure
- Not all gaps are equally important
- Threat intelligence informs which techniques are actively used
- Asset criticality determines business impact

**Current Implementation**: `api/mitre_coverage.go:396-402`
```go
// Build gap list
for _, tech := range tacticData.Techniques {
    ruleCount := coveredTechniques[tech.ID]
    if ruleCount == 0 {
        allGaps = append(allGaps, CoverageGap{
            TechniqueID:   tech.ID,
            TechniqueName: tech.Name,
            Tactics:       []string{tacticData.Name},
        })
    }
}
```

**Enhanced Gap Analysis**:
```go
type CoverageGap struct {
    TechniqueID       string   `json:"technique_id"`
    TechniqueName     string   `json:"technique_name"`
    Tactics           []string `json:"tactics"`
    Platforms         []string `json:"platforms"`

    // Prioritization Factors
    PriorityScore     float64  `json:"priority_score"` // 0-100
    ThreatPrevalence  string   `json:"threat_prevalence"` // "high", "medium", "low"
    AttackLikelihood  string   `json:"attack_likelihood"` // "high", "medium", "low"
    BusinessImpact    string   `json:"business_impact"` // "critical", "high", "medium", "low"

    // Threat Intelligence
    ObservedInWild    bool     `json:"observed_in_wild"` // Active in threat landscape
    UsedByGroups      []string `json:"used_by_groups"` // APT28, FIN7, etc.
    RecentCampaigns   int      `json:"recent_campaigns"` // Count of recent campaigns using this

    // Remediation
    DetectionDifficulty string `json:"detection_difficulty"` // "hard", "medium", "easy"
    RecommendedDataSources []string `json:"recommended_data_sources"`
    SuggestedRules      []string `json:"suggested_rules"` // Rule templates
}

type GapPrioritizer struct {
    attackStorage     ATTACKStorage
    threatIntelFeed   ThreatIntelFeed // External threat intelligence
    assetInventory    AssetInventory  // Organization's assets
}

func (gp *GapPrioritizer) PrioritizeGaps(gaps []*CoverageGap) ([]*CoverageGap, error) {
    for _, gap := range gaps {
        // Fetch technique details
        technique, _ := gp.attackStorage.GetTechniqueByID(gap.TechniqueID)

        // Factor 1: Threat Prevalence (from threat intel)
        prevalence := gp.threatIntelFeed.GetTechniquePrevalence(gap.TechniqueID)
        gap.ThreatPrevalence = prevalence
        prevalenceScore := prevalenceToScore(prevalence) // high=30, medium=20, low=10

        // Factor 2: Attack Likelihood (based on groups using technique)
        groups := gp.attackStorage.GetGroupsUsingTechnique(gap.TechniqueID)
        gap.UsedByGroups = groups
        groupScore := min(len(groups)*5, 30) // Max 30 points

        // Factor 3: Business Impact (from asset inventory)
        impact := gp.assetInventory.GetImpactForPlatforms(technique.Platforms)
        gap.BusinessImpact = impact
        impactScore := impactToScore(impact) // critical=40, high=30, medium=20, low=10

        // Calculate priority score
        gap.PriorityScore = prevalenceScore + groupScore + impactScore
    }

    // Sort by priority score (descending)
    sort.Slice(gaps, func(i, j int) bool {
        return gaps[i].PriorityScore > gaps[j].PriorityScore
    })

    return gaps, nil
}
```

**Acceptance Criteria**:
- [x] All uncovered techniques identified
- [ ] Gaps prioritized by threat prevalence
- [ ] Gaps prioritized by business impact
- [ ] Gaps include threat group usage
- [ ] Gaps include recommended data sources
- [ ] Gaps include detection difficulty rating
- [ ] Top 10 priority gaps highlighted in dashboard
- [ ] Gap closure tracked over time (trending)

**Test Requirements**:
```go
// TEST-MITRE-011: Gap prioritization
func TestGapAnalysis_Prioritization(t *testing.T) {
    prioritizer := NewGapPrioritizer(attackStorage, threatIntel, assetInventory)

    gaps := []*CoverageGap{
        {TechniqueID: "T1055", TechniqueName: "Process Injection"},
        {TechniqueID: "T1548", TechniqueName: "Abuse Elevation Control"},
        {TechniqueID: "T1082", TechniqueName: "System Information Discovery"},
    }

    // Mock threat intel: T1055 is high prevalence
    threatIntel.SetPrevalence("T1055", "high")
    threatIntel.SetPrevalence("T1548", "low")

    // Mock groups: T1055 used by 5 groups, T1548 by 1 group
    attackStorage.SetGroupsUsingTechnique("T1055", []string{"APT28", "FIN7", "LAZARUS"})
    attackStorage.SetGroupsUsingTechnique("T1548", []string{"APT32"})

    // Prioritize gaps
    prioritized, err := prioritizer.PrioritizeGaps(gaps)
    require.NoError(t, err)

    // Verify T1055 is highest priority (high prevalence + multiple groups)
    assert.Equal(t, "T1055", prioritized[0].TechniqueID)
    assert.Greater(t, prioritized[0].PriorityScore, 50.0)
    assert.Equal(t, "high", prioritized[0].ThreatPrevalence)

    // Verify T1548 is lower priority
    assert.Equal(t, "T1548", prioritized[len(prioritized)-1].TechniqueID)
    assert.Less(t, prioritized[len(prioritized)-1].PriorityScore, 30.0)
}
```

**TBDs**:
- [ ] **TBD-MITRE-006**: Threat intel feed integration (MISP, STIX/TAXII?) (Owner: Threat Intel Team, Deadline: Week 4)
- [ ] **TBD-MITRE-007**: Priority score weighting factors (Owner: Security Team, Deadline: Week 3)

---

### 2.6 Threat Group and Campaign Tracking

#### FR-MITRE-009: Threat Group Activity Mapping

**Priority**: P1 (High)
**Status**: ❌ NOT IMPLEMENTED
**Owner**: Threat Intelligence Team

**Requirement Statement**:
System MUST track threat group (APT, cybercrime) activity by mapping alerts to threat groups based on technique usage patterns and support campaign identification.

**Rationale**:
- Attribution helps prioritize response (state-sponsored vs. commodity malware)
- Campaign tracking identifies coordinated attacks
- Threat group TTPs guide defensive improvements
- Executive reporting (are we being targeted by APT groups?)

**Specification**:

**Threat Group Matching**:
```go
type ThreatGroupMatcher struct {
    attackStorage ATTACKStorage
    alertStorage  AlertStorage
}

func (tgm *ThreatGroupMatcher) MatchAlertsToGroups(alert *Alert) ([]*GroupMatch, error) {
    // Get techniques from alert
    techniques := alert.MitreTechniques

    // Find groups using these techniques
    matches := []*GroupMatch{}
    for _, techID := range techniques {
        groups := tgm.attackStorage.GetGroupsUsingTechnique(techID)
        for _, group := range groups {
            // Calculate match score
            matchScore := tgm.calculateGroupMatchScore(alert, group)
            if matchScore > 0.5 { // Threshold
                matches = append(matches, &GroupMatch{
                    GroupID:         group.GetGroupID(),
                    GroupName:       group.Name,
                    MatchScore:      matchScore,
                    MatchedTechniques: techniques,
                })
            }
        }
    }

    return matches, nil
}

type GroupMatch struct {
    GroupID           string   `json:"group_id"`
    GroupName         string   `json:"group_name"`
    MatchScore        float64  `json:"match_score"` // 0-1
    MatchedTechniques []string `json:"matched_techniques"`
    Confidence        string   `json:"confidence"` // "high", "medium", "low"
}
```

**Campaign Detection**:
```go
type CampaignDetector struct {
    alertStorage AlertStorage
}

func (cd *CampaignDetector) DetectCampaigns(timeWindow time.Duration) ([]*Campaign, error) {
    // Group alerts by similarity within time window
    // Similarity factors:
    // - Same threat group matches
    // - Same technique patterns
    // - Same source IP ranges
    // - Same target assets

    campaigns := []*Campaign{}

    // Cluster alerts
    clusters := cd.clusterAlerts(timeWindow)

    for _, cluster := range clusters {
        if len(cluster.Alerts) >= 5 { // Min alerts to constitute campaign
            campaign := &Campaign{
                ID:            generateCampaignID(),
                Name:          fmt.Sprintf("Campaign %s", cluster.StartTime.Format("2006-01-02")),
                StartTime:     cluster.StartTime,
                EndTime:       cluster.EndTime,
                AlertCount:    len(cluster.Alerts),
                Techniques:    cluster.UniqueTechniques,
                SuspectedGroups: cluster.SuspectedGroups,
                Confidence:    cluster.ConfidenceScore,
            }
            campaigns = append(campaigns, campaign)
        }
    }

    return campaigns, nil
}

type Campaign struct {
    ID              string    `json:"id"`
    Name            string    `json:"name"`
    StartTime       time.Time `json:"start_time"`
    EndTime         time.Time `json:"end_time"`
    AlertCount      int       `json:"alert_count"`
    Techniques      []string  `json:"techniques"`
    SuspectedGroups []string  `json:"suspected_groups"`
    Confidence      float64   `json:"confidence"`
    Status          string    `json:"status"` // "active", "contained", "resolved"
}
```

**Acceptance Criteria**:
- [ ] Alerts matched to threat groups based on technique usage
- [ ] Match score calculated from technique overlap
- [ ] Campaign detection identifies coordinated attacks
- [ ] Campaigns tracked over time
- [ ] Dashboard displays suspected threat group activity
- [ ] Analyst can confirm/reject group attribution
- [ ] Group activity trends visualized

**Test Requirements**:
```go
// TEST-MITRE-012: Threat group matching
func TestThreatGroup_Matching(t *testing.T) {
    matcher := NewThreatGroupMatcher(attackStorage, alertStorage)

    // Create alert with techniques used by APT28
    alert := &Alert{
        MitreTechniques: []string{"T1055", "T1003", "T1087"},
    }

    // APT28 known to use these techniques
    attackStorage.SetGroupTechniques("G0007", []string{"T1055", "T1003", "T1087", "T1069"})

    // Match alert to groups
    matches, err := matcher.MatchAlertsToGroups(alert)
    require.NoError(t, err)

    // Verify APT28 matched
    apt28Match := findGroupMatch(matches, "G0007")
    require.NotNil(t, apt28Match)
    assert.Greater(t, apt28Match.MatchScore, 0.7) // High match score
    assert.Len(t, apt28Match.MatchedTechniques, 3)
}
```

---

## 3. Non-Functional Requirements

### 3.1 Performance

#### NFR-MITRE-001: Coverage Calculation Performance

**Priority**: P1 (High)
**Requirement**: Coverage matrix calculation MUST complete within 2 seconds for 1,000 rules and 640 techniques.

**Rationale**: Coverage dashboard should load quickly for analysts.

**Optimization Strategies**:
1. Cache coverage calculations (refresh every 5 minutes)
2. Pre-compute coverage on rule save (incremental updates)
3. Index technique mappings for fast lookup

**Acceptance Criteria**:
- [ ] Coverage API responds in <2s (p95)
- [ ] Coverage matrix supports 1,000+ rules
- [ ] Incremental updates when rules added/modified

---

#### NFR-MITRE-002: ATT&CK Data Import Performance

**Priority**: P1 (High)
**Requirement**: Full ATT&CK framework import MUST complete within 60 seconds.

**Acceptance Criteria**:
- [ ] Enterprise ATT&CK import <60s
- [ ] 640+ techniques imported
- [ ] Relationship graph built
- [ ] Database indexed for fast queries

---

### 3.2 Data Freshness

#### NFR-MITRE-003: ATT&CK Version Updates

**Priority**: P1 (High)
**Requirement**: System MUST detect new ATT&CK versions within 24 hours of release.

**Acceptance Criteria**:
- [ ] Version check runs daily
- [ ] Administrators notified of new versions
- [ ] Auto-update configurable (off by default)

---

### 3.3 Accuracy

#### NFR-MITRE-004: Technique Mapping Validation

**Priority**: P0 (Critical)
**Requirement**: System MUST reject invalid technique IDs and warn about deprecated techniques.

**Acceptance Criteria**:
- [ ] Invalid technique IDs rejected on rule save
- [ ] Deprecated techniques flagged with warning
- [ ] Technique autocomplete shows only valid techniques

---

## 4. Data Models

### 4.1 ATT&CK Entity Schemas

See Section 2.2 (FR-MITRE-003) for complete database schemas.

---

## 5. API Specification

### 5.1 ATT&CK Data Management APIs

#### GET /api/v1/mitre/tactics
List all tactics.

**Response**: `200 OK`
```json
{
  "tactics": [
    {
      "id": "TA0004",
      "name": "Privilege Escalation",
      "short_name": "privilege-escalation",
      "description": "The adversary is trying to gain higher-level permissions."
    }
  ]
}
```

---

#### GET /api/v1/mitre/techniques
List all techniques with optional filtering.

**Query Params**:
- `tactic`: Filter by tactic ID (TA0004)
- `platform`: Filter by platform (Windows, Linux, macOS)
- `search`: Search by name/description
- `subtechniques`: Include sub-techniques (true/false)

**Response**: `200 OK`
```json
{
  "techniques": [
    {
      "id": "T1055",
      "name": "Process Injection",
      "description": "Adversaries may inject code...",
      "platforms": ["Windows", "Linux"],
      "tactics": ["privilege-escalation", "defense-evasion"],
      "data_sources": ["Process: Process Creation"],
      "detection": "Monitor for unusual process behavior...",
      "subtechniques": [
        {"id": "T1055.001", "name": "Dynamic-link Library Injection"},
        {"id": "T1055.002", "name": "Portable Executable Injection"}
      ]
    }
  ]
}
```

---

#### GET /api/v1/mitre/techniques/{id}
Get technique details.

**Response**: `200 OK`
```json
{
  "id": "T1055",
  "name": "Process Injection",
  "description": "Full description...",
  "tactics": ["privilege-escalation", "defense-evasion"],
  "platforms": ["Windows", "Linux", "macOS"],
  "data_sources": ["Process: Process Creation", "Process: Process Modification"],
  "detection": "Monitor for unusual process behavior...",
  "mitigations": [
    {"id": "M1040", "name": "Behavior Prevention on Endpoint"}
  ],
  "groups": [
    {"id": "G0007", "name": "APT28"}
  ],
  "subtechniques": [
    {"id": "T1055.001", "name": "Dynamic-link Library Injection"}
  ],
  "rules_covering": [
    {"rule_id": "rule-001", "rule_name": "Process Injection Detection"}
  ]
}
```

---

#### GET /api/v1/mitre/coverage
Get coverage report.

**Response**: `200 OK` (See current implementation for structure)

---

#### GET /api/v1/mitre/coverage/matrix
Get coverage matrix.

**Response**: `200 OK` (See current implementation for structure)

---

#### GET /api/v1/mitre/navigator/layer
Export coverage as ATT&CK Navigator layer.

**Response**: `200 OK`
```json
{
  "name": "Cerberus Detection Coverage",
  "domain": "enterprise-attack",
  "techniques": [...]
}
```

---

#### POST /api/v1/mitre/import
Trigger ATT&CK data import.

**Request**:
```json
{
  "source_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
  "domain": "enterprise"
}
```

**Response**: `202 Accepted`
```json
{
  "import_id": "import-12345",
  "status": "in_progress"
}
```

---

#### GET /api/v1/mitre/import/{id}/status
Check import status.

**Response**: `200 OK`
```json
{
  "import_id": "import-12345",
  "status": "completed",
  "techniques_imported": 640,
  "tactics_imported": 14,
  "duration_seconds": 45
}
```

---

## 6. UI Requirements

### 6.1 Coverage Dashboard

**Status**: ✅ IMPLEMENTED (`frontend/src/pages/MitreCoverage/`)

**Components**:
- Coverage overview (total %, covered techniques, gaps)
- Tactic breakdown (per-tactic coverage bars)
- Coverage heatmap (color-coded matrix)
- Gap analysis table (prioritized gaps)

**Enhancements Needed**:
- [ ] Sub-technique drill-down
- [ ] Confidence-weighted coverage
- [ ] Trend charts (coverage over time)

---

### 6.2 Technique Detail Page

**Status**: ✅ IMPLEMENTED (`frontend/src/pages/MitreTechniqueDetail/`)

**Displays**:
- Technique description
- Associated tactics
- Detection rules covering technique
- Mitigations
- Threat groups using technique
- Data sources
- External links to MITRE ATT&CK site

---

### 6.3 ATT&CK Matrix Visualization

**Status**: ✅ IMPLEMENTED (`frontend/src/pages/MitreMatrix/`)

**Displays**:
- Full 14-tactic × techniques matrix
- Color-coded by coverage
- Click technique → detail page

---

## 7. Testing Requirements

### 7.1 Unit Tests

**Coverage Target**: ≥80% for MITRE components

**Critical Test Cases**:
- [x] STIX bundle parsing
- [ ] Technique storage and retrieval
- [ ] Coverage calculation
- [ ] Gap identification
- [ ] Navigator layer export
- [ ] Threat group matching

---

### 7.2 Integration Tests

**Test Scenarios**:
- [ ] End-to-end: Import STIX → Store → Generate Coverage → Display in UI
- [ ] Rule mapping → Coverage update
- [ ] Version update → Re-mapping

---

## 8. TBD Tracker

| ID | Description | Owner | Deadline | Priority | Status |
|----|-------------|-------|----------|----------|--------|
| TBD-MITRE-001 | Auto-update schedule | Threat Intel Team | Week 2 | P1 | OPEN |
| TBD-MITRE-002 | Support Mobile/ICS ATT&CK | Threat Intel Team | Week 3 | P2 | OPEN |
| TBD-MITRE-003 | Large bundle import optimization | Dev Team | Week 3 | P1 | OPEN |
| TBD-MITRE-004 | Automatic update policy | Security Team | Week 2 | P0 | OPEN |
| TBD-MITRE-005 | Version retention policy | Ops Team | Week 2 | P1 | OPEN |
| TBD-MITRE-006 | Threat intel feed integration | Threat Intel Team | Week 4 | P2 | OPEN |
| TBD-MITRE-007 | Priority score weighting | Security Team | Week 3 | P1 | OPEN |

---

## 9. Compliance Verification Checklist

### Data Import
- [ ] STIX 2.1 bundle import
- [ ] Tactics, techniques, groups, mitigations stored
- [ ] Sub-techniques supported
- [ ] Relationships preserved
- [ ] Version tracking
- [ ] Automated updates

### Coverage Analysis
- [x] Coverage matrix generated
- [x] Per-tactic coverage calculated
- [x] Gap identification
- [ ] Gap prioritization
- [ ] Navigator layer export
- [x] Heatmap visualization

### Threat Intelligence
- [ ] Threat group activity tracking
- [ ] Campaign detection
- [ ] Alert-to-group matching
- [ ] Group technique usage

---

## 10. References

### MITRE Resources
- MITRE ATT&CK: https://attack.mitre.org/
- ATT&CK STIX Data: https://github.com/mitre-attack/attack-stix-data
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

### Internal Documents
- `docs/requirements/alert-requirements.md`
- `docs/requirements/correlation-rule-requirements.md`

### Related Code
- `mitre/types.go`: ATT&CK data types
- `mitre/loader.go`: STIX bundle loader
- `api/mitre_coverage.go`: Coverage API
- `frontend/src/pages/MitreCoverage/`: Coverage UI

---

## 11. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-16 | Blueprint Architect | Initial comprehensive MITRE ATT&CK requirements |

---

**Document Status**: DRAFT - Pending Threat Intelligence Team Review
**Next Review Date**: 2025-11-23
**Approvers**: Threat Intel Lead, Detection Engineering Lead, Architect
**Classification**: INTERNAL

---

**End of MITRE ATT&CK Integration Requirements Document**

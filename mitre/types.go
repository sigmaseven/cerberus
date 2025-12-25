package mitre

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// STIXBundle represents the top-level STIX 2.1 bundle
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"` // Will be parsed based on type field
}

// ExternalReference represents a reference to an external source
type ExternalReference struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id,omitempty"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// KillChainPhase represents a phase in the MITRE ATT&CK kill chain
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"` // This is the tactic name
}

// AttackPattern represents a MITRE ATT&CK technique or sub-technique
type AttackPattern struct {
	Type                 string              `json:"type"`
	SpecVersion          string              `json:"spec_version"`
	ID                   string              `json:"id"`
	Created              time.Time           `json:"created"`
	Modified             time.Time           `json:"modified"`
	Name                 string              `json:"name"`
	Description          string              `json:"description"`
	ExternalReferences   []ExternalReference `json:"external_references"`
	KillChainPhases      []KillChainPhase    `json:"kill_chain_phases"`
	Revoked              bool                `json:"revoked,omitempty"`
	Deprecated           bool                `json:"x_mitre_deprecated,omitempty"`
	XMitreIsSubTechnique bool                `json:"x_mitre_is_subtechnique,omitempty"`
	Platforms            []string            `json:"x_mitre_platforms,omitempty"`
	Domains              []string            `json:"x_mitre_domains,omitempty"`
	Version              string              `json:"x_mitre_version,omitempty"`
	Detection            string              `json:"x_mitre_detection,omitempty"`
	DataSources          []string            `json:"x_mitre_data_sources,omitempty"`
	DefenseBypassed      []string            `json:"x_mitre_defense_bypassed,omitempty"`
	PermissionsRequired  []string            `json:"x_mitre_permissions_required,omitempty"`
	RemoteSupport        bool                `json:"x_mitre_remote_support,omitempty"`
	SystemRequirements   []string            `json:"x_mitre_system_requirements,omitempty"`
	ImpactType           []string            `json:"x_mitre_impact_type,omitempty"`
	EffectivePermissions []string            `json:"x_mitre_effective_permissions,omitempty"`
}

// Tactic represents a MITRE ATT&CK tactic
type Tactic struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	ExternalReferences []ExternalReference `json:"external_references"`
	ShortName          string              `json:"x_mitre_shortname"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
	Deprecated         bool                `json:"x_mitre_deprecated,omitempty"`
}

// IntrusionSet represents a MITRE ATT&CK group (threat actor)
type IntrusionSet struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Aliases            []string            `json:"aliases,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Revoked            bool                `json:"revoked,omitempty"`
	Deprecated         bool                `json:"x_mitre_deprecated,omitempty"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// Malware represents malware used by threat actors
type Malware struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	IsFamily           bool                `json:"is_family"`
	Aliases            []string            `json:"x_mitre_aliases,omitempty"`
	Platforms          []string            `json:"x_mitre_platforms,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Revoked            bool                `json:"revoked,omitempty"`
	Deprecated         bool                `json:"x_mitre_deprecated,omitempty"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// Tool represents tools used by threat actors
type Tool struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Aliases            []string            `json:"x_mitre_aliases,omitempty"`
	Platforms          []string            `json:"x_mitre_platforms,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Revoked            bool                `json:"revoked,omitempty"`
	Deprecated         bool                `json:"x_mitre_deprecated,omitempty"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// CourseOfAction represents a MITRE ATT&CK mitigation
type CourseOfAction struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Deprecated         bool                `json:"x_mitre_deprecated,omitempty"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// DataSource represents a MITRE ATT&CK data source
type DataSource struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Platforms          []string            `json:"x_mitre_platforms,omitempty"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
	CollectionLayers   []string            `json:"x_mitre_collection_layers,omitempty"`
}

// DataComponent represents a component of a data source
type DataComponent struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	ExternalReferences []ExternalReference `json:"external_references"`
	DataSourceRef      string              `json:"x_mitre_data_source_ref"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// Campaign represents a MITRE ATT&CK campaign
type Campaign struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	FirstSeen          time.Time           `json:"first_seen,omitempty"`
	LastSeen           time.Time           `json:"last_seen,omitempty"`
	Aliases            []string            `json:"aliases,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references"`
	Domains            []string            `json:"x_mitre_domains,omitempty"`
	Version            string              `json:"x_mitre_version,omitempty"`
}

// Relationship represents a relationship between two STIX objects
type Relationship struct {
	Type             string    `json:"type"`
	SpecVersion      string    `json:"spec_version"`
	ID               string    `json:"id"`
	Created          time.Time `json:"created"`
	Modified         time.Time `json:"modified"`
	RelationshipType string    `json:"relationship_type"`
	SourceRef        string    `json:"source_ref"`
	TargetRef        string    `json:"target_ref"`
	Description      string    `json:"description,omitempty"`
}

// MITREFramework represents the complete MITRE ATT&CK framework
type MITREFramework struct {
	Techniques     []AttackPattern
	Tactics        []Tactic
	Groups         []IntrusionSet
	Malware        []Malware
	Tools          []Tool
	Mitigations    []CourseOfAction
	DataSources    []DataSource
	DataComponents []DataComponent
	Campaigns      []Campaign
	Relationships  []Relationship
}

// GetTechniqueID extracts the technique ID (e.g., "T1055.011") from external references
func (ap *AttackPattern) GetTechniqueID() string {
	for _, ref := range ap.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetTacticID extracts the tactic ID (e.g., "TA0006") from external references
func (t *Tactic) GetTacticID() string {
	for _, ref := range t.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetGroupID extracts the group ID (e.g., "G0001") from external references
func (is *IntrusionSet) GetGroupID() string {
	for _, ref := range is.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetSoftwareID extracts the software ID (e.g., "S0001") from external references
func (m *Malware) GetSoftwareID() string {
	for _, ref := range m.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetSoftwareID extracts the software ID (e.g., "S0001") from external references
func (t *Tool) GetSoftwareID() string {
	for _, ref := range t.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetMitigationID extracts the mitigation ID (e.g., "M1001") from external references
func (coa *CourseOfAction) GetMitigationID() string {
	for _, ref := range coa.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// GetTacticNames extracts all tactic names from kill chain phases
func (ap *AttackPattern) GetTacticNames() []string {
	tactics := make([]string, 0)
	for _, kc := range ap.KillChainPhases {
		if kc.KillChainName == "mitre-attack" {
			tactics = append(tactics, kc.PhaseName)
		}
	}
	return tactics
}

// IsSubTechnique checks if this is a sub-technique (e.g., T1055.011)
func (ap *AttackPattern) IsSubTechnique() bool {
	return ap.XMitreIsSubTechnique || strings.Contains(ap.GetTechniqueID(), ".")
}

// GetParentTechniqueID returns the parent technique ID for sub-techniques
func (ap *AttackPattern) GetParentTechniqueID() string {
	techID := ap.GetTechniqueID()
	if strings.Contains(techID, ".") {
		parts := strings.Split(techID, ".")
		return parts[0]
	}
	return ""
}

// Validate validates an AttackPattern
func (ap *AttackPattern) Validate() error {
	if ap.ID == "" {
		return fmt.Errorf("attack pattern missing ID")
	}
	if ap.Name == "" {
		return fmt.Errorf("attack pattern %s missing name", ap.ID)
	}
	if ap.GetTechniqueID() == "" {
		return fmt.Errorf("attack pattern %s missing technique ID in external references", ap.ID)
	}
	return nil
}

// Validate validates a Tactic
func (t *Tactic) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("tactic missing ID")
	}
	if t.Name == "" {
		return fmt.Errorf("tactic %s missing name", t.ID)
	}
	if t.ShortName == "" {
		return fmt.Errorf("tactic %s missing short name", t.ID)
	}
	if t.GetTacticID() == "" {
		return fmt.Errorf("tactic %s missing tactic ID in external references", t.ID)
	}
	return nil
}

// ParseSTIXObject parses a raw JSON object into the appropriate type
func ParseSTIXObject(rawObj map[string]interface{}) (interface{}, error) {
	objType, ok := rawObj["type"].(string)
	if !ok {
		return nil, fmt.Errorf("object missing type field")
	}

	// Marshal back to JSON to unmarshal into specific type
	data, err := json.Marshal(rawObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}

	switch objType {
	case "attack-pattern":
		var ap AttackPattern
		if err := json.Unmarshal(data, &ap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attack pattern: %w", err)
		}
		return ap, nil

	case "x-mitre-tactic":
		var tactic Tactic
		if err := json.Unmarshal(data, &tactic); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tactic: %w", err)
		}
		return tactic, nil

	case "intrusion-set":
		var is IntrusionSet
		if err := json.Unmarshal(data, &is); err != nil {
			return nil, fmt.Errorf("failed to unmarshal intrusion set: %w", err)
		}
		return is, nil

	case "malware":
		var m Malware
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("failed to unmarshal malware: %w", err)
		}
		return m, nil

	case "tool":
		var t Tool
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tool: %w", err)
		}
		return t, nil

	case "course-of-action":
		var coa CourseOfAction
		if err := json.Unmarshal(data, &coa); err != nil {
			return nil, fmt.Errorf("failed to unmarshal course of action: %w", err)
		}
		return coa, nil

	case "x-mitre-data-source":
		var ds DataSource
		if err := json.Unmarshal(data, &ds); err != nil {
			return nil, fmt.Errorf("failed to unmarshal data source: %w", err)
		}
		return ds, nil

	case "x-mitre-data-component":
		var dc DataComponent
		if err := json.Unmarshal(data, &dc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal data component: %w", err)
		}
		return dc, nil

	case "campaign":
		var c Campaign
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("failed to unmarshal campaign: %w", err)
		}
		return c, nil

	case "relationship":
		var r Relationship
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal relationship: %w", err)
		}
		return r, nil

	default:
		// Ignore unsupported types (x-mitre-collection, identity, marking-definition, etc.)
		return nil, nil
	}
}

// Technique is an alias for AttackPattern for storage layer consistency
type Technique = AttackPattern

// TacticCoverage represents coverage statistics for a tactic
type TacticCoverage struct {
	TacticID      string `json:"tactic_id" bson:"tactic_id"`
	TacticName    string `json:"tactic_name" bson:"tactic_name"`
	TotalRules    int    `json:"total_rules" bson:"total_rules"`
	TotalAlerts   int    `json:"total_alerts" bson:"total_alerts"`
	LastAlertTime string `json:"last_alert_time,omitempty" bson:"last_alert_time,omitempty"`
}

// TechniqueCoverage represents coverage statistics for a technique
type TechniqueCoverage struct {
	TechniqueID   string `json:"technique_id" bson:"technique_id"`
	TechniqueName string `json:"technique_name" bson:"technique_name"`
	TotalRules    int    `json:"total_rules" bson:"total_rules"`
	TotalAlerts   int    `json:"total_alerts" bson:"total_alerts"`
	LastAlertTime string `json:"last_alert_time,omitempty" bson:"last_alert_time,omitempty"`
}

// NavigatorLayer represents a MITRE ATT&CK Navigator layer for visualization
type NavigatorLayer struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Domain      string                    `json:"domain"`
	Version     string                    `json:"version"`
	Techniques  []NavigatorLayerTechnique `json:"techniques"`
}

// NavigatorLayerTechnique represents a technique in a Navigator layer
type NavigatorLayerTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// GetTacticColor returns a color for a given tactic name for UI consistency
func GetTacticColor(tacticName string) string {
	colors := map[string]string{
		"reconnaissance":       "#8B4789",
		"resource-development": "#6B5B93",
		"initial-access":       "#5F7A8B",
		"execution":            "#4F8A8B",
		"persistence":          "#458B74",
		"privilege-escalation": "#8B7355",
		"defense-evasion":      "#8B5A3C",
		"credential-access":    "#8B4726",
		"discovery":            "#8B6914",
		"lateral-movement":     "#6E8B3D",
		"collection":           "#548B54",
		"command-and-control":  "#2F8B87",
		"exfiltration":         "#36648B",
		"impact":               "#5D478B",
	}
	color, ok := colors[strings.ToLower(tacticName)]
	if !ok {
		return "#888888"
	}
	return color
}

// GetTacticName returns a human-readable name from a short name
func GetTacticName(shortName string) string {
	names := map[string]string{
		"reconnaissance":       "Reconnaissance",
		"resource-development": "Resource Development",
		"initial-access":       "Initial Access",
		"execution":            "Execution",
		"persistence":          "Persistence",
		"privilege-escalation": "Privilege Escalation",
		"defense-evasion":      "Defense Evasion",
		"credential-access":    "Credential Access",
		"discovery":            "Discovery",
		"lateral-movement":     "Lateral Movement",
		"collection":           "Collection",
		"command-and-control":  "Command and Control",
		"exfiltration":         "Exfiltration",
		"impact":               "Impact",
	}
	name, ok := names[strings.ToLower(shortName)]
	if !ok {
		return shortName
	}
	return name
}

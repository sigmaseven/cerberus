package mitre

import (
	"encoding/json"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// LoadFramework loads the MITRE ATT&CK framework from a STIX JSON file
func LoadFramework(filename string, logger *zap.SugaredLogger) (*MITREFramework, error) {
	logger.Infof("Loading MITRE ATT&CK framework from %s", filename)

	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read MITRE framework file: %w", err)
	}

	// Parse the bundle structure first to get raw objects
	var rawBundle struct {
		Type    string                   `json:"type"`
		ID      string                   `json:"id"`
		Objects []map[string]interface{} `json:"objects"`
	}

	if err := json.Unmarshal(data, &rawBundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal STIX bundle: %w", err)
	}

	if rawBundle.Type != "bundle" {
		return nil, fmt.Errorf("expected STIX bundle, got type: %s", rawBundle.Type)
	}

	logger.Infof("Parsing %d STIX objects from bundle %s", len(rawBundle.Objects), rawBundle.ID)

	// Initialize framework
	framework := &MITREFramework{
		Techniques:     make([]AttackPattern, 0),
		Tactics:        make([]Tactic, 0),
		Groups:         make([]IntrusionSet, 0),
		Malware:        make([]Malware, 0),
		Tools:          make([]Tool, 0),
		Mitigations:    make([]CourseOfAction, 0),
		DataSources:    make([]DataSource, 0),
		DataComponents: make([]DataComponent, 0),
		Campaigns:      make([]Campaign, 0),
		Relationships:  make([]Relationship, 0),
	}

	// Parse each object
	stats := make(map[string]int)
	var parseErrors []error

	for i, rawObj := range rawBundle.Objects {
		objType, ok := rawObj["type"].(string)
		if !ok {
			parseErrors = append(parseErrors, fmt.Errorf("object %d missing type field", i))
			continue
		}

		stats[objType]++

		parsedObj, err := ParseSTIXObject(rawObj)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("object %d (type %s): %w", i, objType, err))
			continue
		}

		// Skip nil results (unsupported types)
		if parsedObj == nil {
			continue
		}

		// Add to appropriate collection
		switch obj := parsedObj.(type) {
		case AttackPattern:
			// Skip revoked or deprecated techniques
			if !obj.Revoked && !obj.Deprecated {
				framework.Techniques = append(framework.Techniques, obj)
			}
		case Tactic:
			if !obj.Deprecated {
				framework.Tactics = append(framework.Tactics, obj)
			}
		case IntrusionSet:
			if !obj.Revoked && !obj.Deprecated {
				framework.Groups = append(framework.Groups, obj)
			}
		case Malware:
			if !obj.Revoked && !obj.Deprecated {
				framework.Malware = append(framework.Malware, obj)
			}
		case Tool:
			if !obj.Revoked && !obj.Deprecated {
				framework.Tools = append(framework.Tools, obj)
			}
		case CourseOfAction:
			if !obj.Deprecated {
				framework.Mitigations = append(framework.Mitigations, obj)
			}
		case DataSource:
			framework.DataSources = append(framework.DataSources, obj)
		case DataComponent:
			framework.DataComponents = append(framework.DataComponents, obj)
		case Campaign:
			framework.Campaigns = append(framework.Campaigns, obj)
		case Relationship:
			framework.Relationships = append(framework.Relationships, obj)
		}
	}

	// Log statistics
	logger.Infof("MITRE ATT&CK framework loaded successfully:")
	logger.Infof("  - Techniques: %d (attack-pattern)", len(framework.Techniques))
	logger.Infof("  - Tactics: %d (x-mitre-tactic)", len(framework.Tactics))
	logger.Infof("  - Groups: %d (intrusion-set)", len(framework.Groups))
	logger.Infof("  - Malware: %d", len(framework.Malware))
	logger.Infof("  - Tools: %d", len(framework.Tools))
	logger.Infof("  - Mitigations: %d (course-of-action)", len(framework.Mitigations))
	logger.Infof("  - Data Sources: %d (x-mitre-data-source)", len(framework.DataSources))
	logger.Infof("  - Data Components: %d (x-mitre-data-component)", len(framework.DataComponents))
	logger.Infof("  - Campaigns: %d", len(framework.Campaigns))
	logger.Infof("  - Relationships: %d", len(framework.Relationships))

	// Log parse statistics
	logger.Infof("Object type counts:")
	for objType, count := range stats {
		logger.Infof("  - %s: %d", objType, count)
	}

	if len(parseErrors) > 0 {
		logger.Warnf("Encountered %d parse errors (objects may be skipped)", len(parseErrors))
		// Log first few errors
		for i, err := range parseErrors {
			if i >= 5 {
				logger.Warnf("  ... and %d more errors", len(parseErrors)-5)
				break
			}
			logger.Warnf("  - %v", err)
		}
	}

	return framework, nil
}

// GetTechniqueByID finds a technique by its ID (e.g., "T1055.011")
func (f *MITREFramework) GetTechniqueByID(techniqueID string) *AttackPattern {
	for i := range f.Techniques {
		if f.Techniques[i].GetTechniqueID() == techniqueID {
			return &f.Techniques[i]
		}
	}
	return nil
}

// GetTacticByShortName finds a tactic by its short name (e.g., "credential-access")
func (f *MITREFramework) GetTacticByShortName(shortName string) *Tactic {
	for i := range f.Tactics {
		if f.Tactics[i].ShortName == shortName {
			return &f.Tactics[i]
		}
	}
	return nil
}

// GetTacticByID finds a tactic by its ID (e.g., "TA0006")
func (f *MITREFramework) GetTacticByID(tacticID string) *Tactic {
	for i := range f.Tactics {
		if f.Tactics[i].GetTacticID() == tacticID {
			return &f.Tactics[i]
		}
	}
	return nil
}

// GetTechniquesByTactic returns all techniques for a given tactic (by tactic short name)
func (f *MITREFramework) GetTechniquesByTactic(tacticShortName string) []AttackPattern {
	techniques := make([]AttackPattern, 0)
	for _, tech := range f.Techniques {
		for _, tacticName := range tech.GetTacticNames() {
			if tacticName == tacticShortName {
				techniques = append(techniques, tech)
				break
			}
		}
	}
	return techniques
}

// GetGroupByID finds a group by its ID (e.g., "G0001")
func (f *MITREFramework) GetGroupByID(groupID string) *IntrusionSet {
	for i := range f.Groups {
		if f.Groups[i].GetGroupID() == groupID {
			return &f.Groups[i]
		}
	}
	return nil
}

// GetMitigationByID finds a mitigation by its ID (e.g., "M1001")
func (f *MITREFramework) GetMitigationByID(mitigationID string) *CourseOfAction {
	for i := range f.Mitigations {
		if f.Mitigations[i].GetMitigationID() == mitigationID {
			return &f.Mitigations[i]
		}
	}
	return nil
}

// GetRelationships returns all relationships of a specific type
func (f *MITREFramework) GetRelationships(relType string) []Relationship {
	rels := make([]Relationship, 0)
	for _, rel := range f.Relationships {
		if rel.RelationshipType == relType {
			rels = append(rels, rel)
		}
	}
	return rels
}

// GetRelationshipsForSource returns all relationships where source_ref matches
func (f *MITREFramework) GetRelationshipsForSource(sourceRef string) []Relationship {
	rels := make([]Relationship, 0)
	for _, rel := range f.Relationships {
		if rel.SourceRef == sourceRef {
			rels = append(rels, rel)
		}
	}
	return rels
}

// GetRelationshipsForTarget returns all relationships where target_ref matches
func (f *MITREFramework) GetRelationshipsForTarget(targetRef string) []Relationship {
	rels := make([]Relationship, 0)
	for _, rel := range f.Relationships {
		if rel.TargetRef == targetRef {
			rels = append(rels, rel)
		}
	}
	return rels
}

// GetMitigationsForTechnique returns all mitigations for a given technique
func (f *MITREFramework) GetMitigationsForTechnique(techniqueID string) []CourseOfAction {
	tech := f.GetTechniqueByID(techniqueID)
	if tech == nil {
		return nil
	}

	mitigations := make([]CourseOfAction, 0)

	// Find "mitigates" relationships where target is this technique
	for _, rel := range f.Relationships {
		if rel.RelationshipType == "mitigates" && rel.TargetRef == tech.ID {
			// Find the mitigation
			for _, mit := range f.Mitigations {
				if mit.ID == rel.SourceRef {
					mitigations = append(mitigations, mit)
					break
				}
			}
		}
	}

	return mitigations
}

// GetTechniquesUsedByGroup returns all techniques used by a given group
func (f *MITREFramework) GetTechniquesUsedByGroup(groupID string) []AttackPattern {
	group := f.GetGroupByID(groupID)
	if group == nil {
		return nil
	}

	techniques := make([]AttackPattern, 0)

	// Find "uses" relationships where source is this group
	for _, rel := range f.Relationships {
		if rel.RelationshipType == "uses" && rel.SourceRef == group.ID {
			// Find the technique
			for _, tech := range f.Techniques {
				if tech.ID == rel.TargetRef {
					techniques = append(techniques, tech)
					break
				}
			}
		}
	}

	return techniques
}

// GetGroupsUsingTechnique returns all groups that use a given technique
func (f *MITREFramework) GetGroupsUsingTechnique(techniqueID string) []IntrusionSet {
	tech := f.GetTechniqueByID(techniqueID)
	if tech == nil {
		return nil
	}

	groups := make([]IntrusionSet, 0)

	// Find "uses" relationships where target is this technique
	for _, rel := range f.Relationships {
		if rel.RelationshipType == "uses" && rel.TargetRef == tech.ID {
			// Find the group
			for _, grp := range f.Groups {
				if grp.ID == rel.SourceRef {
					groups = append(groups, grp)
					break
				}
			}
		}
	}

	return groups
}

// GetSubTechniques returns all sub-techniques for a parent technique
func (f *MITREFramework) GetSubTechniques(parentTechniqueID string) []AttackPattern {
	subTechs := make([]AttackPattern, 0)
	for _, tech := range f.Techniques {
		if tech.IsSubTechnique() && tech.GetParentTechniqueID() == parentTechniqueID {
			subTechs = append(subTechs, tech)
		}
	}
	return subTechs
}

// GetTechniquesByPlatform returns all techniques for a given platform (e.g., "Windows", "Linux")
func (f *MITREFramework) GetTechniquesByPlatform(platform string) []AttackPattern {
	techniques := make([]AttackPattern, 0)
	for _, tech := range f.Techniques {
		for _, p := range tech.Platforms {
			if p == platform {
				techniques = append(techniques, tech)
				break
			}
		}
	}
	return techniques
}

// GetStatistics returns framework statistics
func (f *MITREFramework) GetStatistics() map[string]interface{} {
	// Count sub-techniques
	subTechCount := 0
	for _, tech := range f.Techniques {
		if tech.IsSubTechnique() {
			subTechCount++
		}
	}

	// Count techniques by platform
	platformCounts := make(map[string]int)
	for _, tech := range f.Techniques {
		for _, platform := range tech.Platforms {
			platformCounts[platform]++
		}
	}

	// Count techniques by tactic
	tacticCounts := make(map[string]int)
	for _, tech := range f.Techniques {
		for _, tactic := range tech.GetTacticNames() {
			tacticCounts[tactic]++
		}
	}

	return map[string]interface{}{
		"total_techniques":       len(f.Techniques),
		"sub_techniques":         subTechCount,
		"parent_techniques":      len(f.Techniques) - subTechCount,
		"tactics":                len(f.Tactics),
		"groups":                 len(f.Groups),
		"malware":                len(f.Malware),
		"tools":                  len(f.Tools),
		"software":               len(f.Malware) + len(f.Tools),
		"mitigations":            len(f.Mitigations),
		"data_sources":           len(f.DataSources),
		"data_components":        len(f.DataComponents),
		"campaigns":              len(f.Campaigns),
		"relationships":          len(f.Relationships),
		"techniques_by_tactic":   tacticCounts,
		"techniques_by_platform": platformCounts,
	}
}

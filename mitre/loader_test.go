package mitre

import (
	"testing"

	"go.uber.org/zap"
)

func TestLoadFramework(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	// Test loading the framework
	framework, err := LoadFramework("../mitre_data/enterprise-attack.json", sugar)
	if err != nil {
		t.Fatalf("Failed to load framework: %v", err)
	}

	// Verify we loaded data
	if len(framework.Techniques) == 0 {
		t.Error("No techniques loaded")
	}

	if len(framework.Tactics) == 0 {
		t.Error("No tactics loaded")
	}

	// Log statistics
	stats := framework.GetStatistics()
	t.Logf("Framework statistics: %+v", stats)

	// Test getting a specific technique
	tech := framework.GetTechniqueByID("T1055")
	if tech != nil {
		t.Logf("Found technique T1055: %s", tech.Name)
		t.Logf("  Description: %s", tech.Description[:100]+"...")
		t.Logf("  Platforms: %v", tech.Platforms)
		t.Logf("  Tactics: %v", tech.GetTacticNames())
		t.Logf("  Is sub-technique: %v", tech.IsSubTechnique())
	} else {
		t.Error("Failed to find technique T1055")
	}

	// Test getting tactics
	tactic := framework.GetTacticByShortName("credential-access")
	if tactic != nil {
		t.Logf("Found tactic 'credential-access': %s (%s)", tactic.Name, tactic.GetTacticID())
		t.Logf("  Description: %s", tactic.Description[:100]+"...")
	} else {
		t.Error("Failed to find tactic 'credential-access'")
	}

	// Test getting techniques by tactic
	credAccessTechs := framework.GetTechniquesByTactic("credential-access")
	t.Logf("Found %d techniques for 'credential-access' tactic", len(credAccessTechs))

	// Test sub-techniques
	if tech := framework.GetTechniqueByID("T1055"); tech != nil {
		subTechs := framework.GetSubTechniques("T1055")
		t.Logf("Found %d sub-techniques for T1055", len(subTechs))
		if len(subTechs) > 0 {
			t.Logf("  Example: %s (%s)", subTechs[0].Name, subTechs[0].GetTechniqueID())
		}
	}

	// Test platform filtering
	windowsTechs := framework.GetTechniquesByPlatform("Windows")
	t.Logf("Found %d techniques for Windows platform", len(windowsTechs))

	// Test groups
	if len(framework.Groups) > 0 {
		group := &framework.Groups[0]
		t.Logf("Example group: %s (%s)", group.Name, group.GetGroupID())
		techsUsed := framework.GetTechniquesUsedByGroup(group.GetGroupID())
		t.Logf("  Uses %d techniques", len(techsUsed))
	}

	// Test mitigations
	if tech := framework.GetTechniqueByID("T1055"); tech != nil {
		mitigations := framework.GetMitigationsForTechnique("T1055")
		t.Logf("Found %d mitigations for T1055", len(mitigations))
	}

	// Validate minimum expected counts (based on MITRE ATT&CK v18)
	if len(framework.Techniques) < 200 {
		t.Errorf("Expected at least 200 techniques, got %d", len(framework.Techniques))
	}

	if len(framework.Tactics) < 10 {
		t.Errorf("Expected at least 10 tactics, got %d", len(framework.Tactics))
	}

	if len(framework.Groups) < 100 {
		t.Errorf("Expected at least 100 groups, got %d", len(framework.Groups))
	}

	t.Logf("Framework loaded successfully with %d techniques, %d tactics, %d groups",
		len(framework.Techniques), len(framework.Tactics), len(framework.Groups))
}

func TestAttackPatternHelpers(t *testing.T) {
	// Test technique ID extraction
	ap := AttackPattern{
		ExternalReferences: []ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "T1055.011"},
		},
	}

	if ap.GetTechniqueID() != "T1055.011" {
		t.Errorf("Expected T1055.011, got %s", ap.GetTechniqueID())
	}

	if !ap.IsSubTechnique() {
		t.Error("Expected T1055.011 to be identified as sub-technique")
	}

	if ap.GetParentTechniqueID() != "T1055" {
		t.Errorf("Expected parent T1055, got %s", ap.GetParentTechniqueID())
	}

	// Test tactic extraction
	ap.KillChainPhases = []KillChainPhase{
		{KillChainName: "mitre-attack", PhaseName: "defense-evasion"},
		{KillChainName: "mitre-attack", PhaseName: "privilege-escalation"},
	}

	tactics := ap.GetTacticNames()
	if len(tactics) != 2 {
		t.Errorf("Expected 2 tactics, got %d", len(tactics))
	}

	if tactics[0] != "defense-evasion" || tactics[1] != "privilege-escalation" {
		t.Errorf("Unexpected tactics: %v", tactics)
	}
}

func TestTacticHelpers(t *testing.T) {
	tactic := Tactic{
		ShortName: "credential-access",
		ExternalReferences: []ExternalReference{
			{SourceName: "mitre-attack", ExternalID: "TA0006"},
		},
	}

	if tactic.GetTacticID() != "TA0006" {
		t.Errorf("Expected TA0006, got %s", tactic.GetTacticID())
	}
}

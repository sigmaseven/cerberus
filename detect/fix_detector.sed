# Replace all Conditions patterns with SIGMA YAML format
/ID:.*testinghelpers\.TestRuleID,/{
    N
    N
    s/ID:.*testinghelpers\.TestRuleID,\n\t\t\tEnabled: true,\n\t\t\tConditions: \[\]core\.Condition{\n\t\t\t\t{\n\t\t\t\t\tField:    "event_type",\n\t\t\t\t\tOperator: "equals",\n\t\t\t\t\tValue:    testinghelpers\.TestEventType,\n\t\t\t\t},\n\t\t\t},/ID:      testinghelpers.TestRuleID,\n\t\t\tType:    "sigma",\n\t\t\tEnabled: true,\n\t\t\tSigmaYAML: `\ntitle: Test Rule\ndetection:\n  selection:\n    event_type: user_login\n  condition: selection\n`,/
}

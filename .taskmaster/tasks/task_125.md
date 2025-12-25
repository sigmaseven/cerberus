# Task ID: 125

**Title:** Implement SIGMA YAML security validator with YAML bomb and ReDoS protection

**Status:** done

**Dependencies:** 123 ✓

**Priority:** high

**Description:** Create comprehensive SIGMA YAML validation with security checks for depth limits, anchor/alias limits, size limits, and regex complexity analysis to prevent DoS attacks

**Details:**

Create core/sigma_validator.go:

1. ValidateSigmaYAML function:
   - Size limit: 1MB max (prevent memory exhaustion)
   - Parse YAML with gopkg.in/yaml.v3
   - Depth check: max 50 levels (checkYAMLDepth recursive)
   - Anchor/alias count: max 10 (countAnchorsAliases)
   - Required fields: title, detection
   - Detection must have 'condition' field
   - Level validation (informational/low/medium/high/critical)

2. validateDetectionRegexPatterns:
   - Walk detection blocks recursively
   - Find fields with |re modifier
   - Call validateSingleRegex for each pattern

3. validateSingleRegex:
   - Use detect.AnalyzeRegexComplexity (existing function)
   - Reject patterns with RiskLevel > safe threshold
   - Return descriptive error with pattern and issue

4. Helper functions:
   - checkYAMLDepth: Recursive depth counter
   - countAnchorsAliases: Count & and * characters

5. Import AnalyzeRegexComplexity from detect/regex_complexity.go

See Phase 2.2 in PRD for security implementation details (BLOCKER #7 fix).

**Test Strategy:**

1. Security tests:
   - YAML bomb (deeply nested structure)
   - Large YAML (>1MB)
   - Many anchors/aliases (>10)
   - ReDoS-vulnerable regex patterns

2. Valid SIGMA tests:
   - Minimal valid rule (title + detection)
   - Complex rule with all optional fields
   - Multiple detection blocks
   - Valid regex patterns

3. Invalid YAML tests:
   - Missing required fields
   - Invalid level/status values
   - Missing detection.condition
   - Malformed YAML syntax

4. Regex complexity tests:
   - Safe patterns (simple literals)
   - Unsafe patterns (catastrophic backtracking)
   - Borderline patterns (moderate complexity)

## Subtasks

### 125.1. Implement ValidateSigmaYAML function with size limit, YAML parsing, and required field validation

**Status:** pending  
**Dependencies:** None  

Create core/sigma_validator.go with ValidateSigmaYAML function that enforces 1MB size limit, parses YAML using gopkg.in/yaml.v3, and validates required fields (title, detection with condition field) and level enumeration

**Details:**

Create core/sigma_validator.go file. Implement ValidateSigmaYAML(yamlContent []byte) error function. First check: enforce 1MB (1048576 bytes) size limit to prevent memory exhaustion, return error if exceeded. Use gopkg.in/yaml.v3 to parse YAML into map[string]interface{}. Validate required fields exist: 'title' (non-empty string) and 'detection' (map containing 'condition' field). If 'level' field exists, validate it's one of: informational, low, medium, high, critical. Return descriptive errors for each validation failure. This function is the main entry point for SIGMA YAML security validation.

### 125.2. Implement checkYAMLDepth recursive function to detect deeply nested structures

**Status:** pending  
**Dependencies:** 125.1  

Create recursive checkYAMLDepth helper function that traverses YAML node tree and enforces maximum depth limit of 50 levels to prevent YAML bomb attacks via excessive nesting

**Details:**

In core/sigma_validator.go, implement checkYAMLDepth(node *yaml.Node, currentDepth int, maxDepth int) error. Use yaml.v3's Node API to access raw YAML structure. Recursively traverse node.Content slice. Track currentDepth parameter, increment for each level. When currentDepth exceeds maxDepth (50), return error with depth information. Handle all yaml.Node.Kind types: DocumentNode, MappingNode, SequenceNode, ScalarNode, AliasNode. For MappingNode and SequenceNode, recursively check all children in node.Content. Call this function from ValidateSigmaYAML after initial YAML parsing but before field validation. This prevents stack overflow from malicious deeply nested YAML.

### 125.3. Implement countAnchorsAliases function to prevent anchor/alias bombs

**Status:** pending  
**Dependencies:** 125.1  

Create countAnchorsAliases helper function that counts YAML anchors and aliases in the parsed YAML structure and enforces maximum limit of 10 to prevent billion laughs attacks

**Details:**

In core/sigma_validator.go, implement countAnchorsAliases(node *yaml.Node) (int, error). Recursively traverse yaml.Node tree using node.Content. Count anchors: increment when node.Anchor != empty string. Count aliases: increment when node.Kind == yaml.AliasNode. Track total count across entire YAML document. Return error if total count exceeds 10 (maxAnchorsAliases constant). Call this function from ValidateSigmaYAML after YAML parsing and depth check. YAML anchors (&) and aliases (*) allow reference reuse but can be exploited for exponential expansion attacks. This limit prevents both billion laughs and memory exhaustion while allowing legitimate YAML reuse patterns.

### 125.4. Implement validateDetectionRegexPatterns function to walk detection blocks and find regex modifiers

**Status:** pending  
**Dependencies:** 125.1  

Create validateDetectionRegexPatterns function that recursively walks the detection section of SIGMA YAML, identifies fields with |re modifier, extracts regex patterns, and prepares them for security analysis

**Details:**

In core/sigma_validator.go, implement validateDetectionRegexPatterns(detection map[string]interface{}) error. Recursively walk detection map structure. Detection contains named selection blocks (e.g., 'selection', 'filter') and a 'condition' field. Each selection block is map[string]interface{} with field names as keys. Values can be: string, []interface{} (list), or map with modifiers. Identify regex patterns: if value is string starting with '|re' prefix OR if value is map containing 'modifiers' key with 're' in the list. Extract actual pattern string. Handle both inline syntax (field: '|re pattern') and modifier syntax (field: {value: pattern, modifiers: ['re']}). For each found pattern, call validateSingleRegex(pattern string) to check security. Collect all errors and return combined error message listing all problematic patterns.

### 125.5. Integrate with existing detect/regex_complexity.go AnalyzeRegexComplexity for ReDoS detection

**Status:** pending  
**Dependencies:** 125.4  

Implement validateSingleRegex function that calls existing detect.AnalyzeRegexComplexity to analyze regex pattern security and reject patterns with high ReDoS risk

**Details:**

In core/sigma_validator.go, implement validateSingleRegex(pattern string) error. Import detect package to access AnalyzeRegexComplexity function (already exists in detect/regex_complexity.go with 415 lines of ReDoS detection logic). Call result := detect.AnalyzeRegexComplexity(pattern). Check result.RiskLevel field. Define safe threshold: accept RiskLevel of 'low' and 'safe', reject 'medium', 'high', 'critical'. If rejected, return error with: pattern string, detected RiskLevel, result.Issues slice explaining what makes it unsafe (nested quantifiers, catastrophic backtracking, etc.). This leverages existing comprehensive regex security analysis instead of reimplementing ReDoS detection. The existing function already handles nested quantifiers, exponential backtracking, and complexity scoring.

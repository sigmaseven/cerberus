# Task ID: 128

**Title:** Create config-driven SIGMA field mapper with logsource filtering

**Status:** done

**Dependencies:** 123 ✓

**Priority:** high

**Description:** Build field mapping system that uses config/sigma_field_mappings.yaml to map SIGMA field names to Cerberus event fields with logsource-aware selection and fallback chain

**Details:**

Create detect/sigma_field_mapper.go:

1. FieldMapper struct:
   - mappings map[string]FieldMapping (logsource → field map)
   - globalMapping FieldMapping (generic fallback)
   - fieldAliases map[string]string (from core.FieldAliases)

2. LoadMappings function:
   - Read config/sigma_field_mappings.yaml
   - Parse YAML into map[logsource]map[field]mapped_field
   - Store "generic" as globalMapping
   - Store specific logsources (windows_sysmon, dns, etc.) in mappings

3. MapField function with fallback chain:
   - Step 1: Try logsource-specific mapping (product_service, product, category)
   - Step 2: Try global generic mapping
   - Step 3: Try core.FieldAliases
   - Step 4: Return field as-is (SIGMA standard name)

4. getLogsourceKey:
   - Build key from logsource map (product, service, category)
   - Try combinations: "product_service", "product", "category"
   - Return empty string if no match

5. GetEventFieldValue:
   - Map SIGMA field to Cerberus field
   - Use core.GetQueryFieldName for top-level vs fields. prefix
   - Navigate nested fields with dot notation
   - Handle top-level event fields (event_id, timestamp, etc.)
   - Return nil if field not present

6. Integration with existing config/sigma_field_mappings.yaml:
   - File already has comprehensive mappings for:
     * windows_sysmon, windows_security
     * aws_cloudtrail, azure_ad, gcp_audit
     * dns, firewall, syslog, webserver
     * linux_auditd, powershell
     * generic (fallback)

See Phase 3.4 in PRD for field mapping design (BLOCKER #3 fix).

**Test Strategy:**

1. Mapping tests:
   - Load config/sigma_field_mappings.yaml successfully
   - Map fields with logsource-specific mapping
   - Fallback to generic mapping
   - Fallback to FieldAliases
   - Return unmapped field as-is

2. Logsource key tests:
   - product + service combination
   - product only
   - category only
   - Empty logsource

3. GetEventFieldValue tests:
   - Top-level event fields (event_id, timestamp)
   - Fields in event.Fields map
   - Nested field navigation (fields.user.name)
   - Missing fields return nil

4. Integration tests:
   - Real Windows Sysmon events
   - Real AWS CloudTrail events
   - DNS query events
   - Generic event fallback

5. Config file validation:
   - All logsources in YAML are valid
   - No duplicate mappings
   - All referenced fields exist in core.Event

6. Performance tests:
   - Field lookup latency
   - Cache hit rate (if caching added)

## Subtasks

### 128.1. Create FieldMapper struct with mappings, globalMapping, and fieldAliases integration

**Status:** pending  
**Dependencies:** None  

Define the FieldMapper struct in detect/sigma_field_mapper.go with three core components: mappings map for logsource-specific field mappings, globalMapping for generic fallback, and fieldAliases integration with core.FieldAliases

**Details:**

Create detect/sigma_field_mapper.go and define the FieldMapper struct:
- mappings map[string]FieldMapping: stores logsource-specific mappings (e.g., 'windows_sysmon', 'dns', 'aws_cloudtrail')
- globalMapping FieldMapping: stores the 'generic' fallback mapping from config/sigma_field_mappings.yaml
- fieldAliases map[string]string: integration point with existing core.FieldAliases from core/field_aliases.go
- Add necessary type definitions for FieldMapping (likely map[string]string or similar structure)
- Include mutex for thread-safe access if needed
- Add constructor function NewFieldMapper() that initializes the maps

### 128.2. Implement LoadMappings function to parse config/sigma_field_mappings.yaml

**Status:** pending  
**Dependencies:** 128.1  

Build the LoadMappings function that reads the existing config/sigma_field_mappings.yaml file and parses it into the FieldMapper struct's mapping structures

**Details:**

Implement LoadMappings(configPath string) function:
- Use gopkg.in/yaml.v3 to parse config/sigma_field_mappings.yaml (already exists with 100+ mappings)
- Parse YAML structure into map[logsource]map[field]mapped_field format
- Extract and store 'generic' logsource mapping as globalMapping
- Store all other logsources (windows_sysmon, windows_security, aws_cloudtrail, azure_ad, gcp_audit, dns, firewall, syslog, webserver, linux_auditd, powershell) in the mappings map
- Integrate core.FieldAliases into fieldAliases map
- Return error if file not found, invalid YAML, or missing required 'generic' section
- Validate that each mapping entry has expected structure

### 128.3. Implement getLogsourceKey function for composite key building

**Status:** pending  
**Dependencies:** 128.1  

Create the getLogsourceKey helper function that builds composite keys from SIGMA logsource map (product, service, category) with multiple fallback combinations

**Details:**

Implement getLogsourceKey(logsource map[string]string) string function:
- Extract product, service, and category from logsource map
- Try key combinations in priority order:
  1. 'product_service' (e.g., 'windows_sysmon')
  2. 'product' only (e.g., 'windows')
  3. 'category' only (e.g., 'process_creation')
- Check if each constructed key exists in the FieldMapper.mappings map
- Return the first matching key found
- Return empty string if no match found (triggers fallback to generic)
- Handle edge cases: empty logsource map, missing fields, special characters in keys

### 128.4. Implement MapField function with 4-level fallback chain

**Status:** pending  
**Dependencies:** 128.2, 128.3  

Build the core MapField function that maps SIGMA field names to Cerberus event fields using a 4-level fallback chain: logsource-specific → generic → FieldAliases → as-is

**Details:**

Implement MapField(field string, logsource map[string]string) string function:
- Step 1: Use getLogsourceKey to get logsource-specific key, check mappings[key][field]
- Step 2: If not found, check globalMapping[field] (generic fallback)
- Step 3: If not found, check fieldAliases[field] (core.FieldAliases)
- Step 4: If not found, return field as-is (SIGMA standard name)
- Handle case-insensitive field lookups if needed
- Log mapping path taken for debugging (which fallback level was used)
- Return the mapped Cerberus field name
- Thread-safe implementation if FieldMapper uses mutex

### 128.5. Implement GetEventFieldValue with nested field navigation and top-level handling

**Status:** pending  
**Dependencies:** 128.4  

Create GetEventFieldValue function that maps SIGMA fields to Cerberus fields, retrieves values from events using core.GetQueryFieldName, and handles both top-level and nested field navigation with dot notation

**Details:**

Implement GetEventFieldValue(event map[string]interface{}, sigmaField string, logsource map[string]string) interface{} function:
- Call MapField to get the mapped Cerberus field name
- Use core.GetQueryFieldName to determine if field is top-level or in 'fields.' prefix
- Handle top-level event fields directly (event_id, timestamp, severity, etc.)
- Handle 'fields.' prefixed fields by navigating into event['fields'] map
- Implement dot notation navigation for nested fields (e.g., 'process.parent.image')
- Split field path by '.' and recursively navigate nested maps
- Return nil if field not present at any level
- Handle type assertions safely (map[string]interface{} navigation)
- Support both string and interface{} map types in nested structures

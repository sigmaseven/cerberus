# Task ID: 127

**Title:** Implement complete SIGMA modifier system with all 12+ modifiers

**Status:** done

**Dependencies:** None

**Priority:** high

**Description:** Build comprehensive modifier evaluator supporting equals, contains, startswith, endswith, re, all, base64, base64offset, utf16le, utf16be, wide, windash, cidr, and fieldref modifiers

**Details:**

Create detect/sigma_modifiers.go:

1. ModifierEvaluator struct:
   - regexTimeout time.Duration (for ReDoS protection)

2. EvaluateWithModifiers function:
   - Apply transform modifiers FIRST (base64, utf16*, wide, windash)
   - Determine operator from modifiers (contains, re, cidr, etc.)
   - Handle 'all' modifier (ALL values must match vs ANY)
   - Support list values with OR/AND logic
   - Call compareValues for final comparison

3. Transform modifiers (applyTransformModifiers):
   - base64: Standard and URL-safe decoding
   - base64offset: Try offsets 0,1,2 with padding, strip offset bytes from result
   - utf16le/utf16be: Decode UTF-16 Little/Big Endian using utf16.Decode
   - wide: Same as utf16le
   - windash: Normalize EN DASH, EM DASH, etc. to hyphen

4. Comparison operators (compareValues):
   - equals: String equality
   - contains: strings.Contains
   - startswith: strings.HasPrefix
   - endswith: strings.HasSuffix
   - regex: util.RegexWithTimeout (ReDoS protection)
   - cidr: net.ParseIP + CIDR.Contains
   - fieldref: Return error (requires event context, handled at higher level)

5. Helper functions:
   - decodeUTF16LE/BE: byte[] → uint16[] → runes → string
   - normalizeWindowsDashes: Replace Unicode dashes
   - matchCIDR: IP address in CIDR range

See Phase 3.3 in PRD for complete modifier implementation (BLOCKER #1 fix).

**Test Strategy:**

1. Modifier unit tests (300+ tests):
   - Each modifier individually
   - Modifier combinations (base64 + contains)
   - Transform order correctness
   - Edge cases (invalid base64, malformed UTF-16)

2. Operator tests:
   - All comparison operators
   - List values (OR vs AND logic)
   - 'all' modifier with lists
   - Case sensitivity

3. Security tests:
   - ReDoS patterns timeout
   - Invalid CIDR notation
   - Large base64 payloads

4. Real-world tests:
   - 100+ SIGMA rules from public repos using various modifiers
   - Windows Event Log fields with UTF-16
   - Base64-encoded payloads
   - Network rules with CIDR

5. Performance benchmarks:
   - Modifier application overhead
   - Regex timeout behavior

## Subtasks

### 127.1. Create ModifierEvaluator struct and EvaluateWithModifiers function

**Status:** done  
**Dependencies:** None  

Create detect/sigma_modifiers.go with ModifierEvaluator struct containing regexTimeout field, and implement the main EvaluateWithModifiers function that orchestrates modifier application, operator determination, 'all' modifier handling, and list value OR/AND logic

**Details:**

1. Create ModifierEvaluator struct with regexTimeout time.Duration field for ReDoS protection. 2. Implement EvaluateWithModifiers(value interface{}, pattern interface{}, modifiers []string) (bool, error) function. 3. Apply transform modifiers first (base64, utf16*, wide, windash) by calling applyTransformModifiers. 4. Determine comparison operator from modifiers (contains, re, cidr, etc.) with equals as default. 5. Handle 'all' modifier flag (ALL values must match vs ANY). 6. Support list values with OR logic (any match) or AND logic (all match when 'all' modifier present). 7. Call compareValues for final comparison. 8. Return match result and error if any step fails.

### 127.2. Implement base64 and base64offset transform modifiers

**Status:** done  
**Dependencies:** 127.1  

Implement applyTransformModifiers function with base64 (standard and URL-safe decoding) and base64offset (try offsets 0,1,2 with padding, strip offset bytes from result) transform logic

**Details:**

1. Implement applyTransformModifiers(value string, modifiers []string) (string, error) function. 2. For 'base64' modifier: use encoding/base64.StdEncoding.DecodeString and URLEncoding.DecodeString, try both variants and accept first successful decode. 3. For 'base64offset' modifier: iterate through offsets 0,1,2, add appropriate padding ('=' characters) to align to 4-byte boundary, attempt decode, strip offset bytes from beginning of decoded result if successful. 4. Return first successful decode or error if all attempts fail. 5. Apply modifiers in order specified in modifiers slice.

### 127.3. Implement UTF-16 and windash transform modifiers

**Status:** done  
**Dependencies:** 127.1  

Implement utf16le, utf16be, wide (alias for utf16le), and windash transform modifiers using encoding/binary and unicode/utf16 packages for decoding and dash normalization

**Details:**

1. Extend applyTransformModifiers with utf16le, utf16be, and wide modifiers. 2. Implement decodeUTF16LE(data []byte) (string, error): use binary.LittleEndian to read uint16 values, convert to rune slice with utf16.Decode, return string from runes. 3. Implement decodeUTF16BE(data []byte) (string, error): use binary.BigEndian for uint16 reading, otherwise same as LE. 4. Map 'wide' modifier to utf16le decoding. 5. Implement normalizeWindowsDashes(s string) string for 'windash' modifier: use strings.Replacer to replace EN DASH (U+2013), EM DASH (U+2014), HORIZONTAL BAR (U+2015), and other Unicode dash variants with ASCII hyphen (U+002D). 6. Handle malformed UTF-16 sequences gracefully with error returns.

### 127.4. Implement comparison operators in compareValues function

**Status:** in-progress  
**Dependencies:** 127.1  

Implement compareValues function supporting equals, contains, startswith, endswith, regex (with ReDoS protection), and cidr comparison operators

**Details:**

1. Implement compareValues(fieldValue string, pattern string, operator string, regexTimeout time.Duration) (bool, error) function. 2. For 'equals' operator: return fieldValue == pattern. 3. For 'contains': return strings.Contains(fieldValue, pattern). 4. For 'startswith': return strings.HasPrefix(fieldValue, pattern). 5. For 'endswith': return strings.HasSuffix(fieldValue, pattern). 6. For 'regex' or 're': call util.RegexWithTimeout(pattern, fieldValue, regexTimeout) for ReDoS protection. 7. For 'cidr': call matchCIDR(fieldValue, pattern). 8. For 'fieldref': return error indicating it requires event context and must be handled at higher level. 9. Default operator (no modifier): use 'equals'. 10. Return appropriate error for unsupported operators.

### 127.5. Implement CIDR matching with matchCIDR helper function

**Status:** done  
**Dependencies:** 127.4  

Implement matchCIDR function using net.ParseIP and net.IPNet.Contains for IP address CIDR range matching

**Details:**

1. Implement matchCIDR(ipStr string, cidrStr string) (bool, error) function. 2. Parse IP address with net.ParseIP(ipStr), return error if invalid. 3. Parse CIDR range with net.ParseCIDR(cidrStr), return error if invalid CIDR notation. 4. Use IPNet.Contains(ip) to check if IP is within CIDR range. 5. Handle both IPv4 and IPv6 addresses correctly. 6. Return (true, nil) if IP is in range, (false, nil) if not in range, (false, error) for parsing failures.

### 127.6. Implement list value handling with OR/AND logic and 'all' modifier support

**Status:** done  
**Dependencies:** 127.1, 127.4  

Extend EvaluateWithModifiers to handle list values (both for field values and patterns) with OR logic (any match) by default and AND logic (all match) when 'all' modifier is present

**Details:**

1. In EvaluateWithModifiers, detect if pattern is a list ([]interface{} or []string). 2. For each pattern in list, apply transforms and comparison against field value. 3. Default behavior (no 'all' modifier): OR logic - return true if ANY pattern matches (early exit on first match). 4. With 'all' modifier: AND logic - return true only if ALL patterns match (early exit on first non-match). 5. Handle field value as list: compare each field value against pattern(s), apply same OR/AND logic. 6. Support nested lists (list field values with list patterns). 7. Ensure empty lists are handled correctly (empty pattern list = no match, empty field list depends on 'all' modifier).

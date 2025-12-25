# Visual Correlation Builder - Backend Integration Report

**Date:** 2025-12-25
**Author:** Frontend Team
**Status:** Ready for Integration
**Gatekeeper Review:** PASSED (4 review cycles)

---

## Executive Summary

The Visual Correlation Builder frontend is now complete with full serialization support for all 7 correlation types. This document describes the API contract expectations, data format specifications, and security considerations for backend integration.

---

## 1. API Endpoints Used

### Create Correlation Rule
```
POST /api/correlations
Content-Type: application/json

Request Body: CorrelationCreateRequest
Response: ServiceResult<{ id: string }>
```

### Update Correlation Rule
```
PUT /api/correlations/:id
Content-Type: application/json

Request Body: CorrelationUpdateRequest
Response: ServiceResult<{ id: string }>
```

---

## 2. Data Formats

### 2.1 CorrelationCreateRequest

```typescript
interface CorrelationCreateRequest {
  name: string;           // Max 100 chars, sanitized
  description: string;    // Max 2000 chars, sanitized
  type: CorrelationType;  // 'count' | 'value_count' | 'sequence' | 'rare' | 'statistical' | 'cross_entity' | 'chain'
  config: CorrelationConfig;  // Type-specific configuration
  severity: RuleSeverity;     // 'low' | 'medium' | 'high' | 'critical' | 'informational'
  tags?: string[];
  enabled?: boolean;
  mitreTechniqueIds?: string[];
}
```

### 2.2 Correlation Configurations by Type

#### COUNT
```typescript
interface CountCorrelationConfig {
  type: 'count';
  baseQuery: CqlQuery;
  threshold: number;          // Min: 1
  timeWindow: TimeWindow;
  groupBy: string[];
  maxThreshold?: number;
}
```

#### VALUE_COUNT
```typescript
interface ValueCountCorrelationConfig {
  type: 'value_count';
  baseQuery: CqlQuery;
  countField: string;
  distinctThreshold: number;  // Min: 1
  timeWindow: TimeWindow;
  groupBy: string[];
}
```

#### SEQUENCE
```typescript
interface SequenceCorrelationConfig {
  type: 'sequence';
  steps: SequenceStep[];      // Min 2 steps required
  entityCorrelation: EntityCorrelationMode;
  maxTotalWindow: TimeWindow;
  strictOrder: boolean;
}

interface SequenceStep {
  order: number;              // 1-indexed
  name: string;
  query: CqlQuery;
  maxTimeFromPrevious?: TimeWindow;  // Max time since previous step
}
```

#### RARE
```typescript
interface RareCorrelationConfig {
  type: 'rare';
  baseQuery: CqlQuery;
  rarityField: string;
  baselinePeriod: TimeWindow;
  rarityThreshold: number;    // 0-100 percentage
  minBaselineCount: number;
  groupBy: string[];
}
```

#### STATISTICAL
```typescript
interface StatisticalCorrelationConfig {
  type: 'statistical';
  baseQuery: CqlQuery;
  metricField: string;
  aggregation: StatisticalAggregation;  // 'avg' | 'sum' | 'min' | 'max' | 'count'
  baselinePeriod: TimeWindow;
  detectionWindow: TimeWindow;
  stdDevThreshold: number;
  groupBy: string[];
  minSampleSize?: number;
}
```

#### CROSS_ENTITY
```typescript
interface CrossEntityCorrelationConfig {
  type: 'cross_entity';
  sourceQuery: CqlQuery;
  targetQuery: CqlQuery;
  entityMappings: EntityMapping[];
  timeWindow: TimeWindow;
  minSourceCount: number;
  minTargetCount: number;
}

interface EntityMapping {
  sourceField: string;
  targetField: string;
}
```

#### CHAIN
```typescript
interface ChainCorrelationConfig {
  type: 'chain';
  steps?: ChainStep[];        // Min 2 rule references required
  entityCorrelation?: EntityCorrelationMode;
  maxTotalWindow?: TimeWindow;
  minStepsRequired?: number;  // 1-10, defaults to count of required steps
  alertTemplate?: string;
  templateVariables?: AlertTemplateVariable[];
  conditionalBranches?: ConditionalBranch[];
}

interface ChainStep {
  id: string;
  order: number;
  ruleId: string;             // UUID - must reference existing rule
  ruleName?: string;
  timeWindow?: TimeWindow;    // IMPORTANT: Time until NEXT step, not from previous
  isRequired: boolean;
}
```

### 2.3 Common Types

```typescript
interface CqlQuery {
  query: string;              // CQL query string
  parsedFields?: string[];    // Server-generated
  isValid?: boolean;          // Server-validated
  validationError?: string;
}

interface TimeWindow {
  value: number;
  unit: TimeUnit;  // 'seconds' | 'minutes' | 'hours' | 'days'
}

type EntityCorrelationMode =
  | 'same_host'
  | 'same_user'
  | 'same_source_ip'
  | 'same_destination_ip'
  | 'any';
```

---

## 3. Security Considerations

### 3.1 Input Validation (Frontend)

All user inputs are sanitized before sending to the API:

| Field | Max Length | Sanitization |
|-------|------------|--------------|
| name | 100 chars | HTML entities stripped |
| description | 2000 chars | HTML entities stripped |
| alertTemplate | 2000 chars | HTML entities stripped |
| alertTitle | 200 chars | HTML entities stripped |
| CQL queries | 10000 chars | Validated against injection patterns |

### 3.2 CQL Query Security

The frontend validates CQL queries against dangerous patterns but **the backend must also validate**:

**Blocked patterns (frontend):**
- Stacked queries (`;` followed by SQL keywords)
- UNION SELECT injections
- Comment injections (`--`, `/*`, `#`)
- Time-based attacks (WAITFOR, SLEEP, BENCHMARK)
- Cassandra-specific (ALLOW FILTERING, CONSISTENCY)

**Backend should:**
1. Parse and validate CQL syntax
2. Enforce query whitelisting if applicable
3. Use parameterized queries for any dynamic values

### 3.3 UUID Validation

All rule IDs (especially in CHAIN steps) are validated as UUID v4 format:
- Pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
- Length: exactly 36 characters

The backend should verify referenced rules exist before accepting CHAIN configurations.

---

## 4. API Response Expectations

### 4.1 Success Response
```json
{
  "success": true,
  "data": {
    "id": "uuid-of-created-rule"
  }
}
```

### 4.2 Error Response
```json
{
  "success": false,
  "error": "Human-readable error message"
}
```

### 4.3 Validation Error Response
```json
{
  "success": false,
  "error": "Validation failed",
  "details": {
    "field": "config.threshold",
    "message": "Threshold must be at least 1"
  }
}
```

---

## 5. ChainStep.timeWindow Semantic Clarification

**IMPORTANT:** The `timeWindow` field on `ChainStep` is **forward-looking**:

```
StepA fires ──> [timeWindow: 5min] ──> StepB must fire within 5 minutes

Timeline:
StepA @ t=0
StepB must occur by t=5min (or CHAIN fails)
```

This is NOT "time since previous step" but rather "deadline for next step to occur."

For the last step in a chain, `timeWindow` is typically undefined/ignored.

---

## 6. Deserialization Limitations

Currently, only **COUNT** correlation rules can be fully deserialized for visual editing. Other types will load with a warning and use a template.

**Recommendation:** If edit mode is requested for non-COUNT rules, the backend should:
1. Return the full rule data (for reference display)
2. Consider flagging `supportsVisualEdit: false` in response

---

## 7. Testing Recommendations

### 7.1 Integration Tests
1. Create correlation of each type via API
2. Verify response includes valid UUID
3. Fetch created correlation and validate config matches

### 7.2 Validation Tests
```typescript
// Test cases for backend validation
const testCases = [
  { type: 'count', threshold: 0 },           // Should fail: threshold < 1
  { type: 'sequence', steps: [singleStep] }, // Should fail: < 2 steps
  { type: 'chain', steps: [singleRef] },     // Should fail: < 2 rule refs
  { type: 'rare', rarityThreshold: 150 },    // Should fail: > 100
];
```

### 7.3 Security Tests
1. Send CQL with `; DROP TABLE` - should reject
2. Send name with `<script>alert(1)</script>` - should sanitize
3. Send invalid UUID in CHAIN step - should reject

---

## 8. Migration Notes

If migrating from the existing wizard-based correlation builder:

1. **No schema changes required** - uses same `CorrelationConfig` types
2. **Visual metadata stored separately** - node positions not sent to backend
3. **Backwards compatible** - rules created via wizard can be edited visually (COUNT only)

---

## 9. Files Modified

| File | Purpose |
|------|---------|
| `src/pages/Correlations/VisualBuilder/utils/serialization.ts` | Core serialization (1400 lines) |
| `src/pages/Correlations/VisualBuilder/VisualCorrelationBuilder.tsx` | API integration |
| `src/services/correlationService.ts` | Lenient schema validation |
| `src/types/correlation.ts` | Type definitions (ChainStep JSDoc) |

---

## 10. Contact

For questions about this integration:
- **Frontend:** Review `serialization.ts` for detailed implementation
- **Type definitions:** See `src/types/correlation.ts`
- **API contract:** See `src/services/correlationService.ts`

---

**End of Report**

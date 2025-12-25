import { z } from 'zod';

/**
 * Zod schemas for API response validation.
 *
 * SECURITY: All API responses MUST be validated against these schemas
 * to prevent runtime errors from malformed or malicious data.
 *
 * Benefits:
 * - Type-safe API responses at runtime
 * - Early detection of API contract changes
 * - Protection against malformed/malicious responses
 * - Self-documenting API structure
 *
 * @module api.schemas
 */

// ============================================================================
// Primitive Schemas
// ============================================================================

/**
 * Severity levels for alerts and rules
 */
export const SeveritySchema = z.enum(['Low', 'Medium', 'High', 'Critical']);

/**
 * Alert status values - must match backend core.AlertStatus
 */
export const AlertStatusSchema = z.enum([
  'Pending',
  'Acknowledged',
  'Investigating',
  'Resolved',
  'Escalated',
  'Closed',
  'Dismissed',
  'FalsePositive',
]);

/**
 * ISO 8601 datetime string
 */
export const DateTimeSchema = z.string().datetime();

/**
 * Optional ISO 8601 datetime string
 */
export const OptionalDateTimeSchema = z.string().datetime().optional();

// ============================================================================
// Core Entity Schemas
// ============================================================================

/**
 * Event schema - validates event structure from backend
 *
 * SECURITY: Event fields can contain user-generated content that must be sanitized
 */
export const EventSchema = z.object({
  event_id: z.string(),
  event_type: z.string(),
  fields: z.record(z.unknown()), // Dynamic fields - sanitize when rendering
  raw_data: z.string(),
  severity: z.string(),
  source_format: z.string(),
  source_ip: z.string(),
  timestamp: z.string(), // Backend sends RFC3339 format
  ingested_at: z.string().optional(), // When event was ingested
  listener_id: z.string().optional(), // Which listener received it
  listener_name: z.string().optional(), // Listener name
  source: z.string().optional(), // Event source
});

export type Event = z.infer<typeof EventSchema>;

/**
 * Alert schema - validates alert structure from backend
 */
export const AlertSchema = z.object({
  alert_id: z.string(),
  event: EventSchema,
  event_id: z.string(),
  jira_ticket_id: z.string().optional(),
  rule_id: z.string(),
  severity: z.string(),
  status: AlertStatusSchema,
  timestamp: z.string(),
  last_seen: z.string().optional(), // Last time this alert was seen
  fingerprint: z.string().optional(), // Alert fingerprint for deduplication
  duplicate_count: z.number().optional(), // Number of duplicate alerts
  event_ids: z.array(z.string()).optional(), // Related event IDs
});

export type Alert = z.infer<typeof AlertSchema>;

/**
 * Action schema - validates action configuration
 */
export const ActionSchema = z.object({
  id: z.string(),
  type: z.string(),
  config: z.record(z.unknown()),
});

export type Action = z.infer<typeof ActionSchema>;

/**
 * Condition schema - validates rule condition structure
 */
export const ConditionSchema = z.object({
  field: z.string(),
  logic: z.enum(['AND', 'OR']),
  operator: z.string(),
  value: z.string(),
});

export type Condition = z.infer<typeof ConditionSchema>;

/**
 * Rule schema - validates rule structure from backend
 * Supports both SIGMA rules (with detection) and simple rules (with conditions)
 */
export const RuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: z.string(),
  enabled: z.boolean(),
  version: z.number(),
  type: z.string().optional(), // 'sigma' or 'cql'
  conditions: z.array(ConditionSchema).optional().default([]),
  actions: z.array(ActionSchema).optional().default([]),
  tags: z.array(z.string()).optional(),
  mitre_tactics: z.array(z.string()).optional(),
  mitre_techniques: z.array(z.string()).optional(),
  // SIGMA rule fields
  detection: z.record(z.unknown()).optional(), // SIGMA detection logic
  logsource: z.record(z.unknown()).optional(), // SIGMA logsource
  references: z.array(z.string()).optional(),
  false_positives: z.array(z.string()).optional(),
  author: z.string().optional(),
  query: z.string().optional(), // CQL query string
});

export type Rule = z.infer<typeof RuleSchema>;

/**
 * Correlation Rule schema
 * TASK #184: Conditions field removed from backend - use SIGMA correlation syntax instead
 * Backend returns created_at and updated_at timestamps
 */
export const CorrelationRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: z.string(),
  version: z.number(),
  sequence: z.array(z.string()),
  window: z.number(), // nanoseconds
  actions: z.array(ActionSchema).optional().default([]),
  created_at: z.string().optional(), // Backend returns RFC3339 timestamp
  updated_at: z.string().optional(), // Backend returns RFC3339 timestamp
});

export type CorrelationRule = z.infer<typeof CorrelationRuleSchema>;

// ============================================================================
// Pagination Schemas
// ============================================================================

/**
 * Cursor-based pagination response for events
 * PERFORMANCE: Use cursor pagination for large datasets (O(1) vs O(n))
 */
export const EventsPageSchema = z.object({
  events: z.array(EventSchema),
  next_cursor: z.string().optional(),
  has_more: z.boolean(),
});

export type EventsPage = z.infer<typeof EventsPageSchema>;

/**
 * Offset-based pagination response (legacy)
 * Zod v4 compatible function that returns a schema
 */
export function PaginationResponseSchema<T extends z.ZodTypeAny>(itemSchema: T) {
  // Guard against undefined/null itemSchema
  if (!itemSchema) {
    throw new Error('itemSchema is required for PaginationResponseSchema');
  }

  return z.object({
    items: z.array(itemSchema),
    total: z.number(),
    page: z.number(),
    limit: z.number(),
    total_pages: z.number().optional(), // Optional for backwards compatibility
  });
}

// ============================================================================
// Dashboard & Stats Schemas
// ============================================================================

/**
 * Dashboard statistics schema
 */
export const DashboardStatsSchema = z.object({
  total_events: z.number(),
  active_alerts: z.number(),
  rules_fired: z.number(),
  system_health: z.string(),
});

export type DashboardStats = z.infer<typeof DashboardStatsSchema>;

/**
 * Chart data point schema
 */
export const ChartDataSchema = z.object({
  timestamp: z.string(),
  events: z.number(),
  alerts: z.number(),
});

export type ChartData = z.infer<typeof ChartDataSchema>;

/**
 * Listener status schema
 */
export const ListenerStatusSchema = z.object({
  syslog: z.object({
    active: z.boolean(),
    port: z.number(),
    events_per_minute: z.number(),
    errors: z.number(),
  }),
  cef: z.object({
    active: z.boolean(),
    port: z.number(),
    events_per_minute: z.number(),
    errors: z.number(),
  }),
  json: z.object({
    active: z.boolean(),
    port: z.number(),
    events_per_minute: z.number(),
    errors: z.number(),
  }),
});

export type ListenerStatus = z.infer<typeof ListenerStatusSchema>;

// ============================================================================
// Search Schemas
// ============================================================================

/**
 * Time range schema
 */
export const TimeRangeSchema = z.object({
  start: z.string(),
  end: z.string(),
});

export type TimeRange = z.infer<typeof TimeRangeSchema>;

/**
 * Search request schema
 */
export const SearchRequestSchema = z.object({
  query: z.string(),
  time_range: TimeRangeSchema.optional(),
  page: z.number().optional(),
  limit: z.number().optional(),
  sort_by: z.string().optional(),
  sort_order: z.enum(['asc', 'desc']).optional(),
  fields: z.array(z.string()).optional(),
  params: z.record(z.unknown()).optional(),
});

export type SearchRequest = z.infer<typeof SearchRequestSchema>;

/**
 * Search response schema
 */
export const SearchResponseSchema = z.object({
  events: z.array(z.record(z.unknown())),
  total: z.number(),
  page: z.number(),
  limit: z.number(),
  execution_time_ms: z.number(),
  query: z.string(),
  time_range: TimeRangeSchema.optional(),
});

export type SearchResponse = z.infer<typeof SearchResponseSchema>;

/**
 * Saved search schema - matches backend API response format
 */
export const SavedSearchSchema = z.object({
  id: z.string().optional(),
  name: z.string(),
  description: z.string(),
  query: z.string(),
  filters: z.record(z.unknown()).nullable().optional(),
  created_by: z.string(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
  is_public: z.boolean(),
  tags: z.array(z.string()).nullable().optional(),
  usage_count: z.number().optional(),
});

export type SavedSearch = z.infer<typeof SavedSearchSchema>;

/**
 * Saved searches response schema - paginated list
 * NOTE: items can be null from backend when empty, we transform to empty array
 */
export const SavedSearchesResponseSchema = z.object({
  items: z.array(SavedSearchSchema).nullable().transform(val => val ?? []),
  total: z.number(),
});

export type SavedSearchesResponse = z.infer<typeof SavedSearchesResponseSchema>;

// ============================================================================
// WebSocket Message Schemas
// ============================================================================

/**
 * WebSocket alert message schema
 */
export const WebSocketAlertSchema = z.object({
  type: z.literal('alert'),
  data: AlertSchema,
});

/**
 * WebSocket event message schema
 */
export const WebSocketEventSchema = z.object({
  type: z.literal('event'),
  data: EventSchema,
});

/**
 * WebSocket heartbeat message schema
 */
export const WebSocketHeartbeatSchema = z.object({
  type: z.literal('heartbeat'),
  timestamp: z.number(),
});

/**
 * WebSocket stats update schema
 */
export const WebSocketStatsSchema = z.object({
  type: z.literal('stats'),
  data: DashboardStatsSchema,
});

/**
 * Discriminated union of all WebSocket message types
 *
 * SECURITY: All WebSocket messages must be validated against this schema
 */
export const WebSocketMessageSchema = z.discriminatedUnion('type', [
  WebSocketAlertSchema,
  WebSocketEventSchema,
  WebSocketHeartbeatSchema,
  WebSocketStatsSchema,
]);

export type WebSocketMessage = z.infer<typeof WebSocketMessageSchema>;

// ============================================================================
// API Response Wrappers
// ============================================================================

/**
 * Generic API response wrapper
 */
export const ApiResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    data: dataSchema,
    message: z.string().optional(),
    error: z.string().optional(),
  });

/**
 * API error response schema
 */
export const ApiErrorSchema = z.object({
  error: z.string(),
  message: z.string().optional(),
  code: z.string().optional(),
  details: z.unknown().optional(),
});

export type ApiError = z.infer<typeof ApiErrorSchema>;

// ============================================================================
// Listener Template Schemas
// ============================================================================

/**
 * Listener type enum - must match backend ListenerType
 */
export const ListenerTypeSchema = z.enum(['syslog', 'cef', 'json', 'fluentd', 'fluentbit']);

/**
 * Listener protocol enum - must match backend ListenerProtocol
 */
export const ListenerProtocolSchema = z.enum(['udp', 'tcp', 'http']);

/**
 * Listener form config schema - matches backend storage.DynamicListener
 * BLOCKING-2 FIX: Runtime validation for ListenerTemplate API response
 */
export const ListenerFormConfigSchema = z.object({
  name: z.string().max(200).optional(),
  description: z.string().max(1000).optional(),
  type: ListenerTypeSchema,
  protocol: ListenerProtocolSchema,
  host: z.string().max(255),
  port: z.number().int().min(1).max(65535),
  tls: z.boolean(),
  cert_file: z.string().max(500).optional(),
  key_file: z.string().max(500).optional(),
  tags: z.array(z.string().max(100)).max(50).optional(),
  source: z.string().max(200),
  field_mapping: z.string().max(500).optional(),
});

export type ListenerFormConfig = z.infer<typeof ListenerFormConfigSchema>;

/**
 * Listener template schema - validates template structure from backend
 * SECURITY: Templates come from backend storage which could be compromised
 * BLOCKING-2 FIX: Validates all fields with strict limits to prevent DoS
 */
export const ListenerTemplateSchema = z.object({
  id: z.string().min(1).max(100),
  name: z.string().min(1).max(200),
  description: z.string().max(1000),
  category: z.string().min(1).max(100),
  icon: z.string().max(50),
  config: ListenerFormConfigSchema,
  tags: z.array(z.string().max(100)).max(50),
});

export type ListenerTemplateValidated = z.infer<typeof ListenerTemplateSchema>;

/**
 * Array of listener templates - validates entire response
 * BLOCKING-2 FIX: Limit array size to prevent DoS attacks
 */
export const ListenerTemplatesArraySchema = z.array(ListenerTemplateSchema).max(100);

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Validates data against a Zod schema and returns typed result.
 *
 * SECURITY: Use this to validate all API responses before using them.
 *
 * @param schema - Zod schema to validate against
 * @param data - Unknown data to validate
 * @param errorContext - Context string for error messages
 * @returns Validated, typed data
 * @throws Error if validation fails
 *
 * @example
 * ```typescript
 * const events = validateSchema(EventsPageSchema, response.data, 'GET /api/events');
 * ```
 */
export function validateSchema<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  errorContext: string
): T {
  try {
    // Guard against undefined/null schema
    if (!schema) {
      throw new Error(`Schema is undefined for context: ${errorContext}`);
    }

    // Guard against undefined/null data
    if (data === undefined || data === null) {
      if (import.meta.env.DEV) {
        console.warn(`API returned null/undefined data [${errorContext}]`);
      }
      throw new Error(`API returned null/undefined data [${errorContext}]`);
    }

    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      if (import.meta.env.DEV) {
        console.error(`API validation failed [${errorContext}]:`, {
          errors: error.errors,
          data,
        });
      }
      throw new Error(
        `Invalid API response format [${errorContext}]: ${error.errors
          .map((e) => `${e.path.join('.')}: ${e.message}`)
          .join(', ')}`
      );
    }
    // Re-throw other errors (including our guard errors)
    throw error;
  }
}

/**
 * Safely validates data and returns null if validation fails.
 * Use when you want to handle invalid data gracefully.
 *
 * @param schema - Zod schema to validate against
 * @param data - Unknown data to validate
 * @returns Validated data or null if invalid
 */
export function safeValidateSchema<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): T | null {
  try {
    return schema.parse(data);
  } catch {
    return null;
  }
}

// ============================================================================
// Feed Schemas (TASK 155.3)
// SIGMA rule feed management for importing rules from external sources
// ============================================================================

/**
 * Feed type enum - git or filesystem source
 */
export const FeedTypeSchema = z.enum(['git', 'filesystem']);

export type FeedType = z.infer<typeof FeedTypeSchema>;

/**
 * Feed status enum - operational state of the feed
 */
export const FeedStatusSchema = z.enum(['active', 'disabled', 'error', 'syncing']);

export type FeedStatus = z.infer<typeof FeedStatusSchema>;

/**
 * Feed update strategy enum - when to sync the feed
 */
export const FeedUpdateStrategySchema = z.enum(['manual', 'startup', 'scheduled']);

export type FeedUpdateStrategy = z.infer<typeof FeedUpdateStrategySchema>;

/**
 * Feed statistics schema - sync and rule counts
 */
export const FeedStatsSchema = z.object({
  total_rules: z.number().int().min(0),
  imported_rules: z.number().int().min(0),
  updated_rules: z.number().int().min(0),
  skipped_rules: z.number().int().min(0),
  failed_rules: z.number().int().min(0),
  last_sync: z.string().optional(),
  last_sync_duration: z.number().min(0).optional(),
  sync_count: z.number().int().min(0),
  last_error: z.string().max(2000).optional(),
});

export type FeedStats = z.infer<typeof FeedStatsSchema>;

/**
 * Feed schema - complete feed configuration and state
 * SECURITY: Validates URL patterns and limits string lengths to prevent DoS
 */
export const FeedSchema = z.object({
  id: z.string().min(1).max(100),
  name: z.string().min(1).max(200),
  description: z.string().max(1000).optional(),
  type: FeedTypeSchema,
  status: FeedStatusSchema,
  enabled: z.boolean(),
  priority: z.number().int().min(0).max(1000),
  url: z.string().url().max(2000).optional(),
  branch: z.string().max(200).optional(),
  path: z.string().max(500).optional(),
  auth_config: z.record(z.unknown()).optional(),
  include_paths: z.array(z.string().max(500)).max(100).optional(),
  exclude_paths: z.array(z.string().max(500)).max(100).optional(),
  include_tags: z.array(z.string().max(100)).max(100).optional(),
  exclude_tags: z.array(z.string().max(100)).max(100).optional(),
  min_severity: z.string().max(50).optional(),
  auto_enable_rules: z.boolean(),
  update_strategy: FeedUpdateStrategySchema,
  update_schedule: z.string().max(100).optional(),
  last_sync: z.string().optional(),
  next_sync: z.string().optional(),
  stats: FeedStatsSchema,
  tags: z.array(z.string().max(100)).max(50).optional(),
  metadata: z.record(z.unknown()).optional(),
  created_at: z.string(),
  updated_at: z.string(),
  created_by: z.string().max(200).optional(),
});

export type Feed = z.infer<typeof FeedSchema>;

/**
 * Feed sync result schema - result of a feed synchronization
 */
export const FeedSyncResultSchema = z.object({
  feed_id: z.string().min(1).max(100),
  feed_name: z.string().max(200),
  success: z.boolean(),
  start_time: z.string(),
  end_time: z.string(),
  duration: z.number().min(0),
  stats: FeedStatsSchema,
  errors: z.array(z.string().max(2000)).max(1000),
});

export type FeedSyncResult = z.infer<typeof FeedSyncResultSchema>;

/**
 * Feed template schema - predefined feed configurations
 * SECURITY: Templates come from backend, validate all fields
 */
export const FeedTemplateSchema = z.object({
  id: z.string().min(1).max(100),
  name: z.string().min(1).max(200),
  description: z.string().max(1000),
  type: FeedTypeSchema,
  config: FeedSchema.partial(),
});

export type FeedTemplate = z.infer<typeof FeedTemplateSchema>;

/**
 * Feed test result schema - result of testing feed connectivity
 */
export const FeedTestResultSchema = z.object({
  success: z.boolean(),
  message: z.string().max(2000),
  rules_found: z.number().int().min(0).optional(),
  connection_time_ms: z.number().min(0).optional(),
  errors: z.array(z.string().max(2000)).max(100).optional(),
});

export type FeedTestResult = z.infer<typeof FeedTestResultSchema>;

/**
 * Array of feeds - validates entire list response
 * BLOCKING-2: Limit array size to prevent DoS attacks
 */
export const FeedsArraySchema = z.array(FeedSchema).max(500);

/**
 * Array of feed templates - validates template list response
 * BLOCKING-2: Limit array size to prevent DoS attacks
 */
export const FeedTemplatesArraySchema = z.array(FeedTemplateSchema).max(100);

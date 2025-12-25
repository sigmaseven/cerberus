// API Response Types based on OpenAPI specification

export interface Event {
  event_id: string;
  event_type: string;
  fields: Record<string, unknown>;
  raw_data: string;
  severity: string;
  source_format: string;
  source_ip: string;
  timestamp: string;
}

export interface Alert {
  alert_id: string;
  event: Event;
  event_id: string;
  jira_ticket_id?: string;
  rule_id: string;
  severity: string;
  status: AlertStatus;
  timestamp: string;
  // Extended alert fields
  fingerprint?: string;
  duplicate_count?: number;
  last_seen?: string;
  event_ids?: string[];
  assigned_to?: string;
  threat_intel?: ThreatIntelEntry[];
  // Disposition fields
  disposition?: AlertDisposition;
  disposition_reason?: string;
  disposition_set_at?: string;
  disposition_set_by?: string;
  investigation_id?: string;
}

export interface ThreatIntelEntry {
  source: string;
  indicator: string;
  type: string;
  confidence: number;
  severity: string;
  tags?: string[];
}

export type AlertDisposition =
  | 'undetermined'
  | 'true_positive'
  | 'false_positive'
  | 'benign'
  | 'suspicious'
  | 'inconclusive';

export enum AlertStatus {
  Pending = 'Pending',
  Acknowledged = 'Acknowledged',
  Investigating = 'Investigating',
  Resolved = 'Resolved',
  Escalated = 'Escalated',
  Closed = 'Closed',
  Dismissed = 'Dismissed',
  FalsePositive = 'FalsePositive',
}

export interface StatusChange {
  alert_id: string;
  from_status: AlertStatus;
  to_status: AlertStatus;
  changed_by: string;
  changed_at: string;
  note?: string;
}

export interface Action {
  config: Record<string, unknown>;
  id: string;
  type: string;
}

export interface Condition {
  field: string;
  logic: 'AND' | 'OR';
  operator: string;
  value: string;
}

export interface CorrelationConfig {
  type: 'event_count' | 'value_count' | 'sequence' | 'temporal' | 'rare' | 'statistical' | 'chain';
  group_by?: string[];
  timespan?: string;
  ordered?: boolean;
  events?: string[];
  distinct_field?: string;
  baseline_window?: string;
  std_dev_threshold?: number;
}

export interface Rule {
  actions: Action[];
  conditions: Condition[];
  description: string;
  enabled: boolean;
  id: string;
  name: string;
  severity: string;
  version: number;
  type?: string; // 'sigma' or 'cql'
  tags?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  // SIGMA rule fields
  detection?: Record<string, unknown>; // SIGMA detection logic
  logsource?: Record<string, unknown>; // SIGMA logsource
  references?: string[];
  false_positives?: string[];
  author?: string;
  query?: string; // CQL query string
  // Extended fields for unified rules API
  sigma_yaml?: string;
  correlation_config?: CorrelationConfig;
  lifecycle_status?: LifecycleStatus;
  condition?: string;
}

// TASK #184: Conditions field removed from backend - use SIGMA correlation syntax instead
export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  version: number;
  sequence: string[];
  window: number; // nanoseconds
  actions?: Action[];
  created_at?: string;
  updated_at?: string;
}

export interface DashboardStats {
  total_events: number;
  active_alerts: number;
  rules_fired: number;
  system_health: string;
}

export interface ChartData {
  timestamp: string;
  events: number;
  alerts: number;
}

// Legacy static listener status (for backwards compatibility)
export interface StaticListenerStatus {
  syslog: {
    active: boolean;
    port: number;
    events_per_minute: number;
    errors: number;
  };
  cef: {
    active: boolean;
    port: number;
    events_per_minute: number;
    errors: number;
  };
  json: {
    active: boolean;
    port: number;
    events_per_minute: number;
    errors: number;
  };
}

// Listener type options
export type ListenerType = 'syslog' | 'cef' | 'json' | 'fluentd' | 'fluentbit';
export type ListenerProtocol = 'udp' | 'tcp' | 'http';
export type ListenerStatusValue = 'stopped' | 'starting' | 'running' | 'error';

// Dynamic Listener (new API)
export interface DynamicListener {
  id: string;
  name: string;
  description: string;
  type: ListenerType;
  protocol: ListenerProtocol;
  host: string;
  port: number;
  tls: boolean;
  cert_file?: string;
  key_file?: string;
  status: ListenerStatusValue;
  tags: string[];
  source: string;
  field_mapping?: string;
  events_received: number;
  events_per_minute: number;
  error_count: number;
  last_event?: string;
  created_at: string;
  created_by: string;
  updated_at: string;
  started_at?: string;
  stopped_at?: string;
}

// Listener Template for quick configuration
export interface ListenerTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  icon: string;
  tags: string[];
  config: Partial<ListenerForm>;
}

// Form type for creating/editing listeners
export interface ListenerForm {
  name: string;
  description: string;
  type: ListenerType;
  protocol: ListenerProtocol;
  host: string;
  port: number;
  tls: boolean;
  cert_file?: string;
  key_file?: string;
  tags?: string[];
  source: string;
  field_mapping?: string;
}

// Real-time listener statistics
export interface ListenerStats {
  events_received: number;
  events_per_minute: number;
  error_count: number;
  error_rate: number;
  last_event?: string;
  uptime_duration: number;
}

// Response from start/stop/restart operations
export interface ListenerControlResponse {
  status: string;
  message: string;
}

// Union type for backwards compatibility
export type ListenerStatus = StaticListenerStatus | DynamicListener[];

// Form Types
export interface LoginForm {
  username: string;
  password: string;
}

export interface RuleForm {
  id?: string;
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  conditions: Condition[];
  actions: Action[];
}

// TASK #184: Conditions field removed from backend - use SIGMA correlation syntax instead
export interface CorrelationRuleForm {
  id?: string;
  name: string;
  description: string;
  severity: string;
  version: number;
  window: number;
  sequence: string[];
  actions?: Action[];
}

export interface ActionForm {
  id?: string;
  type: string;
  config: Record<string, unknown>;
}

// UI State Types
export interface TableState {
  page: number;
  pageSize: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  filters?: Record<string, unknown>;
}

export interface ApiResponse<T> {
  data: T;
  message?: string;
  error?: string;
}

export interface PaginationResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  total_pages?: number; // Optional for backwards compatibility
}

// Import/Export Types
export interface ImportResult {
  success: boolean;
  totalProcessed: number;
  successfulImports: number;
  failedImports: number;
  conflicts: ImportConflict[];
  errors: ImportError[];
}

export interface ImportConflict {
  ruleId: string;
  reason: string;
  resolution: string;
}

export interface ImportError {
  ruleId?: string;
  message: string;
}

// Event Search Types
export interface TimeRange {
  start: string;
  end: string;
}

export interface SearchRequest {
  query: string;
  time_range?: TimeRange;
  page?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  fields?: string[];
  params?: Record<string, unknown>;
}

export interface SearchResponse {
  events: Record<string, unknown>[];
  total: number;
  page: number;
  limit: number;
  execution_time_ms: number;
  query: string;
  time_range?: TimeRange;
}

export interface SavedSearch {
  id?: string;
  name: string;
  description: string;
  query: string;
  filters?: Record<string, unknown> | null;
  created_by: string;
  created_at?: string;
  updated_at?: string;
  is_public: boolean;
  tags?: string[] | null;
  usage_count?: number;
}

export interface SearchField {
  name: string;
  type: string;
  description: string;
}

export interface SearchOperator {
  value: string;
  label: string;
  symbol?: string;
  types: string[];
}

export interface QueryValidationResult {
  valid: boolean;
  error?: string;
  message?: string;
}

export interface ExportRequest {
  query: string;
  time_range?: TimeRange;
  format: 'json' | 'csv';
  limit?: number;
}

export interface SavedSearchesResponse {
  items: SavedSearch[];
  total: number;
}

// =============================================================================
// Feed Types (TASK 155)
// SIGMA rule feed management for importing rules from external sources
// =============================================================================

export type FeedType = 'git' | 'filesystem';
export type FeedStatus = 'active' | 'disabled' | 'error' | 'syncing';
export type FeedUpdateStrategy = 'manual' | 'startup' | 'scheduled';

export interface FeedStats {
  total_rules: number;
  imported_rules: number;
  updated_rules: number;
  skipped_rules: number;
  failed_rules: number;
  last_sync?: string;
  last_sync_duration?: number;
  sync_count: number;
  last_error?: string;
}

export interface Feed {
  id: string;
  name: string;
  description?: string;
  type: FeedType;
  status: FeedStatus;
  enabled: boolean;
  priority: number;
  url?: string;
  branch?: string;
  path?: string;
  auth_config?: Record<string, unknown>;
  include_paths?: string[];
  exclude_paths?: string[];
  include_tags?: string[];
  exclude_tags?: string[];
  min_severity?: string;
  auto_enable_rules: boolean;
  update_strategy: FeedUpdateStrategy;
  update_schedule?: string;
  last_sync?: string;
  next_sync?: string;
  stats: FeedStats;
  tags?: string[];
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  created_by?: string;
}

export interface FeedSyncResult {
  feed_id: string;
  feed_name: string;
  success: boolean;
  start_time: string;
  end_time: string;
  duration: number;
  stats: FeedStats;
  errors: string[];
}

export interface FeedTemplate {
  id: string;
  name: string;
  description: string;
  type: FeedType;
  config: Partial<Feed>;
}

export interface FeedForm {
  name: string;
  description?: string;
  type: FeedType;
  enabled: boolean;
  priority: number;
  url?: string;
  branch?: string;
  path?: string;
  auth_config?: Record<string, unknown>;
  include_paths?: string[];
  exclude_paths?: string[];
  include_tags?: string[];
  exclude_tags?: string[];
  min_severity?: string;
  auto_enable_rules: boolean;
  update_strategy: FeedUpdateStrategy;
  update_schedule?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface FeedTestResult {
  success: boolean;
  message: string;
  rules_found?: number;
  connection_time_ms?: number;
  errors?: string[];
}

// TASK 157.2: Feed summary statistics for dashboard widget
export type FeedHealthStatus = 'healthy' | 'warning' | 'error';

export interface FeedsSummary {
  total_feeds: number;
  active_feeds: number;
  total_rules: number;
  last_sync: string | null;
  health_status: FeedHealthStatus;
  error_count: number;
}

// =============================================================================
// Unified Rules API Types (TASK 174.7)
// Consolidated detection and correlation rules with SIGMA YAML support
// =============================================================================

export type RuleCategory = 'detection' | 'correlation' | 'all';
export type LifecycleStatus = 'experimental' | 'test' | 'stable' | 'deprecated' | 'active' | 'archived';

/**
 * Unified rule list request parameters
 * Supports filtering by category, lifecycle status, and logsource
 */
export interface UnifiedRulesListRequest {
  category?: RuleCategory;
  lifecycle_status?: LifecycleStatus;
  logsource_category?: string;
  logsource_product?: string;
  enabled?: boolean;
  limit?: number;
  offset?: number;
  page?: number;
}

/**
 * Unified rule response wrapper
 * Contains both rule data and category metadata
 */
export interface UnifiedRuleResponse {
  category: RuleCategory;
  rule: Rule | CorrelationRule;
}

/**
 * Paginated unified rules response
 */
export interface UnifiedRulesResponse {
  items: UnifiedRuleResponse[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
  category: RuleCategory;
}

/**
 * Bulk operation request for multiple rules
 */
export interface BulkOperationRequest {
  rule_ids: string[];
}

/**
 * Bulk operation response with partial success tracking
 */
export interface BulkOperationResponse {
  processed: number;
  failed: number;
  errors?: string[];
}

/**
 * Rule validation request
 */
export interface ValidateRuleRequest {
  sigma_yaml: string;
}

/**
 * Rule validation response with detailed feedback
 */
export interface ValidateRuleResponse {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  category: RuleCategory;
}

/**
 * Rule lifecycle transition request
 */
export interface LifecycleTransitionRequest {
  status: LifecycleStatus;
  comment?: string;
}

/**
 * Lifecycle history entry
 */
export interface LifecycleHistoryEntry {
  timestamp: string;
  from_status: LifecycleStatus;
  to_status: LifecycleStatus;
  changed_by: string;
  comment?: string;
}

/**
 * Rule test request with sample events
 */
export interface RuleTestRequest {
  rule_id?: string;
  sigma_yaml?: string;
  events: Record<string, unknown>[];
}

/**
 * Rule test result
 */
export interface RuleTestResult {
  matched: boolean;
  match_count: number;
  events_tested: number;
  matches: Array<{
    event_index: number;
    matched_conditions: string[];
  }>;
  errors?: string[];
}

/**
 * Batch rule test request
 */
export interface BatchRuleTestRequest {
  rule_id: string;
  event_ids: string[];
}

/**
 * Rule performance statistics
 */
export interface RulePerformanceStats {
  rule_id: string;
  rule_name: string;
  total_executions: number;
  total_matches: number;
  avg_execution_time_ms: number;
  max_execution_time_ms: number;
  min_execution_time_ms: number;
  false_positive_count: number;
  last_executed?: string;
  period_start: string;
  period_end: string;
}

/**
 * Slow rule entry
 */
export interface SlowRule {
  rule_id: string;
  rule_name: string;
  avg_execution_time_ms: number;
  executions_count: number;
}

/**
 * False positive report request
 */
export interface FalsePositiveReportRequest {
  rule_id: string;
  event_id: string;
  alert_id?: string;
  reason?: string;
  suggested_fix?: string;
}

/**
 * False positive report response
 */
export interface FalsePositiveReportResponse {
  reported: boolean;
  report_id: string;
  message: string;
}

/**
 * CQL to SIGMA migration request
 */
export interface MigrateCQLRequest {
  rule_ids?: string[];
  auto_enable?: boolean;
  preserve_originals?: boolean;
}

/**
 * CQL migration result
 */
export interface MigrationResult {
  rule_id: string;
  rule_name: string;
  success: boolean;
  sigma_rule_id?: string;
  error?: string;
  warnings?: string[];
}

/**
 * CQL migration response
 */
export interface MigrateCQLResponse {
  total: number;
  migrated: number;
  failed: number;
  results: MigrationResult[];
}

/**
 * Import rules request (multipart form data)
 */
export interface ImportRulesFormData {
  files: File[];
  overwrite_existing?: boolean;
  dry_run?: boolean;
}

/**
 * Import result for a single file
 */
export interface RuleImportResult {
  filename: string;
  status: 'imported' | 'updated' | 'skipped' | 'failed';
  message?: string;
  rule_id?: string;
}

/**
 * Import rules response
 */
export interface ImportRulesResponse {
  total: number;
  imported: number;
  updated: number;
  skipped: number;
  failed: number;
  results: RuleImportResult[];
}

/**
 * Export rules request parameters
 */
export interface ExportRulesRequest {
  format?: 'sigma' | 'json';
  category?: RuleCategory;
  rule_ids?: string[];
}
// API Response Types based on OpenAPI specification

export interface Event {
  event_id: string;
  event_type: string;
  fields: Record<string, any>;
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
}

export enum AlertStatus {
  Pending = 'Pending',
  Acknowledged = 'Acknowledged',
  Dismissed = 'Dismissed',
}

export interface Action {
  config: Record<string, any>;
  id: string;
  type: string;
}

export interface Condition {
  field: string;
  logic: 'AND' | 'OR';
  operator: string;
  value: string;
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
}

export interface CorrelationRule {
  actions: Action[];
  conditions: Condition[];
  description: string;
  id: string;
  name: string;
  sequence: string[];
  severity: string;
  version: number;
  window: number; // nanoseconds
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

export interface ListenerStatus {
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

export interface CorrelationRuleForm {
  id?: string;
  name: string;
  description: string;
  severity: string;
  version: number;
  window: number;
  sequence: string[];
  conditions: Condition[];
  actions: Action[];
}

export interface ActionForm {
  id?: string;
  type: string;
  config: Record<string, any>;
}

// UI State Types
export interface TableState {
  page: number;
  pageSize: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  filters?: Record<string, any>;
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
  total_pages: number;
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
  params?: Record<string, any>;
}

export interface SearchResponse {
  events: Record<string, any>[];
  total: number;
  page: number;
  limit: number;
  execution_time_ms: number;
  query: string;
  time_range?: TimeRange;
}

export interface SavedSearch {
  id?: string;
  user_id?: string;
  name: string;
  description: string;
  query: string;
  time_range?: TimeRange;
  tags: string[];
  is_default: boolean;
  is_shared: boolean;
  shared_with: string[];
  created_at?: string;
  updated_at?: string;
  last_used?: string;
  use_count?: number;
  metadata?: Record<string, any>;
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
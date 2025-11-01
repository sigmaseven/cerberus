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
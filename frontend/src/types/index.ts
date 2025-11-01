export interface Event {
  event_id: string;
  timestamp: string;
  source_format: string;
  source_ip?: string;
  event_type: string;
  severity: string;
  raw_data: string;
  fields: Record<string, unknown>;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  event_id: string;
  timestamp: string;
  severity: string;
  status: string;
  jira_ticket_id?: string;
  event: Event;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: string;
  version: string;
  enabled?: boolean;
  conditions: Condition[];
  actions: Action[];
}

export interface Condition {
  field: string;
  operator: string;
  value: unknown;
  logic: string;
}

export interface Action {
  id?: string;
  type: string;
  config: Record<string, unknown>;
}

export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  version: string;
  window: number; // in nanoseconds
  conditions?: Condition[];
  sequence: string[];
  actions: Action[];
  enabled?: boolean;
}

export interface ListenerConfig {
  syslog: {
    port: number;
    host: string;
  };
  cef: {
    port: number;
    host: string;
  };
  json: {
    port: number;
    host: string;
    tls: boolean;
  };
}
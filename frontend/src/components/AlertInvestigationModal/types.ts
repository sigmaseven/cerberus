import { Alert, Event, StatusChange } from '../../types';

export interface AlertInvestigation {
  alert: Alert;
  event: Event;
  statusHistory: StatusChange[];
  relatedAlerts?: Alert[];
  relatedEvents?: Event[];
}

export interface InvestigationNote {
  id: string;
  alert_id: string;
  user: string;
  timestamp: string;
  content: string;
  category?: 'malicious' | 'benign' | 'needs-review';
}

export interface AlertInvestigationModalProps {
  alert: Alert | null;
  open: boolean;
  onClose: () => void;
  onAlertUpdated?: () => void;
}

export type TabValue = 'overview' | 'timeline' | 'related' | 'investigation' | 'raw';

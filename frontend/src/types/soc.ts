export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IncidentStatus = 'Open' | 'Investigating' | 'Escalated' | 'Closed';

export interface AlertIncident {
  alert_id: string;
  timestamp: string;
  host: string;
  severity: SeverityLevel;
  risk_score: number;
  mitre_id: string;
  mitre_name: string;
  detection_title: string;
  process_command: string;
  process_image: string;
  dest_ip: string;
  dest_port: number;
  shannon_entropy: number;
  status: IncidentStatus;
  matched_rules?: string[];
  matched_iocs?: string[];
  raw_ecs?: Record<string, any>;
}

export interface TriageKPIs {
  total_events: number;
  critical_alerts: number;
  high_alerts: number;
  avg_risk_score: number;
  latency_ms: number;
}

export interface SeverityDistribution {
  name: SeverityLevel;
  count: number;
  color: string;
}

export interface MitreDistribution {
  technique: string;
  count: number;
}

export interface TriageResult {
  total_events: number;
  alert_count: number;
  alerts: AlertIncident[];
  kpis: TriageKPIs;
  distributions: {
    severity: SeverityDistribution[];
    mitre: MitreDistribution[];
  };
}

export interface IOCEntry {
  value: string;
  threat: string;
  severity: string;
  tags?: string[];
}

export interface IOCStore {
  stats: {
    sha256_count: number;
    domains_count: number;
    ips_count: number;
  };
  iocs: {
    sha256: IOCEntry[];
    ips: IOCEntry[];
    domains: IOCEntry[];
  };
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tactic_name: string;
  description: string;
  count: number;
}

export interface MitreTacticGroup {
  tactic_id: string;
  tactic_name: string;
  description: string;
  techniques: MitreTechnique[];
  total_hits: number;
}

export interface SystemSubsystem {
  name: string;
  status: string;
  version?: string;
  healthy: boolean;
  rules_loaded?: number;
  estimators?: number;
  db_path?: string;
  port?: number;
}

export interface HealthStatus {
  status: string;
  subsystems: Record<string, SystemSubsystem>;
  engine_status: string;
  timestamp: number;
}

export interface SystemSettings {
  worker_threads: number;
  max_memory_ceiling_mb: number;
  server_port: number;
  syslog_port: number;
  default_export_format: string;
  min_risk_threshold: number;
  contamination: number;
  n_estimators: number;
}

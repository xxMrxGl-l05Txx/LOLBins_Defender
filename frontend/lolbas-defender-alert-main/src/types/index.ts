
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type AlertStatus = "new" | "acknowledged" | "resolved" | "false_positive";

export type ConnectionState = "connecting" | "online" | "offline";

export interface AlertRule {
  binary?: string;
  description?: string;
  mitre_attack_id?: string;
  mitre_link?: string;
  command_patterns?: string[];
  parent_process_hints?: string[];
}

export interface AlertProcessInfo {
  pid?: number;
  ppid?: number;
  name?: string;
  exe?: string;
  cmdline?: string[];
  username?: string;
  create_time?: number;
}

export interface AlertMetadata {
  test?: boolean;
  rule?: AlertRule;
  patterns_matched?: string[];
  process_info?: AlertProcessInfo;
  detection_result?: {
    threat_type?: string;
    confidence_score?: number;
    indicators_matched?: string[];
    recommended_actions?: string[];
  };
  suspicious_connections?: Array<{
    remote_address?: string;
    remote_port?: number;
    status?: string;
  }>;
  [key: string]: unknown;
}

export interface SecurityAlert {
  id: string;
  /** Milliseconds since epoch */
  timestamp: number;
  type: string;
  severity: Severity;
  binary: string | null;
  command: string | null;
  processId: number | null;
  userName: string | null;
  systemName: string | null;
  mitreId: string | null;
  mitreLink: string | null;
  details: string;
  status: AlertStatus;
  acknowledgedAt: number | null;
  resolvedAt: number | null;
  metadata: AlertMetadata;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
  mitigation: string;
}

export interface ChartData {
  name: string;
  value: number;
}

export interface TimelinePoint {
  /** ISO date (YYYY-MM-DD) */
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk: number;
}

export interface DashboardSummary {
  alerts: {
    total: number;
    total_24h: number;
    new: number;
    active: number;
    critical_24h: number;
    high_24h: number;
    by_status: Record<AlertStatus, number>;
    by_severity: Record<Severity, number>;
  };
  system: {
    cpu_percent: number | null;
    memory_percent: number | null;
    disk_percent: number | null;
    process_count: number | null;
    timestamp: number | null;
  };
  risk_score: number;
  timeline: TimelinePoint[];
  distribution: ChartData[];
  timestamp: string;
}

export interface BackendStatus {
  status: string;
  version: string;
  hostname: string;
  uptime_seconds: number;
  service: null | {
    running: boolean;
    uptime_seconds: number;
    statistics: {
      cycles_completed: number;
      last_cycle_time: number;
      last_scan_at: number | null;
    };
    configuration: {
      monitoring_interval: number;
      lolbin_detection_enabled: boolean;
    };
  };
  capabilities: {
    scan: boolean;
    authentication: boolean;
  };
}

export interface MonitoringSettings {
  cpu_threshold: number;
  memory_threshold: number;
  disk_threshold: number;
  network_threshold: number;
  monitor_interval: number;
  enable_lolbin_detection: boolean;
  enable_process_monitoring: boolean;
  enable_file_monitoring: boolean;
  enable_registry_monitoring: boolean;
}

export interface AlertingSettings {
  enable_email_alerts: boolean;
  enable_sms_alerts: boolean;
  enable_desktop_notifications: boolean;
  enable_webhook_alerts: boolean;
  alert_cooldown_seconds: number;
  max_alerts_per_hour: number;
  email_smtp_server: string | null;
  email_smtp_port: number;
  email_username: string | null;
  webhook_url: string | null;
}

export interface SystemConfig {
  monitoring: MonitoringSettings;
  alerting: AlertingSettings;
  api: {
    host: string;
    port: number;
    enable_cors: boolean;
    enable_rate_limiting: boolean;
    rate_limit_per_minute: number;
    enable_authentication: boolean;
  };
  log_level: string;
  data_retention_days: number;
  enable_auto_cleanup: boolean;
}

export interface ConfigUpdate {
  monitoring?: Partial<MonitoringSettings>;
  alerting?: Partial<Pick<AlertingSettings,
    "enable_desktop_notifications" | "enable_email_alerts" | "enable_webhook_alerts" |
    "alert_cooldown_seconds" | "max_alerts_per_hour">>;
  log_level?: string;
  data_retention_days?: number;
  enable_auto_cleanup?: boolean;
}

export type ReportFormat = "html" | "csv" | "json";

export interface ReportFile {
  filename: string;
  format: ReportFormat;
  size: number;
  created: string;
  download_url: string;
}

export interface ReportRequest {
  format: ReportFormat;
  /** 0 means all time */
  days: number;
  include_details: boolean;
  include_mitre: boolean;
  include_commands: boolean;
}

export interface DetectionRule {
  binary: string;
  description: string;
  mitre_attack_id: string | null;
  mitre_link: string | null;
  command_patterns: string[];
  parent_process_hints: string[];
  /** Highest severity this rule can produce */
  severity: Severity;
}

export interface RuleTestResult {
  binary: string;
  known_binary: boolean;
  matched: boolean;
  severity: Severity | null;
  patterns_matched: string[];
  rule: DetectionRule | null;
}

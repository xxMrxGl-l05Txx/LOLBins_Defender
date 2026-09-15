import type {
  AlertMetadata,
  AlertStatus,
  BackendStatus,
  ConfigUpdate,
  DashboardSummary,
  DetectionRule,
  ReportFile,
  ReportRequest,
  RuleTestResult,
  SecurityAlert,
  Severity,
  SystemConfig,
} from "@/types";

// Empty base means same-origin requests, which the Vite dev server proxies to the backend
export const API_BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/+$/, "");
const API_KEY = import.meta.env.VITE_API_KEY;

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export const errorMessage = (error: unknown, fallback: string): string =>
  error instanceof Error && error.message ? error.message : fallback;

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (API_KEY) {
    headers.set("X-API-Key", API_KEY);
  }

  try {
    return await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError("Cannot reach the monitoring backend", 0);
  }
}

async function errorFrom(response: Response): Promise<ApiError> {
  let message = "";
  try {
    const body = await response.json();
    message = typeof body?.error === "string" ? body.error : "";
  } catch {
    // Not a JSON error body (e.g. the dev proxy reporting the backend is down)
  }
  if (!message) {
    message = response.status >= 500
      ? "The monitoring backend is not responding"
      : `Request failed (${response.status})`;
  }
  return new ApiError(message, response.status);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await send(path, init);
  if (!response.ok) {
    throw await errorFrom(response);
  }
  return (await response.json()) as T;
}

interface RawAlert {
  id: string;
  timestamp: number;
  type: string;
  severity: string;
  binary: string | null;
  command: string | null;
  process_id: number | null;
  user_name: string | null;
  system_name: string | null;
  mitre_id: string | null;
  mitre_link: string | null;
  details: string | null;
  status: string;
  acknowledged_at: number | null;
  resolved_at: number | null;
  metadata: AlertMetadata | null;
}

const toMillis = (seconds: number | null | undefined): number | null =>
  typeof seconds === "number" ? Math.round(seconds * 1000) : null;

export function mapAlert(raw: RawAlert): SecurityAlert {
  const severity = String(raw.severity ?? "").toUpperCase() as Severity;
  const status = raw.status as AlertStatus;

  return {
    id: raw.id,
    timestamp: toMillis(raw.timestamp) ?? Date.now(),
    type: raw.type || "unknown",
    severity: SEVERITIES.includes(severity) ? severity : "MEDIUM",
    binary: raw.binary || null,
    command: raw.command || null,
    processId: raw.process_id ?? null,
    userName: raw.user_name || null,
    systemName: raw.system_name || null,
    mitreId: raw.mitre_id || null,
    mitreLink: raw.mitre_link || null,
    details: raw.details ?? "",
    status: STATUSES.includes(status) ? status : "new",
    acknowledgedAt: toMillis(raw.acknowledged_at),
    resolvedAt: toMillis(raw.resolved_at),
    metadata: raw.metadata ?? {},
  };
}

export interface AlertQuery {
  limit?: number;
  offset?: number;
  severity?: Severity;
  status?: AlertStatus | AlertStatus[];
  type?: string;
  /** Free-text search across binary, command, details, host, user and MITRE id */
  q?: string;
  /** Epoch seconds */
  start_date?: number;
}

export const api = {
  getStatus: () => request<BackendStatus>("/api/v1/status"),

  getAlerts: async (params: AlertQuery = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined || value === null || value === "") return;
      if (Array.isArray(value)) {
        if (value.length > 0) query.set(key, value.join(","));
        return;
      }
      query.set(key, String(value));
    });
    const data = await request<{ alerts: RawAlert[]; pagination: { total: number } }>(`/api/v1/alerts?${query}`);
    return { alerts: data.alerts.map(mapAlert), total: data.pagination.total };
  },

  getAlert: async (id: string) => {
    const data = await request<{ alert: RawAlert }>(`/api/v1/alerts/${encodeURIComponent(id)}`);
    return mapAlert(data.alert);
  },

  updateAlertStatus: async (id: string, status: AlertStatus) => {
    const data = await request<{ alert: RawAlert }>(`/api/v1/alerts/${encodeURIComponent(id)}/status`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    return mapAlert(data.alert);
  },

  bulkUpdateStatus: async (ids: string[], status: AlertStatus) => {
    const data = await request<{ updated: number }>("/api/v1/alerts/status", {
      method: "PUT",
      body: JSON.stringify({ ids, status }),
    });
    return data.updated;
  },

  clearAlerts: async () => {
    const data = await request<{ deleted: number }>("/api/v1/alerts", { method: "DELETE" });
    return data.deleted;
  },

  createTestAlert: async (severity: Severity = "HIGH") => {
    const data = await request<{ alert: RawAlert }>("/api/v1/alerts/test", {
      method: "POST",
      body: JSON.stringify({ severity }),
    });
    return mapAlert(data.alert);
  },

  triggerScan: () => request<{ message: string }>("/api/v1/scan", { method: "POST" }),

  getSummary: (days = 7) => request<DashboardSummary>(`/api/v1/dashboard/summary?days=${days}`),

  getRules: async () => {
    const data = await request<{ rules: DetectionRule[] }>("/api/v1/rules");
    return data.rules;
  },

  testRule: (command: string, binary?: string) =>
    request<RuleTestResult>("/api/v1/rules/test", {
      method: "POST",
      body: JSON.stringify({ command, binary: binary || undefined }),
    }),

  getConfig: async () => {
    const data = await request<{ config: SystemConfig }>("/api/v1/config");
    return data.config;
  },

  updateConfig: async (update: ConfigUpdate) => {
    const data = await request<{ config: SystemConfig }>("/api/v1/config", {
      method: "PUT",
      body: JSON.stringify(update),
    });
    return data.config;
  },

  listReports: async () => {
    const data = await request<{ reports: ReportFile[] }>("/api/v1/reports");
    return data.reports;
  },

  generateReport: async (report: ReportRequest) => {
    const data = await request<{ report: ReportFile }>("/api/v1/reports/generate", {
      method: "POST",
      body: JSON.stringify({ type: "summary", ...report }),
    });
    return data.report;
  },
};

/**
 * Download a backend file through fetch so the API key header (if any) is sent,
 * then hand it to the browser as a file save.
 */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const response = await send(path);
  if (!response.ok) {
    throw await errorFrom(response);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

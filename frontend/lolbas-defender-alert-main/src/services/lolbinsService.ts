
import type { AlertStatus, MitreTechnique, SecurityAlert, Severity } from "../types";

// MITRE ATT&CK techniques referenced by the backend LOLBin rules and threat patterns
export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  "T1059.001": {
    id: "T1059.001",
    name: "Command and Scripting Interpreter: PowerShell",
    tactic: "Execution",
    description: "Adversaries may abuse PowerShell commands and scripts for execution, often with encoded commands or download cradles.",
    url: "https://attack.mitre.org/techniques/T1059/001/",
    mitigation: "Enable PowerShell script block logging, use Constrained Language Mode, and restrict execution with application control."
  },
  "T1105": {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: "Command and Control",
    description: "Adversaries may transfer tools or other files from an external system into a compromised environment.",
    url: "https://attack.mitre.org/techniques/T1105/",
    mitigation: "Use network intrusion detection/prevention systems to detect and block suspicious file transfers."
  },
  "T1140": {
    id: "T1140",
    name: "Deobfuscate/Decode Files or Information",
    tactic: "Defense Evasion",
    description: "Adversaries may use obfuscated files or information to hide artifacts of an intrusion.",
    url: "https://attack.mitre.org/techniques/T1140/",
    mitigation: "Analyze file hashes and signatures to detect obfuscation techniques."
  },
  "T1218.005": {
    id: "T1218.005",
    name: "System Binary Proxy Execution: Mshta",
    tactic: "Defense Evasion",
    description: "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and JavaScript or VBScript.",
    url: "https://attack.mitre.org/techniques/T1218/005/",
    mitigation: "Block execution of mshta.exe through application control if it is not required."
  },
  "T1218.007": {
    id: "T1218.007",
    name: "System Binary Proxy Execution: Msiexec",
    tactic: "Defense Evasion",
    description: "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads, including remote MSI packages.",
    url: "https://attack.mitre.org/techniques/T1218/007/",
    mitigation: "Disable the AlwaysInstallElevated policy and restrict msiexec from installing packages from remote locations."
  },
  "T1218.009": {
    id: "T1218.009",
    name: "System Binary Proxy Execution: Regsvcs/Regasm",
    tactic: "Defense Evasion",
    description: "Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted .NET utility.",
    url: "https://attack.mitre.org/techniques/T1218/009/",
    mitigation: "Block Regsvcs.exe and Regasm.exe with application control where they are not needed."
  },
  "T1218.010": {
    id: "T1218.010",
    name: "System Binary Proxy Execution: Regsvr32",
    tactic: "Defense Evasion",
    description: "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code, including remote COM scriptlets.",
    url: "https://attack.mitre.org/techniques/T1218/010/",
    mitigation: "Use application control to prevent Regsvr32 from loading untrusted DLLs or scriptlets."
  },
  "T1218.011": {
    id: "T1218.011",
    name: "System Binary Proxy Execution: Rundll32",
    tactic: "Defense Evasion",
    description: "Adversaries may abuse rundll32.exe to proxy execution of malicious code.",
    url: "https://attack.mitre.org/techniques/T1218/011/",
    mitigation: "Use Group Policy to restrict rundll32.exe execution from user directories."
  },
  "T1047": {
    id: "T1047",
    name: "Windows Management Instrumentation",
    tactic: "Execution",
    description: "Adversaries may abuse WMI to execute malicious commands and payloads, locally or on remote systems.",
    url: "https://attack.mitre.org/techniques/T1047/",
    mitigation: "Restrict WMI permissions and monitor for process creation via WMI and shadow copy deletion."
  },
  "T1197": {
    id: "T1197",
    name: "BITS Jobs",
    tactic: "Defense Evasion, Persistence",
    description: "Adversaries may abuse BITS to download, execute, and clean up after code.",
    url: "https://attack.mitre.org/techniques/T1197/",
    mitigation: "Monitor for BITS jobs created by non-standard users or with suspicious parameters."
  },
  "T1543.003": {
    id: "T1543.003",
    name: "Create or Modify System Process: Windows Service",
    tactic: "Persistence, Privilege Escalation",
    description: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
    url: "https://attack.mitre.org/techniques/T1543/003/",
    mitigation: "Restrict who can create or modify services and alert on new services with unusual binary paths."
  },
  "T1021": {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    description: "Adversaries may use valid accounts to log into remote services such as RDP, SMB or WinRM.",
    url: "https://attack.mitre.org/techniques/T1021/",
    mitigation: "Use multi-factor authentication and limit remote service access to required accounts."
  },
  "T1041": {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
    url: "https://attack.mitre.org/techniques/T1041/",
    mitigation: "Use network data loss prevention and monitor for unusual outbound data volumes."
  },
  "T1053": {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Execution, Persistence",
    description: "Adversaries may abuse task scheduling to execute malicious code at startup or on a schedule.",
    url: "https://attack.mitre.org/techniques/T1053/",
    mitigation: "Restrict task creation permissions and audit newly created scheduled tasks."
  },
  "T1548": {
    id: "T1548",
    name: "Abuse Elevation Control Mechanism",
    tactic: "Privilege Escalation",
    description: "Adversaries may circumvent mechanisms such as UAC to gain higher-level permissions.",
    url: "https://attack.mitre.org/techniques/T1548/",
    mitigation: "Set UAC to the highest level and remove users from the local administrators group."
  }
};

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

// Full class names so Tailwind can find them; colors come from --sev-* in index.css
export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical",
  HIGH: "bg-sev-high",
  MEDIUM: "bg-sev-medium",
  LOW: "bg-sev-low",
};

export const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-sev-critical",
  HIGH: "text-sev-high",
  MEDIUM: "text-sev-medium",
  LOW: "text-sev-low",
};

export const SEVERITY_CHART_COLORS: Record<Severity, string> = {
  CRITICAL: "hsl(var(--sev-critical))",
  HIGH: "hsl(var(--sev-high))",
  MEDIUM: "hsl(var(--sev-medium))",
  LOW: "hsl(var(--sev-low))",
};

export const STATUS_LABELS: Record<AlertStatus, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

export const humanize = (value: string): string => {
  const text = value.replace(/_/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
};

/** Short display name: the binary for process alerts, otherwise the alert type */
export const alertTitle = (alert: Pick<SecurityAlert, "binary" | "type">): string =>
  alert.binary || humanize(alert.type);

export const formatDate = (timestamp: number | null | undefined): string => {
  if (!timestamp) return "—";
  return new Date(timestamp).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

export const formatShortDateTime = (timestamp: number): string =>
  new Date(timestamp).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export const formatDay = (isoDate: string, options: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" }) =>
  new Date(`${isoDate}T00:00:00`).toLocaleDateString(undefined, options);

export const formatRelativeTime = (timestamp: number | null | undefined): string => {
  if (!timestamp) return "never";
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
};

export const formatDuration = (seconds: number | null | undefined): string => {
  if (seconds === null || seconds === undefined) return "—";
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${total}s`;
};

export const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const formatPercent = (value: number | null | undefined): string =>
  typeof value === "number" ? `${value.toFixed(1)}%` : "—";

export const getMitreTechniqueDetails = (techniqueId: string): MitreTechnique | undefined => {
  return MITRE_TECHNIQUES[techniqueId];
};

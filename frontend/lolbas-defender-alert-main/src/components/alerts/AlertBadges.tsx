import { cn } from "@/lib/utils";
import { SEVERITY_BG, SEVERITY_LABELS, STATUS_LABELS } from "@/services/lolbinsService";
import type { AlertStatus, Severity } from "@/types";

const SEVERITY_PILL: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical/15 text-sev-critical",
  HIGH: "bg-sev-high/15 text-sev-high",
  MEDIUM: "bg-sev-medium/15 text-sev-medium",
  LOW: "bg-sev-low/15 text-sev-low",
};

const STATUS_DOT: Record<AlertStatus, string> = {
  new: "bg-foreground",
  acknowledged: "bg-sev-medium",
  resolved: "bg-ok",
  false_positive: "bg-muted-foreground/60",
};

export const SeverityBadge = ({ severity, className }: { severity: Severity; className?: string }) => (
  <span
    className={cn(
      "inline-flex h-5 shrink-0 items-center rounded px-1.5 font-mono text-[10px] font-medium uppercase tracking-wider",
      SEVERITY_PILL[severity],
      className
    )}
  >
    {SEVERITY_LABELS[severity]}
  </span>
);

export const SeverityDot = ({ severity, className }: { severity: Severity; className?: string }) => (
  <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", SEVERITY_BG[severity], className)} aria-hidden="true" />
);

export const StatusBadge = ({ status, className }: { status: AlertStatus; className?: string }) => (
  <span
    className={cn(
      "inline-flex h-5 shrink-0 items-center gap-1.5 whitespace-nowrap rounded border px-1.5 text-2xs font-medium",
      status === "new" ? "text-foreground" : "text-muted-foreground",
      className
    )}
  >
    <span className={cn("h-1.5 w-1.5 rounded-full", STATUS_DOT[status])} />
    {STATUS_LABELS[status]}
  </span>
);

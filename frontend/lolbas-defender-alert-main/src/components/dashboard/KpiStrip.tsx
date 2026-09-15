import React from "react";
import { Link } from "react-router-dom";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { DashboardSummary } from "@/types";

const RISK_SEGMENTS = 20;

const riskLevel = (score: number) => {
  if (score >= 70) return { label: "Critical", text: "text-sev-critical", bar: "bg-sev-critical" };
  if (score >= 40) return { label: "Elevated", text: "text-sev-high", bar: "bg-sev-high" };
  if (score > 0) return { label: "Guarded", text: "text-sev-medium", bar: "bg-sev-medium" };
  return { label: "Clear", text: "text-ok", bar: "bg-ok" };
};

const KpiCell = ({
  label,
  value,
  sub,
  to,
  loading,
}: {
  label: string;
  value: React.ReactNode;
  sub: React.ReactNode;
  to?: string;
  loading: boolean;
}) => {
  const content = (
    <>
      <div className="label-caps">{label}</div>
      <div className="mt-2 font-mono text-3xl font-medium tabular leading-none">
        {loading ? <Skeleton className="h-8 w-14" /> : value}
      </div>
      <div className="mt-2.5 truncate text-xs text-muted-foreground">{loading ? " " : sub}</div>
    </>
  );

  const className = "block bg-card p-4";
  return to ? (
    <Link to={to} className={cn(className, "transition-colors hover:bg-accent/40")}>{content}</Link>
  ) : (
    <div className={className}>{content}</div>
  );
};

const KpiStrip = ({ summary, loading }: { summary?: DashboardSummary; loading: boolean }) => {
  const risk = summary?.risk_score ?? 0;
  const level = riskLevel(risk);
  const filled = Math.round((risk / 100) * RISK_SEGMENTS);
  const alerts = summary?.alerts;
  const resolved = alerts?.by_status.resolved ?? 0;
  const falsePositives = alerts?.by_status.false_positive ?? 0;

  return (
    <div className="grid gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-2 lg:grid-cols-5">
      <div className="bg-card p-4 sm:col-span-2 lg:col-span-1">
        <div className="flex items-center justify-between">
          <span className="label-caps">Risk score</span>
          {!loading && <span className={cn("text-xs font-medium", level.text)}>{level.label}</span>}
        </div>
        <div className="mt-2 flex items-baseline gap-1.5 leading-none">
          {loading ? (
            <Skeleton className="h-8 w-14" />
          ) : (
            <>
              <span className={cn("font-mono text-3xl font-medium tabular", level.text)}>{risk}</span>
              <span className="font-mono text-xs text-muted-foreground">/100</span>
            </>
          )}
        </div>
        <div className="mt-3 flex gap-[3px]" aria-hidden="true">
          {Array.from({ length: RISK_SEGMENTS }).map((_, index) => (
            <span key={index} className={cn("h-1.5 flex-1 rounded-[1px]", index < filled ? level.bar : "bg-muted")} />
          ))}
        </div>
      </div>

      <KpiCell
        label="Open alerts"
        value={alerts?.active ?? 0}
        sub={`${alerts?.new ?? 0} awaiting triage`}
        to="/alerts"
        loading={loading}
      />
      <KpiCell
        label="Last 24 hours"
        value={alerts?.total_24h ?? 0}
        sub={`${alerts?.critical_24h ?? 0} critical · ${alerts?.high_24h ?? 0} high`}
        to="/alerts?status=all"
        loading={loading}
      />
      <KpiCell
        label="Closed"
        value={resolved + falsePositives}
        sub={`${resolved} resolved · ${falsePositives} false positive`}
        to="/alerts?status=resolved"
        loading={loading}
      />
      <KpiCell
        label="All time"
        value={alerts?.total ?? 0}
        sub="stored detections"
        loading={loading}
      />
    </div>
  );
};

export default KpiStrip;

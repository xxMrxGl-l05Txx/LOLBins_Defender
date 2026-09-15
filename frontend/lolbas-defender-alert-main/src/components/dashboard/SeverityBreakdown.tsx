import { Link } from "react-router-dom";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel } from "@/components/common/Panel";
import { SeverityDot } from "@/components/alerts/AlertBadges";
import { cn } from "@/lib/utils";
import { SEVERITIES, SEVERITY_BG, SEVERITY_LABELS } from "@/services/lolbinsService";
import type { DashboardSummary } from "@/types";

const SeverityBreakdown = ({ summary, loading }: { summary?: DashboardSummary; loading: boolean }) => {
  const counts = summary?.alerts.by_severity;
  const total = counts ? SEVERITIES.reduce((sum, severity) => sum + counts[severity], 0) : 0;

  return (
    <Panel title="Severity mix" description="All stored alerts">
      {loading ? (
        <Skeleton className="h-20 w-full" />
      ) : (
        <>
          <div className="flex h-2 overflow-hidden rounded-full bg-muted" aria-hidden="true">
            {total > 0 &&
              SEVERITIES.map((severity) => (
                <span
                  key={severity}
                  className={cn("h-full", SEVERITY_BG[severity])}
                  style={{ width: `${(counts[severity] / total) * 100}%` }}
                />
              ))}
          </div>
          <ul className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2">
            {SEVERITIES.map((severity) => (
              <li key={severity}>
                <Link
                  to={`/alerts?status=all&severity=${severity.toLowerCase()}`}
                  className="flex items-center justify-between gap-2 rounded text-xs hover:text-foreground"
                >
                  <span className="flex items-center gap-2 text-muted-foreground">
                    <SeverityDot severity={severity} />
                    {SEVERITY_LABELS[severity]}
                  </span>
                  <span className="font-mono tabular">
                    {counts?.[severity] ?? 0}
                    <span className="ml-1.5 text-muted-foreground">
                      {total > 0 ? `${Math.round(((counts?.[severity] ?? 0) / total) * 100)}%` : "—"}
                    </span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
};

export default SeverityBreakdown;

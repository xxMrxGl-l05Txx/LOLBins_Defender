import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { Panel } from "@/components/common/Panel";
import { SeverityDot, StatusBadge } from "@/components/alerts/AlertBadges";
import { useAlerts } from "@/context/AlertContext";
import { cn } from "@/lib/utils";
import { alertTitle, formatRelativeTime } from "@/services/lolbinsService";

const LatestAlerts = ({ className }: { className?: string }) => {
  const { alerts, isLoading, openAlert } = useAlerts();
  const latest = alerts.slice(0, 8);

  return (
    <Panel
      className={className}
      flush
      title="Latest detections"
      description="Newest first · click to inspect"
      actions={
        <Link to="/alerts" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          All alerts
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      }
    >
      {isLoading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} className="h-10 w-full" />)}
        </div>
      ) : latest.length === 0 ? (
        <EmptyState
          title="No detections yet"
          description="Suspicious LOLBin activity will show up here. Run a scan or create a test alert to check the pipeline."
        />
      ) : (
        <ul className="divide-y">
          {latest.map((alert) => (
            <li key={alert.id}>
              <button
                type="button"
                onClick={() => openAlert(alert.id)}
                className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-accent/40 focus-visible:bg-accent/40 focus-visible:outline-none"
              >
                <SeverityDot severity={alert.severity} />
                <div className="min-w-0">
                  <div className={cn("truncate text-[13px]", alert.binary && "font-mono text-[12.5px]")}>{alertTitle(alert)}</div>
                  <div className="truncate text-xs text-muted-foreground">{alert.command ?? alert.details}</div>
                </div>
                <div className="flex items-center gap-3">
                  <StatusBadge status={alert.status} className="hidden sm:inline-flex" />
                  <span className="w-14 text-right font-mono text-2xs text-muted-foreground tabular">
                    {formatRelativeTime(alert.timestamp)}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
};

export default LatestAlerts;

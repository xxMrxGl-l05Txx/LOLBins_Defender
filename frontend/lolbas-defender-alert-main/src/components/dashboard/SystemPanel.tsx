import { Skeleton } from "@/components/ui/skeleton";
import { Meter } from "@/components/common/Meter";
import { Panel } from "@/components/common/Panel";
import { useAlerts } from "@/context/AlertContext";
import { formatDuration, formatPercent, formatRelativeTime } from "@/services/lolbinsService";
import type { DashboardSummary } from "@/types";

const SystemPanel = ({ summary, loading, className }: { summary?: DashboardSummary; loading: boolean; className?: string }) => {
  const { backendStatus } = useAlerts();
  const system = summary?.system;
  const sampledAt = system?.timestamp ? system.timestamp * 1000 : null;
  const service = backendStatus?.service;

  const resources: Array<[string, number | null | undefined]> = [
    ["CPU", system?.cpu_percent],
    ["Memory", system?.memory_percent],
    ["Disk", system?.disk_percent],
  ];

  return (
    <Panel
      className={className}
      title="System"
      description={sampledAt ? `Sampled ${formatRelativeTime(sampledAt)}` : "Waiting for the first scan"}
    >
      {loading ? (
        <Skeleton className="h-[260px] w-full" />
      ) : (
        <div className="flex h-full flex-col">
          <div className="space-y-4">
            {resources.map(([label, value]) => (
              <div key={label}>
                <div className="mb-1.5 flex items-baseline justify-between">
                  <span className="text-xs text-muted-foreground">{label}</span>
                  <span className="font-mono text-[13px] tabular">{formatPercent(value)}</span>
                </div>
                <Meter value={value} />
              </div>
            ))}
          </div>

          <dl className="mt-6 grid grid-cols-2 gap-px overflow-hidden rounded-md border bg-border text-xs">
            {[
              ["Processes", system?.process_count ?? "—"],
              ["Scans run", service?.statistics.cycles_completed ?? "—"],
              ["Service uptime", formatDuration(service?.uptime_seconds ?? backendStatus?.uptime_seconds)],
              ["Last cycle", service?.statistics.last_cycle_time ? `${service.statistics.last_cycle_time.toFixed(2)}s` : "—"],
            ].map(([label, value]) => (
              <div key={label as string} className="bg-card px-3 py-2.5">
                <dt className="text-2xs text-muted-foreground">{label}</dt>
                <dd className="mt-0.5 font-mono text-[13px] tabular">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </Panel>
  );
};

export default SystemPanel;

import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { Panel } from "@/components/common/Panel";
import type { DashboardSummary } from "@/types";

const TopSources = ({ summary, loading }: { summary?: DashboardSummary; loading: boolean }) => {
  const sources = summary?.distribution ?? [];
  const max = Math.max(1, ...sources.map((source) => source.value));

  return (
    <Panel title="Top sources" description="Binaries and alert types, last 7 days" flush={!loading && sources.length === 0}>
      {loading ? (
        <Skeleton className="h-32 w-full" />
      ) : sources.length === 0 ? (
        <EmptyState title="Nothing detected" description="No alerts in the last 7 days." className="py-8" />
      ) : (
        <ul className="space-y-1.5">
          {sources.map((source) => (
            <li key={source.name} className="relative flex h-7 items-center justify-between gap-3 overflow-hidden rounded px-2 text-xs">
              <span
                className="absolute inset-y-0 left-0 rounded bg-muted"
                style={{ width: `${(source.value / max) * 100}%` }}
                aria-hidden="true"
              />
              <span className="relative truncate font-mono">{source.name}</span>
              <span className="relative font-mono tabular text-muted-foreground">{source.value}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
};

export default TopSources;

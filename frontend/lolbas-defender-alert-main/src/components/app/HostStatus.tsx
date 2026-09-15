import { useAlerts } from "@/context/AlertContext";
import { useNow } from "@/hooks/use-now";
import { cn } from "@/lib/utils";
import { formatRelativeTime } from "@/services/lolbinsService";
import ScanButton from "@/components/alerts/ScanButton";
import ThemeToggle from "./ThemeToggle";

const HostStatus = () => {
  const { connection, backendStatus } = useAlerts();
  useNow(5000);
  const service = backendStatus?.service;

  let state = { dot: "bg-muted-foreground", label: "Connecting", live: false };
  if (connection === "offline") {
    state = { dot: "bg-sev-critical", label: "Backend offline", live: false };
  } else if (connection === "online" && service?.running) {
    state = { dot: "bg-ok", label: "Monitoring", live: true };
  } else if (connection === "online") {
    state = { dot: "bg-sev-medium", label: "API only", live: false };
  }

  const lastScan = service?.statistics.last_scan_at ? service.statistics.last_scan_at * 1000 : null;

  return (
    <div className="rounded-lg border bg-background p-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-medium">
          <span className="relative flex h-2 w-2">
            {state.live && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-40" />}
            <span className={cn("relative inline-flex h-2 w-2 rounded-full", state.dot)} />
          </span>
          {state.label}
        </div>
        <ThemeToggle className="-mr-1" />
      </div>
      <dl className="mt-2 space-y-1 font-mono text-2xs text-muted-foreground">
        <div className="flex justify-between gap-3">
          <dt>host</dt>
          <dd className="truncate text-foreground/80">{backendStatus?.hostname ?? "—"}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt>last scan</dt>
          <dd>{service ? formatRelativeTime(lastScan) : "—"}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt>interval</dt>
          <dd>{service ? `${service.configuration.monitoring_interval}s` : "—"}</dd>
        </div>
      </dl>
      <ScanButton size="xs" className="mt-3 w-full" />
    </div>
  );
};

export default HostStatus;

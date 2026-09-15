import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Check, Eye, RotateCcw, Search, ShieldX, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/common/EmptyState";
import { Panel } from "@/components/common/Panel";
import { SegmentedControl, type SegmentOption } from "@/components/common/SegmentedControl";
import { SeverityDot, StatusBadge } from "./AlertBadges";
import { useAlerts } from "@/context/AlertContext";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { cn } from "@/lib/utils";
import { SEVERITIES, alertTitle, formatRelativeTime, humanize } from "@/services/lolbinsService";
import type { AlertStatus, SecurityAlert, Severity } from "@/types";

type StatusFilter = "open" | "all" | AlertStatus;
type SeverityFilter = "all" | Severity;

const STATUS_OPTIONS: ReadonlyArray<SegmentOption<StatusFilter>> = [
  { value: "open", label: "Open" },
  { value: "new", label: "New" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False+" },
  { value: "all", label: "All" },
];

const SEVERITY_OPTIONS: ReadonlyArray<SegmentOption<SeverityFilter>> = [
  { value: "all", label: "All" },
  ...SEVERITIES.map((severity) => ({ value: severity, label: severity[0] + severity.slice(1).toLowerCase() })),
];

const PAGE_SIZE = 40;

const matchesStatus = (alert: SecurityAlert, filter: StatusFilter) => {
  if (filter === "all") return true;
  if (filter === "open") return alert.status === "new" || alert.status === "acknowledged";
  return alert.status === filter;
};

const AlertList = () => {
  const { alerts, totalAlerts, isLoading, openAlert, bulkSetStatus } = useAlerts();
  const [searchParams, setSearchParams] = useSearchParams();

  const statusParam = (searchParams.get("status") as StatusFilter) || "open";
  const status: StatusFilter = STATUS_OPTIONS.some((option) => option.value === statusParam) ? statusParam : "open";
  const severityParam = (searchParams.get("severity") || "all").toUpperCase();
  const severity: SeverityFilter = severityParam === "ALL" ? "all" : (SEVERITIES.includes(severityParam as Severity) ? (severityParam as Severity) : "all");

  const [search, setSearch] = useState(() => searchParams.get("q") ?? "");
  const debouncedSearch = useDebouncedValue(search.trim(), 200);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [pending, setPending] = useState(false);

  const setParam = (key: string, value: string | null) => {
    setSearchParams((params) => {
      const next = new URLSearchParams(params);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    }, { replace: true });
  };

  // Keep the q param in sync with the debounced search box
  useEffect(() => {
    setParam("q", debouncedSearch || null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch]);

  const filtered = useMemo(() => {
    const term = debouncedSearch.toLowerCase();
    return alerts.filter((alert) => {
      if (!matchesStatus(alert, status)) return false;
      if (severity !== "all" && alert.severity !== severity) return false;
      if (!term) return true;
      return [alertTitle(alert), alert.type, alert.details, alert.command, alert.systemName, alert.userName, alert.mitreId, alert.id]
        .some((field) => field?.toLowerCase().includes(term));
    });
  }, [alerts, status, severity, debouncedSearch]);

  useEffect(() => setVisibleCount(PAGE_SIZE), [status, severity, debouncedSearch]);

  // Drop selections that are no longer in the filtered view
  useEffect(() => {
    setSelected((current) => {
      if (current.size === 0) return current;
      const visible = new Set(filtered.map((alert) => alert.id));
      const next = new Set([...current].filter((id) => visible.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [filtered]);

  const visible = filtered.slice(0, visibleCount);
  const allVisibleSelected = visible.length > 0 && visible.every((alert) => selected.has(alert.id));
  const someVisibleSelected = visible.some((alert) => selected.has(alert.id));

  const toggleAll = () => {
    setSelected((current) => {
      const next = new Set(current);
      if (allVisibleSelected) visible.forEach((alert) => next.delete(alert.id));
      else visible.forEach((alert) => next.add(alert.id));
      return next;
    });
  };

  const toggleOne = (id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const applyBulk = async (nextStatus: AlertStatus) => {
    setPending(true);
    const ok = await bulkSetStatus([...selected], nextStatus);
    if (ok) setSelected(new Set());
    setPending(false);
  };

  const resultLabel = totalAlerts > alerts.length
    ? `${filtered.length} of latest ${alerts.length}`
    : `${filtered.length} alert${filtered.length === 1 ? "" : "s"}`;

  return (
    <Panel
      flush
      title={<span className="flex items-center gap-2">Alerts <span className="font-mono text-2xs font-normal text-muted-foreground tabular">{resultLabel}</span></span>}
      actions={
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search…"
            className="h-8 w-44 pl-8 text-[13px] sm:w-60"
            aria-label="Search alerts"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
              aria-label="Clear search"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      }
    >
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2.5">
        <SegmentedControl
          aria-label="Filter by status"
          value={status}
          onChange={(value) => setParam("status", value === "open" ? null : value)}
          options={STATUS_OPTIONS}
        />
        <SegmentedControl
          aria-label="Filter by severity"
          value={severity}
          onChange={(value) => setParam("severity", value === "all" ? null : value.toLowerCase())}
          options={SEVERITY_OPTIONS}
        />
      </div>

      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 border-b bg-accent/40 px-4 py-2">
          <span className="text-xs font-medium">{selected.size} selected</span>
          <div className="ml-auto flex flex-wrap gap-1.5">
            <Button size="xs" variant="outline" disabled={pending} onClick={() => applyBulk("acknowledged")}>
              <Eye />
              Acknowledge
            </Button>
            <Button size="xs" variant="outline" disabled={pending} onClick={() => applyBulk("resolved")}>
              <Check />
              Resolve
            </Button>
            <Button size="xs" variant="outline" disabled={pending} onClick={() => applyBulk("false_positive")}>
              <ShieldX />
              False positive
            </Button>
            <Button size="xs" variant="outline" disabled={pending} onClick={() => applyBulk("new")}>
              <RotateCcw />
              Reopen
            </Button>
            <Button size="xs" variant="ghost" onClick={() => setSelected(new Set())}>
              Clear
            </Button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="px-4 py-12 text-center text-[13px] text-muted-foreground">Loading alerts…</div>
      ) : visible.length === 0 ? (
        <EmptyState
          title={alerts.length === 0 ? "No alerts recorded" : "No alerts match these filters"}
          description={alerts.length === 0
            ? "Run a scan or create a test alert to verify the pipeline."
            : "Try a different status, severity or search term."}
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="border-b text-left align-middle">
                <th className="w-10 py-2 pl-4">
                  <Checkbox
                    checked={allVisibleSelected ? true : someVisibleSelected ? "indeterminate" : false}
                    onCheckedChange={toggleAll}
                    aria-label="Select all visible alerts"
                  />
                </th>
                <th className="label-caps py-2 pr-3 font-medium">Alert</th>
                <th className="label-caps hidden py-2 pr-3 font-medium lg:table-cell">Detail</th>
                <th className="label-caps hidden py-2 pr-3 font-medium md:table-cell">Host</th>
                <th className="label-caps py-2 pr-3 font-medium">Status</th>
                <th className="label-caps py-2 pr-4 text-right font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((alert) => {
                const isSelected = selected.has(alert.id);
                return (
                  <tr
                    key={alert.id}
                    onClick={() => openAlert(alert.id)}
                    className={cn(
                      "cursor-pointer border-b border-border/60 transition-colors last:border-0 hover:bg-accent/40",
                      isSelected && "bg-accent/50"
                    )}
                  >
                    <td className="py-2.5 pl-4" onClick={(event) => event.stopPropagation()}>
                      <Checkbox checked={isSelected} onCheckedChange={() => toggleOne(alert.id)} aria-label={`Select ${alertTitle(alert)}`} />
                    </td>
                    <td className="max-w-[240px] py-2.5 pr-3">
                      <div className="flex items-center gap-2">
                        <SeverityDot severity={alert.severity} />
                        <span className={cn("truncate", alert.binary && "font-mono text-[12.5px]")}>{alertTitle(alert)}</span>
                      </div>
                      <div className="mt-0.5 pl-4 text-2xs text-muted-foreground">{humanize(alert.type)}</div>
                    </td>
                    <td className="hidden max-w-[340px] py-2.5 pr-3 lg:table-cell">
                      <span className={cn("block truncate text-xs text-muted-foreground", alert.command && "font-mono")}>
                        {alert.command ?? alert.details}
                      </span>
                    </td>
                    <td className="hidden py-2.5 pr-3 font-mono text-xs text-muted-foreground md:table-cell">
                      {alert.systemName ?? "—"}
                    </td>
                    <td className="py-2.5 pr-3">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="whitespace-nowrap py-2.5 pr-4 text-right font-mono text-2xs text-muted-foreground tabular">
                      {formatRelativeTime(alert.timestamp)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filtered.length > visibleCount && (
            <div className="flex justify-center border-t px-4 py-3">
              <Button variant="outline" size="sm" onClick={() => setVisibleCount((count) => count + PAGE_SIZE)}>
                Show more ({filtered.length - visibleCount} remaining)
              </Button>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
};

export default AlertList;

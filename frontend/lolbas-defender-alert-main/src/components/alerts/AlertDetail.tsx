import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Check, ChevronRight, Eye, RotateCcw, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { CopyButton } from "@/components/common/CopyButton";
import { HighlightedCommand } from "@/components/common/HighlightedCommand";
import { useAlerts } from "@/context/AlertContext";
import { api, ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  alertTitle,
  formatDate,
  formatRelativeTime,
  getMitreTechniqueDetails,
  humanize,
} from "@/services/lolbinsService";
import { SeverityBadge, StatusBadge } from "./AlertBadges";
import type { AlertStatus } from "@/types";

interface AlertDetailProps {
  alertId: string;
  variant?: "page" | "sheet";
}

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <section className="mt-6 border-t pt-5">
    <h3 className="label-caps mb-3">{title}</h3>
    {children}
  </section>
);

const Field = ({ label, children, className }: { label: string; children?: React.ReactNode; className?: string }) => (
  <div className={cn("min-w-0", className)}>
    <dt className="text-2xs text-muted-foreground">{label}</dt>
    <dd className="mt-0.5 break-words text-[13px]">
      {children ?? <span className="text-muted-foreground">—</span>}
    </dd>
  </div>
);

const Chip = ({ children, tone }: { children: React.ReactNode; tone?: "match" }) => (
  <code
    className={cn(
      "rounded border px-1.5 py-0.5 font-mono text-2xs",
      tone === "match" ? "border-sev-high/30 bg-sev-high/10 text-sev-high" : "bg-background text-muted-foreground"
    )}
  >
    {children}
  </code>
);

const AlertDetail = ({ alertId, variant = "page" }: AlertDetailProps) => {
  const navigate = useNavigate();
  const { getAlertById, setAlertStatus, closeAlert } = useAlerts();
  const [pending, setPending] = useState<AlertStatus | null>(null);
  const isSheet = variant === "sheet";

  const { data: alert, isLoading, error, refetch } = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => api.getAlert(alertId),
    placeholderData: () => getAlertById(alertId),
    retry: false,
  });

  if (!alert) {
    if (isLoading) {
      return (
        <div className={cn("space-y-3", isSheet && "p-6")}>
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-8 w-2/3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-32 w-full" />
        </div>
      );
    }

    const notFound = !error || (error instanceof ApiError && error.status === 404);
    return (
      <div className={cn("py-12 text-center", isSheet && "px-6")}>
        <p className="text-[15px] font-medium">{notFound ? "Alert not found" : "Could not load alert"}</p>
        <p className="mt-1 text-[13px] text-muted-foreground">
          {notFound ? "It may have been deleted or removed by the retention policy." : errorMessage(error, "Unknown error")}
        </p>
        {!notFound && (
          <Button className="mt-4" size="sm" variant="outline" onClick={() => refetch()}>
            Retry
          </Button>
        )}
      </div>
    );
  }

  const meta = alert.metadata ?? {};
  const technique = alert.mitreId ? getMitreTechniqueDetails(alert.mitreId) : undefined;
  const mitreUrl = technique?.url ?? alert.mitreLink ?? undefined;
  const detection = meta.detection_result;
  const connections = meta.suspicious_connections ?? [];
  const processInfo = meta.process_info;
  const observed = typeof meta.value === "number" ? meta.value : undefined;
  const threshold = typeof meta.threshold === "number" ? meta.threshold : undefined;
  const patterns = meta.patterns_matched ?? [];
  const isOpen = alert.status === "new" || alert.status === "acknowledged";

  const change = async (status: AlertStatus) => {
    setPending(status);
    await setAlertStatus(alert.id, status);
    setPending(null);
  };

  const events = [
    { label: "Detected", time: alert.timestamp },
    alert.acknowledgedAt ? { label: "Acknowledged", time: alert.acknowledgedAt } : null,
    alert.resolvedAt
      ? {
          label: alert.status === "false_positive"
            ? "Marked false positive"
            : alert.status === "resolved" ? "Resolved" : "Closed, later reopened",
          time: alert.resolvedAt,
        }
      : null,
  ].filter(Boolean) as Array<{ label: string; time: number }>;

  const rawEvent = JSON.stringify(alert, null, 2);

  return (
    <div className={cn(isSheet && "px-5 pb-10 pt-6 sm:px-6")}>
      <header className={cn(isSheet && "pr-8")}>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          <span className="font-mono text-2xs text-muted-foreground">{humanize(alert.type)}</span>
        </div>
        <h2
          className={cn(
            "mt-3 break-words font-semibold tracking-tight",
            isSheet ? "text-lg" : "text-2xl",
            alert.binary && "font-mono"
          )}
        >
          {alertTitle(alert)}
        </h2>
        <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{alert.details}</p>
        <p className="mt-2 text-xs text-muted-foreground">
          <span className="text-foreground/80">{formatDate(alert.timestamp)}</span>
          {" · "}
          {formatRelativeTime(alert.timestamp)}
          {alert.systemName && <> · <span className="font-mono">{alert.systemName}</span></>}
        </p>
      </header>

      <div className="mt-5 flex flex-wrap items-center gap-2">
        {alert.status === "new" && (
          <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => change("acknowledged")}>
            <Eye />
            Acknowledge
          </Button>
        )}
        {isOpen ? (
          <>
            <Button size="sm" disabled={pending !== null} onClick={() => change("resolved")}>
              <Check />
              Resolve
            </Button>
            <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => change("false_positive")}>
              <ShieldX />
              False positive
            </Button>
          </>
        ) : (
          <Button size="sm" variant="outline" disabled={pending !== null} onClick={() => change("new")}>
            <RotateCcw />
            Reopen
          </Button>
        )}
        {isSheet && (
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto text-muted-foreground"
            onClick={() => {
              closeAlert();
              navigate(`/alert/${alert.id}`);
            }}
          >
            Full page
            <ArrowUpRight />
          </Button>
        )}
      </div>

      {meta.test && (
        <div className="mt-5 rounded-md border border-dashed px-3 py-2.5 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Test alert.</span> Generated from the console to verify the alert
          pipeline — no command was executed.
        </div>
      )}

      {alert.command && (
        <Section title="Command line">
          <HighlightedCommand command={alert.command} patterns={patterns} />
          {patterns.length > 0 && (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-2xs text-muted-foreground">Matched</span>
              {patterns.map((pattern) => <Chip key={pattern} tone="match">{pattern}</Chip>)}
            </div>
          )}
        </Section>
      )}

      <Section title="Context">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
          <Field label="Host">{alert.systemName && <span className="font-mono text-xs">{alert.systemName}</span>}</Field>
          <Field label="User">{alert.userName && <span className="font-mono text-xs">{alert.userName}</span>}</Field>
          <Field label="Process ID">{alert.processId !== null && <span className="font-mono text-xs tabular">{alert.processId}</span>}</Field>
          {processInfo?.ppid !== undefined && (
            <Field label="Parent PID"><span className="font-mono text-xs tabular">{processInfo.ppid}</span></Field>
          )}
          {observed !== undefined && (
            <Field label="Observed">
              <span className="font-mono text-xs tabular">
                {observed.toFixed(1)}%{threshold !== undefined && <span className="text-muted-foreground"> / {threshold}% limit</span>}
              </span>
            </Field>
          )}
          {processInfo?.exe && (
            <Field label="Executable" className="col-span-full">
              <span className="font-mono text-xs">{processInfo.exe}</span>
            </Field>
          )}
          <Field label="Alert ID" className="col-span-full">
            <span className="flex items-center gap-1">
              <span className="truncate font-mono text-xs text-muted-foreground">{alert.id}</span>
              <CopyButton value={alert.id} label="Copy alert ID" />
            </span>
          </Field>
        </dl>
      </Section>

      {(meta.rule?.description || detection) && (
        <Section title="Detection">
          {meta.rule?.description && <p className="text-[13px] leading-relaxed">{meta.rule.description}</p>}
          {meta.rule?.parent_process_hints && meta.rule.parent_process_hints.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-2xs text-muted-foreground">Typically abused from</span>
              {meta.rule.parent_process_hints.map((hint) => <Chip key={hint}>{hint}</Chip>)}
            </div>
          )}
          {detection && (
            <div className="space-y-3">
              <p className="text-[13px]">
                {detection.threat_type}
                {typeof detection.confidence_score === "number" && (
                  <span className="ml-2 font-mono text-xs text-muted-foreground">
                    confidence {Math.round(detection.confidence_score * 100)}%
                  </span>
                )}
              </p>
              {detection.indicators_matched && detection.indicators_matched.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {detection.indicators_matched.map((indicator) => <Chip key={indicator} tone="match">{indicator}</Chip>)}
                </div>
              )}
              {detection.recommended_actions && detection.recommended_actions.length > 0 && (
                <ul className="space-y-1.5 text-[13px]">
                  {detection.recommended_actions.map((action) => (
                    <li key={action} className="flex gap-2">
                      <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-muted-foreground" />
                      {action}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Section>
      )}

      {connections.length > 0 && (
        <Section title="Network connections">
          <ul className="divide-y rounded-md border font-mono text-xs">
            {connections.map((connection, index) => (
              <li key={index} className="flex items-center justify-between px-3 py-2">
                <span>{connection.remote_address}:{connection.remote_port}</span>
                <span className="text-muted-foreground">{connection.status}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {alert.mitreId && (
        <Section title="MITRE ATT&CK">
          <div className="rounded-md border p-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="font-mono text-xs text-muted-foreground">{alert.mitreId}</div>
                <div className="mt-0.5 text-[13px] font-medium">{technique?.name ?? "Technique details"}</div>
                {technique && <div className="mt-0.5 text-2xs text-muted-foreground">Tactic · {technique.tactic}</div>}
              </div>
              {mitreUrl && (
                <Button variant="outline" size="xs" asChild>
                  <a href={mitreUrl} target="_blank" rel="noopener noreferrer">
                    attack.mitre.org
                    <ArrowUpRight />
                  </a>
                </Button>
              )}
            </div>
            {technique && (
              <>
                <p className="mt-3 text-[13px] leading-relaxed text-muted-foreground">{technique.description}</p>
                <div className="mt-3 border-t pt-3 text-[13px] leading-relaxed">
                  <span className="label-caps mr-2">Mitigation</span>
                  {technique.mitigation}
                </div>
              </>
            )}
          </div>
        </Section>
      )}

      <Section title="Timeline">
        <ol className="relative ml-1 space-y-4 border-l pl-4">
          {events.map((event) => (
            <li key={event.label} className="relative">
              <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full border-2 border-background bg-muted-foreground" />
              <div className="text-[13px]">{event.label}</div>
              <div className="font-mono text-2xs text-muted-foreground">{formatDate(event.time)}</div>
            </li>
          ))}
        </ol>
      </Section>

      <div className="mt-6 border-t pt-4">
        <Collapsible>
          <CollapsibleTrigger className="group inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
            <ChevronRight className="h-3.5 w-3.5 transition-transform group-data-[state=open]:rotate-90" />
            Raw event
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="relative mt-3">
              <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 pr-10 font-mono text-2xs leading-relaxed">
                {rawEvent}
              </pre>
              <CopyButton value={rawEvent} label="Copy JSON" className="absolute right-1.5 top-1.5" />
            </div>
          </CollapsibleContent>
        </Collapsible>
      </div>
    </div>
  );
};

export default AlertDetail;

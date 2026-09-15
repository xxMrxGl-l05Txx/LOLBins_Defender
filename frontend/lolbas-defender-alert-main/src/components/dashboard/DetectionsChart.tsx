import { useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel } from "@/components/common/Panel";
import { SegmentedControl } from "@/components/common/SegmentedControl";
import { SeverityDot } from "@/components/alerts/AlertBadges";
import {
  SEVERITIES,
  SEVERITY_CHART_COLORS,
  SEVERITY_LABELS,
  formatDay,
} from "@/services/lolbinsService";
import type { DashboardSummary, TimelinePoint } from "@/types";

type Mode = "volume" | "risk";

const AXIS_TICK = { fill: "hsl(var(--muted-foreground))", fontSize: 11, fontFamily: "IBM Plex Mono, monospace" };

const ChartTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ payload: TimelinePoint }> }) => {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;

  return (
    <div className="min-w-[180px] rounded-md border bg-popover px-3 py-2.5 text-xs shadow-lg">
      <div className="font-medium">{formatDay(point.date, { weekday: "long", month: "short", day: "numeric" })}</div>
      <div className="mt-2 space-y-1">
        {SEVERITIES.map((severity) => (
          <div key={severity} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <SeverityDot severity={severity} className="h-1.5 w-1.5" />
              {SEVERITY_LABELS[severity]}
            </span>
            <span className="font-mono tabular">{point[severity.toLowerCase() as "critical"]}</span>
          </div>
        ))}
      </div>
      <div className="mt-2 flex justify-between border-t pt-2 font-mono tabular">
        <span className="font-sans text-muted-foreground">Total · risk</span>
        <span>{point.total} · {point.risk}</span>
      </div>
    </div>
  );
};

const DetectionsChart = ({ summary, loading, className }: { summary?: DashboardSummary; loading: boolean; className?: string }) => {
  const [mode, setMode] = useState<Mode>("volume");
  const data = summary?.timeline ?? [];
  const total = data.reduce((sum, point) => sum + point.total, 0);
  // Bottom-to-top stacking order
  const stack = [...SEVERITIES].reverse();

  return (
    <Panel
      className={className}
      title="Detections"
      description={loading ? "Last 7 days" : `${total} alert${total === 1 ? "" : "s"} in the last 7 days`}
      actions={
        <SegmentedControl
          aria-label="Chart mode"
          value={mode}
          onChange={(value) => setMode(value)}
          options={[{ value: "volume", label: "Volume" }, { value: "risk", label: "Risk" }]}
        />
      }
    >
      <div className="h-[260px]">
        {loading ? (
          <Skeleton className="h-full w-full" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            {mode === "volume" ? (
              <BarChart data={data} margin={{ top: 8, right: 4, left: -16, bottom: 0 }} barCategoryGap="30%">
                <CartesianGrid vertical={false} stroke="hsl(var(--border))" />
                <XAxis dataKey="date" tickFormatter={(value) => formatDay(value)} tickLine={false} axisLine={false} tick={AXIS_TICK} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={AXIS_TICK} width={40} />
                <Tooltip cursor={{ fill: "hsl(var(--muted) / 0.7)" }} content={<ChartTooltip />} />
                {stack.map((severity) => (
                  <Bar
                    key={severity}
                    dataKey={severity.toLowerCase()}
                    stackId="severity"
                    fill={SEVERITY_CHART_COLORS[severity]}
                    maxBarSize={40}
                    isAnimationActive={false}
                  />
                ))}
              </BarChart>
            ) : (
              <AreaChart data={data} margin={{ top: 8, right: 4, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(var(--sev-high))" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="hsl(var(--sev-high))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} stroke="hsl(var(--border))" />
                <XAxis dataKey="date" tickFormatter={(value) => formatDay(value)} tickLine={false} axisLine={false} tick={AXIS_TICK} />
                <YAxis domain={[0, 100]} tickLine={false} axisLine={false} tick={AXIS_TICK} width={40} />
                <Tooltip cursor={{ stroke: "hsl(var(--border))" }} content={<ChartTooltip />} />
                <Area
                  type="monotone"
                  dataKey="risk"
                  stroke="hsl(var(--sev-high))"
                  strokeWidth={1.75}
                  fill="url(#riskFill)"
                  dot={{ r: 2.5, fill: "hsl(var(--card))", stroke: "hsl(var(--sev-high))", strokeWidth: 1.5 }}
                  activeDot={{ r: 4 }}
                  isAnimationActive={false}
                />
              </AreaChart>
            )}
          </ResponsiveContainer>
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-2xs text-muted-foreground">
        {mode === "volume" ? (
          SEVERITIES.map((severity) => (
            <span key={severity} className="inline-flex items-center gap-1.5">
              <SeverityDot severity={severity} className="h-1.5 w-1.5" />
              {SEVERITY_LABELS[severity]}
            </span>
          ))
        ) : (
          <span>Daily risk: critical 20 · high 10 · medium 3 · low 1 point per alert, capped at 100</span>
        )}
      </div>
    </Panel>
  );
};

export default DetectionsChart;

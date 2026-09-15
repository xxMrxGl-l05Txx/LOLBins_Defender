import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileDown, FileText } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/common/EmptyState";
import { Panel } from "@/components/common/Panel";
import { SegmentedControl } from "@/components/common/SegmentedControl";
import { useAlerts } from "@/context/AlertContext";
import { api, downloadFile, errorMessage } from "@/lib/api";
import { formatBytes, formatRelativeTime } from "@/services/lolbinsService";
import type { ReportFormat } from "@/types";

const FORMATS = [
  { value: "html" as const, label: "HTML" },
  { value: "csv" as const, label: "CSV" },
  { value: "json" as const, label: "JSON" },
];

const RANGES = [
  { value: "1" as const, label: "24h" },
  { value: "7" as const, label: "7 days" },
  { value: "30" as const, label: "30 days" },
  { value: "0" as const, label: "All" },
];

const FORMAT_HINT: Record<ReportFormat, string> = {
  html: "Self-contained page with charts, top alerts and recommendations.",
  csv: "One row per alert for spreadsheets or SIEM import.",
  json: "Full alert data, statistics and recent metrics.",
};

const ReportsPanel = () => {
  const { connection } = useAlerts();
  const queryClient = useQueryClient();
  const offline = connection !== "online";

  const [format, setFormat] = useState<ReportFormat>("html");
  const [range, setRange] = useState("7");
  const [includeDetails, setIncludeDetails] = useState(true);
  const [includeMitre, setIncludeMitre] = useState(true);
  const [includeCommands, setIncludeCommands] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const reportsQuery = useQuery({ queryKey: ["reports"], queryFn: api.listReports, retry: false });
  const reports = reportsQuery.data ?? [];

  const generate = async () => {
    setGenerating(true);
    try {
      const report = await api.generateReport({
        format,
        days: Number(range),
        include_details: includeDetails,
        include_mitre: includeMitre,
        include_commands: includeCommands,
      });
      await downloadFile(report.download_url, report.filename);
      toast.success("Report generated", { description: report.filename });
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    } catch (error) {
      toast.error(errorMessage(error, "Failed to generate report"));
    } finally {
      setGenerating(false);
    }
  };

  const download = async (url: string, filename: string) => {
    setDownloading(filename);
    try {
      await downloadFile(url, filename);
    } catch (error) {
      toast.error(errorMessage(error, "Failed to download report"));
    } finally {
      setDownloading(null);
    }
  };

  const options: Array<[string, boolean, (v: boolean) => void, string]> = [
    ["Details", includeDetails, setIncludeDetails, "Alert descriptions and recommendations"],
    ["Commands", includeCommands, setIncludeCommands, "Full command lines"],
    ["MITRE ATT&CK", includeMitre, setIncludeMitre, "Technique IDs and links"],
  ];

  return (
    <div className="grid items-start gap-4 lg:grid-cols-5 lg:gap-5">
      <Panel title="Generate report" className="lg:col-span-2">
        <div className="space-y-5">
          <div>
            <Label className="mb-2 block text-xs">Format</Label>
            <SegmentedControl aria-label="Report format" value={format} onChange={(value) => setFormat(value)} options={FORMATS} />
            <p className="mt-2 text-2xs text-muted-foreground">{FORMAT_HINT[format]}</p>
          </div>

          <div>
            <Label className="mb-2 block text-xs">Time range</Label>
            <SegmentedControl aria-label="Time range" value={range} onChange={(value) => setRange(value)} options={RANGES} />
          </div>

          <div>
            <Label className="mb-2 block text-xs">Include</Label>
            <div className="space-y-2">
              {options.map(([label, checked, setChecked, hint]) => (
                <label key={label} className="flex cursor-pointer items-start gap-2.5">
                  <Checkbox checked={checked} onCheckedChange={(value) => setChecked(value === true)} className="mt-0.5" />
                  <span>
                    <span className="text-[13px]">{label}</span>
                    <span className="block text-2xs text-muted-foreground">{hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <Button className="w-full" onClick={generate} disabled={generating || offline}>
            <FileDown />
            {generating ? "Generating…" : "Generate & download"}
          </Button>
        </div>
      </Panel>

      <Panel
        flush
        className="lg:col-span-3"
        title="Recent reports"
        description="Includes scheduled daily and weekly summaries"
        actions={
          <Button variant="ghost" size="xs" onClick={() => reportsQuery.refetch()} disabled={reportsQuery.isFetching}>
            Refresh
          </Button>
        }
      >
        {reportsQuery.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-10 w-full" />)}
          </div>
        ) : reportsQuery.isError ? (
          <EmptyState title="Could not load reports" description={errorMessage(reportsQuery.error, "The backend is unreachable.")} />
        ) : reports.length === 0 ? (
          <EmptyState title="No reports yet" description="Generate one, or wait for the scheduled daily summary." />
        ) : (
          <ul className="divide-y">
            {reports.slice(0, 20).map((report) => (
              <li key={report.filename} className="flex items-center gap-3 px-4 py-2.5">
                <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-xs">{report.filename}</div>
                  <div className="text-2xs text-muted-foreground">
                    <span className="uppercase">{report.format}</span> · {formatBytes(report.size)} · {formatRelativeTime(new Date(report.created).getTime())}
                  </div>
                </div>
                <Button
                  size="xs"
                  variant="outline"
                  disabled={downloading === report.filename}
                  onClick={() => download(report.download_url, report.filename)}
                >
                  <Download />
                  Download
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
};

export default ReportsPanel;

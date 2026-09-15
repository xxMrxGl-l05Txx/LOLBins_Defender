import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/common/PageHeader";
import ScanButton from "@/components/alerts/ScanButton";
import TestAlertMenu from "@/components/alerts/TestAlertMenu";
import KpiStrip from "@/components/dashboard/KpiStrip";
import DetectionsChart from "@/components/dashboard/DetectionsChart";
import SystemPanel from "@/components/dashboard/SystemPanel";
import SeverityBreakdown from "@/components/dashboard/SeverityBreakdown";
import TopSources from "@/components/dashboard/TopSources";
import LatestAlerts from "@/components/dashboard/LatestAlerts";
import { useDashboardSummary } from "@/hooks/use-dashboard-summary";
import { useCsvExport } from "@/hooks/use-csv-export";
import { useAlerts } from "@/context/AlertContext";

const Dashboard = () => {
  const { data: summary, isLoading } = useDashboardSummary();
  const { exportCsv, exporting } = useCsvExport();
  const { connection, backendStatus } = useAlerts();
  const loading = isLoading || !summary;
  const offline = connection !== "online";

  return (
    <>
      <PageHeader
        eyebrow={`console / ${backendStatus?.hostname ?? "overview"}`}
        title="Overview"
        description="Live posture across LOLBin detections, anomalies and host resources."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => exportCsv(0)} disabled={exporting || offline}>
              <Download />
              {exporting ? "Exporting…" : "Export CSV"}
            </Button>
            <TestAlertMenu />
            <ScanButton />
          </>
        }
      />

      <div className="space-y-4 lg:space-y-5">
        <KpiStrip summary={summary} loading={loading} />

        <div className="grid gap-4 lg:grid-cols-3 lg:gap-5">
          <DetectionsChart summary={summary} loading={loading} className="lg:col-span-2" />
          <SystemPanel summary={summary} loading={loading} />
        </div>

        <div className="grid items-start gap-4 lg:grid-cols-3 lg:gap-5">
          <LatestAlerts className="lg:col-span-2" />
          <div className="space-y-4 lg:space-y-5">
            <SeverityBreakdown summary={summary} loading={loading} />
            <TopSources summary={summary} loading={loading} />
          </div>
        </div>
      </div>
    </>
  );
};

export default Dashboard;

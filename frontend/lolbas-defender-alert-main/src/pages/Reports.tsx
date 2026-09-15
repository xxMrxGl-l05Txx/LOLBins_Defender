import { PageHeader } from "@/components/common/PageHeader";
import ReportsPanel from "@/components/reports/ReportsPanel";

const Reports = () => (
  <>
    <PageHeader
      eyebrow="console / reports"
      title="Reports"
      description="Export detections and system activity as an HTML summary, a CSV for analysis, or JSON for automation."
    />
    <ReportsPanel />
  </>
);

export default Reports;

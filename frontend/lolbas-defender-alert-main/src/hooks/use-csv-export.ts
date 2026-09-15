import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, downloadFile, errorMessage } from "@/lib/api";

/** Generate a CSV report on the backend and download it */
export const useCsvExport = () => {
  const queryClient = useQueryClient();
  const [exporting, setExporting] = useState(false);

  const exportCsv = async (days = 0) => {
    setExporting(true);
    try {
      const report = await api.generateReport({
        format: "csv",
        days,
        include_details: true,
        include_mitre: true,
        include_commands: true,
      });
      await downloadFile(report.download_url, report.filename);
      toast.success("CSV exported", { description: report.filename });
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    } catch (error) {
      toast.error(errorMessage(error, "Export failed"));
    } finally {
      setExporting(false);
    }
  };

  return { exportCsv, exporting };
};

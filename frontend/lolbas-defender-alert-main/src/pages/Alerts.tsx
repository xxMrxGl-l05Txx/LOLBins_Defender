import { useState } from "react";
import { Trash2 } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button, buttonVariants } from "@/components/ui/button";
import { PageHeader } from "@/components/common/PageHeader";
import ScanButton from "@/components/alerts/ScanButton";
import TestAlertMenu from "@/components/alerts/TestAlertMenu";
import AlertList from "@/components/alerts/AlertList";
import { useAlerts } from "@/context/AlertContext";
import { useCsvExport } from "@/hooks/use-csv-export";
import { Download } from "lucide-react";

const Alerts = () => {
  const { totalAlerts, clearAllAlerts, connection } = useAlerts();
  const { exportCsv, exporting } = useCsvExport();
  const [clearing, setClearing] = useState(false);
  const offline = connection !== "online";

  const handleClearAll = async () => {
    setClearing(true);
    await clearAllAlerts();
    setClearing(false);
  };

  return (
    <>
      <PageHeader
        eyebrow="console / alerts"
        title="Alerts"
        description="Triage detections: acknowledge, resolve or flag false positives. Select rows for bulk actions."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => exportCsv(0)} disabled={exporting || offline}>
              <Download />
              {exporting ? "Exporting…" : "Export CSV"}
            </Button>
            <TestAlertMenu />
            <ScanButton />
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" size="sm" disabled={offline || clearing || totalAlerts === 0} className="text-sev-critical hover:text-sev-critical">
                  <Trash2 />
                  Clear all
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Delete all alerts?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This permanently deletes all {totalAlerts} alert{totalAlerts === 1 ? "" : "s"} from the database.
                    Generated reports are kept. This cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction className={buttonVariants({ variant: "destructive" })} onClick={handleClearAll}>
                    Delete all
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </>
        }
      />
      <AlertList />
    </>
  );
};

export default Alerts;

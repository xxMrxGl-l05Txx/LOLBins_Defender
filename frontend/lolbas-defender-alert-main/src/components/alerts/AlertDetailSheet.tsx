import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { useAlerts } from "@/context/AlertContext";
import AlertDetail from "./AlertDetail";

/** Right-hand drawer for inspecting an alert without leaving the current page */
const AlertDetailSheet = () => {
  const { selectedAlertId, closeAlert } = useAlerts();

  return (
    <Sheet open={selectedAlertId !== null} onOpenChange={(open) => !open && closeAlert()}>
      <SheetContent side="right" className="w-full overflow-y-auto p-0 sm:max-w-xl" aria-describedby={undefined}>
        <SheetTitle className="sr-only">Alert details</SheetTitle>
        {selectedAlertId && <AlertDetail alertId={selectedAlertId} variant="sheet" />}
      </SheetContent>
    </Sheet>
  );
};

export default AlertDetailSheet;

import { Button } from "@/components/ui/button";
import { useAlerts } from "@/context/AlertContext";

const OfflineBanner = () => {
  const { connection, refresh } = useAlerts();

  if (connection !== "offline") {
    return null;
  }

  return (
    <div className="border-b border-sev-critical/25 bg-sev-critical/10 px-4 py-2.5 sm:px-6 lg:px-8" role="alert">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-3 gap-y-2 text-[13px]">
        <span className="h-2 w-2 shrink-0 rounded-full bg-sev-critical" />
        <span className="font-medium">Backend unreachable.</span>
        <span className="text-muted-foreground">Start the service from the project root:</span>
        <code className="rounded border bg-background/70 px-1.5 py-0.5 font-mono text-xs">
          python -m backend.utils.enhanced_service_runner
        </code>
        <Button size="xs" variant="outline" className="ml-auto" onClick={refresh}>
          Retry
        </Button>
      </div>
    </div>
  );
};

export default OfflineBanner;

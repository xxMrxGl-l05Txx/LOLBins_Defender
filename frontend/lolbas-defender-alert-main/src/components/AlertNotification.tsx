import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useAlerts } from "@/context/AlertContext";
import { cn } from "@/lib/utils";
import { SEVERITY_BG, alertTitle } from "@/services/lolbinsService";
import { SeverityBadge } from "@/components/alerts/AlertBadges";

const DISPLAY_MS = 8000;

const AlertNotification = () => {
  const { incomingAlerts, dismissIncoming, openAlert } = useAlerts();
  const navigate = useNavigate();
  const [paused, setPaused] = useState(false);
  const latest = incomingAlerts[0];
  const latestId = latest?.id;

  // Restart the auto-dismiss timer whenever a newer alert arrives; hovering pauses it
  useEffect(() => {
    if (!latestId || paused) return;
    const timer = setTimeout(dismissIncoming, DISPLAY_MS);
    return () => clearTimeout(timer);
  }, [latestId, paused, dismissIncoming]);

  if (!latest) {
    return null;
  }

  const moreCount = incomingAlerts.length - 1;

  const inspect = () => {
    dismissIncoming();
    setPaused(false);
    if (moreCount > 0) {
      navigate("/alerts?status=new");
    } else {
      openAlert(latest.id);
    }
  };

  return (
    <div
      className="fixed bottom-4 right-4 z-50 w-[calc(100vw-2rem)] max-w-sm animate-slide-up"
      role="status"
      aria-live="polite"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div className="relative overflow-hidden rounded-lg border bg-popover shadow-2xl shadow-black/25">
        <span className={cn("absolute inset-y-0 left-0 w-[3px]", SEVERITY_BG[latest.severity])} />
        <div className="p-3.5 pl-5">
          <div className="flex items-center justify-between gap-2">
            <span className="label-caps">New detection</span>
            <SeverityBadge severity={latest.severity} />
          </div>
          <div className={cn("mt-2 truncate text-[13px] font-medium", latest.binary && "font-mono")}>
            {alertTitle(latest)}
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{latest.details}</p>
          <div className="mt-3 flex items-center justify-between gap-2">
            <span className="truncate text-2xs text-muted-foreground">
              {moreCount > 0 ? `+${moreCount} more new alert${moreCount === 1 ? "" : "s"}` : latest.systemName}
            </span>
            <div className="flex shrink-0 gap-1.5">
              <Button size="xs" variant="ghost" onClick={dismissIncoming}>
                Dismiss
              </Button>
              <Button size="xs" onClick={inspect}>
                {moreCount > 0 ? "Review all" : "Inspect"}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertNotification;

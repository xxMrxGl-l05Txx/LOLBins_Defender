import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button, type ButtonProps } from "@/components/ui/button";
import { useAlerts } from "@/context/AlertContext";
import { cn } from "@/lib/utils";

interface ScanButtonProps {
  className?: string;
  size?: ButtonProps["size"];
  variant?: ButtonProps["variant"];
}

const ScanButton = ({ className, size = "sm", variant = "outline" }: ScanButtonProps) => {
  const { triggerScan, backendStatus, connection } = useAlerts();
  const [scanning, setScanning] = useState(false);

  // The API can run without the monitoring service, in which case scans are unavailable
  const unavailable = backendStatus !== undefined && !backendStatus.capabilities.scan;

  const handleScan = async () => {
    setScanning(true);
    const started = await triggerScan();
    setTimeout(() => setScanning(false), started ? 3000 : 0);
  };

  return (
    <Button
      variant={variant}
      size={size}
      className={className}
      onClick={handleScan}
      disabled={scanning || connection !== "online" || unavailable}
      title={unavailable ? "Scanning requires the monitoring service" : "Run a monitoring cycle now"}
    >
      <RefreshCw className={cn(scanning && "animate-spin")} />
      {scanning ? "Scanning…" : "Scan now"}
    </Button>
  );
};

export default ScanButton;

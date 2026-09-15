import { useState } from "react";
import { ChevronDown, FlaskConical } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAlerts } from "@/context/AlertContext";
import { SEVERITIES, SEVERITY_LABELS } from "@/services/lolbinsService";
import { SeverityDot } from "./AlertBadges";

const TestAlertMenu = () => {
  const { generateTestAlert, connection } = useAlerts();
  const [creating, setCreating] = useState(false);

  const create = async (severity: (typeof SEVERITIES)[number]) => {
    setCreating(true);
    await generateTestAlert(severity);
    setCreating(false);
  };

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={creating || connection !== "online"}>
          <FlaskConical />
          {creating ? "Creating…" : "Test alert"}
          <ChevronDown className="text-muted-foreground" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Simulated detection — nothing is executed
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {SEVERITIES.map((severity) => (
          <DropdownMenuItem key={severity} onSelect={() => void create(severity)} className="text-[13px]">
            <SeverityDot severity={severity} className="mr-2" />
            {SEVERITY_LABELS[severity]} severity
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default TestAlertMenu;

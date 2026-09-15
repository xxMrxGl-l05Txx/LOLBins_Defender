import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTheme } from "next-themes";
import { FlaskConical, Moon, RefreshCw, Sun } from "lucide-react";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { SeverityDot } from "@/components/alerts/AlertBadges";
import { useAlerts } from "@/context/AlertContext";
import { OPEN_COMMAND_PALETTE_EVENT } from "@/lib/command-palette";
import { alertTitle, formatRelativeTime } from "@/services/lolbinsService";
import { NAV_GROUPS } from "./SidebarContent";

const PAGES = NAV_GROUPS.flatMap((group) => group.items);

const CommandPalette = () => {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { alerts, connection, backendStatus, triggerScan, generateTestAlert, openAlert } = useAlerts();
  const { resolvedTheme, setTheme } = useTheme();
  const online = connection === "online";

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((current) => !current);
      }
    };
    const onOpen = () => setOpen(true);

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener(OPEN_COMMAND_PALETTE_EVENT, onOpen);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener(OPEN_COMMAND_PALETTE_EVENT, onOpen);
    };
  }, []);

  const run = (action: () => void) => {
    setOpen(false);
    action();
  };

  const isDark = resolvedTheme !== "light";

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="top-[20%] max-w-xl translate-y-0 gap-0 overflow-hidden p-0" aria-describedby={undefined}>
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <Command className="bg-popover [&_[cmdk-group-heading]]:label-caps [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-2">
          <CommandInput placeholder="Jump to a page, run an action or find an alert…" className="h-12 text-[13px]" />
          <CommandList className="max-h-[380px]">
            <CommandEmpty className="py-8 text-center text-[13px] text-muted-foreground">No matches.</CommandEmpty>

            <CommandGroup heading="Go to">
              {PAGES.map((page) => (
                <CommandItem key={page.to} value={`go to ${page.label}`} onSelect={() => run(() => navigate(page.to))} className="gap-2.5 text-[13px]">
                  <page.icon className="h-4 w-4 text-muted-foreground" strokeWidth={1.75} />
                  {page.label}
                </CommandItem>
              ))}
            </CommandGroup>

            <CommandSeparator />

            <CommandGroup heading="Actions">
              <CommandItem
                value="run scan now monitoring cycle"
                disabled={!online || backendStatus?.capabilities.scan === false}
                onSelect={() => run(() => void triggerScan())}
                className="gap-2.5 text-[13px]"
              >
                <RefreshCw className="h-4 w-4 text-muted-foreground" />
                Run scan now
              </CommandItem>
              <CommandItem
                value="create test alert simulated"
                disabled={!online}
                onSelect={() => run(() => void generateTestAlert("HIGH"))}
                className="gap-2.5 text-[13px]"
              >
                <FlaskConical className="h-4 w-4 text-muted-foreground" />
                Create test alert
              </CommandItem>
              <CommandItem
                value="toggle theme dark light appearance"
                onSelect={() => run(() => setTheme(isDark ? "light" : "dark"))}
                className="gap-2.5 text-[13px]"
              >
                {isDark ? <Sun className="h-4 w-4 text-muted-foreground" /> : <Moon className="h-4 w-4 text-muted-foreground" />}
                Switch to {isDark ? "light" : "dark"} theme
              </CommandItem>
            </CommandGroup>

            {alerts.length > 0 && (
              <>
                <CommandSeparator />
                <CommandGroup heading="Recent alerts">
                  {alerts.slice(0, 15).map((alert) => (
                    <CommandItem
                      key={alert.id}
                      value={`${alertTitle(alert)} ${alert.details} ${alert.command ?? ""} ${alert.id}`}
                      onSelect={() => run(() => openAlert(alert.id))}
                      className="gap-2.5 text-[13px]"
                    >
                      <SeverityDot severity={alert.severity} />
                      <span className={alert.binary ? "shrink-0 font-mono text-xs" : "shrink-0"}>{alertTitle(alert)}</span>
                      <span className="truncate text-xs text-muted-foreground">{alert.details}</span>
                      <CommandShortcut className="shrink-0 font-mono tracking-normal">{formatRelativeTime(alert.timestamp)}</CommandShortcut>
                    </CommandItem>
                  ))}
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </DialogContent>
    </Dialog>
  );
};

export default CommandPalette;

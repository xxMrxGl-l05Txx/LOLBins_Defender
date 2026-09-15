import { Link, useLocation } from "react-router-dom";
import { Bell, FileText, LayoutGrid, ScanSearch, Search, SlidersHorizontal } from "lucide-react";
import { Kbd } from "@/components/common/Kbd";
import { useAlerts } from "@/context/AlertContext";
import { isMacPlatform, openCommandPalette } from "@/lib/command-palette";
import { cn } from "@/lib/utils";
import HostStatus from "./HostStatus";
import { Wordmark } from "./Logo";

export const NAV_GROUPS = [
  {
    label: "Monitor",
    items: [
      { to: "/", label: "Overview", icon: LayoutGrid },
      { to: "/alerts", label: "Alerts", icon: Bell },
      { to: "/rules", label: "Detection rules", icon: ScanSearch },
    ],
  },
  {
    label: "Manage",
    items: [
      { to: "/reports", label: "Reports", icon: FileText },
      { to: "/settings", label: "Settings", icon: SlidersHorizontal },
    ],
  },
];

const isActivePath = (pathname: string, to: string) => {
  if (to === "/") return pathname === "/";
  if (to === "/alerts") return pathname.startsWith("/alerts") || pathname.startsWith("/alert/");
  return pathname.startsWith(to);
};

const SidebarContent = () => {
  const { pathname } = useLocation();
  const { alerts } = useAlerts();
  const newCount = alerts.filter((alert) => alert.status === "new").length;

  return (
    <div className="flex h-full flex-col">
      <div className="px-4 pb-4 pt-5">
        <Link to="/" className="inline-block rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50">
          <Wordmark />
        </Link>
      </div>

      <div className="px-3">
        <button
          type="button"
          onClick={openCommandPalette}
          className="flex h-8 w-full items-center gap-2 rounded-md border bg-background px-2.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground"
        >
          <Search className="h-3.5 w-3.5" />
          <span className="flex-1 text-left">Search…</span>
          <Kbd>{isMacPlatform() ? "⌘K" : "Ctrl K"}</Kbd>
        </button>
      </div>

      <nav className="mt-5 flex-1 space-y-5 overflow-y-auto px-3" aria-label="Main">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <div className="label-caps mb-1.5 px-2.5">{group.label}</div>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = isActivePath(pathname, item.to);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] transition-colors",
                        active
                          ? "bg-accent font-medium text-foreground"
                          : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                      )}
                    >
                      <item.icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                      <span className="flex-1">{item.label}</span>
                      {item.to === "/alerts" && newCount > 0 && (
                        <span className="rounded bg-foreground px-1.5 font-mono text-[10px] font-medium leading-4 text-background tabular">
                          {newCount}
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="p-3">
        <HostStatus />
      </div>
    </div>
  );
};

export default SidebarContent;

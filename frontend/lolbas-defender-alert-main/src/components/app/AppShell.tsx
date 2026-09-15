import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { Menu, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import AlertDetailSheet from "@/components/alerts/AlertDetailSheet";
import AlertNotification from "@/components/AlertNotification";
import { openCommandPalette } from "@/lib/command-palette";
import CommandPalette from "./CommandPalette";
import { LogoMark } from "./Logo";
import OfflineBanner from "./OfflineBanner";
import SidebarContent from "./SidebarContent";

const AppShell = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const { pathname } = useLocation();

  useEffect(() => {
    setMenuOpen(false);
    window.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <div className="min-h-screen bg-background">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r bg-card lg:block">
        <SidebarContent />
      </aside>

      <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b bg-background/90 px-4 backdrop-blur lg:hidden">
        <Link to="/" className="flex items-center gap-2">
          <LogoMark className="h-6 w-6" />
          <span className="text-[13px] font-semibold tracking-tight">LOLBins Defender</span>
        </Link>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" onClick={openCommandPalette} aria-label="Search">
            <Search />
          </Button>
          <Button variant="ghost" size="icon" onClick={() => setMenuOpen(true)} aria-label="Open navigation">
            <Menu />
          </Button>
        </div>
      </div>

      <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
        <SheetContent side="left" className="w-72 bg-card p-0 sm:max-w-72" aria-describedby={undefined}>
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarContent />
        </SheetContent>
      </Sheet>

      <div className="lg:pl-60">
        <OfflineBanner />
        <main className="mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>

      <AlertDetailSheet />
      <AlertNotification />
      <CommandPalette />
    </div>
  );
};

export default AppShell;

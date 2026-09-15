import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AlertProvider } from "@/context/AlertContext";
import AppShell from "@/components/app/AppShell";
import Dashboard from "@/pages/Dashboard";
import Alerts from "@/pages/Alerts";
import AlertDetailPage from "@/pages/AlertDetailPage";
import Rules from "@/pages/Rules";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import NotFound from "@/pages/NotFound";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Live security data should not be served stale from cache on navigation
      staleTime: 0,
      refetchOnWindowFocus: true,
    },
  },
});

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem storageKey="lolbins-theme" disableTransitionOnChange>
      <TooltipProvider delayDuration={200}>
        <AlertProvider>
          <BrowserRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<Dashboard />} />
                <Route path="alerts" element={<Alerts />} />
                <Route path="alert/:id" element={<AlertDetailPage />} />
                <Route path="rules" element={<Rules />} />
                <Route path="reports" element={<Reports />} />
                <Route path="settings" element={<Settings />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </BrowserRouter>
          <Sonner />
        </AlertProvider>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;

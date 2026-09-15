
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, errorMessage } from "@/lib/api";
import type { AlertStatus, BackendStatus, ConnectionState, SecurityAlert, Severity } from "../types";

const ALERT_POLL_MS = 5000;
const STATUS_POLL_MS = 10000;
const ALERT_FETCH_LIMIT = 500;
const NOTIFICATIONS_KEY = "lolbins-defender:dashboard-notifications";

const STATUS_TOASTS: Record<AlertStatus, string> = {
  new: "Alert reopened",
  acknowledged: "Alert acknowledged",
  resolved: "Alert resolved",
  false_positive: "Marked as false positive",
};

const BULK_VERBS: Record<AlertStatus, string> = {
  new: "reopened",
  acknowledged: "acknowledged",
  resolved: "resolved",
  false_positive: "marked as false positive",
};

const readNotificationPreference = (): boolean => {
  try {
    return localStorage.getItem(NOTIFICATIONS_KEY) !== "false";
  } catch {
    return true;
  }
};

type AlertContextType = {
  /** Most recent alerts (up to ALERT_FETCH_LIMIT), newest first */
  alerts: SecurityAlert[];
  /** Total number of alerts stored by the backend */
  totalAlerts: number;
  isLoading: boolean;
  connection: ConnectionState;
  backendStatus: BackendStatus | undefined;
  refresh: () => void;
  getAlertById: (id: string) => SecurityAlert | undefined;
  setAlertStatus: (id: string, status: AlertStatus) => Promise<boolean>;
  bulkSetStatus: (ids: string[], status: AlertStatus) => Promise<boolean>;
  clearAllAlerts: () => Promise<boolean>;
  generateTestAlert: (severity?: Severity) => Promise<boolean>;
  triggerScan: () => Promise<boolean>;
  /** Alert shown in the detail drawer */
  selectedAlertId: string | null;
  openAlert: (id: string) => void;
  closeAlert: () => void;
  /** Alerts that arrived since the console was opened, for the pop-up notification */
  incomingAlerts: SecurityAlert[];
  dismissIncoming: () => void;
  notificationsEnabled: boolean;
  setNotificationsEnabled: (enabled: boolean) => void;
};

const AlertContext = createContext<AlertContextType | undefined>(undefined);

export const AlertProvider = ({ children }: { children: React.ReactNode }) => {
  const queryClient = useQueryClient();
  const [incomingAlerts, setIncomingAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [notificationsEnabled, setNotificationsEnabledState] = useState(readNotificationPreference);
  const seenIds = useRef<Set<string> | null>(null);

  const alertsQuery = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api.getAlerts({ limit: ALERT_FETCH_LIMIT }),
    refetchInterval: ALERT_POLL_MS,
    retry: false,
  });

  const statusQuery = useQuery({
    queryKey: ["status"],
    queryFn: api.getStatus,
    refetchInterval: STATUS_POLL_MS,
    retry: false,
  });

  const connection: ConnectionState = statusQuery.isError
    ? "offline"
    : statusQuery.isSuccess ? "online" : "connecting";

  const alerts = useMemo(() => alertsQuery.data?.alerts ?? [], [alertsQuery.data]);

  // Surface alerts that were not present on the previous poll
  useEffect(() => {
    const latest = alertsQuery.data?.alerts;
    if (!latest) return;

    if (seenIds.current === null) {
      seenIds.current = new Set(latest.map((alert) => alert.id));
      return;
    }

    const seen = seenIds.current;
    const fresh = latest.filter((alert) => !seen.has(alert.id));
    fresh.forEach((alert) => seen.add(alert.id));

    const freshNew = fresh.filter((alert) => alert.status === "new");
    if (freshNew.length > 0 && notificationsEnabled) {
      setIncomingAlerts((previous) => [...freshNew, ...previous].slice(0, 20));
    }
  }, [alertsQuery.data, notificationsEnabled]);

  const invalidate = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alert"] });
    queryClient.invalidateQueries({ queryKey: ["summary"] });
  }, [queryClient]);

  const refresh = useCallback(() => {
    invalidate();
    queryClient.invalidateQueries({ queryKey: ["status"] });
  }, [invalidate, queryClient]);

  const getAlertById = useCallback(
    (id: string) => alerts.find((alert) => alert.id === id),
    [alerts]
  );

  const setAlertStatus = useCallback(async (id: string, status: AlertStatus) => {
    try {
      const updated = await api.updateAlertStatus(id, status);
      queryClient.setQueryData(["alert", id], updated);
      toast.success(STATUS_TOASTS[status]);
      invalidate();
      return true;
    } catch (error) {
      toast.error(errorMessage(error, "Failed to update alert"));
      return false;
    }
  }, [invalidate, queryClient]);

  const bulkSetStatus = useCallback(async (ids: string[], status: AlertStatus) => {
    if (ids.length === 0) return true;
    try {
      const updated = await api.bulkUpdateStatus(ids, status);
      toast.success(`${updated} alert${updated === 1 ? "" : "s"} ${BULK_VERBS[status]}`);
      invalidate();
      return true;
    } catch (error) {
      toast.error(errorMessage(error, "Failed to update alerts"));
      return false;
    }
  }, [invalidate]);

  const clearAllAlerts = useCallback(async () => {
    try {
      const deleted = await api.clearAlerts();
      setIncomingAlerts([]);
      setSelectedAlertId(null);
      toast.success(`Deleted ${deleted} alert${deleted === 1 ? "" : "s"}`);
      invalidate();
      return true;
    } catch (error) {
      toast.error(errorMessage(error, "Failed to delete alerts"));
      return false;
    }
  }, [invalidate]);

  const generateTestAlert = useCallback(async (severity: Severity = "HIGH") => {
    try {
      await api.createTestAlert(severity);
      toast.success("Test alert created", { description: "It will appear in the feed within a few seconds." });
      invalidate();
      return true;
    } catch (error) {
      toast.error(errorMessage(error, "Failed to create test alert"));
      return false;
    }
  }, [invalidate]);

  const triggerScan = useCallback(async () => {
    try {
      await api.triggerScan();
      toast.success("Scan started", { description: "New detections will appear in a few seconds." });
      // A cycle takes a few seconds; refresh once it has had time to finish
      [3000, 8000].forEach((delay) => setTimeout(refresh, delay));
      return true;
    } catch (error) {
      toast.error(errorMessage(error, "Failed to start scan"));
      return false;
    }
  }, [refresh]);

  const openAlert = useCallback((id: string) => setSelectedAlertId(id), []);
  const closeAlert = useCallback(() => setSelectedAlertId(null), []);
  const dismissIncoming = useCallback(() => setIncomingAlerts([]), []);

  const setNotificationsEnabled = useCallback((enabled: boolean) => {
    setNotificationsEnabledState(enabled);
    if (!enabled) setIncomingAlerts([]);
    try {
      localStorage.setItem(NOTIFICATIONS_KEY, String(enabled));
    } catch {
      // Storage unavailable (private mode); the preference lasts for this session
    }
  }, []);

  const value = useMemo<AlertContextType>(() => ({
    alerts,
    totalAlerts: alertsQuery.data?.total ?? 0,
    isLoading: alertsQuery.isPending,
    connection,
    backendStatus: statusQuery.data,
    refresh,
    getAlertById,
    setAlertStatus,
    bulkSetStatus,
    clearAllAlerts,
    generateTestAlert,
    triggerScan,
    selectedAlertId,
    openAlert,
    closeAlert,
    incomingAlerts,
    dismissIncoming,
    notificationsEnabled,
    setNotificationsEnabled,
  }), [
    alerts, alertsQuery.data, alertsQuery.isPending, connection, statusQuery.data, refresh,
    getAlertById, setAlertStatus, bulkSetStatus, clearAllAlerts, generateTestAlert, triggerScan,
    selectedAlertId, openAlert, closeAlert, incomingAlerts, dismissIncoming,
    notificationsEnabled, setNotificationsEnabled,
  ]);

  return <AlertContext.Provider value={value}>{children}</AlertContext.Provider>;
};

export const useAlerts = (): AlertContextType => {
  const context = useContext(AlertContext);
  if (context === undefined) {
    throw new Error("useAlerts must be used within an AlertProvider");
  }
  return context;
};

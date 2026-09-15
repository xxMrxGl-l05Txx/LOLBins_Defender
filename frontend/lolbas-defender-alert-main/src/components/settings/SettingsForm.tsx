import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel } from "@/components/common/Panel";
import { useAlerts } from "@/context/AlertContext";
import { api, errorMessage } from "@/lib/api";
import type { SystemConfig } from "@/types";

type NumericField =
  | "monitor_interval" | "cpu_threshold" | "memory_threshold" | "disk_threshold"
  | "alert_cooldown_seconds" | "max_alerts_per_hour" | "data_retention_days";

type ToggleField =
  | "enable_lolbin_detection" | "enable_process_monitoring"
  | "enable_desktop_notifications" | "enable_auto_cleanup";

type FormState = Record<NumericField, string> & Record<ToggleField, boolean>;

// Ranges mirror the validation in backend/core/config.py
const NUMBER_FIELDS: Record<NumericField, { label: string; min: number; max: number; integer: boolean; unit: string; help: string }> = {
  monitor_interval: { label: "Scan interval", min: 5, max: 86400, integer: true, unit: "s", help: "How often processes and metrics are checked" },
  cpu_threshold: { label: "CPU threshold", min: 1, max: 100, integer: false, unit: "%", help: "Alert above this CPU usage" },
  memory_threshold: { label: "Memory threshold", min: 1, max: 100, integer: false, unit: "%", help: "Alert above this memory usage" },
  disk_threshold: { label: "Disk threshold", min: 1, max: 100, integer: false, unit: "%", help: "Alert above this disk usage" },
  alert_cooldown_seconds: { label: "Alert cooldown", min: 0, max: 86400, integer: true, unit: "s", help: "Minimum gap between repeated resource alerts" },
  max_alerts_per_hour: { label: "Notification limit", min: 1, max: 100000, integer: true, unit: "/hr", help: "Max desktop/email/webhook notifications per hour" },
  data_retention_days: { label: "Data retention", min: 1, max: 3650, integer: true, unit: "days", help: "Delete alerts, metrics and reports older than this" },
};

const toForm = (config: SystemConfig): FormState => ({
  monitor_interval: String(config.monitoring.monitor_interval),
  cpu_threshold: String(config.monitoring.cpu_threshold),
  memory_threshold: String(config.monitoring.memory_threshold),
  disk_threshold: String(config.monitoring.disk_threshold),
  alert_cooldown_seconds: String(config.alerting.alert_cooldown_seconds),
  max_alerts_per_hour: String(config.alerting.max_alerts_per_hour),
  data_retention_days: String(config.data_retention_days),
  enable_lolbin_detection: config.monitoring.enable_lolbin_detection,
  enable_process_monitoring: config.monitoring.enable_process_monitoring,
  enable_desktop_notifications: config.alerting.enable_desktop_notifications,
  enable_auto_cleanup: config.enable_auto_cleanup,
});

const validate = (form: FormState): Partial<Record<NumericField, string>> => {
  const errors: Partial<Record<NumericField, string>> = {};
  (Object.keys(NUMBER_FIELDS) as NumericField[]).forEach((field) => {
    const spec = NUMBER_FIELDS[field];
    const raw = form[field].trim();
    const value = Number(raw);
    if (raw === "" || Number.isNaN(value)) errors[field] = "Enter a number";
    else if (spec.integer && !Number.isInteger(value)) errors[field] = "Whole number only";
    else if (value < spec.min || value > spec.max) errors[field] = `${spec.min}–${spec.max}`;
  });
  return errors;
};

const NumberField = ({ field, value, error, onChange }: {
  field: NumericField; value: string; error?: string; onChange: (value: string) => void;
}) => {
  const spec = NUMBER_FIELDS[field];
  return (
    <div className="space-y-1.5">
      <Label htmlFor={field} className="text-xs">{spec.label}</Label>
      <div className="flex items-center gap-2">
        <Input
          id={field}
          type="number"
          inputMode="decimal"
          min={spec.min}
          max={spec.max}
          step={spec.integer ? 1 : 0.5}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="h-8 w-28 font-mono text-[13px] tabular"
          aria-invalid={Boolean(error)}
        />
        <span className="text-xs text-muted-foreground">{spec.unit}</span>
      </div>
      <p className={error ? "text-2xs text-sev-critical" : "text-2xs text-muted-foreground"}>{error ?? spec.help}</p>
    </div>
  );
};

const Toggle = ({ id, label, description, checked, onChange, disabled }: {
  id: string; label: string; description: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean;
}) => (
  <div className="flex items-center justify-between gap-4 py-1">
    <div className="min-w-0 space-y-0.5">
      <Label htmlFor={id} className="text-[13px]">{label}</Label>
      <p className="text-2xs text-muted-foreground">{description}</p>
    </div>
    <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
  </div>
);

const SettingsForm = () => {
  const queryClient = useQueryClient();
  const { notificationsEnabled, setNotificationsEnabled } = useAlerts();
  const configQuery = useQuery({ queryKey: ["config"], queryFn: api.getConfig, retry: false });
  const config = configQuery.data;

  const [form, setForm] = useState<FormState | null>(null);
  const [dashboardNotifications, setDashboardNotifications] = useState(notificationsEnabled);
  const [errors, setErrors] = useState<Partial<Record<NumericField, string>>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (config && form === null) setForm(toForm(config));
  }, [config, form]);

  if (configQuery.isPending || (config && !form)) {
    return <Panel><Skeleton className="h-64 w-full" /></Panel>;
  }

  if (!config || !form) {
    return (
      <Panel title="Settings unavailable" description={errorMessage(configQuery.error, "Could not load configuration from the backend")}>
        <Button variant="outline" size="sm" onClick={() => configQuery.refetch()}>Retry</Button>
      </Panel>
    );
  }

  const update = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((previous) => (previous ? { ...previous, [key]: value } : previous));
    setErrors((previous) => ({ ...previous, [key]: undefined }));
  };

  const dirty =
    JSON.stringify(form) !== JSON.stringify(toForm(config)) ||
    dashboardNotifications !== notificationsEnabled;

  const reset = () => {
    setForm(toForm(config));
    setDashboardNotifications(notificationsEnabled);
    setErrors({});
  };

  const save = async () => {
    const validationErrors = validate(form);
    setErrors(validationErrors);
    if (Object.keys(validationErrors).length > 0) {
      toast.error("Fix the highlighted fields");
      return;
    }

    setSaving(true);
    try {
      const saved = await api.updateConfig({
        monitoring: {
          monitor_interval: Number(form.monitor_interval),
          cpu_threshold: Number(form.cpu_threshold),
          memory_threshold: Number(form.memory_threshold),
          disk_threshold: Number(form.disk_threshold),
          enable_lolbin_detection: form.enable_lolbin_detection,
          enable_process_monitoring: form.enable_process_monitoring,
        },
        alerting: {
          enable_desktop_notifications: form.enable_desktop_notifications,
          alert_cooldown_seconds: Number(form.alert_cooldown_seconds),
          max_alerts_per_hour: Number(form.max_alerts_per_hour),
        },
        data_retention_days: Number(form.data_retention_days),
        enable_auto_cleanup: form.enable_auto_cleanup,
      });
      queryClient.setQueryData(["config"], saved);
      queryClient.invalidateQueries({ queryKey: ["status"] });
      setForm(toForm(saved));
      setNotificationsEnabled(dashboardNotifications);
      toast.success("Settings saved", { description: "Applied from the next monitoring cycle." });
    } catch (error) {
      toast.error(errorMessage(error, "Failed to save settings"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4 lg:space-y-5">
      <div className="grid gap-4 lg:grid-cols-2 lg:gap-5">
        <Panel title="Detection" description="What the monitor inspects each cycle">
          <div className="space-y-3">
            <Toggle
              id="lolbin-detection"
              label="LOLBin detection"
              description="Flag suspicious use of built-in Windows binaries"
              checked={form.enable_lolbin_detection}
              onChange={(value) => update("enable_lolbin_detection", value)}
            />
            <Toggle
              id="process-monitoring"
              label="Process monitoring"
              description="Collect process and connection details (required for LOLBin detection)"
              checked={form.enable_process_monitoring}
              onChange={(value) => update("enable_process_monitoring", value)}
            />
            <div className="border-t pt-3">
              <NumberField field="monitor_interval" value={form.monitor_interval} error={errors.monitor_interval} onChange={(value) => update("monitor_interval", value)} />
            </div>
          </div>
        </Panel>

        <Panel title="Resource thresholds" description="Raise an alert when usage exceeds these limits">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <NumberField field="cpu_threshold" value={form.cpu_threshold} error={errors.cpu_threshold} onChange={(value) => update("cpu_threshold", value)} />
            <NumberField field="memory_threshold" value={form.memory_threshold} error={errors.memory_threshold} onChange={(value) => update("memory_threshold", value)} />
            <NumberField field="disk_threshold" value={form.disk_threshold} error={errors.disk_threshold} onChange={(value) => update("disk_threshold", value)} />
          </div>
        </Panel>

        <Panel title="Notifications" description="How alerts reach you">
          <div className="space-y-3">
            <Toggle
              id="desktop-notifications"
              label="Desktop notifications"
              description="System-tray popup on the monitored machine"
              checked={form.enable_desktop_notifications}
              onChange={(value) => update("enable_desktop_notifications", value)}
            />
            <Toggle
              id="dashboard-notifications"
              label="Dashboard notifications"
              description="Pop up new alerts in this browser while the console is open"
              checked={dashboardNotifications}
              onChange={setDashboardNotifications}
            />
            <div className="grid grid-cols-2 gap-4 border-t pt-3">
              <NumberField field="alert_cooldown_seconds" value={form.alert_cooldown_seconds} error={errors.alert_cooldown_seconds} onChange={(value) => update("alert_cooldown_seconds", value)} />
              <NumberField field="max_alerts_per_hour" value={form.max_alerts_per_hour} error={errors.max_alerts_per_hour} onChange={(value) => update("max_alerts_per_hour", value)} />
            </div>
            <p className="border-t pt-3 text-2xs text-muted-foreground">
              Email {config.alerting.enable_email_alerts && config.alerting.email_smtp_server ? "enabled" : "not configured"}
              {" · "}
              Webhook {config.alerting.enable_webhook_alerts && config.alerting.webhook_url ? "enabled" : "not configured"}.
              Credentials and webhook URLs are edited in config.json.
            </p>
          </div>
        </Panel>

        <Panel title="Data" description="Storage and retention">
          <div className="space-y-3">
            <Toggle
              id="auto-cleanup"
              label="Automatic cleanup"
              description="Delete data past the retention period every night"
              checked={form.enable_auto_cleanup}
              onChange={(value) => update("enable_auto_cleanup", value)}
            />
            <div className="border-t pt-3">
              <NumberField field="data_retention_days" value={form.data_retention_days} error={errors.data_retention_days} onChange={(value) => update("data_retention_days", value)} />
            </div>
            <p className="border-t pt-3 font-mono text-2xs text-muted-foreground">
              api {config.api.host}:{config.api.port} · auth {config.api.enable_authentication ? "on" : "off"} · log {config.log_level}
            </p>
          </div>
        </Panel>
      </div>

      <div className="sticky bottom-4 flex items-center justify-end gap-2 rounded-lg border bg-card/95 px-4 py-3 backdrop-blur">
        <span className="mr-auto text-xs text-muted-foreground">{dirty ? "Unsaved changes" : "All changes saved"}</span>
        <Button variant="outline" size="sm" onClick={reset} disabled={!dirty || saving}>Reset</Button>
        <Button size="sm" onClick={save} disabled={!dirty || saving}>{saving ? "Saving…" : "Save settings"}</Button>
      </div>
    </div>
  );
};

export default SettingsForm;

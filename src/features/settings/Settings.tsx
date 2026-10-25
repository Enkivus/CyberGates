import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  Bot,
  Database,
  HardDrive,
  Info,
  Moon,
  RefreshCw,
  Save,
  ShieldOff,
  Sun,
} from "lucide-react";
import { api } from "../../lib/api";
import type { StorageInfo } from "../../lib/types";
import type { Theme } from "../../lib/theme";
import {
  ErrorState,
  InfoRow,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";
import { formatBytes } from "../../lib/format";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { useToast } from "../../components/ToastProvider";
import { requiresRetentionConfirmation } from "../../lib/retention";

function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange?: (value: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange?.(!checked)}
      className={`relative h-6 w-11 shrink-0 rounded-full border transition-colors ${
        checked ? "border-transparent bg-accent" : "border-line bg-surface-3"
      } ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
    >
      <span
        className={`absolute top-0.5 h-4.5 w-4.5 rounded-full bg-white shadow-sm transition-transform ${
          checked ? "translate-x-[22px]" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

export function Settings({
  theme,
  onThemeChange,
}: {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
}) {
  const [storage, setStorage] = useState<StorageInfo | null>(null);
  const [notifications, setNotifications] = useState(true);
  const [retention, setRetention] = useState(90);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);
  const [confirmRetention, setConfirmRetention] = useState(false);
  const { showToast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [settings, info] = await Promise.all([
        api.getSettings(),
        api.getStorageInfo(),
      ]);
      const map = new Map(settings.map((entry) => [entry.key, entry.value]));
      setNotifications(map.get("notifications") !== "false");
      setRetention(Number(map.get("retentionDays") ?? info.retentionDays));
      setStorage(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (key: string, value: string, successMessage: string) => {
    setSaving(key);
    setError(null);
    try {
      await api.updateSetting(key, value);
      showToast(successMessage, "success");
      if (key === "retentionDays") {
        setStorage((current) =>
          current ? { ...current, retentionDays: Number(value) } : current,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(null);
    }
  };

  const saveRetention = () => {
    const nextRetention = Math.min(3650, Math.max(1, Math.round(retention)));
    setConfirmRetention(false);
    void save(
      "retentionDays",
      String(nextRetention),
      "Retention updated and expired records pruned.",
    );
  };

  const handleRetentionSave = () => {
    const nextRetention = Math.min(3650, Math.max(1, Math.round(retention)));
    if (storage && requiresRetentionConfirmation(storage.retentionDays, nextRetention)) {
      setConfirmRetention(true);
      return;
    }
    saveRetention();
  };

  return (
    <div className="fade-in">
      <PageHeader
        title="Settings"
        subtitle="Local preferences and data controls. CyberGates is offline-first; no telemetry or cloud features are active."
      />

      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
      {loading && !storage ? (
        <Panel>
          <LoadingState label="Loading settings" />
        </Panel>
      ) : (
        <div className="grid gap-5 xl:grid-cols-2">
          <Panel>
            <PanelHeader
              title="Appearance"
              description="Theme preference is stored locally on this device."
            />
            <div className="p-5">
              <div className="grid grid-cols-2 gap-3">
                {(["dark", "light"] as const).map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => onThemeChange(option)}
                    className={`flex items-center gap-3 rounded-xl border p-4 text-left transition-colors ${
                      theme === option
                        ? "border-accent bg-accent-soft"
                        : "border-line bg-surface-2 hover:bg-surface-3"
                    }`}
                  >
                    {option === "dark" ? (
                      <Moon className="h-5 w-5 text-accent" aria-hidden />
                    ) : (
                      <Sun className="h-5 w-5 text-warn" aria-hidden />
                    )}
                    <div>
                      <p className="text-sm font-semibold capitalize text-ink">{option}</p>
                      <p className="text-[11px] text-muted">
                        {option === "dark" ? "Low-light console" : "High-contrast daylight"}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="Notifications"
              description="Local notifications for important findings when notification support is implemented."
            />
            <div className="flex items-center justify-between gap-4 p-5">
              <div className="flex items-start gap-3">
                <Bell className="mt-0.5 h-4 w-4 text-accent" aria-hidden />
                <div>
                  <p className="text-xs font-semibold text-ink">Finding notifications</p>
                  <p className="mt-0.5 text-[11px] leading-relaxed text-muted">
                    Preference only. OS notification delivery is not implemented yet, so
                    no notifications are currently sent.
                  </p>
                </div>
              </div>
              <Toggle
                checked={notifications}
                label="Finding notifications"
                onChange={(value) => {
                  setNotifications(value);
                  void save(
                    "notifications",
                    String(value),
                    "Notification preference saved. Delivery is not implemented yet.",
                  );
                }}
              />
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="Data retention"
              description="Audits and activity logs older than this are removed on startup and when the value changes."
            />
            <div className="p-5">
              <div className="flex items-end gap-3">
                <label className="flex-1 text-xs text-muted">
                  Retention period (days)
                  <input
                    type="number"
                    min={1}
                    max={3650}
                    value={retention}
                    onChange={(event) => setRetention(Number(event.target.value))}
                    className="input mt-1.5"
                  />
                </label>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={saving === "retentionDays"}
                  onClick={handleRetentionSave}
                >
                  <Save className="h-4 w-4" aria-hidden />
                  Save
                </button>
              </div>
              <p className="mt-2 text-[11px] text-faint">
                Minimum 1 day, maximum 3650 days. Deleting local history cannot be undone.
              </p>
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title="Privacy and AI"
              description="Optional remote capabilities are off and cannot be enabled until real integrations exist."
            />
            <div className="divide-y divide-line/70">
              <div className="flex items-center justify-between gap-4 p-5">
                <div className="flex items-start gap-3">
                  <ShieldOff className="mt-0.5 h-4 w-4 text-ok" aria-hidden />
                  <div>
                    <p className="text-xs font-semibold text-ink">Telemetry</p>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-muted">
                      No telemetry exists in CyberGates. There is nothing to opt into.
                    </p>
                  </div>
                </div>
                <Toggle checked={false} disabled label="Telemetry" />
              </div>
              <div className="flex items-center justify-between gap-4 p-5">
                <div className="flex items-start gap-3">
                  <Bot className="mt-0.5 h-4 w-4 text-warn" aria-hidden />
                  <div>
                    <p className="text-xs font-semibold text-ink">AI security assistant</p>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-muted">
                      No provider is configured. The assistant cannot be enabled and no
                      data is sent anywhere.
                    </p>
                  </div>
                </div>
                <Toggle checked={false} disabled label="AI security assistant" />
              </div>
            </div>
          </Panel>

          <Panel className="xl:col-span-2">
            <PanelHeader
              title="Local storage"
              description="All findings, settings, and reports remain on this device."
              actions={
                <button type="button" className="btn btn-sm" onClick={() => void load()}>
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                  Refresh
                </button>
              }
            />
            {storage ? (
              <div className="grid gap-x-8 gap-y-0 px-5 py-3 md:grid-cols-2">
                <div>
                  <InfoRow label="Data directory" value={storage.dataDir} mono />
                  <InfoRow label="Database" value={storage.databasePath} mono />
                  <InfoRow label="Database size" value={formatBytes(storage.databaseBytes)} />
                  <InfoRow label="Retention" value={`${storage.retentionDays} days`} />
                </div>
                <div>
                  <InfoRow label="Reports directory" value={storage.reportsDir} mono />
                  <InfoRow label="Logs directory" value={storage.logDir} mono />
                  <InfoRow label="Audit trail" value="Local SQLite, access-controlled by OS" />
                  <InfoRow label="Cloud sync" value="Not implemented" />
                </div>
              </div>
            ) : (
              <div className="p-5 text-xs text-muted">Storage information unavailable.</div>
            )}
          </Panel>

          <Panel className="xl:col-span-2">
            <PanelHeader title="About and limitations" />
            <div className="grid gap-5 p-5 md:grid-cols-[1fr_auto]">
              <div className="space-y-3 text-xs leading-relaxed text-muted">
                <div className="flex items-start gap-3">
                  <Info className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
                  <p>
                    CyberGates v0.1.0 is an early build. Posture auditing, process and
                    connection inventory, persisted findings, and audit reports are real.
                    Malware scanning, vulnerability matching, firewall changes, event
                    monitoring, incident response, AI, and multi-device management are not
                    implemented.
                  </p>
                </div>
                <div className="flex items-start gap-3">
                  <Database className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />
                  <p>
                    Reports may contain sensitive system information. Review exported
                    files before sharing. Recovery keys, passwords, and API keys are never
                    read or stored by CyberGates.
                  </p>
                </div>
                <div className="flex items-start gap-3">
                  <HardDrive className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />
                  <p>
                    A passing posture audit is not proof that the device is free of
                    malware. Unimplemented checks are explicitly excluded from the score.
                  </p>
                </div>
              </div>
              <div className="rounded-xl border border-line bg-surface-2 px-4 py-3 text-center">
                <p className="text-[10px] uppercase tracking-[0.12em] text-faint">Version</p>
                <p className="mt-1 text-lg font-semibold text-ink">0.1.0</p>
                <p className="mt-1 text-[10px] text-faint">Local-first preview</p>
              </div>
            </div>
          </Panel>
        </div>
      )}
      <ConfirmDialog
        open={confirmRetention}
        title="Reduce data retention?"
        description="This may permanently remove local audit and activity records older than the new retention period. Continue with the shorter period?"
        confirmLabel="Reduce retention"
        destructive
        onConfirm={saveRetention}
        onCancel={() => setConfirmRetention(false)}
      />
    </div>
  );
}

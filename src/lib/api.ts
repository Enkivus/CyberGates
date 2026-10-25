import { invoke } from "@tauri-apps/api/core";
import type {
  AuditLogEntry,
  AuditRecord,
  AdvisoryReport,
  AdvisoryUpdate,
  Dashboard,
  Finding,
  FirewallSnapshot,
  InstalledApp,
  IncidentDetail,
  IncidentExport,
  IncidentRecord,
  ModuleStatus,
  LoadedServiceInventory,
  NetworkConnection,
  HostDiagnostic,
  NetworkSnapshot,
  ProcessInfo,
  ReportExport,
  SettingEntry,
  StorageInfo,
  SystemInfo,
  StartupInventory,
} from "./types";

interface BackendError {
  code?: string;
  message?: string;
}

function describeError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const candidate = error as BackendError;
    if (typeof candidate.message === "string") return candidate.message;
  }
  if (error instanceof Error) return error.message;
  return "The local CyberGates service returned an unknown error.";
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw new Error(describeError(error));
  }
}

export const api = {
  getDashboard: () => call<Dashboard>("get_dashboard"),
  runAudit: () => call<Dashboard>("run_audit"),
  getSystemInfo: () => call<SystemInfo>("get_system_info"),
  getProcesses: (limit = 250) => call<ProcessInfo[]>("get_processes", { limit }),
  getStartupInventory: () => call<StartupInventory>("get_startup_inventory"),
  getLoadedServices: () => call<LoadedServiceInventory>("get_loaded_services"),
  getNetworkConnections: () =>
    call<NetworkConnection[]>("get_network_connections"),
  getNetworkSnapshot: () => call<NetworkSnapshot>("get_network_snapshot"),
  diagnoseHost: (host: string) => call<HostDiagnostic>("diagnose_host", { host }),
  getInstalledApps: () => call<InstalledApp[]>("get_installed_apps"),
  getFirewallSnapshot: () => call<FirewallSnapshot | null>("get_firewall_snapshot"),
  updateAdvisoryDatabase: () => call<AdvisoryUpdate>("update_advisory_database"),
  getAdvisoryReport: () => call<AdvisoryReport>("get_advisory_report"),
  getModuleStatuses: () => call<ModuleStatus[]>("get_module_statuses"),
  getOpenFindings: (limit = 500) =>
    call<Finding[]>("get_open_findings", { limit }),
  getIncidents: (limit = 100) => call<IncidentRecord[]>("get_incidents", { limit }),
  getIncident: (incidentId: string) => call<IncidentDetail>("get_incident", { incidentId }),
  createIncident: (findingId: string) => call<IncidentRecord>("create_incident", { findingId }),
  addIncidentNote: (incidentId: string, note: string) =>
    call<void>("add_incident_note", { incidentId, note }),
  setIncidentStatus: (incidentId: string, status: string, note: string) =>
    call<void>("set_incident_status", { incidentId, status, note }),
  exportIncidentReport: (incidentId: string, format: "json" | "html") =>
    call<IncidentExport>("export_incident_report", { incidentId, format }),
  getAuditHistory: (limit = 50) =>
    call<AuditRecord[]>("get_audit_history", { limit }),
  getAuditFindings: (auditId: string) =>
    call<Finding[]>("get_audit_findings", { auditId }),
  getSettings: () => call<SettingEntry[]>("get_settings"),
  updateSetting: (key: string, value: string) =>
    call<SettingEntry>("update_setting", { key, value }),
  exportReport: (auditId: string, format: "json" | "html") =>
    call<ReportExport>("export_report", { auditId, format }),
  getAuditLog: (limit = 100) => call<AuditLogEntry[]>("get_audit_log", { limit }),
  getStorageInfo: () => call<StorageInfo>("get_storage_info"),
};

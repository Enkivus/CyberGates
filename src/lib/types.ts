export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CheckStatus =
  | "pass"
  | "warning"
  | "fail"
  | "unavailable"
  | "not_applicable";

export type ModuleStatusValue = "available" | "partial" | "planned" | "unavailable";

export interface ScoreFactor {
  id: string;
  title: string;
  category: string;
  status: CheckStatus;
  severity: Severity;
  weight: number;
  earned: number;
  evidence: string;
  explanation: string;
  remediation: string;
  verification: string;
  source: string;
}

export interface Finding {
  id: string;
  auditId: string;
  checkId: string;
  title: string;
  severity: Severity;
  status: string;
  category: string;
  evidence: string;
  explanation: string;
  remediation: string;
  verification: string;
  source: string;
  detectedAt: string;
  resolvedAt: string | null;
}

export interface AuditRecord {
  id: string;
  startedAt: string;
  finishedAt: string | null;
  score: number | null;
  status: string;
  platform: string;
  findingsCount: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SystemInfo {
  hostname: string;
  osName: string;
  osVersion: string;
  kernelVersion: string;
  architecture: string;
  cpuBrand: string;
  cpuCores: number;
  memoryTotalMb: number;
  uptimeSeconds: number;
  platform: string;
  supported: boolean;
  notes: string[];
}

export interface Dashboard {
  system: SystemInfo;
  score: number | null;
  scoreLabel: string;
  earned: number;
  evaluated: number;
  factors: ScoreFactor[];
  findings: Finding[];
  counts: SeverityCounts;
  lastAudit: AuditRecord | null;
  generatedAt: string;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  cpuPercent: number;
  memoryMb: number;
  executable: string | null;
  runTimeSeconds: number;
}

export interface NetworkConnection {
  protocol: string;
  localAddress: string;
  remoteAddress: string;
  state: string;
  pid: number | null;
  process: string | null;
}

export interface ModuleStatus {
  id: string;
  name: string;
  status: ModuleStatusValue;
  detail: string;
}

export interface AuditLogEntry {
  id: number;
  at: string;
  action: string;
  detail: string;
  outcome: string;
}

export interface SettingEntry {
  key: string;
  value: string;
}

export interface StorageInfo {
  dataDir: string;
  reportsDir: string;
  logDir: string;
  databasePath: string;
  databaseBytes: number;
  retentionDays: number;
}

export interface ReportExport {
  path: string;
  format: string;
  bytes: number;
  auditId: string;
  warning: string;
}

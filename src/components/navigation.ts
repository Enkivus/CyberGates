import type { LucideIcon } from "lucide-react";
import {
  Activity,
  DatabaseBackup,
  EyeOff,
  FileText,
  Flame,
  LayoutDashboard,
  MonitorSmartphone,
  Network,
  ScanLine,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  UserLock,
  Wrench,
  Bug,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  group: string;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard, group: "Command Center" },
  {
    to: "/threat-protection",
    label: "Threat Protection",
    icon: ShieldCheck,
    group: "Protection",
  },
  { to: "/scanner", label: "Security Scanner", icon: ScanLine, group: "Protection" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug, group: "Protection" },
  { to: "/firewall", label: "Firewall", icon: Flame, group: "Protection" },
  {
    to: "/network",
    label: "Network Security",
    icon: Network,
    group: "Network & System",
  },
  {
    to: "/monitoring",
    label: "System Monitoring",
    icon: Activity,
    group: "Network & System",
  },
  { to: "/privacy", label: "Privacy", icon: EyeOff, group: "Network & System" },
  {
    to: "/incidents",
    label: "Incident Response",
    icon: Siren,
    group: "Response",
  },
  {
    to: "/backup",
    label: "Backup and Recovery",
    icon: DatabaseBackup,
    group: "Response",
  },
  { to: "/toolkit", label: "Security Toolkit", icon: Wrench, group: "Tools" },
  { to: "/account", label: "Account Security", icon: UserLock, group: "Tools" },
  {
    to: "/devices",
    label: "Device Management",
    icon: MonitorSmartphone,
    group: "Tools",
  },
  { to: "/reports", label: "Reports and History", icon: FileText, group: "Records" },
  { to: "/settings", label: "Settings", icon: Settings, group: "Records" },
];

export const NAV_GROUPS = Array.from(
  NAV_ITEMS.reduce((groups, item) => {
    const existing = groups.get(item.group) ?? [];
    existing.push(item);
    groups.set(item.group, existing);
    return groups;
  }, new Map<string, NavItem[]>()),
);

export function findNavItem(pathname: string): NavItem {
  const exact = NAV_ITEMS.find((item) => item.to === pathname);
  return exact ?? NAV_ITEMS[0];
}

export { ShieldAlert };

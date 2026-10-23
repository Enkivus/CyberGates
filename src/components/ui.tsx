import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  CircleHelp,
  MinusCircle,
  XCircle,
} from "lucide-react";
import type { CheckStatus, ModuleStatusValue, Severity } from "../lib/types";
import { titleCase } from "../lib/format";

export function Panel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={`panel ${className}`}>{children}</section>;
}

export function PanelHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="panel-header">
      <div>
        <h2 className="text-sm font-semibold tracking-tight text-ink">{title}</h2>
        {description ? (
          <p className="mt-0.5 text-xs text-muted">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle ? (
          <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`chip sev-${severity}`}>{titleCase(severity)}</span>;
}

export function CheckStatusBadge({ status }: { status: CheckStatus }) {
  return (
    <span className={`chip border-transparent status-${status}`}>
      {titleCase(status)}
    </span>
  );
}

export function ModuleStatusBadge({ status }: { status: ModuleStatusValue }) {
  const styles: Record<ModuleStatusValue, string> = {
    available: "status-pass border-transparent",
    partial: "status-warning border-transparent",
    planned: "status-unavailable border-transparent",
    unavailable: "status-unavailable border-transparent",
  };
  return <span className={`chip ${styles[status]}`}>{titleCase(status)}</span>;
}

export function CheckIcon({ status }: { status: CheckStatus }) {
  const common = "h-4 w-4 shrink-0";
  switch (status) {
    case "pass":
      return <CheckCircle2 className={`${common} text-ok`} aria-hidden />;
    case "warning":
      return <AlertTriangle className={`${common} text-warn`} aria-hidden />;
    case "fail":
      return <XCircle className={`${common} text-danger`} aria-hidden />;
    case "unavailable":
      return <CircleHelp className={`${common} text-muted`} aria-hidden />;
    default:
      return <MinusCircle className={`${common} text-faint`} aria-hidden />;
  }
}

export function KpiCard({
  label,
  value,
  hint,
  icon,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: ReactNode;
  tone?: "neutral" | "ok" | "warn" | "danger" | "accent";
}) {
  const tones = {
    neutral: "text-muted bg-surface-2",
    ok: "text-ok bg-ok-soft",
    warn: "text-warn bg-warn-soft",
    danger: "text-danger bg-danger-soft",
    accent: "text-accent bg-accent-soft",
  };
  return (
    <div className="panel-flat flex items-start gap-3 p-4">
      <div className={`rounded-lg p-2 ${tones[tone]}`}>{icon}</div>
      <div className="min-w-0 flex-1">
        <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
          {label}
        </p>
        <p className="mt-1 truncate text-xl font-semibold tracking-tight text-ink">
          {value}
        </p>
        {hint ? <p className="mt-0.5 text-xs text-muted">{hint}</p> : null}
      </div>
    </div>
  );
}

export function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-6 border-b border-line/60 py-2 last:border-0">
      <span className="shrink-0 text-xs text-muted">{label}</span>
      <span
        className={`min-w-0 break-words text-right text-xs font-medium text-ink ${
          mono ? "mono" : ""
        }`}
      >
        {value}
      </span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-3 rounded-xl bg-surface-2 p-3 text-muted">
        {icon ?? <Circle className="h-5 w-5" aria-hidden />}
      </div>
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      <p className="mt-1 max-w-md text-xs leading-relaxed text-muted">{description}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="space-y-3 p-6" role="status" aria-live="polite">
      <div className="skeleton h-4 w-1/3" />
      <div className="skeleton h-24 w-full" />
      <div className="skeleton h-4 w-2/3" />
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="m-6 rounded-xl border border-danger/30 bg-danger-soft p-5">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-danger" aria-hidden />
        <div>
          <h3 className="text-sm font-semibold text-ink">Something went wrong</h3>
          <p className="mt-1 break-words text-xs leading-relaxed text-muted">{message}</p>
          {onRetry ? (
            <button type="button" className="btn btn-sm mt-3" onClick={onRetry}>
              Try again
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function ScoreRing({
  score,
  label,
  size = 168,
}: {
  score: number | null;
  label: string;
  size?: number;
}) {
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const value = score ?? 0;
  const offset = circumference - (value / 100) * circumference;
  const color =
    score === null
      ? "var(--muted)"
      : score >= 90
        ? "var(--ok)"
        : score >= 75
          ? "var(--accent)"
          : score >= 50
            ? "var(--warn)"
            : "var(--danger)";

  return (
    <div
      className="relative flex shrink-0 items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Security score ${score ?? "unknown"}, ${label}`}
    >
      <svg width={size} height={size} viewBox="0 0 160 160" className="-rotate-90">
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="var(--line)"
          strokeWidth="10"
        />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms ease, stroke 300ms ease" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-4xl font-semibold tracking-tight" style={{ color }}>
          {score ?? "—"}
        </span>
        <span className="mt-0.5 text-[11px] font-semibold uppercase tracking-[0.1em] text-muted">
          {label}
        </span>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, FlaskConical, ShieldQuestion } from "lucide-react";
import { api } from "../lib/api";
import type { ModuleStatus, ModuleStatusValue } from "../lib/types";
import {
  ErrorState,
  ModuleStatusBadge,
  PageHeader,
  Panel,
  PanelHeader,
} from "./ui";
import { titleCase } from "../lib/format";

export interface Capability {
  label: string;
  state: ModuleStatusValue;
  detail: string;
}

export function ModulePage({
  moduleId,
  title,
  subtitle,
  capabilities,
  safety,
}: {
  moduleId: string;
  title: string;
  subtitle: string;
  capabilities: Capability[];
  safety: string;
}) {
  const [module, setModule] = useState<ModuleStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api
      .getModuleStatuses()
      .then((modules) => {
        if (!active) return;
        setModule(modules.find((item) => item.id === moduleId) ?? null);
        setError(null);
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, [moduleId]);

  return (
    <div className="fade-in">
      <PageHeader
        title={title}
        subtitle={subtitle}
        actions={
          module ? <ModuleStatusBadge status={module.status} /> : undefined
        }
      />

      {error ? <ErrorState message={error} /> : null}

      <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
        <Panel>
          <PanelHeader
            title="Implementation status"
            description="CyberGates reports exactly what exists. Nothing below is simulated."
          />
          <div className="p-5">
            {module ? (
              <div className="mb-5 rounded-xl border border-line bg-surface-2 p-4">
                <div className="flex items-center gap-2">
                  <ModuleStatusBadge status={module.status} />
                  <span className="text-sm font-semibold text-ink">{module.name}</span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-muted">
                  {module.detail}
                </p>
              </div>
            ) : null}

            <div className="space-y-3">
              {capabilities.map((capability) => (
                <div
                  key={capability.label}
                  className="flex items-start gap-3 rounded-xl border border-line/70 p-3.5"
                >
                  <ModuleStatusBadge status={capability.state} />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-ink">{capability.label}</p>
                    <p className="mt-0.5 text-xs leading-relaxed text-muted">
                      {capability.detail}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-5 rounded-xl border border-line bg-surface-2 p-4">
              <div className="flex items-center gap-2 text-xs font-semibold text-ink">
                <FlaskConical className="h-4 w-4 text-accent" aria-hidden />
                {titleCase("Current capability")}
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-muted">
                Only capabilities marked <strong>Available</strong> or{" "}
                <strong>Partial</strong> are backed by real code.{" "}
                <strong>Planned</strong> items have no working implementation yet and
                do not affect your security score.
              </p>
            </div>
          </div>
        </Panel>

        <div className="space-y-5">
          <Panel>
            <PanelHeader title="Safety and scope" />
            <div className="p-5">
              <div className="flex items-start gap-3">
                <ShieldQuestion className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
                <p className="text-xs leading-relaxed text-muted">{safety}</p>
              </div>
            </div>
          </Panel>

          <Panel>
            <PanelHeader title="Where to go now" />
            <div className="space-y-2 p-4">
              <Link
                to="/"
                className="flex items-center justify-between rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-xs font-medium text-ink transition-colors hover:bg-surface-3"
              >
                Run a local posture audit from Overview
                <ArrowUpRight className="h-3.5 w-3.5 text-muted" aria-hidden />
              </Link>
              <Link
                to="/reports"
                className="flex items-center justify-between rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-xs font-medium text-ink transition-colors hover:bg-surface-3"
              >
                Review audit history and exports
                <ArrowUpRight className="h-3.5 w-3.5 text-muted" aria-hidden />
              </Link>
              <Link
                to="/settings"
                className="flex items-center justify-between rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-xs font-medium text-ink transition-colors hover:bg-surface-3"
              >
                Inspect local data and retention
                <ArrowUpRight className="h-3.5 w-3.5 text-muted" aria-hidden />
              </Link>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

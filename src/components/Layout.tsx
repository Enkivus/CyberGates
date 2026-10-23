import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  Moon,
  Shield,
  Sun,
} from "lucide-react";
import type { Theme } from "../lib/theme";
import { findNavItem, NAV_GROUPS } from "./navigation";

const STORAGE_KEY = "cybergates.sidebar-collapsed";

export function Layout({
  theme,
  onToggleTheme,
}: {
  theme: Theme;
  onToggleTheme: () => void;
}) {
  const location = useLocation();
  const current = findNavItem(location.pathname);
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === "true";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, String(collapsed));
    } catch {
      // Ignore storage failures.
    }
  }, [collapsed]);

  return (
    <div className="flex h-full overflow-hidden bg-canvas text-ink">
      <aside
        className={`flex shrink-0 flex-col border-r border-line bg-surface transition-[width] duration-200 ${
          collapsed ? "w-[76px]" : "w-[258px]"
        }`}
      >
        <div
          className={`flex h-16 items-center gap-3 border-b border-line px-4 ${
            collapsed ? "justify-center" : ""
          }`}
        >
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent-strong">
            <Shield className="h-5 w-5" aria-hidden />
          </div>
          {!collapsed ? (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold tracking-tight">
                CyberGates
              </p>
              <p className="text-[10px] uppercase tracking-[0.14em] text-faint">
                Security console
              </p>
            </div>
          ) : null}
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-2.5 py-4" aria-label="Main">
          {NAV_GROUPS.map(([group, items]) => (
            <div key={group}>
              {!collapsed ? (
                <p className="mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-faint">
                  {group}
                </p>
              ) : (
                <div className="mx-2 mb-2 border-t border-line" />
              )}
              <div className="space-y-0.5">
                {items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === "/"}
                      title={collapsed ? item.label : undefined}
                      className={({ isActive }) =>
                        `nav-item ${isActive ? "nav-item-active" : ""} ${
                          collapsed ? "justify-center px-0" : ""
                        }`
                      }
                    >
                      <Icon className="h-[17px] w-[17px] shrink-0" aria-hidden />
                      {!collapsed ? <span className="truncate">{item.label}</span> : null}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-line p-2.5">
          <div
            className={`mb-1 rounded-lg px-2.5 py-2 text-[10px] leading-relaxed text-faint ${
              collapsed ? "hidden" : ""
            }`}
          >
            <p className="font-semibold text-muted">Local-first by design</p>
            <p>No data leaves this device without explicit consent.</p>
          </div>
          <button
            type="button"
            className="nav-item justify-center px-0"
            onClick={() => setCollapsed((value) => !value)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" aria-hidden />
            ) : (
              <>
                <ChevronLeft className="h-4 w-4" aria-hidden />
                <span>Collapse</span>
              </>
            )}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface/80 px-6 backdrop-blur">
          <div className="flex min-w-0 items-center gap-3">
            <span className="chip border-transparent status-pass">Local-only</span>
            <div className="h-4 w-px bg-line" />
            <div className="min-w-0">
              <p className="text-[10px] uppercase tracking-[0.12em] text-faint">
                {current.group}
              </p>
              <h2 className="truncate text-sm font-semibold text-ink">
                {current.label}
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden text-[11px] text-faint sm:block">v0.1.0</span>
            <button
              type="button"
              onClick={onToggleTheme}
              className="btn btn-sm"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? (
                <Sun className="h-4 w-4" aria-hidden />
              ) : (
                <Moon className="h-4 w-4" aria-hidden />
              )}
            </button>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1500px] px-6 py-6 lg:px-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useState } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Overview } from "./features/overview/Overview";
import { Monitoring } from "./features/monitoring/Monitoring";
import { NetworkSecurity } from "./features/network/NetworkSecurity";
import { Reports } from "./features/reports/Reports";
import { Settings } from "./features/settings/Settings";
import {
  AccountSecurity,
  Backup,
  Devices,
  FirewallPage,
  IncidentResponse,
  Privacy,
  Scanner,
  ThreatProtection,
  Toolkit,
  Vulnerabilities,
} from "./features/modules/ModulePages";
import { api } from "./lib/api";
import { applyTheme, initialTheme, type Theme } from "./lib/theme";

export default function App() {
  const [theme, setTheme] = useState<Theme>(() => initialTheme());

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const changeTheme = useCallback((next: Theme) => {
    setTheme(next);
    applyTheme(next);
    void api.updateSetting("theme", next).catch(() => {
      // Theme is already applied locally; persistence failure is non-fatal.
    });
  }, []);

  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout theme={theme} onToggleTheme={() => changeTheme(theme === "dark" ? "light" : "dark")} />}>
          <Route index element={<Overview />} />
          <Route path="threat-protection" element={<ThreatProtection />} />
          <Route path="scanner" element={<Scanner />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="network" element={<NetworkSecurity />} />
          <Route path="firewall" element={<FirewallPage />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route path="privacy" element={<Privacy />} />
          <Route path="account" element={<AccountSecurity />} />
          <Route path="incidents" element={<IncidentResponse />} />
          <Route path="backup" element={<Backup />} />
          <Route path="toolkit" element={<Toolkit />} />
          <Route path="devices" element={<Devices />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings theme={theme} onThemeChange={changeTheme} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

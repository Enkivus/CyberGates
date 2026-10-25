import { useCallback, useEffect, useMemo, useState } from "react";
import { Globe2, Network, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { api } from "../../lib/api";
import type { NetworkConnection, NetworkSnapshot } from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";

type Filter = "all" | "tcp" | "udp" | "listening" | "established";

export function NetworkSecurity() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [snapshot, setSnapshot] = useState<NetworkSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextConnections, nextSnapshot] = await Promise.all([
        api.getNetworkConnections(),
        api.getNetworkSnapshot(),
      ]);
      setConnections(nextConnections);
      setSnapshot(nextSnapshot);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return connections.filter((connection) => {
      if (filter === "tcp" && connection.protocol !== "TCP") return false;
      if (filter === "udp" && connection.protocol !== "UDP") return false;
      if (filter === "listening" && connection.state !== "LISTEN") return false;
      if (filter === "established" && connection.state !== "ESTABLISHED") return false;
      if (!needle) return true;
      return [
        connection.process,
        connection.localAddress,
        connection.remoteAddress,
        connection.state,
        String(connection.pid ?? ""),
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [connections, filter, query]);

  const listening = connections.filter((connection) => connection.state === "LISTEN").length;
  const remote = new Set(
    connections
      .map((connection) => connection.remoteAddress)
      .filter((address) => address && !address.startsWith("127.") && !address.startsWith("[::1]")),
  ).size;

  return (
    <div className="fade-in">
      <PageHeader
        title="Network Security"
        subtitle="Read-only inventory of active TCP/UDP sockets and the owning processes, collected with native tooling. No traffic is intercepted."
        actions={
          <button
            type="button"
            className="btn"
            onClick={() => void load()}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />

      <div className="mb-5 grid gap-4 sm:grid-cols-3">
        <KpiCard
          label="Visible sockets"
          value={connections.length}
          hint="TCP + UDP entries from the OS"
          icon={<Network className="h-4 w-4" aria-hidden />}
          tone="accent"
        />
        <KpiCard
          label="Listening services"
          value={listening}
          hint="Sockets accepting inbound connections"
          icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
          tone={listening > 0 ? "warn" : "ok"}
        />
        <KpiCard
          label="Remote endpoints"
          value={remote}
          hint="Distinct non-loopback peers"
          icon={<Globe2 className="h-4 w-4" aria-hidden />}
          tone="neutral"
        />
      </div>

      <div className="mb-4 rounded-xl border border-warn/30 bg-warn-soft px-4 py-3 text-xs leading-relaxed text-muted">
        <strong className="text-ink">Read-only:</strong> CyberGates does not perform
        network discovery, port scanning, traffic interception, DNS reputation lookups,
        or firewall changes here. Those operations require explicit authorization,
        scope controls, and rate limits that are not implemented yet. Some sockets owned
        by other users or system services may not be visible without elevated
        permissions.
      </div>

      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHeader
            title="Network interfaces"
            description={snapshot?.source ?? "Read-only local interface inventory"}
          />
          {!snapshot?.available ? (
            <EmptyState
              title="Interface inventory unavailable"
              description={snapshot?.scopeNote ?? "Loading local network configuration."}
            />
          ) : snapshot.interfaces.length === 0 ? (
            <EmptyState title="No interfaces found" description={snapshot.scopeNote} />
          ) : (
            <div className="divide-y divide-border">
              {snapshot.interfaces.map((iface) => (
                <div key={iface.name} className="flex items-start justify-between gap-4 py-3 first:pt-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 font-medium">
                      <span>{iface.name}</span>
                      <span className={`chip ${iface.up ? "status-pass border-transparent" : ""}`}>
                        {iface.up ? "Up" : "Down"}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted">
                      {iface.addresses.length ? iface.addresses.map((address) => (
                        <span className="mono" key={address}>{address}</span>
                      )) : <span>No non-loopback address exposed</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHeader
            title="Configured DNS resolvers"
            description="Local resolver configuration; no DNS traffic is queried or intercepted."
          />
          {!snapshot?.available ? (
            <EmptyState
              title="DNS configuration unavailable"
              description={snapshot?.warnings.join(" ") ?? "Loading local resolver configuration."}
            />
          ) : snapshot.dnsServers.length === 0 ? (
            <EmptyState title="No resolver addresses exposed" description={snapshot.scopeNote} />
          ) : (
            <ul className="space-y-2">
              {snapshot.dnsServers.map((server) => (
                <li className="mono rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm" key={server}>
                  {server}
                </li>
              ))}
            </ul>
          )}
          {snapshot?.warnings.map((warning) => (
            <p className="mt-3 text-xs text-muted" key={warning}>{warning}</p>
          ))}
        </Panel>
      </div>

      <Panel>
        <PanelHeader
          title="Active connections"
          description="Parsed from native socket listings. Empty fields mean the OS did not expose the value."
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <select
                className="select w-36 py-1.5 text-xs"
                value={filter}
                onChange={(event) => setFilter(event.target.value as Filter)}
                aria-label="Connection filter"
              >
                <option value="all">All</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="listening">Listening</option>
                <option value="established">Established</option>
              </select>
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                  aria-hidden
                />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Filter address or process"
                  className="input w-56 py-1.5 pl-8 text-xs"
                  aria-label="Filter connections"
                />
              </div>
            </div>
          }
        />
        {error ? (
          <ErrorState message={error} onRetry={() => void load()} />
        ) : loading && connections.length === 0 ? (
          <LoadingState label="Loading network connections" />
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No matching connections"
            description={
              connections.length === 0
                ? "No sockets were returned. The native connection provider may not be implemented for this platform or may require additional permissions."
                : "Adjust the filter or search query."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Proto</th>
                  <th>Process</th>
                  <th>Local</th>
                  <th>Remote</th>
                  <th>State</th>
                  <th>PID</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((connection, index) => (
                  <tr key={`${connection.protocol}-${connection.localAddress}-${index}`}>
                    <td className="text-xs font-semibold text-muted">{connection.protocol}</td>
                    <td className="font-medium">{connection.process ?? "Unknown"}</td>
                    <td className="mono text-[11px]">{connection.localAddress}</td>
                    <td className="mono text-[11px] text-muted">
                      {connection.remoteAddress || "—"}
                    </td>
                    <td>
                      <span
                        className={`chip ${
                          connection.state === "LISTEN"
                            ? "status-warning border-transparent"
                            : connection.state === "ESTABLISHED"
                              ? "status-pass border-transparent"
                              : ""
                        }`}
                      >
                        {connection.state || "—"}
                      </span>
                    </td>
                    <td className="mono text-xs text-faint">{connection.pid ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

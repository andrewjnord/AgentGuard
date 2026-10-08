import { useMemo, useState } from 'react';
import { RefreshCw, Server, Waypoints } from 'lucide-react';
import type { McpServer } from '../api/types';
import { Empty, ErrorBanner, SkeletonRows, Switch } from '../components/ui';
import { ago, errMsg, num } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { href } from '../lib/router';
import { useApp } from '../lib/store';

function Launch({ s }: { s: McpServer }) {
  if (s.transport === 'http') return <code className="launch">{s.url}</code>;
  return <code className="launch" title={[s.command, ...s.args].join(' ')}><b>{s.command}</b> {s.args.join(' ')}</code>;
}

export default function McpServers() {
  const { api, toast } = useApp();
  const servers = useAsync(() => api.mcpServers(), [api]);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState<Set<string>>(new Set());

  const groups = useMemo(() => {
    const m = new Map<string, McpServer[]>();
    for (const s of servers.data ?? []) m.set(s.client, [...(m.get(s.client) ?? []), s]);
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [servers.data]);

  const rescan = async () => {
    setScanning(true);
    try { const list = await api.rescanMcp(); servers.setData(() => list); toast(`Found ${num(list.length)} MCP servers`, 'ok'); }
    catch (e) { toast(errMsg(e), 'error'); } finally { setScanning(false); }
  };

  const toggle = async (s: McpServer, enabled: boolean) => {
    setBusy((b) => new Set(b).add(s.id));
    servers.setData((l) => l?.map((x) => (x.id === s.id ? { ...x, proxied: enabled } : x)));
    try {
      const updated = await api.setMcpProxy(s.id, enabled);
      servers.setData((l) => l?.map((x) => (x.id === s.id ? updated : x)));
      toast(enabled ? `${s.name} in ${s.client} now routes through AgentGuard. Restart ${s.client} to apply.` : `${s.name} in ${s.client} no longer proxied`, 'ok');
    } catch (e) {
      servers.setData((l) => l?.map((x) => (x.id === s.id ? s : x)));
      toast(errMsg(e), 'error');
    } finally { setBusy((b) => { const n = new Set(b); n.delete(s.id); return n; }); }
  };

  const total = servers.data?.length ?? 0;
  const proxied = servers.data?.filter((s) => s.proxied).length ?? 0;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>MCP servers</h1>
          <p className="lede">Servers configured in each AI client. Proxied servers send every tool call through AgentGuard, so the policy can block or hold it.</p>
        </div>
        <div className="actions">
          {servers.data && <span className="muted num-cell">{num(proxied)} of {num(total)} proxied</span>}
          <button className="btn" onClick={rescan} disabled={scanning}><RefreshCw size={14} className={scanning ? 'spin' : ''} />{scanning ? 'Scanning…' : 'Rescan configs'}</button>
        </div>
      </div>
      {servers.error && <ErrorBanner error={servers.error} onRetry={servers.reload} />}
      {!servers.data && !servers.error && <section className="panel"><SkeletonRows rows={6} cols={4} /></section>}
      {servers.data && total === 0 && (
        <section className="panel"><Empty icon={Server} title="No MCP servers configured" action={<button className="btn" onClick={rescan}>Rescan configs</button>}>
          AgentGuard reads MCP configs for Claude Desktop, Claude Code, Cursor, VS Code and Windsurf. Add a server in one of them and rescan.
        </Empty></section>
      )}
      <div className="grid">
        {groups.map(([client, list]) => (
          <section className="panel" key={client}>
            <div className="panel-head">
              <h2>{client}</h2>
              <span className="sub">{list.length} {list.length === 1 ? 'server' : 'servers'}</span>
              <span className="right muted path" title={list[0].configPath}>{list[0].configPath}</span>
            </div>
            <div className="table-wrap">
              <table className="data mcp-table">
                <thead><tr><th>Server</th><th>Transport</th><th>Launch</th><th>Last call</th><th>Proxy</th></tr></thead>
                <tbody>
                  {list.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <span className="stack">
                          <a className="strong" href={href('timeline', { agentId: s.agentId })}>{s.name}</a>
                          <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>{s.scope === 'project' ? 'Project config' : 'User config'}{s.configPath !== list[0].configPath && <> · <span className="path">{s.configPath}</span></>}</span>
                        </span>
                      </td>
                      <td><span className="chip">{s.transport === 'stdio' ? 'stdio' : 'HTTP'}</span></td>
                      <td style={{ maxWidth: 420 }}><Launch s={s} /></td>
                      <td className="nowrap muted">{ago(s.lastCallAt)}</td>
                      <td>
                        <span className="row">
                          <Switch checked={s.proxied} disabled={busy.has(s.id)} onChange={(v) => void toggle(s, v)} label={`Proxy ${s.name} in ${client}`} hideLabel />
                          <span className={s.proxied ? 'ink2' : 'muted'} style={{ fontSize: 'var(--fs-xs)' }}>{s.proxied ? <><Waypoints size={12} style={{ verticalAlign: -2 }} /> Enforced</> : 'Not proxied'}</span>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

import { useState, type ReactNode } from 'react';
import {
  Activity, Bell, Bot, FileCode2, Hand, LayoutDashboard, Moon, OctagonX, Play, Server, Settings, Sun, type LucideIcon,
} from 'lucide-react';
import type { Mode } from '../api/types';
import { MODES } from '../api/types';
import { duration, errMsg, num } from '../lib/format';
import { href, type Page } from '../lib/router';
import { useApp } from '../lib/store';
import { Logo } from './Logo';
import { Dialog } from './ui';

const NAV: { page: Page; label: string; icon: LucideIcon; group?: string }[] = [
  { page: 'overview', label: 'Overview', icon: LayoutDashboard },
  { page: 'agents', label: 'Agents', icon: Bot, group: 'Inventory' },
  { page: 'mcp', label: 'MCP servers', icon: Server },
  { page: 'timeline', label: 'Timeline', icon: Activity, group: 'Activity' },
  { page: 'approvals', label: 'Approvals', icon: Hand },
  { page: 'alerts', label: 'Alerts', icon: Bell },
  { page: 'policy', label: 'Policy', icon: FileCode2, group: 'Configuration' },
  { page: 'settings', label: 'Settings', icon: Settings },
];
export const PAGE_TITLES: Record<Page, string> = Object.fromEntries(NAV.map((n) => [n.page, n.label])) as Record<Page, string>;

const MODE_HELP: Record<Mode, string> = {
  monitor: 'Log everything, block nothing',
  enforce: 'Apply the policy: block and ask as written',
  strict: 'Unknown agents and unmatched actions need approval',
};

function ModeSwitch() {
  const { api, status, setStatus, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<Mode | null>(null);
  const mode = status?.mode;
  const set = async (m: Mode) => {
    setConfirm(null);
    setBusy(true);
    try { setStatus(await api.setMode(m)); toast(`Mode set to ${m}`, 'ok'); } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(false); }
  };
  return (
    <>
      <span className="mode-label" id="mode-label">Mode</span>
      <div className="mode-switch" role="radiogroup" aria-labelledby="mode-label">
        {MODES.map((m) => (
          <button key={m} role="radio" aria-checked={mode === m} data-mode={m} disabled={busy} title={MODE_HELP[m]}
            onClick={() => { if (m !== mode) { if (m === 'monitor') setConfirm(m); else void set(m); } }}>
            <span className="pip" aria-hidden="true" />{m[0].toUpperCase() + m.slice(1)}
          </button>
        ))}
      </div>
      {confirm && (
        <Dialog title="Switch to monitor mode?" onClose={() => setConfirm(null)}
          footer={<><button className="btn" onClick={() => setConfirm(null)} data-autofocus>Cancel</button><button className="btn primary" onClick={() => void set(confirm)}>Switch to monitor</button></>}>
          <p className="ink2">AgentGuard will keep recording every action but will stop blocking and stop asking for approval. Rules marked block will only raise alerts.</p>
        </Dialog>
      )}
    </>
  );
}

function KillSwitch() {
  const { api, status, setStatus, toast } = useApp();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const engaged = status?.killSwitch.engaged ?? false;
  const run = async (action: 'engage' | 'release' | 'terminate') => {
    setBusy(true);
    try {
      const s = await api.killSwitch(action);
      setStatus(s);
      toast(action === 'release' ? 'Agents released' : action === 'terminate' ? 'All agents terminated' : `Kill switch engaged: ${num(s.killSwitch.suspendedPids)} processes suspended`, 'ok');
      setOpen(false);
    } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(false); }
  };
  const active = status?.counts.activeAgents ?? 0;
  return (
    <>
      <button className={`kill ${engaged ? 'engaged' : ''}`} onClick={() => setOpen(true)} aria-haspopup="dialog">
        {engaged ? <Play size={15} /> : <OctagonX size={16} />}
        {engaged ? 'Release agents' : 'Kill switch'}
      </button>
      {open && !engaged && (
        <Dialog title="Stop every AI agent on this PC?" onClose={() => setOpen(false)}
          footer={<>
            <button className="btn" onClick={() => setOpen(false)} data-autofocus>Cancel</button>
            <button className="btn danger-outline" onClick={() => void run('terminate')} disabled={busy}>Terminate all</button>
            <button className="btn danger" onClick={() => void run('engage')} disabled={busy}><OctagonX size={15} />{busy ? 'Engaging…' : 'Suspend all agents'}</button>
          </>}>
          <p className="ink2">
            The kill switch suspends all {num(active)} running agents and their child processes, and blocks their network access.
            Nothing is lost: you can release them from the same button.
          </p>
          <p className="muted" style={{ fontSize: 'var(--fs-sm)' }}>Terminate ends the processes instead. Unsaved work in those agents will be lost.</p>
        </Dialog>
      )}
      {open && engaged && (
        <Dialog title="Release suspended agents?" onClose={() => setOpen(false)}
          footer={<>
            <button className="btn" onClick={() => setOpen(false)} data-autofocus>Keep suspended</button>
            <button className="btn primary" onClick={() => void run('release')} disabled={busy}><Play size={15} />{busy ? 'Releasing…' : 'Release agents'}</button>
          </>}>
          <p className="ink2">{num(status?.killSwitch.suspendedPids ?? 0)} suspended processes will resume and their network access will be restored. The policy applies to them again immediately.</p>
        </Dialog>
      )}
    </>
  );
}

export function Shell({ page, theme, onToggleTheme, children }: { page: Page; theme: 'light' | 'dark'; onToggleTheme: () => void; children: ReactNode }) {
  const { status, conn, pending, api } = useApp();
  const engaged = status?.killSwitch.engaged ?? false;
  const connLabel = { open: 'Live', connecting: 'Connecting', reconnecting: 'Reconnecting', offline: 'Offline' }[conn];
  return (
    <div className={`shell ${engaged ? 'killed' : ''}`}>
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <Logo />
          <div className="brand-text stack">
            <span className="brand-name">AgentGuard</span>
            <span className="brand-sub">for Windows</span>
          </div>
        </div>
        <div className="nav">
          {NAV.map((n) => {
            const count = n.page === 'approvals' ? pending.length : n.page === 'alerts' ? status?.counts.openAlerts ?? 0 : 0;
            return (
              <div key={n.page} style={{ display: 'contents' }}>
                {n.group && <div className="nav-group">{n.group}</div>}
                <a href={href(n.page)} aria-current={page === n.page ? 'page' : undefined} title={n.label}>
                  <n.icon size={17} aria-hidden="true" />
                  <span className="label">{n.label}</span>
                  {count > 0 && <span className={`count ${n.page === 'approvals' ? 'ask' : ''}`} aria-label={`${count} ${n.page === 'approvals' ? 'pending' : 'open'}`}>{count > 99 ? '99+' : count}</span>}
                  {count > 0 && n.page === 'approvals' && <span className="badge-dot" aria-hidden="true" />}
                </a>
              </div>
            );
          })}
        </div>
        <div className="sidebar-foot">
          <span>Version {status?.version ?? '–'}{api.isMock ? ' (demo data)' : ''}</span>
          {status && <span>Service up {duration(status.uptimeSeconds)}</span>}
        </div>
      </nav>
      <header className="topbar">
        <span className="topbar-title">{PAGE_TITLES[page]}</span>
        <span className="spacer" />
        <ModeSwitch />
        <span className="conn" data-state={conn} title={`Live updates: ${connLabel}`} role="status">
          <span className="dot" aria-hidden="true" /><span className="label">{connLabel}</span>
        </span>
        <button className="btn ghost icon" onClick={onToggleTheme} aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Light theme' : 'Dark theme'}>
          {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
        </button>
        <KillSwitch />
      </header>
      <main className="main" id="main">
        {engaged && (
          <div className="banner kill-banner" role="alert">
            <OctagonX size={16} />
            <span><strong>Kill switch engaged.</strong> All AI agents are suspended and cut off from the network{status?.killSwitch.since ? ` since ${new Date(status.killSwitch.since).toLocaleTimeString()}` : ''}.</span>
          </div>
        )}
        {children}
      </main>
    </div>
  );
}

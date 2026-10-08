import { useEffect, useId, useRef, type ReactNode } from 'react';
import { AppWindow, Bot, CircleHelp, Cpu, Puzzle, Server, Terminal, X, type LucideIcon } from 'lucide-react';
import type { AgentKind, Severity, Verdict } from '../api/types';

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <span className={`verdict ${verdict}`}>{verdict}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="sev" data-sev={severity}>
      <span className="bars" aria-hidden="true"><i /><i /><i /><i /></span>
      {severity}
    </span>
  );
}

const KIND_ICONS: Record<AgentKind, LucideIcon> = {
  cli: Terminal, desktop: AppWindow, 'ide-extension': Puzzle, 'local-model': Cpu, 'mcp-server': Server, unknown: CircleHelp,
};
export const KIND_LABELS: Record<AgentKind, string> = {
  cli: 'CLI agent', desktop: 'Desktop app', 'ide-extension': 'IDE extension', 'local-model': 'Local model', 'mcp-server': 'MCP server', unknown: 'Unrecognised',
};
export function KindIcon({ kind, size = 'md' }: { kind: AgentKind; size?: 'sm' | 'md' }) {
  const I = KIND_ICONS[kind] ?? Bot;
  return <span className={`kind-icon ${size === 'sm' ? 'sm' : ''}`} title={KIND_LABELS[kind]}><I size={size === 'sm' ? 13 : 16} aria-hidden="true" /></span>;
}

export function Skeleton({ w = '100%', h = 12, style }: { w?: number | string; h?: number; style?: React.CSSProperties }) {
  return <span className="skel" style={{ display: 'block', width: w, height: h, ...style }} aria-hidden="true" />;
}

export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div style={{ padding: '6px 16px' }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} style={{ display: 'grid', gridTemplateColumns: `repeat(${cols}, 1fr)`, gap: 16, padding: '11px 0', borderBottom: '1px solid var(--line)' }}>
          {Array.from({ length: cols }, (_, j) => <Skeleton key={j} w={`${50 + ((i * 7 + j * 13) % 45)}%`} />)}
        </div>
      ))}
    </div>
  );
}

export function Empty({ icon: Icon, title, children, action }: { icon: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <Icon size={30} strokeWidth={1.5} aria-hidden="true" />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="banner error" role="alert">
      <span style={{ flex: 1 }}>{error}</span>
      {onRetry && <button className="btn sm" onClick={onRetry}>Try again</button>}
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled, hideLabel }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; hideLabel?: boolean }) {
  return (
    <label className="switch">
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} aria-label={hideLabel ? label : undefined} />
      <span className="track" aria-hidden="true" />
      {!hideLabel && <span>{label}</span>}
    </label>
  );
}

function useEscape(onClose: () => void) {
  const ref = useRef(onClose); ref.current = onClose;
  useEffect(() => {
    const on = (e: KeyboardEvent) => { if (e.key === 'Escape') ref.current(); };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, []);
}

/** Moves focus into the container on open and restores it on close. */
function useFocusTrap<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const first = el?.querySelector<HTMLElement>('[data-autofocus]') ?? el?.querySelector<HTMLElement>('button, [href], input, select, textarea');
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab' || !el) return;
      const f = [...el.querySelectorAll<HTMLElement>('button:not(:disabled), [href], input:not(:disabled), select, textarea, [tabindex="0"]')];
      if (!f.length) return;
      const a = f[0], b = f[f.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); b.focus(); }
      else if (!e.shiftKey && document.activeElement === b) { e.preventDefault(); a.focus(); }
    };
    el?.addEventListener('keydown', onKey);
    return () => { el?.removeEventListener('keydown', onKey); prev?.focus?.(); };
  }, []);
  return ref;
}

export function Drawer({ title, subtitle, icon, onClose, children, footer }: { title: ReactNode; subtitle?: ReactNode; icon?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  useEscape(onClose);
  const ref = useFocusTrap<HTMLDivElement>();
  const id = useId();
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby={id} ref={ref}>
        <div className="drawer-head">
          {icon}
          <div className="stack" style={{ flex: 1 }}>
            <h2 id={id}>{title}</h2>
            {subtitle && <div className="muted" style={{ fontSize: 'var(--fs-sm)' }}>{subtitle}</div>}
          </div>
          <button className="btn ghost icon" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </aside>
    </>
  );
}

export function Dialog({ title, onClose, children, footer, wide, labelledBy }: { title?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean; labelledBy?: string }) {
  useEscape(onClose);
  const ref = useFocusTrap<HTMLDivElement>();
  const id = useId();
  return (
    <>
      <div className="scrim dialog-scrim" onClick={onClose} />
      <div className={`dialog ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={labelledBy ?? id} ref={ref}>
        <div className="dialog-body">
          {title && <h2 id={id}>{title}</h2>}
          {children}
        </div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </>
  );
}

/** Pretty-printed, lightly syntax-coloured JSON. */
export function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2) ?? 'null';
  const parts: ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) parts.push(<span key={i++} className={m[2] ? 'k' : 's'}>{m[1]}</span>, m[2] ?? '');
    else if (m[3]) parts.push(<span key={i++} className="b">{m[3]}</span>);
    else parts.push(<span key={i++} className="n">{m[4]}</span>);
    last = re.lastIndex;
  }
  parts.push(text.slice(last));
  return <pre className="json">{parts}</pre>;
}

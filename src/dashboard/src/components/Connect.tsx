import { useState } from 'react';
import { KeyRound, ShieldAlert } from 'lucide-react';
import { Logo } from './Logo';

export function Connect({ reason, busy, onSubmit }: { reason: 'missing' | 'rejected' | 'unreachable'; busy: boolean; onSubmit: (token: string) => void }) {
  const [token, setToken] = useState('');
  return (
    <div className="connect">
      <form className="connect-card" onSubmit={(e) => { e.preventDefault(); if (token.trim()) onSubmit(token.trim()); }}>
        <div className="row" style={{ gap: 10 }}>
          <Logo size={30} />
          <span className="brand-name" style={{ fontSize: 19 }}>AgentGuard</span>
        </div>
        <div className="stack" style={{ gap: 6 }}>
          <h1>Open AgentGuard from the tray icon</h1>
          <p className="muted">
            The dashboard needs an access token from the AgentGuard service. Opening it from the tray icon signs you in
            automatically. You can also paste a token below.
          </p>
        </div>
        {reason === 'rejected' && (
          <div className="banner error" role="alert"><ShieldAlert size={16} />The service rejected that token. It may have been rotated when the service restarted.</div>
        )}
        {reason === 'unreachable' && (
          <div className="banner warn" role="alert"><ShieldAlert size={16} />The AgentGuard service is not responding on this machine. Check that the AgentGuard service is running.</div>
        )}
        <div className="field">
          <label htmlFor="token">Access token</label>
          <div className="input-icon">
            <KeyRound size={15} />
            <input id="token" className="input mono" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} placeholder="Paste token" autoFocus />
          </div>
          <span className="hint">The token is kept for this browser tab only.</span>
        </div>
        <button className="btn primary" type="submit" disabled={!token.trim() || busy} style={{ height: 36 }}>{busy ? 'Connecting…' : 'Connect'}</button>
      </form>
    </div>
  );
}

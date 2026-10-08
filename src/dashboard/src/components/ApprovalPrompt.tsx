import { useEffect, useRef, useState } from 'react';
import { Hand } from 'lucide-react';
import { useApp, useStream } from '../lib/store';
import { ApprovalCard } from './ApprovalCard';
import { Dialog } from './ui';
import { navigate } from '../lib/router';

/**
 * Global prompt: when an `approval` stream message arrives with status "pending", show it in a modal so the
 * dashboard alone can be used to approve. Approvals already pending at load are listed on the Approvals page
 * instead, so opening the dashboard does not ambush the user.
 */
export function ApprovalPrompt({ suppressed }: { suppressed: boolean }) {
  const { pending } = useApp();
  const [queue, setQueue] = useState<string[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const original = useRef(document.title);

  useStream((m) => {
    if (m.type === 'approval' && m.data.status === 'pending') {
      setQueue((q) => (q.includes(m.data.id) ? q : [...q, m.data.id]));
    }
  });

  const live = queue.filter((id) => !dismissed.has(id) && pending.some((p) => p.id === id));
  const current = pending.find((p) => p.id === live[0]);

  useEffect(() => {
    const t = original.current;
    document.title = pending.length ? `(${pending.length}) Approval needed · AgentGuard` : t;
    return () => { document.title = t; };
  }, [pending.length]);

  if (!current || suppressed) return null;
  const more = live.length - 1;
  const close = () => setDismissed((d) => new Set(d).add(current.id));
  return (
    <Dialog onClose={close} wide labelledBy="approval-prompt-title">
      <div className="row" style={{ gap: 10 }}>
        <span className="prompt-icon"><Hand size={18} /></span>
        <div className="stack">
          <h2 id="approval-prompt-title">An agent is waiting for your decision</h2>
          <span className="muted" style={{ fontSize: 'var(--fs-sm)' }}>
            The action is on hold. If nobody answers before the timer runs out, it is denied.
            {more > 0 && ` ${more} more waiting.`}
          </span>
        </div>
      </div>
      <ApprovalCard approval={current} />
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="btn ghost sm" onClick={() => { close(); navigate('approvals'); }}>Open approvals</button>
        <button className="btn ghost sm" onClick={close}>Decide later</button>
      </div>
    </Dialog>
  );
}

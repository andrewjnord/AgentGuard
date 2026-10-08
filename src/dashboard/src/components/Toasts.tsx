import { CircleCheck, CircleX, Info, X } from 'lucide-react';
import { useApp } from '../lib/store';

export function Toasts() {
  const { toasts, dismissToast } = useApp();
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          {t.kind === 'ok' ? <CircleCheck size={16} color="var(--ok)" /> : t.kind === 'error' ? <CircleX size={16} color="var(--block)" /> : <Info size={16} color="var(--accent)" />}
          <span>{t.text}</span>
          <button className="btn ghost sm icon x" onClick={() => dismissToast(t.id)} aria-label="Dismiss"><X size={14} /></button>
        </div>
      ))}
    </div>
  );
}

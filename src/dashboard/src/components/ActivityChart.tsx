import { useEffect, useMemo, useRef, useState } from 'react';
import type { ActivityBucket } from '../api/types';
import { hm, num } from '../lib/format';

/**
 * Hourly stacked bars: each bar is the hour's total, split into blocked (bottom, red), asked (amber) and
 * everything else (neutral). Hover or focus a bar for exact counts. A table view is offered for screen readers.
 */
export function ActivityChart({ buckets, height = 220 }: { buckets: ActivityBucket[]; height?: number }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [W, setW] = useState(720);
  useEffect(() => {
    const el = wrap.current; if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const H = height;
  const pad = { l: 36, r: 8, t: 10, b: 24 };
  const innerW = W - pad.l - pad.r; const innerH = H - pad.t - pad.b;

  const { max, ticks } = useMemo(() => {
    const m = Math.max(4, ...buckets.map((b) => b.total));
    const step = niceStep(m / 4);
    const top = Math.ceil(m / step) * step;
    return { max: top, ticks: Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step) };
  }, [buckets]);

  const n = Math.max(1, buckets.length);
  const slot = innerW / n;
  const barW = Math.max(3, Math.min(22, slot - 2));
  const y = (v: number) => pad.t + innerH - (v / max) * innerH;
  const hb = hover !== null ? buckets[hover] : null;

  return (
    <div className="chart" ref={wrap}>
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label="Agent actions per hour over the last 24 hours" onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} className="grid" />
            <text x={pad.l - 8} y={y(t)} className="tick" textAnchor="end" dominantBaseline="middle">{num(t)}</text>
          </g>
        ))}
        {buckets.map((b, i) => {
          const x = pad.l + i * slot + (slot - barW) / 2;
          const other = Math.max(0, b.total - b.blocked - b.asked);
          const segs = [
            { v: b.blocked, cls: 'seg-block' },
            { v: b.asked, cls: 'seg-ask' },
            { v: other, cls: 'seg-rest' },
          ];
          let acc = 0;
          const gap = 1.5;
          const visible = segs.filter((s) => s.v > 0);
          return (
            <g key={b.ts} className={hover !== null && hover !== i ? 'dim' : ''}>
              {visible.map((s, k) => {
                const y0 = y(acc); acc += s.v; const y1 = y(acc);
                const isTop = k === visible.length - 1;
                const h = Math.max(1, y0 - y1 - (isTop ? 0 : gap));
                return isTop
                  ? <path key={s.cls} className={s.cls} d={roundTop(x, y0 - h, barW, h, Math.min(3, barW / 2, h))} />
                  : <rect key={s.cls} className={s.cls} x={x} y={y0 - h} width={barW} height={h} />;
              })}
              {(i % (W < 560 ? 6 : 3) === 0) && (
                <text x={x + barW / 2} y={H - 6} className="tick" textAnchor="middle">{hm(b.ts)}</text>
              )}
              <rect x={pad.l + i * slot} y={pad.t} width={slot} height={innerH} fill="transparent"
                tabIndex={0} aria-label={`${hm(b.ts)}: ${b.total} actions, ${b.blocked} blocked, ${b.asked} asked`}
                onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} className="hit" />
            </g>
          );
        })}
        <line x1={pad.l} x2={W - pad.r} y1={y(0)} y2={y(0)} className="axis" />
      </svg>
      {hb && hover !== null && (
        <div className="chart-tip" style={{ left: `${((pad.l + hover * slot + slot / 2) / W) * 100}%` }} role="status">
          <div className="strong">{hm(hb.ts)}–{hm(new Date(Date.parse(hb.ts) + 3600000).toISOString())}</div>
          <div className="tip-row"><span className="sw rest" />Total<b>{num(hb.total)}</b></div>
          <div className="tip-row"><span className="sw ask" />Asked<b>{num(hb.asked)}</b></div>
          <div className="tip-row"><span className="sw block" />Blocked<b>{num(hb.blocked)}</b></div>
        </div>
      )}
      <table className="sr-only">
        <caption>Actions per hour</caption>
        <thead><tr><th>Hour</th><th>Total</th><th>Asked</th><th>Blocked</th></tr></thead>
        <tbody>{buckets.map((b) => <tr key={b.ts}><td>{hm(b.ts)}</td><td>{b.total}</td><td>{b.asked}</td><td>{b.blocked}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

export function ChartLegend({ totals }: { totals: { total: number; asked: number; blocked: number } }) {
  return (
    <div className="legend">
      <span><i className="sw rest" />All actions <b>{num(totals.total)}</b></span>
      <span><i className="sw ask" />Asked <b>{num(totals.asked)}</b></span>
      <span><i className="sw block" />Blocked <b>{num(totals.blocked)}</b></span>
    </div>
  );
}

function niceStep(raw: number): number {
  const p = 10 ** Math.floor(Math.log10(Math.max(raw, 1)));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

function roundTop(x: number, y: number, w: number, h: number, r: number): string {
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

import { forwardRef, useImperativeHandle, useMemo, useRef, useState } from 'react';

export interface YamlEditorHandle { goToLine: (line: number) => void }

const LINE_H = 20; // px; must match .yaml-editor line-height
const PAD_T = 10;

/**
 * Plain textarea with a line-number gutter. Error lines are marked in the gutter and with a highlight band
 * behind the text. No external editor dependency.
 */
export const YamlEditor = forwardRef<YamlEditorHandle, {
  value: string; onChange: (v: string) => void; errorLines?: Set<number>; activeLine?: number | null; readOnly?: boolean; label: string;
}>(function YamlEditor({ value, onChange, errorLines, activeLine, readOnly, label }, ref) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const bands = useRef<HTMLDivElement>(null);
  const [cursorLine, setCursorLine] = useState(1);
  const lineCount = useMemo(() => value.split('\n').length, [value]);

  useImperativeHandle(ref, () => ({
    goToLine(line: number) {
      const el = ta.current; if (!el) return;
      const lines = el.value.split('\n');
      const l = Math.max(1, Math.min(line, lines.length));
      let pos = 0; for (let i = 0; i < l - 1; i++) pos += lines[i].length + 1;
      el.focus();
      el.setSelectionRange(pos, pos + lines[l - 1].length);
      el.scrollTop = Math.max(0, (l - 1) * LINE_H - el.clientHeight / 3);
      setCursorLine(l);
    },
  }), []);

  const syncScroll = () => {
    const el = ta.current; if (!el) return;
    if (gutter.current) gutter.current.scrollTop = el.scrollTop;
    if (bands.current) bands.current.style.transform = `translateY(${-el.scrollTop}px)`;
  };
  const trackCursor = () => {
    const el = ta.current; if (!el) return;
    setCursorLine(el.value.slice(0, el.selectionStart).split('\n').length);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    // Tab inserts two spaces (YAML forbids tabs). Escape releases focus so keyboard users are not trapped.
    if (e.key === 'Tab' && !e.shiftKey && !readOnly) {
      e.preventDefault();
      const { selectionStart: s, selectionEnd: en } = el;
      const next = el.value.slice(0, s) + '  ' + el.value.slice(en);
      onChange(next);
      requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2));
    } else if (e.key === 'Enter' && !readOnly) {
      // Keep indentation of the current line.
      const s = el.selectionStart;
      const lineStart = el.value.lastIndexOf('\n', s - 1) + 1;
      const indent = /^ */.exec(el.value.slice(lineStart, s))?.[0] ?? '';
      const extra = /:\s*$/.test(el.value.slice(lineStart, s)) ? '  ' : '';
      if (indent || extra) {
        e.preventDefault();
        const ins = `\n${indent}${extra}`;
        onChange(el.value.slice(0, s) + ins + el.value.slice(el.selectionEnd));
        requestAnimationFrame(() => el.setSelectionRange(s + ins.length, s + ins.length));
      }
    } else if (e.key === 'Escape') {
      el.blur();
    }
  };

  const marked = [...(errorLines ?? [])];
  return (
    <div className={`yaml-editor ${readOnly ? 'ro' : ''}`}>
      <div className="yaml-gutter" ref={gutter} aria-hidden="true">
        <div style={{ paddingTop: PAD_T, paddingBottom: 200 }}>
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i} className={`ln ${errorLines?.has(i + 1) ? 'err' : ''} ${cursorLine === i + 1 ? 'cur' : ''}`}>{i + 1}</div>
          ))}
        </div>
      </div>
      <div className="yaml-area">
        <div className="yaml-bands" ref={bands} aria-hidden="true">
          {marked.map((l) => <div key={l} className="band err" style={{ top: PAD_T + (l - 1) * LINE_H }} />)}
          {activeLine && <div className="band active" style={{ top: PAD_T + (activeLine - 1) * LINE_H }} />}
        </div>
        <textarea ref={ta} value={value} readOnly={readOnly} spellCheck={false} autoCapitalize="off" autoComplete="off" autoCorrect="off" wrap="off"
          aria-label={label} onChange={(e) => onChange(e.target.value)} onScroll={syncScroll} onKeyDown={onKeyDown} onKeyUp={trackCursor} onClick={trackCursor} onSelect={trackCursor} />
      </div>
      <div className="yaml-status" aria-live="off">
        <span>Ln {cursorLine}</span><span>{lineCount} lines</span><span>YAML · spaces</span>
      </div>
    </div>
  );
});

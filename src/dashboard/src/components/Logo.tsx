export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg className="brand-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2.5 4.5 6.8v8.4c0 7.2 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.1 11.5-14.3V6.8L16 2.5Z" fill="var(--accent)" />
      <path d="M16 8.2v15.6M10.2 13.4h11.6M11.8 19.2h8.4" stroke="var(--panel)" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  );
}

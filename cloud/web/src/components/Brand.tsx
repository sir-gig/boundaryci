export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? "brand-compact" : ""}`} aria-label="BoundaryCI Cloud">
      <span className="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 28 32" role="img">
          <path d="M14 1.5 26 6v8.7c0 7.6-5 13.2-12 15.8C7 27.9 2 22.3 2 14.7V6l12-4.5Z" />
          <path d="M9.2 15.6 12.4 19l6.7-7.2" />
        </svg>
      </span>
      <span className="brand-name">Boundary<span>CI</span></span>
      {!compact && <span className="brand-product">Cloud</span>}
    </div>
  );
}

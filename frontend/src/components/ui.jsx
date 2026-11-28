// Shared UI components. Styles live in index.css under the same class names.
import { useEffect, useId, useRef, useState } from 'react';
import { OctagonAlert, TriangleAlert, CircleAlert, CircleDot, CircleCheck, Info, Inbox, CircleX, RotateCw, X, ArrowUp, ArrowDown } from 'lucide-react';
import { severityKey, SEVERITY_LABELS } from '../utils/riskScore';

const cx = (...names) => names.filter(Boolean).join(' ');

const glyph = { size: 12, strokeWidth: 2.5, 'aria-hidden': true };
const SEVERITY_GLYPHS = {
  critical: <OctagonAlert {...glyph} />, high: <TriangleAlert {...glyph} />, medium: <CircleAlert {...glyph} />,
  low: <CircleDot {...glyph} />, info: <Info {...glyph} />,
};
const OK_GLYPH = <CircleCheck {...glyph} />;

export const PageHeader = ({ title, description, actions }) => (
  <header className="page-header">
    <div className="page-header-text">
      <h1>{title}</h1>
      {description && <p>{description}</p>}
    </div>
    {actions && <div className="page-header-actions">{actions}</div>}
  </header>
);

export const Button = ({ variant = 'secondary', size, icon: Icon, iconOnly, className, children, type = 'button', ...props }) => (
  <button
    type={type}
    className={cx('btn', variant !== 'secondary' && `btn-${variant}`, size === 'sm' && 'btn-sm', iconOnly && 'btn-icon', className)}
    {...props}
  >
    {Icon && <Icon size={size === 'sm' ? 14 : 16} aria-hidden="true" />}
    {iconOnly ? <span className="sr-only">{children}</span> : children}
  </button>
);

/* Severity badge: <Badge severity="HIGH" /> shows the glyph and label; children override the label.
   Neutral tag: <Badge>KEV</Badge>. Accent tag: <Badge tone="accent">. Clean/healthy status: <Badge tone="ok">. */
export const Badge = ({ severity, tone, mono, title, children }) => {
  const key = severityKey(severity);
  return (
    <span className={cx('badge', key && `badge-${key}`, tone === 'accent' && 'badge-accent', tone === 'ok' && 'badge-ok', mono && 'badge-score')} title={title}>
      {key ? SEVERITY_GLYPHS[key] : tone === 'ok' && OK_GLYPH}
      {children ?? (key ? SEVERITY_LABELS[key] : null)}
    </span>
  );
};

export const Card = ({ title, subtitle, actions, flush, className, children, ...props }) => (
  <section className={cx('card', flush && 'card-flush', className)} {...props}>
    {(title || actions) && (
      <div className="card-header">
        <div>
          {title && <h2 className="card-title">{title}</h2>}
          {subtitle && <div className="card-subtitle">{subtitle}</div>}
        </div>
        {actions}
      </div>
    )}
    <div className="card-body">{children}</div>
  </section>
);

export const KpiStrip = ({ items }) => (
  <div className="kpi-strip">
    {items.map(item => (
      <div className="kpi" key={item.label}>
        <div className="kpi-label">{item.label}</div>
        <div className="kpi-value">{item.value ?? '–'}</div>
        {item.note && <div className="kpi-note">{item.note}</div>}
      </div>
    ))}
  </div>
);

export const Skeleton = ({ width = '100%', height, lines = 1 }) => (
  <div aria-hidden="true">
    {Array.from({ length: lines }, (_, i) => (
      <div key={i} className={cx('skeleton', !height && 'skeleton-line')}
        style={{ width: lines > 1 && i === lines - 1 ? '60%' : width, height }} />
    ))}
  </div>
);

export const EmptyState = ({ icon: Icon = Inbox, title, children, action }) => (
  <div className="state" role="status">
    <div className="state-title"><Icon size={16} aria-hidden="true" />{title}</div>
    {children && <p>{children}</p>}
    {action && <div className="state-actions">{action}</div>}
  </div>
);

export const ErrorState = ({ title = 'Could not load this data', children, onRetry }) => (
  <div className="state state-error" role="alert">
    <div className="state-title"><CircleX size={16} aria-hidden="true" />{title}</div>
    {children && <p>{children}</p>}
    {onRetry && <div className="state-actions"><Button size="sm" icon={RotateCw} onClick={onRetry}>Try again</Button></div>}
  </div>
);

/* Table with its own loading, error and empty states.
   columns: [{ key, header, render?(row), align?: 'right', mono?, truncate?, width?, sortable? }]
   Clickable rows (onRowClick) are reachable by Tab and open with Enter or Space. */
export const Table = ({
  columns, rows, rowKey = 'id', onRowClick, selectedKey, caption,
  loading, error, onRetry, emptyTitle = 'Nothing to show', emptyText, sort, onSort, skeletonRows = 6, maxHeight,
}) => {
  if (error) return <ErrorState onRetry={onRetry}>{error}</ErrorState>;
  if (!loading && rows?.length === 0) return <EmptyState title={emptyTitle}>{emptyText}</EmptyState>;
  const keyOf = (row) => (typeof rowKey === 'function' ? rowKey(row) : row[rowKey]);
  return (
    <div className="table-wrap" style={maxHeight ? { maxHeight } : undefined}>
      <table className="table" aria-busy={loading || undefined}>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {columns.map(col => {
              const active = sort?.key === col.key;
              return (
                <th key={col.key} scope="col" className={col.align === 'right' ? 'align-right' : undefined}
                  style={col.width ? { width: col.width } : undefined}
                  aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}>
                  {col.sortable && onSort ? (
                    <button type="button" className="sort-btn" onClick={() => onSort(col.key)}>
                      {col.header}
                      {active && (sort.dir === 'asc' ? <ArrowUp size={12} aria-hidden="true" /> : <ArrowDown size={12} aria-hidden="true" />)}
                    </button>
                  ) : col.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: skeletonRows }, (_, i) => (
              <tr key={i}>{columns.map(col => <td key={col.key}><Skeleton width={col.align === 'right' ? '40px' : '70%'} /></td>)}</tr>
            ))
            : rows.map(row => {
              const key = keyOf(row);
              const open = onRowClick ? () => onRowClick(row) : undefined;
              return (
                <tr key={key}
                  className={cx(onRowClick && 'clickable', selectedKey === key && 'selected')}
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={onRowClick ? selectedKey === key : undefined}
                  onClick={open}
                  onKeyDown={open && (e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } })}>
                  {columns.map(col => (
                    <td key={col.key}
                      className={cx(col.align === 'right' && 'align-right', col.mono && 'mono', col.truncate && 'truncate', col.truncate && !col.width && 'grow')}
                      style={col.truncate && col.width ? { maxWidth: col.width } : undefined}>
                      {col.render ? col.render(row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
  );
};

export const Input = ({ label, hideLabel, hint, error, icon: Icon, id, multiline, className, ...props }) => {
  const autoId = useId();
  const inputId = id || autoId;
  const describedBy = [hint && `${inputId}-hint`, error && `${inputId}-error`].filter(Boolean).join(' ') || undefined;
  const Tag = multiline ? 'textarea' : 'input';
  return (
    <div className={cx('field', className)}>
      {label && <label htmlFor={inputId} className={hideLabel ? 'sr-only' : 'field-label'}>{label}</label>}
      <div className="input-box">
        {Icon && <Icon size={14} aria-hidden="true" />}
        <Tag id={inputId} className="input" aria-invalid={error ? true : undefined} aria-describedby={describedBy} {...props} />
      </div>
      {hint && <div id={`${inputId}-hint`} className="field-hint">{hint}</div>}
      {error && <div id={`${inputId}-error`} className="field-error"><CircleX size={12} aria-hidden="true" />{error}</div>}
    </div>
  );
};

/* Native <dialog>: traps focus, closes on Esc, returns focus to the opener */
export const Modal = ({ open, onClose, title, children, footer, className, drawer }) => {
  const ref = useRef(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      // showModal focuses the header's Close button; a form modal starts in its first field, a detail drawer stays there
      if (!drawer) dialog.querySelector('.modal-body :is(input, select, textarea)')?.focus();
    }
    if (!open && dialog.open) dialog.close();
  }, [open, drawer]);
  return (
    <dialog ref={ref} className={cx('modal', drawer && 'modal-drawer', className)} aria-labelledby={titleId}
      onCancel={e => { e.preventDefault(); onClose?.(); }}
      onClick={e => { if (e.target === ref.current) onClose?.(); }}>
      {open && (
        <>
          <div className="modal-header">
            <div id={titleId} className="modal-title" role="heading" aria-level={2}>{title}</div>
            <Button variant="ghost" size="sm" icon={X} iconOnly onClick={onClose}>Close</Button>
          </div>
          <div className="modal-body">{children}</div>
          {footer && <div className="modal-footer">{footer}</div>}
        </>
      )}
    </dialog>
  );
};

/* tabs: [{ id, label, count? }]. Arrow keys move between tabs (WAI-ARIA tabs pattern). */
export const Tabs = ({ tabs, value, onChange, label }) => {
  const [focusId, setFocusId] = useState(null);
  const refs = useRef({});
  useEffect(() => { if (focusId) refs.current[focusId]?.focus(); }, [focusId]);
  const move = (e, index) => {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const next = tabs[(index + step + tabs.length) % tabs.length];
    onChange(next.id);
    setFocusId(next.id);
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, i) => (
        <button key={tab.id} ref={el => { refs.current[tab.id] = el; }} type="button" role="tab" className="tab"
          aria-selected={value === tab.id} tabIndex={value === tab.id ? 0 : -1}
          onClick={() => onChange(tab.id)} onKeyDown={e => move(e, i)}>
          {tab.label}
          {tab.count != null && <span className="tab-count">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
};

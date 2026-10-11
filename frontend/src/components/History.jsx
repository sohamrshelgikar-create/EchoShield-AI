import RiskBadge from './RiskBadge.jsx'
import { ClockIcon } from './Icons.jsx'

const fmt = (iso) =>
  new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' })

export default function History({ items, onSelect, onClear }) {
  return (
    <section aria-labelledby="history-title">
      <div className="mb-1 flex items-center justify-between px-1">
        <h2 id="history-title" className="flex items-center gap-2 text-sm font-semibold text-slate-300">
          <ClockIcon className="h-4 w-4 text-slate-500" />
          Recent analyses
        </h2>
        {items.length > 0 && (
          <button type="button" onClick={onClear} className="rounded text-xs text-slate-500 transition hover:text-slate-200">
            Clear history
          </button>
        )}
      </div>
      <p className="mb-3 px-1 text-xs text-slate-500">
        Saved only in this browser (local storage). It is not uploaded, and clearing site data removes it.
      </p>

      {items.length === 0 ? (
        <div className="glass rounded-xl px-4 py-6 text-center text-sm text-slate-500">
          Nothing yet. Your last 5 checks will appear here.
        </div>
      ) : (
        <ul className="space-y-2">
          {items.map((h) => (
            <li key={h.id}>
              <button
                type="button"
                onClick={() => onSelect(h)}
                className="glass flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left transition duration-200 hover:border-accent/40 hover:bg-white/3"
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-slate-200">{h.message}</span>
                  <span className="mt-0.5 block text-xs text-slate-500">{fmt(h.at)}</span>
                </span>
                <span className="text-xs tabular-nums text-slate-500">{h.result.risk_score}</span>
                <RiskBadge level={h.result.risk_level} size="sm" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

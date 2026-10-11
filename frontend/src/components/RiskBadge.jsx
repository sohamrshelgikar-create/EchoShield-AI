import { riskFor } from '../lib/risk.js'

export default function RiskBadge({ level, size = 'md' }) {
  const r = riskFor(level)
  const pad = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border font-medium ${pad} ${r.soft}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: r.color }} aria-hidden="true" />
      {level}
    </span>
  )
}

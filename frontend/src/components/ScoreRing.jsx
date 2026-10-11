import { useEffect, useState } from 'react'

const R = 52
const C = 2 * Math.PI * R

/** Circular gauge. The arc animates from empty to the score on mount. */
export default function ScoreRing({ score, color }) {
  const [shown, setShown] = useState(0)

  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score))
    return () => cancelAnimationFrame(id)
  }, [score])

  return (
    <div
      className="relative h-32 w-32 shrink-0"
      role="img"
      aria-label={`Risk score ${score} out of 100`}
    >
      <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
        <circle cx="64" cy="64" r={R} fill="none" stroke="rgba(148,170,214,0.14)" strokeWidth="8" />
        <circle
          cx="64"
          cy="64"
          r={R}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={C * (1 - shown / 100)}
          style={{
            transition: 'stroke-dashoffset 1.1s cubic-bezier(0.22, 1, 0.36, 1)',
            filter: `drop-shadow(0 0 6px ${color}66)`,
          }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-3xl font-semibold tabular-nums text-white">{score}</div>
          <div className="-mt-0.5 text-xs text-slate-500">out of 100</div>
        </div>
      </div>
    </div>
  )
}

import { riskFor } from '../lib/risk.js'
import RiskBadge from './RiskBadge.jsx'
import ScoreRing from './ScoreRing.jsx'
import { AlertIcon, CheckIcon, LinkIcon } from './Icons.jsx'

const SEVERITY = [
  { key: 'high', title: 'Strong evidence', dot: 'bg-risk-high' },
  { key: 'medium', title: 'Supporting signals', dot: 'bg-risk-medium' },
  { key: 'low', title: 'Weak signals (common in genuine messages too)', dot: 'bg-slate-500' },
]

function Section({ title, children }) {
  return (
    <section className="border-t border-line pt-5">
      <h3 className="mb-3 text-sm font-semibold text-slate-300">{title}</h3>
      {children}
    </section>
  )
}

function speak(text) {
  if (!('speechSynthesis' in window) || !text) return
  window.speechSynthesis.cancel()
  window.speechSynthesis.speak(new SpeechSynthesisUtterance(text))
}

export default function ResultCard({ result }) {
  const r = riskFor(result.risk_level)
  const { indicator_details: details, recommendations, urls_found: urls, ai_explanation: ai } = result
  const noteFor = (name) => ai?.indicator_notes.find((n) => n.name === name)?.why_it_matters
  const canSpeak = typeof window !== 'undefined' && 'speechSynthesis' in window
  const usedAi = result.analysis_source === 'local+bedrock'

  return (
    <article
      className="glass animate-rise rounded-2xl p-5 sm:p-7"
      style={{ boxShadow: `0 1px 0 rgba(255,255,255,0.04) inset, 0 30px 70px -34px ${r.color}55` }}
      aria-live="polite"
    >
      <div className="mb-5 flex flex-wrap items-center gap-2 text-xs">
        <span
          className={`rounded-full border px-2.5 py-1 ${
            usedAi ? 'border-accent/40 bg-accent/10 text-accent' : 'border-line bg-white/3 text-slate-400'
          }`}
        >
          {usedAi ? 'Local rules + AI explanation' : 'Local rules only'}
        </span>
        {canSpeak && (
          <button
            type="button"
            onClick={() => speak(result.spoken_summary || result.summary)}
            className="rounded-full border border-line px-2.5 py-1 text-slate-300 transition hover:border-accent/40 hover:text-white"
          >
            ▶ Read the answer aloud
          </button>
        )}
      </div>

      <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center">
        <ScoreRing score={result.risk_score} color={r.color} />
        <div className="text-center sm:text-left">
          <RiskBadge level={result.risk_level} />
          <h2 className={`mt-3 text-xl font-semibold ${r.text}`}>{result.threat_type || r.label}</h2>
          <p className="mt-2 max-w-prose text-[15px] leading-relaxed text-slate-300">{result.summary}</p>
        </div>
      </div>

      {result.ai_notice && (
        <p className="mt-5 rounded-lg border border-risk-medium/30 bg-risk-medium/10 px-3 py-2 text-sm text-amber-100">
          {result.ai_notice}
        </p>
      )}

      <div className="mt-6 space-y-5">
        {ai && (
          <Section title="AI explanation">
            <p className="text-[15px] leading-relaxed text-slate-300">{ai.summary}</p>
            <p className="mt-2 text-xs text-slate-500">
              Written by an AI model ({ai.provider}) to explain the findings below. It does not change the score
              or the risk level, and it has not checked any link or sender.
            </p>
          </Section>
        )}

        {details.length > 0 ? (
          SEVERITY.map(({ key, title, dot }) => {
            const group = details.filter((d) => d.severity === key)
            if (group.length === 0) return null
            return (
              <Section key={key} title={title}>
                <ul className="space-y-3">
                  {group.map((d, i) => (
                    <li key={`${d.name}-${i}`} className="flex gap-3 text-[15px] leading-relaxed text-slate-300">
                      <span className={`mt-2 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} aria-hidden="true" />
                      <span>
                        <span className="font-medium text-slate-100">{d.name}</span>
                        {d.evidence && <span className="block text-slate-400">{d.evidence}</span>}
                        {noteFor(d.name) && (
                          <span className="mt-1 block text-sm text-accent/90">Why it matters: {noteFor(d.name)}</span>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </Section>
            )
          })
        ) : (
          <Section title="What we checked">
            <p className="flex gap-3 text-[15px] leading-relaxed text-slate-300">
              <AlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
              No known scam indicators were found. That does not prove the message is safe or genuine.
            </p>
          </Section>
        )}

        {urls.length > 0 && (
          <Section title="Links in this message">
            <ul className="space-y-2">
              {urls.map((u) => (
                <li key={u} className="flex items-start gap-3 text-sm text-slate-400">
                  <LinkIcon className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                  {/* Plain text on purpose: never make a suspicious link clickable. */}
                  <code className="break-all font-mono text-[13px] text-slate-300">{u}</code>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-500">
              Shown as plain text so you don't open them by accident. EchoShield has not opened or looked up these links.
            </p>
          </Section>
        )}

        {recommendations.length > 0 && (
          <Section title="What to do next">
            <ul className="space-y-2">
              {recommendations.map((item, i) => (
                <li key={i} className="flex gap-3 text-[15px] leading-relaxed text-slate-300">
                  <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-risk-none" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </Section>
        )}

        <p className="rounded-lg border border-line bg-white/3 px-3 py-2 text-xs leading-relaxed text-slate-400">
          {result.disclaimer}
        </p>
      </div>
    </article>
  )
}

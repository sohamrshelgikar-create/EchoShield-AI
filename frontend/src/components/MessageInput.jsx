import { MAX_LENGTH, MIN_LENGTH } from '../lib/api.js'
import { EXAMPLES } from '../lib/examples.js'
import { Spinner } from './Icons.jsx'

export default function MessageInput({ value, onChange, onSubmit, loading, aiAvailable, useAi, onUseAiChange }) {
  const tooShort = value.trim().length < MIN_LENGTH
  const nearLimit = value.length > MAX_LENGTH * 0.9

  const handleKey = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && !tooShort && !loading) onSubmit()
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        if (!tooShort && !loading) onSubmit()
      }}
      className="glass rounded-2xl p-3 transition-colors focus-within:border-accent/40 sm:p-4"
    >
      <label htmlFor="message" className="px-2 pt-1 text-sm font-medium text-slate-200">
        Is this message a scam?
      </label>
      <textarea
        id="message"
        value={value}
        onChange={(e) => onChange(e.target.value.slice(0, MAX_LENGTH))}
        onKeyDown={handleKey}
        rows={6}
        placeholder="Paste the SMS, WhatsApp or email text here…"
        className="mt-1 block min-h-40 w-full resize-y rounded-xl bg-transparent p-2 text-[15px] leading-relaxed text-slate-100 placeholder:text-slate-500 focus:outline-none"
      />

      <div className="flex flex-wrap items-center gap-2 px-2 pb-2">
        <span className="text-xs text-slate-500">Try a sample:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            type="button"
            onClick={() => onChange(ex.text)}
            className="rounded-full border border-line px-3 py-1 text-xs text-slate-300 transition hover:border-accent/40 hover:text-white"
          >
            {ex.label}
          </button>
        ))}
      </div>

      <div className="mt-1 flex flex-col gap-3 border-t border-line pt-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1 text-xs text-slate-500">
          <span className={`tabular-nums ${nearLimit ? 'text-risk-medium' : ''}`}>
            {value.length.toLocaleString()} / {MAX_LENGTH.toLocaleString()}
          </span>
          {aiAvailable && (
            <label className="flex cursor-pointer items-center gap-2 text-slate-400">
              <input
                type="checkbox"
                checked={useAi}
                onChange={(e) => onUseAiChange(e.target.checked)}
                className="accent-[#6ea2ff]"
              />
              Add an AI explanation (Amazon Bedrock)
            </label>
          )}
        </div>

        <button
          type="submit"
          disabled={tooShort || loading}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-linear-to-b from-[#6ea2ff] to-[#3f78e6] px-6 py-3 text-sm font-semibold text-white shadow-[0_8px_24px_-8px_rgba(79,140,255,0.7)] transition duration-200 hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45 disabled:shadow-none disabled:hover:brightness-100"
        >
          {loading ? (
            <>
              <Spinner className="h-4 w-4" />
              Checking…
            </>
          ) : (
            'Analyze message'
          )}
        </button>
      </div>
      <p className="px-2 pt-3 text-xs leading-relaxed text-slate-500">
        {aiAvailable && useAi
          ? 'Your text goes to the EchoShield backend. A copy with phone numbers, codes, emails and link paths masked is also sent to Amazon Bedrock for the AI explanation.'
          : 'Your text goes only to the EchoShield backend you are running.'}{' '}
        Please don't paste real passwords, PINs or OTPs.
      </p>
    </form>
  )
}

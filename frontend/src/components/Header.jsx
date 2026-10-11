import { ShieldIcon } from './Icons.jsx'

const PILLS = {
  loading: { dot: 'bg-slate-500', text: 'Checking server…' },
  offline: { dot: 'bg-risk-high', text: 'Server not reachable' },
  local: { dot: 'bg-risk-none', text: 'Local analysis mode' },
  bedrock: { dot: 'bg-accent', text: 'Local analysis + AI explanation (Amazon Bedrock)' },
}

export default function Header({ server, onRetry }) {
  const pill = PILLS[server] ?? PILLS.loading
  return (
    <header className="flex flex-col items-center text-center">
      <div className="relative mb-5 grid h-14 w-14 place-items-center rounded-2xl border border-line bg-ink-800/80">
        <span className="absolute inset-0 -z-10 rounded-2xl bg-accent/25 blur-xl" aria-hidden="true" />
        <ShieldIcon className="h-7 w-7 text-accent" />
      </div>
      <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">EchoShield AI</h1>
      <p className="mt-3 max-w-md text-balance text-[15px] leading-relaxed text-slate-400">
        Not sure about a message? Paste it below and ask: is this a scam? I'll check it for phishing,
        UPI and OTP fraud and tell you what to do next.
      </p>
      <div
        className="mt-4 inline-flex items-center gap-2 rounded-full border border-line bg-white/3 px-3 py-1 text-xs text-slate-400"
        role="status"
      >
        <span className={`h-1.5 w-1.5 rounded-full ${pill.dot}`} aria-hidden="true" />
        {pill.text}
        {server === 'offline' && (
          <button type="button" onClick={onRetry} className="ml-1 rounded text-accent hover:underline">
            Retry
          </button>
        )}
      </div>
    </header>
  )
}

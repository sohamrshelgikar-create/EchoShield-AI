import { useCallback, useEffect, useRef, useState } from 'react'
import Header from './components/Header.jsx'
import MessageInput from './components/MessageInput.jsx'
import ResultCard from './components/ResultCard.jsx'
import ErrorBanner from './components/ErrorBanner.jsx'
import History from './components/History.jsx'
import { analyzeMessage, ApiError, getHealth, normalizeResult } from './lib/api.js'
import { useHistory } from './hooks/useHistory.js'

const toHealthState = (res) =>
  res.ok
    ? { state: res.bedrockEnabled ? 'bedrock' : 'local', bedrockEnabled: res.bedrockEnabled }
    : { state: 'offline', bedrockEnabled: false }

export default function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [health, setHealth] = useState({ state: 'loading', bedrockEnabled: false })
  const [useAi, setUseAi] = useState(true)
  const { items, add, clear } = useHistory()

  const resultRef = useRef(null)
  const abortRef = useRef(null)

  const checkServer = useCallback(async () => {
    setHealth((h) => ({ ...h, state: 'loading' }))
    setHealth(toHealthState(await getHealth()))
  }, [])

  useEffect(() => {
    // Initial server check. State is only set after the request resolves.
    let active = true
    getHealth().then((res) => active && setHealth(toHealthState(res)))
    return () => {
      active = false
      abortRef.current?.abort()
    }
  }, [])

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [result])

  async function handleAnalyze() {
    const text = message.trim()
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await analyzeMessage(text, { useAi, signal: controller.signal })
      setResult(data)
      add(text, data)
    } catch (err) {
      if (err.name === 'AbortError') return
      setError(err instanceof ApiError ? err.message : 'Something went wrong. Please try again.')
      if (err instanceof ApiError && err.message.startsWith('Could not reach')) {
        setHealth({ state: 'offline', bedrockEnabled: false })
      }
    } finally {
      if (abortRef.current === controller) setLoading(false)
    }
  }

  function handleSelect(entry) {
    setMessage(entry.message)
    setResult(normalizeResult(entry.result))
    setError('')
  }

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-3xl flex-col px-4 pb-16 pt-12 sm:px-6 sm:pt-16">
      <Header server={health.state} onRetry={checkServer} />

      <main className="mt-10 space-y-6">
        <MessageInput
          value={message}
          onChange={setMessage}
          onSubmit={handleAnalyze}
          loading={loading}
          aiAvailable={health.bedrockEnabled}
          useAi={useAi}
          onUseAiChange={setUseAi}
        />

        {error && <ErrorBanner message={error} onRetry={handleAnalyze} onDismiss={() => setError('')} />}

        <div ref={resultRef} className="scroll-mt-6">
          {result && <ResultCard key={`${result.risk_score}-${result.summary}`} result={result} />}
        </div>

        <History items={items} onSelect={handleSelect} onClear={clear} />
      </main>

      <footer className="mt-auto space-y-2 pt-12 text-center text-xs leading-relaxed text-slate-600">
        <p>
          EchoShield gives guidance, not a guarantee. Automated checks can be wrong in both directions. If you
          lose money to fraud, call the National Cyber Crime Helpline 1930.
        </p>
        <p>
          A voice-style web prototype for the Alexa+ track. It is not an Alexa skill and does not connect to Alexa.
        </p>
      </footer>
    </div>
  )
}

// Base URL of the FastAPI backend. Override with VITE_API_URL in frontend/.env if needed.
export const API_BASE = (import.meta.env?.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '')
export const MIN_LENGTH = 3
export const MAX_LENGTH = 5000
const REQUEST_TIMEOUT_MS = 30000

export const DEFAULT_DISCLAIMER =
  'This is an automated risk assessment, not proof of fraud or of safety, and it can be wrong.'

export class ApiError extends Error {}

/** FastAPI returns `detail` as a string (our handlers) or a list (framework defaults). */
function readDetail(body) {
  const d = body?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0]?.msg) return d[0].msg
  return null
}

const asStrings = (v) => (Array.isArray(v) ? v.map((x) => String(x)) : [])

/**
 * Make any response (fresh or from older saved history) safe to render.
 * Everything is coerced to plain strings/arrays; the UI renders them as text only.
 */
export function normalizeResult(data) {
  const details = Array.isArray(data?.indicator_details)
    ? data.indicator_details.map((d) => ({
        name: String(d?.name ?? ''),
        evidence: String(d?.evidence ?? ''),
        severity: ['high', 'medium', 'low'].includes(d?.severity) ? d.severity : 'low',
      }))
    : asStrings(data?.indicators).map((name) => ({ name, evidence: '', severity: 'medium' }))

  const ai = data?.ai_explanation
  return {
    risk_level: ['NONE', 'LOW', 'MEDIUM', 'HIGH'].includes(data?.risk_level) ? data.risk_level : 'LOW',
    risk_score: Math.max(0, Math.min(100, Number(data?.risk_score) || 0)),
    summary: String(data?.summary ?? ''),
    threat_type: String(data?.threat_type ?? ''),
    indicator_details: details,
    recommendations: asStrings(data?.recommendations),
    urls_found: asStrings(data?.urls_found),
    spoken_summary: String(data?.spoken_summary ?? ''),
    analysis_source: data?.analysis_source === 'local+bedrock' ? 'local+bedrock' : 'local',
    ai_status: String(data?.ai_status ?? 'disabled'),
    ai_notice: data?.ai_notice ? String(data.ai_notice) : null,
    ai_explanation: ai
      ? {
          summary: String(ai.summary ?? ''),
          provider: String(ai.provider ?? 'Amazon Bedrock'),
          indicator_notes: Array.isArray(ai.indicator_notes)
            ? ai.indicator_notes.map((n) => ({
                name: String(n?.name ?? ''),
                why_it_matters: String(n?.why_it_matters ?? ''),
              }))
            : [],
        }
      : null,
    disclaimer: String(data?.disclaimer || DEFAULT_DISCLAIMER),
  }
}

async function request(path, options = {}, signal) {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, REQUEST_TIMEOUT_MS)
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort)

  try {
    return await fetch(`${API_BASE}${path}`, { ...options, signal: controller.signal })
  } catch (err) {
    if (err.name === 'AbortError' && !timedOut) throw err // cancelled by the app, not an error
    throw new ApiError(
      timedOut
        ? 'The server took too long to respond. Please try again.'
        : `Could not reach the EchoShield server at ${API_BASE}. Check that the backend is running, then try again.`,
    )
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}

export async function analyzeMessage(message, { useAi = true, signal } = {}) {
  const res = await request(
    '/api/analyze',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, use_ai: useAi }),
    },
    signal,
  )

  if (!res.ok) {
    const body = await res.json().catch(() => null)
    throw new ApiError(readDetail(body) ?? `The server returned an error (${res.status}). Please try again.`)
  }
  let data
  try {
    data = await res.json()
  } catch {
    throw new ApiError('The server sent an unreadable response. Please try again.')
  }
  return normalizeResult(data)
}

/** Returns { ok: true, bedrockEnabled } or { ok: false }. Never throws. */
export async function getHealth(signal) {
  try {
    const res = await request('/api/health', {}, signal)
    if (!res.ok) return { ok: false }
    const data = await res.json()
    return {
      ok: true,
      bedrockEnabled: Boolean(data?.bedrock?.enabled),
      bedrockStatus: String(data?.bedrock?.status ?? 'disabled'),
    }
  } catch {
    return { ok: false }
  }
}

import { afterEach, describe, expect, it, vi } from 'vitest'
import { analyzeMessage, ApiError, getHealth, normalizeResult } from './api.js'

const okBody = {
  risk_level: 'HIGH', risk_score: 90, summary: 's', threat_type: 'Possible phishing',
  indicators: ['x'], indicator_details: [{ name: 'Urgency', evidence: 'e', severity: 'high' }],
  recommendations: ['Do not click'], urls_found: [], spoken_summary: 'hi',
  analysis_source: 'local', ai_status: 'disabled', ai_notice: null, ai_explanation: null, disclaimer: 'd',
}

const mockFetch = (impl) => vi.stubGlobal('fetch', vi.fn(impl))
const json = (status, body) => Promise.resolve(new Response(JSON.stringify(body), { status }))

afterEach(() => vi.unstubAllGlobals())

describe('analyzeMessage', () => {
  it('posts the message and returns a normalised result', async () => {
    mockFetch(() => json(200, okBody))
    const r = await analyzeMessage('hello there', { useAi: false })
    const [url, init] = fetch.mock.calls[0]
    expect(url).toMatch(/\/api\/analyze$/)
    expect(JSON.parse(init.body)).toEqual({ message: 'hello there', use_ai: false })
    expect(r.risk_level).toBe('HIGH')
    expect(r.indicator_details[0].severity).toBe('high')
  })

  it('shows a friendly message when the server cannot be reached', async () => {
    mockFetch(() => Promise.reject(new TypeError('Failed to fetch')))
    await expect(analyzeMessage('hello there')).rejects.toThrow(/Could not reach the EchoShield server/)
  })

  it('surfaces validation messages from the API (422)', async () => {
    mockFetch(() => json(422, { detail: 'Message must be at least 3 characters.' }))
    await expect(analyzeMessage('ab')).rejects.toThrow('Message must be at least 3 characters.')
  })

  it('reads FastAPI list-style details', async () => {
    mockFetch(() => json(422, { detail: [{ msg: 'Field required' }] }))
    await expect(analyzeMessage('abc')).rejects.toThrow('Field required')
  })

  it('uses a generic message for 500s with no usable body', async () => {
    mockFetch(() => Promise.resolve(new Response('oops', { status: 500 })))
    const err = await analyzeMessage('abc').catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.message).toMatch(/server returned an error \(500\)/)
  })

  it('rejects an unreadable success body', async () => {
    mockFetch(() => Promise.resolve(new Response('not json', { status: 200 })))
    await expect(analyzeMessage('abc')).rejects.toThrow(/unreadable response/)
  })

  it('lets cancellations through as AbortError instead of showing an error', async () => {
    const controller = new AbortController()
    mockFetch((_u, init) => new Promise((_res, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), { name: 'AbortError' })))))
    const p = analyzeMessage('abc', { signal: controller.signal })
    controller.abort()
    await expect(p).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('getHealth', () => {
  it('reports bedrock state', async () => {
    mockFetch(() => json(200, { status: 'ok', bedrock: { enabled: true, status: 'configured' } }))
    expect(await getHealth()).toMatchObject({ ok: true, bedrockEnabled: true })
  })
  it('never throws when offline', async () => {
    mockFetch(() => Promise.reject(new TypeError('down')))
    expect(await getHealth()).toEqual({ ok: false })
  })
})

describe('normalizeResult', () => {
  it('upgrades an old saved result that only has string indicators', () => {
    const r = normalizeResult({ risk_level: 'MEDIUM', risk_score: 40, summary: 's', indicators: ['Old indicator'], recommendations: [], urls_found: [] })
    expect(r.indicator_details).toEqual([{ name: 'Old indicator', evidence: '', severity: 'medium' }])
    expect(r.analysis_source).toBe('local')
    expect(r.disclaimer).toBeTruthy()
  })
  it('clamps and sanitises unexpected values', () => {
    const r = normalizeResult({ risk_level: 'EXTREME', risk_score: 9999, indicator_details: [{ severity: 'weird' }] })
    expect(r.risk_level).toBe('LOW')
    expect(r.risk_score).toBe(100)
    expect(r.indicator_details[0].severity).toBe('low')
  })
})

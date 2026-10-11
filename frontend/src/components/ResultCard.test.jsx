import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import ResultCard from './ResultCard.jsx'
import { normalizeResult } from '../lib/api.js'

afterEach(cleanup)

const base = {
  risk_level: 'HIGH', risk_score: 88, summary: 'Looks risky.', threat_type: 'Possible phishing',
  indicator_details: [
    { name: 'Asks for sensitive details', evidence: 'Asks for your OTP.', severity: 'high' },
    { name: 'Generic greeting', evidence: "Contains 'dear customer'.", severity: 'low' },
  ],
  recommendations: ['Do not click the link.'], urls_found: ['http://bit.ly/x'],
  spoken_summary: 'Looks risky.', analysis_source: 'local', ai_status: 'disabled', disclaimer: 'Automated and can be wrong.',
}

describe('ResultCard', () => {
  it('shows score, level, evidence groups, actions, disclaimer and a local-only badge', () => {
    render(<ResultCard result={normalizeResult(base)} />)
    expect(screen.getByText('88')).toBeTruthy()
    expect(screen.getByText('HIGH')).toBeTruthy()
    expect(screen.getByText('Strong evidence')).toBeTruthy()
    expect(screen.getByText(/Weak signals/)).toBeTruthy()
    expect(screen.getByText('Do not click the link.')).toBeTruthy()
    expect(screen.getByText('Automated and can be wrong.')).toBeTruthy()
    expect(screen.getByText('Local rules only')).toBeTruthy()
  })

  it('distinguishes an AI-assisted result and labels it as not changing the score', () => {
    const ai = { ...base, analysis_source: 'local+bedrock', ai_status: 'used',
      ai_explanation: { summary: 'AI says why.', provider: 'Amazon Bedrock', indicator_notes: [{ name: 'Asks for sensitive details', why_it_matters: 'Banks never ask.' }] } }
    render(<ResultCard result={normalizeResult(ai)} />)
    expect(screen.getByText('Local rules + AI explanation')).toBeTruthy()
    expect(screen.getByText('AI says why.')).toBeTruthy()
    expect(screen.getByText(/does not change the score/)).toBeTruthy()
    expect(screen.getByText(/Banks never ask\./)).toBeTruthy()
  })

  it('shows the fallback notice when the AI layer was unavailable', () => {
    const r = { ...base, ai_status: 'unavailable', ai_notice: 'AI explanation is unavailable. Showing the local analysis.' }
    render(<ResultCard result={normalizeResult(r)} />)
    expect(screen.getByText(/AI explanation is unavailable/)).toBeTruthy()
    expect(screen.getByText('Local rules only')).toBeTruthy()
  })

  it('renders message-derived text as plain text and never as HTML or links', () => {
    const hostile = { ...base,
      summary: '<img src=x onerror="window.__pwned=1">',
      indicator_details: [{ name: '<b>bold</b>', evidence: '<script>window.__pwned=1</script>', severity: 'high' }],
      urls_found: ['javascript:alert(1)//<svg onload=alert(1)>'] }
    const { container } = render(<ResultCard result={normalizeResult(hostile)} />)
    expect(container.querySelector('img, script, svg[onload], a')).toBeNull()
    expect(container.textContent).toContain('<script>window.__pwned=1</script>')
    expect(window.__pwned).toBeUndefined()
  })

  it('does not claim safety when nothing was found', () => {
    render(<ResultCard result={normalizeResult({ ...base, risk_level: 'NONE', risk_score: 0, indicator_details: [], threat_type: 'No scam pattern detected' })} />)
    expect(screen.getByText(/does not prove the message is safe/)).toBeTruthy()
  })
})

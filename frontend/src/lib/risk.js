// Single source of truth for risk-level presentation.
export const RISK = {
  NONE: {
    label: 'No risk found',
    color: '#4ade9a',
    text: 'text-risk-none',
    soft: 'bg-risk-none/10 border-risk-none/30 text-risk-none',
  },
  LOW: {
    label: 'Low risk',
    color: '#5b9bff',
    text: 'text-risk-low',
    soft: 'bg-risk-low/10 border-risk-low/30 text-risk-low',
  },
  MEDIUM: {
    label: 'Medium risk',
    color: '#f5a524',
    text: 'text-risk-medium',
    soft: 'bg-risk-medium/10 border-risk-medium/30 text-risk-medium',
  },
  HIGH: {
    label: 'High risk',
    color: '#f0545b',
    text: 'text-risk-high',
    soft: 'bg-risk-high/10 border-risk-high/30 text-risk-high',
  },
}

export const riskFor = (level) => RISK[level] ?? RISK.LOW

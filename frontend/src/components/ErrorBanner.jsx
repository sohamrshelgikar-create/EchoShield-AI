import { AlertIcon } from './Icons.jsx'

export default function ErrorBanner({ message, onRetry, onDismiss }) {
  return (
    <div
      role="alert"
      className="animate-fade flex flex-col gap-3 rounded-xl border border-risk-high/30 bg-risk-high/10 px-4 py-3 text-sm text-red-200 sm:flex-row sm:items-start"
    >
      <div className="flex flex-1 items-start gap-3">
        <AlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-risk-high" />
        <p className="leading-relaxed">{message}</p>
      </div>
      <div className="flex gap-3 pl-7 sm:pl-0">
        {onRetry && (
          <button type="button" onClick={onRetry} className="rounded font-medium text-white underline-offset-2 hover:underline">
            Try again
          </button>
        )}
        <button type="button" onClick={onDismiss} className="rounded text-red-200/70 transition hover:text-white" aria-label="Dismiss error">
          Dismiss
        </button>
      </div>
    </div>
  )
}

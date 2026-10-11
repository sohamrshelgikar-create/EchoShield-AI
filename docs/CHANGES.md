# What changed and why

## Problems found in the uploaded project
- `.env.example` defaulted to `USE_BEDROCK=true`, `ap-south-1` and a Claude Sonnet 4.5 global inference profile, which disagreed with the `us-east-1` / Nova Micro plan, and asked for AWS access keys.
- The Bedrock client read access keys from the environment and ignored AWS profiles.
- The model's score, summary and indicators replaced the local analysis, so the AI could silently change the classification. Local rules were only a fallback.
- Message text was sent to the model unmasked.
- Any AWS error text was logged, and AWS was retried on every request (no pause after errors such as access denied).
- No startup validation, no tests, CORS missing `http://127.0.0.1:5173`, README mentioned Python 3.11.
- Analyzer: generic wording ("dear customer", "refund") counted as threats; "enter" + OTP flagged genuine OTP texts; no detection of APK/remote-access apps, parcel, job or investment scams; weak signals could stack to HIGH; no severity or evidence per indicator.
- Frontend: no distinction between local and AI results, no disclaimer, no retry, history not described as browser-local.

## Backend
| File | Change |
|------|--------|
| `backend/config.py` | New. Validated settings, safe defaults (`USE_BEDROCK=false`), no key settings. |
| `backend/schemas.py` | New. Pydantic request/response models; extra fields rejected. |
| `backend/analyzer.py` | Rewritten rules: severity + evidence per indicator, weak vs strong, genuine-OTP handling, new scam types, brand/link mismatch, threat type, spoken summary. Local analyzer is the only source of score and level. |
| `backend/bedrock_analyzer.py` -> `backend/bedrock_explainer.py` | Renamed and rewritten: explanation-only, profile+region session, bounded timeout, no retries, output validation, contradiction checks, error classification, cooldown, safe notices. |
| `backend/redact.py` | New. Masks numbers, emails, OTP-like codes, URL paths. |
| `backend/service.py` | Local first, optional AI second; any AI failure keeps the local result. |
| `backend/main.py` | App factory, lifespan startup, body-size limit (413), friendly 422s that never echo input, generic 500, richer `/api/health`, CORS from settings. |
| `backend/check_bedrock.py` | New. Single-call Bedrock check. |
| `.env.example`, `.gitignore`, `requirements*.txt`, `pytest.ini` | Rewritten or new. |
| `tests/*` | New. 111 tests, AWS mocked. |

## Frontend
| File | Change |
|------|--------|
| `src/lib/api.js` | Configurable base URL, 30s timeout, response normalisation (also for old history), health check. |
| `src/components/ResultCard.jsx` | Local vs AI badge, threat type, evidence grouped by strength, AI explanation block, links as plain text, disclaimer, read-aloud. |
| `src/components/MessageInput.jsx` | Conversational prompt, samples, AI toggle, accurate privacy note. |
| `src/components/Header.jsx`, `ErrorBanner.jsx`, `History.jsx`, `App.jsx` | Server status pill, retry, empty state, browser-local history note, Alexa+ prototype note. |
| `src/lib/examples.js` | New sample texts. |
| `src/**/*.test.*`, `vite.config.js`, `package.json` | vitest + Testing Library; API-error and safe-rendering tests. |

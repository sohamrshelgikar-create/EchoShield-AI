# EchoShield AI

A personal scam-safety assistant. Paste a suspicious SMS, WhatsApp message or email and ask: *is this a scam?*
EchoShield returns a risk score, the specific evidence behind it, and safe next steps.

- **Backend:** FastAPI. A deterministic **local rule-based analyzer** decides the score and risk level.
- **AI layer (optional):** Amazon Bedrock (Converse API, `amazon.nova-micro-v1:0`) adds a plain-language *explanation*.
  The AI **never changes the score or level**. If Bedrock is off, unavailable or returns bad output, the app
  keeps working with local analysis.
- **Frontend:** React + Vite + Tailwind dashboard with history saved in your browser.

> **Alexa+ track:** this is a voice-style **web prototype** (conversational prompt, spoken-style summary,
> "read aloud" using your browser's speech synthesis). It is **not** an Alexa skill and does not connect to Alexa.

Automated assessments can be wrong in both directions. "No indicators found" never means "safe".

---

## 1. Requirements

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.13 (3.12 also tested) | Check with `py --list` |
| Node.js | 20 or newer | Built and tested with Node 22 |
| AWS CLI | any recent v2 | Only needed to use Bedrock |

## 2. Run the backend (Windows PowerShell)

From the `EchoShield-AI` folder:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn backend.main:app --reload
```

If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then open a new terminal.

Check it works: open http://127.0.0.1:8000/api/health. You should see `"mode":"local"`.
Interactive docs: http://127.0.0.1:8000/docs

## 3. Run the frontend (second PowerShell window)

```powershell
cd EchoShield-AI\frontend
npm install
npm run dev
```

Open **http://localhost:5173**. The header pill shows whether the server is reachable and whether AI explanations are on.
If your backend is not at `http://127.0.0.1:8000`, copy `frontend\.env.example` to `frontend\.env` and set `VITE_API_URL`.

## 4. Configuration (`.env`, no secrets)

| Variable | Default | Meaning |
|----------|---------|---------|
| `USE_BEDROCK` | `false` | `false` = local analysis only, no AWS code runs. Must be `true` or `false`. |
| `AWS_PROFILE` | `echoshield` | AWS CLI profile used by boto3 |
| `AWS_REGION` | `us-east-1` | Region for Bedrock |
| `BEDROCK_MODEL_ID` | `amazon.nova-micro-v1:0` | Model used for explanations |
| `BEDROCK_MAX_TOKENS` | `512` | Output limit per call (64 to 2048) |
| `BEDROCK_TIMEOUT_SECONDS` | `10` | Read timeout (1 to 60) |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed browser origins (no `*`) |

Invalid values stop the server at startup with a clear message. **Do not put AWS access keys in `.env`**; the app
ignores them and uses the named CLI profile instead.

## 5. Turn on Bedrock (only after AWS access is verified)

Do these in order, and stop at the first step that fails:

1. Confirm your profile works: `aws sts get-caller-identity --profile echoshield`
2. Make sure your AWS account verification is complete and your IAM user/role is allowed to call the model (see section 6).
3. In `.env` set `USE_BEDROCK=true`.
4. Run the one-call check (it makes exactly **one** small model request):
   ```powershell
   python -m backend.check_bedrock
   ```
5. Restart `uvicorn`. The frontend pill should now say "Local analysis + AI explanation".

Being listed in the Bedrock model catalog does **not** guarantee you can invoke a model. If Bedrock refuses (for example
because account verification is pending), EchoShield shows a short notice, keeps the local result, and **pauses AWS
calls for 15 minutes** (60 seconds for temporary errors such as throttling) instead of retrying. Details go to the
server log as `Bedrock unavailable: kind=...`, never to the browser. `/api/health` shows `last_error` as a kind
such as `access_denied`.

### What data goes to Bedrock
Only when `USE_BEDROCK=true` and the user leaves "AI explanation" on: the local findings plus the message text with
phone/account numbers, emails, OTP-like codes and URL paths masked and truncated to 2,500 characters. Names and free
text are **not** detected, so do not paste anything you would not want processed by AWS.

### Cost
Nova Micro is a low-cost model, outputs are capped at `BEDROCK_MAX_TOKENS`, and there are no automatic retries.
Check current prices on the Amazon Bedrock pricing page and keep your $10 budget alert.

## 6. AWS: what you must do manually

1. Finish AWS account verification, then re-check Bedrock access in the console.
2. Confirm `amazon.nova-micro-v1:0` can be invoked in `us-east-1` for your account (Bedrock console, Model catalog).
3. Give the identity behind the `echoshield` profile a least-privilege policy such as below. **Do not use administrator access.**
   (Converse calls are authorised by `bedrock:InvokeModel`.)
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["bedrock:InvokeModel"],
       "Resource": "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"
     }]
   }
   ```
   If you later switch to the `us.amazon.nova-micro-v1:0` inference profile, the policy must also allow that
   inference-profile ARN and the underlying models in the profile's regions.
4. Keep the $10 budget alert. Never commit `~/.aws/credentials`; this repo's `.gitignore` already excludes `.env` and credentials files.
5. This project creates no AWS resources and deploys nothing.

Which AWS service is used: **Amazon Bedrock Runtime**, `Converse` API, via boto3 with
`boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)`.

## 7. API

`GET /api/health` returns `{status, version, mode, bedrock: {enabled, status, last_error}}` (no secrets).

`POST /api/analyze` body: `{"message": "...", "use_ai": true}` (message 3 to 5000 characters; unknown fields rejected;
request body limit 32 KB).

```json
{
  "risk_level": "HIGH",                  // NONE | LOW | MEDIUM | HIGH
  "risk_score": 100,                     // 0..100, always from the local analyzer
  "summary": "...",
  "threat_type": "Possible credential or OTP theft (phishing)",
  "indicators": ["Name: evidence", "..."],
  "indicator_details": [{"name": "...", "evidence": "...", "severity": "high"}],   // high=strong, medium=supporting, low=weak
  "recommendations": ["Never share your OTP...", "..."],
  "urls_found": ["http://bit.ly/..."],
  "spoken_summary": "Two or three short sentences for voice.",
  "analysis_source": "local",            // local | local+bedrock
  "ai_status": "disabled",               // disabled | skipped | used | unavailable
  "ai_notice": null,                     // short, safe reason when the AI layer was unavailable
  "ai_explanation": null,                // {summary, indicator_notes[], provider} when used
  "disclaimer": "..."
}
```

Errors: `422` invalid input (`{"detail": "..."}`, your text is never echoed back), `413` body too large, `500` generic.
Existing keys (`risk_level` in capitals, `indicators`, `recommendations`, `urls_found`) are unchanged so older clients keep
working; new fields are additive.

Try it:

```powershell
$body = @{ message = "Dear customer, your SBI KYC expires today. Share your OTP now: http://bit.ly/sbi-kyc" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/analyze -Method Post -Body $body -ContentType "application/json"
```

## 8. Tests

Backend (no AWS calls; Bedrock is mocked):

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Frontend:

```powershell
cd frontend
npm test
npm run lint
npm run build
```

### What was actually run for this version

| Check | Result | Environment |
|-------|--------|-------------|
| Backend `pytest` (111 tests) | passed | Python 3.12.3 and 3.13.13, Linux |
| Frontend `vitest` (16 tests) | passed | Node 22, Linux |
| `npm run build`, `npm run lint` | passed, 0 warnings | Node 22, Linux |
| Real server started with Bedrock enabled but no AWS profile | stayed up, local fallback, AI paused | Python 3.13.13, Linux |
| Windows 11 / PowerShell run | **not run** | commands follow standard Windows usage |
| Any real Bedrock invocation | **not run** (no credentials, no AWS calls made) | you verify with `python -m backend.check_bedrock` |
| Visual check in a real browser | **not run** | build and component tests only |

## 9. Limitations

- Rules are tuned for India-focused patterns (SBI, HDFC, UPI, KYC, OTP, parcel and job scams) and common Hinglish phrases. They will miss new or unusual scams and can flag unusual genuine messages.
- Link checks are pattern-based (shorteners, look-alike domains, raw IPs, odd TLDs). **No link is opened or looked up** and no threat-intelligence service is used. The list of official brand domains is small and not exhaustive.
- Redaction removes numbers, emails and URL paths but cannot find names or other free text.
- The 15-minute pause after an AWS error is per server process and resets when the server restarts.
- History is stored in your browser's local storage on this device only.
- The body-size limit protects the API, but there is no authentication or rate limiting. Do not expose this server publicly as-is.
- Real Alexa integration (a custom skill calling this API) is not built.

## 10. Troubleshooting

| Symptom | Fix |
|---------|-----|
| "Could not reach the EchoShield server" | Start `uvicorn`, and open the app at `http://localhost:5173` (not another port or host) |
| Server exits with `ConfigError` | Fix the named variable in `.env` (for example `USE_BEDROCK` must be `true` or `false`) |
| AI notice says access is not enabled | Verification or permissions are incomplete. Local analysis still works. Fix in AWS, then restart the server |
| AI notice says the AWS profile could not be used | Check `aws configure list-profiles` includes the name in `AWS_PROFILE` |
| Port 8000 or 5173 busy | Close the other process, or run `uvicorn backend.main:app --port 8001` and set `VITE_API_URL` |

## 11. Layout

```
EchoShield-AI/
├── backend/
│   ├── main.py               routes, validation, CORS, body limit
│   ├── config.py             settings + startup validation
│   ├── schemas.py            Pydantic request/response models
│   ├── analyzer.py           deterministic local analyzer (source of truth)
│   ├── redact.py             masks personal data before any AI call
│   ├── bedrock_explainer.py  optional Bedrock explanation, validation, cooldown
│   ├── service.py            local result first, AI explanation second
│   └── check_bedrock.py      one-call Bedrock check
├── tests/                    pytest suite (mocked AWS)
├── frontend/                 React + Vite + Tailwind, vitest tests
├── docs/CHANGES.md           what changed and why
├── .env.example  .gitignore  requirements*.txt  pytest.ini
```

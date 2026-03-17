# CyberShield AI
### Smart Cyber Defense Platform — IndiaNext Hackathon 2026

No trained ML model needed. Claude API handles all detection + explanation.

---

## Project Structure

```
cybershield/
├── app.py                  ← Flask backend (run this)
├── requirements.txt        ← Python dependencies
├── .env.example            ← Copy to .env with your API key
├── README.md
│
├── templates/
│   └── index.html          ← Full frontend (served by Flask)
│
└── static/                 ← Put any images/icons here (optional)
```

---

## Setup (5 minutes)

### Step 1 — Python environment

```bash
# Make sure Python 3.9+ is installed
python --version

# Create virtual environment (recommended)
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Get Anthropic API Key

1. Go to https://console.anthropic.com
2. Sign up (free credits on signup)
3. Create an API key
4. Copy it — looks like: `sk-ant-api03-...`

### Step 4 — Set your API key

**Option A — Environment variable (recommended for deployment):**
```bash
# Windows CMD:
set ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# Windows PowerShell:
$env:ANTHROPIC_API_KEY="sk-ant-api03-your-key-here"

# Mac/Linux:
export ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

**Option B — Paste in frontend (easiest for demo):**
Just run the server and paste the key in the header input on the website.

### Step 5 — Run the server

```bash
python app.py
```

You'll see:
```
==================================================
  CyberShield AI — Backend Server
  Running at: http://localhost:5000
==================================================
```

### Step 6 — Open the app

Open your browser and go to:
```
http://localhost:5000
```

That's it. Paste your API key in the header → Save → All 6 modules work.

---

## How It Works (No ML Model)

```
User Input
    │
    ▼
Flask Backend (app.py)
    │
    ├── Local heuristics run first (instant, no API needed)
    │     - Email: urgency words, domain mismatch, URL patterns
    │     - URL: entropy score, typosquatting, bad TLDs
    │     - Prompt: regex pattern matching for injection
    │     - Behavior: rule-based anomaly flags
    │
    ▼
Claude API (claude-sonnet-4-20250514)
    │
    ├── Receives: user input + local pre-analysis
    ├── Returns: risk score, explanation, indicators, actions
    │
    ▼
Frontend
    └── Displays results with confidence ring, risk bars, AI explanation
```

The local heuristics give Claude **extra context** — so the AI explanation is
more precise and grounded, not just vague guessing.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Check if backend is running |
| POST | `/api/scan/email` | Scan email for phishing/fraud |
| POST | `/api/scan/url` | Analyze malicious URL |
| POST | `/api/scan/prompt` | Detect prompt injection |
| POST | `/api/scan/deepfake` | Analyze synthetic content |
| POST | `/api/scan/behavior` | User behavior anomaly |
| POST | `/api/chat` | Ask AI about a scan result |

All POST endpoints accept JSON body with:
```json
{
  "text": "...",        // or "url", "event" depending on endpoint
  "api_key": "sk-ant-..." 
}
```

---

## For Deployment (Hackathon submission needs live link)

### Vercel / Railway / Render (free)

**Render (easiest):**
1. Push to GitHub
2. Go to render.com → New Web Service
3. Connect repo → set `ANTHROPIC_API_KEY` in environment
4. Build command: `pip install -r requirements.txt`
5. Start command: `python app.py`
6. Done — get your live URL

---

## Connecting Your Friend's Trained Model (future)

When your teammate's email/URL model is ready:

```python
# In app.py, inside scan_email() route, add before call_claude():

import pickle
model = pickle.load(open('models/email_model.pkl', 'rb'))
vectorizer = pickle.load(open('models/vectorizer.pkl', 'rb'))

# Get model prediction
features = vectorizer.transform([email_text])
prediction = model.predict(features)[0]       # 0=legit, 1=phishing
probability = model.predict_proba(features)[0][1]  # confidence

# Pass to Claude for explanation
user_content += f"\n\nML MODEL OUTPUT:\n- Prediction: {'PHISHING' if prediction else 'LEGIT'}\n- Probability: {probability:.2%}"
```

The rest of the code stays the same — Claude uses the model output as extra evidence.

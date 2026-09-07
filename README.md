# 🛡️ UPI Shield — AI-Powered Scam & Coercion Detector

**Contextual digital payment scam and coercion detector** that uses NLP to analyse SMS, WhatsApp, and UPI payment messages for fraud indicators. Outputs a **Threat Meter** and **bilingual (English/Hindi) safety warnings**.

## Features

- 🧠 **Hybrid NLP Engine** — Hugging Face zero-shot classification + linguistic pattern analysis
- 📊 **Threat Meter** — Animated circular gauge with composite risk scoring
- 🔍 **5-Category Analysis** — Financial fraud, urgency tactics, authority impersonation, phishing, coercion
- 🇮🇳 **Bilingual Safety Cards** — Pre-authored English + Hindi safety advisories
- 🔗 **UPI Intent Parser** — Parse `upi://pay?...` deep links for suspicious patterns
- 🎨 **Premium Dark UI** — Glassmorphism, animations, responsive design

## Quick Start

```bash
# 1. Install dependencies (with transformer model support)
pip install -r requirements.txt

# 2. Run the server
python app.py

# 3. Open http://localhost:8000
```

### Lite Mode (without PyTorch / Transformers)

```bash
# Install only FastAPI
pip install fastapi uvicorn python-multipart pydantic

# Run in pattern-only mode
set UPI_SHIELD_NO_MODEL=1
python app.py
```

## Demo

1. Open `http://localhost:8000`
2. Paste a scam message (or click a sample chip)
3. Click **Analyze Message**
4. View the Threat Meter, category breakdown, and bilingual safety cards

### Example Scam Message
```
Your recent transaction of Rs 12000 failed. A verification refund of Rs 11999
has been initiated. To receive refund, share your UPI PIN and OTP sent to your
registered mobile number immediately.
```
→ **Flagged as HIGH RISK** with phishing + urgency + coercion indicators.

## Architecture

```
upi-shield/
├── app.py              # FastAPI server + API endpoints
├── nlp_engine.py       # Hybrid NLP scam detection engine
├── upi_parser.py       # UPI intent string parser
├── requirements.txt    # Python dependencies
├── README.md
└── static/
    ├── index.html      # Frontend
    ├── style.css       # Dark theme styles
    └── script.js       # Client-side logic
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Analyze message text for scam indicators |
| `POST` | `/api/parse-upi` | Parse and analyze UPI intent strings |
| `GET`  | `/api/health` | Health check and model status |

## Tech Stack

- **Backend**: Python, FastAPI, Uvicorn
- **NLP**: Hugging Face Transformers (zero-shot classification with BART-MNLI)
- **Frontend**: Vanilla HTML/CSS/JS with premium dark theme
- **Design**: Inter font, glassmorphism, SVG animations

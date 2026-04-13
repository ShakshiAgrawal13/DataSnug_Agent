# 🛡️ DataSnug — AI-Powered Data Loss Prevention

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.0.0-black?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/Scikit--Learn-1.4.0-orange?style=for-the-badge&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/ML-Logistic%20Regression-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Hackathon-Rank%207-gold?style=for-the-badge"/>
</p>

<p align="center">
  <b>Detect. Prevent. Protect.</b><br/>
  A dual-engine AI system that detects sensitive data leakage across enterprise networks in real time.
</p>

---

## 🏆 About

**DataSnug** was built for **Intrusion Hackathon 2nd Edition** under the **AI/ML Track** — Problem Statement #10: *AI-Powered Data Loss Prevention for Enterprise Systems.*

Our team secured **Rank 7** out of all participating teams.

The project tackles a critical enterprise problem — organizations unknowingly leaking sensitive data like personal information, financial records, credentials, and intellectual property through emails, files, and network transfers.

---

## 🎯 Problem Statement

> *"Develop an AI system capable of detecting and preventing sensitive data leakage across enterprise networks."*

Organizations store sensitive information such as personal data, financial records, and intellectual property. DataSnug analyzes text and files to detect potential data leaks and prevent unauthorized data transfers — in real time.

---

## ✨ Features

- 🔍 **Dual-Engine Detection** — Pattern matching + ML model working together
- 🤖 **AI/ML Classification** — Trained Logistic Regression model with TF-IDF vectorization
- 📊 **Real-Time Risk Scoring** — Weighted scoring system (HIGH / MEDIUM / LOW / SAFE)
- 📁 **File & Text Scanning** — Supports `.txt`, `.csv`, `.log`, `.json` files
- 🎭 **Data Masking** — Sensitive values are never fully exposed on screen
- 🚨 **Live Alert Log** — Every scan is logged with timestamp and risk level
- 📈 **Stats Dashboard** — Live counters for total, high, medium, low risk scans
- 🧪 **Quick Test Samples** — One-click demo data for instant testing

---

## 🔍 What DataSnug Detects

| Data Type | Example | Risk Level |
|---|---|---|
| Credit Card Number | 4111 xxxx xxxx 1111 | 🔴 HIGH |
| Aadhaar Number | 2345 xxxx xxxx | 🔴 HIGH |
| Social Security Number | 123-xx-6789 | 🔴 HIGH |
| Password (plaintext) | password=xxxxx | 🔴 HIGH |
| API Key / Token | sk-xxxxxxxxxxxxxxxx | 🔴 HIGH |
| Email Address | john@example.com | 🟡 MEDIUM |
| Phone Number | +91 98xxxxx210 | 🟡 MEDIUM |
| Date of Birth | DOB: xx/xx/1995 | 🟡 MEDIUM |
| IP Address | 192.168.x.x | 🔵 LOW |
| Suspicious Content | AI-detected intent | 🟡 MEDIUM |

---

## 🧠 How It Works

```
User Input (Text / File)
        ↓
┌─────────────────────────────┐
│   ENGINE 1 — Pattern Engine │  Regex-based exact matching
│   Finds known sensitive     │  Credit cards, SSN, emails,
│   data formats instantly    │  passwords, Aadhaar, etc.
└─────────────────────────────┘
              +
┌─────────────────────────────┐
│   ENGINE 2 — ML Model       │  TF-IDF + Logistic Regression
│   Detects suspicious        │  Trained on 44 labeled samples
│   content by context        │  100% training accuracy
└─────────────────────────────┘
              ↓
     Weighted Risk Score
  ┌────────────────────────┐
  │  Score 0     → SAFE ✅  │
  │  Score 1–3   → LOW  🔵  │
  │  Score 4–8   → MEDIUM 🟡│
  │  Score 9+    → HIGH  🔴 │
  └────────────────────────┘
              ↓
    Result shown on Dashboard
    Alert logged in real time
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.8+, Flask 3.0 |
| ML / AI | Scikit-learn, TF-IDF Vectorizer, Logistic Regression |
| Pattern Engine | Python `re` module (Regex) |
| Model Storage | Pickle (.pkl) serialization |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Google Fonts (Orbitron, Inter, Share Tech Mono) |

---

## 📁 Project Structure

```
DataSnug/
│
├── app.py                  ← Flask server & API endpoints
├── train.py                ← ML model training script
├── requirements.txt        ← Python dependencies
│
├── models/
│   ├── detector.py         ← Core detection engine (Pattern + ML)
│   ├── classifier.pkl      ← Pre-trained ML model (saved)
│   └── __init__.py
│
├── templates/
│   └── index.html          ← Main dashboard (all-in-one)
│
├── static/
│   ├── css/style.css       ← Dashboard styling
│   └── js/main.js          ← Frontend logic
│
├── data/
│   └── sample_data.txt     ← Demo file with sensitive data
│
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/DataSnug.git
cd DataSnug
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Train the AI model** *(only needed once)*
```bash
python train.py
```

**4. Run the application**
```bash
python app.py
```

**5. Open in browser**
```
http://localhost:5000
```

---

## 🧪 Demo

Once the app is running:

1. Click **💳 Financial Data** → See HIGH RISK detection
2. Click **✅ Safe Text** → See SAFE result  
3. Go to **File Scan** tab → Upload `data/sample_data.txt`
4. Watch the **Live Alert Log** and **Stats** update in real time

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Loads the dashboard |
| POST | `/scan/text` | Scans plain text input |
| POST | `/scan/file` | Scans an uploaded file |
| GET | `/alerts` | Returns last 20 alerts |
| GET | `/stats` | Returns scan statistics |

### Example Request
```bash
curl -X POST http://localhost:5000/scan/text \
  -H "Content-Type: application/json" \
  -d '{"text": "Email: john@example.com, Card: 4111111111111111"}'
```

### Example Response
```json
{
  "risk_level": "HIGH",
  "risk_score": 11,
  "total_matches": 2,
  "ai_verdict": "SENSITIVE",
  "ai_confidence": 91.3,
  "summary": "⚠️ Detected 2 sensitive data types. Risk: HIGH",
  "findings": [
    {
      "type": "Credit Card Number",
      "emoji": "💳",
      "risk": "HIGH",
      "count": 1,
      "samples": ["41**********11"]
    },
    {
      "type": "Email Address",
      "emoji": "📧",
      "risk": "MEDIUM",
      "count": 1,
      "samples": ["jo**********om"]
    }
  ]
}
```

---

## 🤖 ML Model Details

| Parameter | Value |
|---|---|
| Algorithm | Logistic Regression |
| Vectorizer | TF-IDF (ngram_range 1–2, max_features 1000) |
| Training Samples | 44 labeled examples |
| Classes | SAFE (0), SENSITIVE (1) |
| Training Accuracy | 100% |
| Model File | `models/classifier.pkl` |

To retrain with new data, add examples to `train.py` and run:
```bash
python train.py
```

---

## 🔒 Security Design

- **Data Masking** — Raw sensitive values are never fully displayed. Only first 2 and last 2 characters are shown (`41**********11`)
- **No Data Storage** — Scanned content is never saved to disk
- **Local Processing** — Everything runs on your own machine, no data sent to external servers

---

## 🙌 Team

Built with 💙 at **Intrusion Hackathon 2nd Edition**

> Add your team member names and GitHub profiles here

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

## ⭐ Support

If you found this project helpful, please consider giving it a **star** on GitHub!

It means a lot and helps others discover the project. 🙏

---

<p align="center">
  Made with 💙 | Intrusion Hackathon 2nd Edition | AI/ML Track | Rank 7 🏆
</p>

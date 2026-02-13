# 🛡️ Secure Phishing Detection Platform

A sophisticated, full-stack cybersecurity solution designed to detect and analyze phishing threats in real-time. This platform combines machine learning models with rule-based heuristics to provide accurate risk assessments for URLs and email content.

## ✨ Features

### 🔍 Advanced Detection Engine
- **Hybrid Analysis**: Combines ML-based prediction with static rule-based analysis for maximum accuracy.
- **Real-time Scanning**: Instant analysis of URLs and email bodies.
- **Batch Processing**: Analyze up to 50 URLs simultaneously for enterprise-grade throughput.
- **Detailed Reports**: Comprehensive breakdown of risk scores, suspicious features, and confidence levels.

### � Security & Encryption
- **AES-256-GCM Encryption**: All authentication payloads are encrypted end-to-end.
- **HMAC-SHA256 Integrity**: Tamper-proof request verification.
- **RSA-2048 Key Exchange**: Secure session key delivery (production mode).
- **Replay Attack Prevention**: Timestamp-based payload expiry.
- **JWT Authentication**: Stateless, secure session management.
- **2FA / OTP via Email**: One-time passwords sent via Gmail SMTP.
- **Rate Limiting**: Built-in protection against brute-force and abuse.
- **Audit Logging**: Comprehensive tracking of user actions and system events.
- **RBAC**: Role-based access control (Admin, Analyst, User, Guest).

### 👤 User Experience
- **Detection History**: Personal dashboard to track and review past analyses.
- **Admin Panel**: User management, audit logs, and system statistics.
- **Interactive API Docs**: Auto-generated Swagger UI and ReDoc.

## �️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React.js, Vite |
| **Backend** | Python 3, FastAPI, Uvicorn |
| **Database** | SQLite + SQLAlchemy ORM |
| **ML Engine** | Scikit-learn, NumPy |
| **Auth** | python-jose (JWT), passlib (bcrypt) |
| **Encryption** | cryptography (AES-256-GCM, RSA-2048) |
| **Rate Limiting** | SlowAPI |

## 🚀 Quick Start

### Prerequisites
- **Python** 3.10 or higher
- **Node.js** 16.0 or higher
- **npm**

### Backend Setup

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
```

Edit `backend/.env` with your actual values (see Configuration below), then start the server:

```bash
python3 run.py
```

The FastAPI server will start on **http://localhost:5000**

- Swagger API Docs: **http://localhost:5000/docs**
- ReDoc: **http://localhost:5000/redoc**

### Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

The React app will start on **http://localhost:5173**

## ⚙️ Configuration

### Environment Variables (`backend/.env`)

```ini
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-16-char-app-password

SECRET_KEY=your-secret-key-change-in-production
JWT_SECRET=your-jwt-secret-key-change-in-production
DATABASE_URL=sqlite:///./instance/phishing_db.db
```

### Gmail SMTP Setup (Required for OTP/2FA)

1. Go to [Google Account Settings](https://myaccount.google.com/security) → **Security**
2. Enable **2-Step Verification**
3. Search for **App Passwords** and generate a new password for "Mail"
4. Use the generated 16-character password as your `SENDER_PASSWORD`

> **Note:** You cannot use your regular Gmail password. You must use an App Password.

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/request-otp` | Request OTP via email |
| POST | `/api/auth/verify-otp` | Verify OTP and login |
| POST | `/api/auth/login` | Password-based login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/profile` | Get user profile |
| POST | `/api/auth/change-password` | Change password |

### Encrypted Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/crypto/handshake` | Get AES session key |
| GET | `/api/auth/crypto/public-key` | Get RSA public key |
| POST | `/api/auth/secure-register` | AES-encrypted registration |
| POST | `/api/auth/secure-request-otp` | AES-encrypted OTP request |
| POST | `/api/auth/secure-verify-otp` | AES-encrypted OTP verification |

### Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/detection/analyze` | Analyze a single URL |
| POST | `/api/detection/batch` | Analyze multiple URLs (max 50) |
| GET | `/api/detection/history` | Get analysis history |
| GET | `/api/detection/result/{id}` | Get specific result |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | Get dashboard statistics |
| GET | `/api/dashboard/recent` | Get recent analyses |
| GET | `/api/dashboard/report` | Get user report |

### Admin (requires admin role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | List all users |
| GET | `/api/admin/users/{id}` | Get user details |
| PUT | `/api/admin/users/{id}/toggle` | Activate/deactivate user |
| GET | `/api/admin/audit-logs` | View audit logs |
| GET | `/api/admin/statistics` | System-wide statistics |

## 📁 Project Structure

```
phishing-detection-platform/
├── backend/
│   ├── app/
│   │   ├── __init__.py          # FastAPI app factory
│   │   ├── ml_engine/           # Hybrid ML + rule-based detector
│   │   ├── models/              # SQLAlchemy models
│   │   ├── routes/              # API route handlers
│   │   └── utils/               # Security, validation, crypto utilities
│   ├── .env.example
│   ├── requirements.txt
│   └── run.py                   # Uvicorn entry point
├── frontend/
│   ├── src/
│   │   ├── pages/               # React page components
│   │   └── services/            # API client + AES encryption
│   ├── package.json
│   └── vite.config.js
├── .gitignore
└── README.md
```

---

© 2026 Phishing Detection Platform. Secure your digital experience.
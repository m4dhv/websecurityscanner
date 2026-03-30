# Web Security Scanner Browser Extension - Complete Documentation

## 🎯 Project Overview

This project transforms your Python security scanner into a **browser extension** with **database integration** for vulnerability tracking and analysis.

### Components

```
┌─────────────────────────────────────────────────────────┐
│         Browser Extension (Chrome/Firefox)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ popup.html   │  │ content.js   │  │background.js │  │
│  │ popup.js     │  │(Link scanner)│  │(Services)    │  │
│  │ popup.css    │  │              │  │              │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└──────────────┬──────────────────────────────────────────┘
               │ HTTP/REST API
               ↓
┌─────────────────────────────────────────────────────────┐
│          Backend API (Flask - Python)                   │
│  ┌──────────────────────────────────────────────────┐   │
│  │ /api/scan/start                                  │   │
│  │ /api/scan/{id}/report                            │   │
│  │ /api/scan/{id}/complete                          │   │
│  │ /api/scans (list all)                            │   │
│  │ /api/scan/{id} (details)                         │   │
│  │ /api/stats (statistics)                          │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────┬──────────────────────────────────────────┘
               │ SQL Queries
               ↓
┌─────────────────────────────────────────────────────────┐
│      Database (PostgreSQL or SQLite)                    │
│  ┌──────────────────┐  ┌──────────────────────────┐    │
│  │ scan_sessions    │  │ vulnerabilities          │    │
│  │ - id (PK)        │  │ - id (PK)                │    │
│  │ - target_url     │  │ - session_id (FK)        │    │
│  │ - scan_date      │  │ - vulnerability_type     │    │
│  │ - status         │  │ - url                    │    │
│  │ - total_urls     │  │ - parameter              │    │
│  │ - vuln_found     │  │ - payload                │    │
│  │ - duration       │  │ - severity               │    │
│  │ - browser        │  │ - timestamp              │    │
│  └──────────────────┘  └──────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 File Structure

```
web-security-scanner/
│
├── Backend Files
│   ├── backend_api.py              # Flask REST API
│   ├── requirements.txt            # Python dependencies
│   ├── .env.example               # Environment template
│   └── dashboard.py               # Optional dashboard
│
├── Extension Files
│   ├── manifest.json              # Extension config
│   ├── popup.html                 # Popup UI
│   ├── popup.css                  # Popup styling
│   ├── popup.js                   # Popup logic
│   ├── content.js                 # Page content script
│   ├── background.js              # Service worker
│   └── images/                    # Icon assets
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── Documentation
│   ├── SETUP_GUIDE.md             # Detailed setup
│   ├── README.md                  # This file
│   └── quick-start.sh             # Auto setup script
│
└── Original File
    └── scanner.py                 # Your original scanner
```

---

## 🚀 Quick Start (5 Minutes)

### 1. Install Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Start server
python backend_api.py
```

The API will be available at `http://localhost:5000`

### 2. Load Extension

**Chrome:**
1. Visit `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the extension folder

**Firefox:**
1. Visit `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select any file from extension folder

### 3. Configure
- Click extension icon → ⚙️ Settings
- API URL: `http://localhost:5000`
- Save Settings

### 4. Start Scanning
- Visit any website
- Click extension icon → **Start Scan**
- View results in popup
- Check database via API

---

## 🔧 How It Works

### Scanning Flow

```
User clicks "Start Scan"
    ↓
Extension creates scan session (POST /api/scan/start)
    ↓
Extension extracts links from page
    ↓
For each URL:
  - Check for SQL injection payloads
  - Check for XSS payloads
  - Check for sensitive information
    ↓
Each vulnerability found → Report to API (POST /api/scan/{id}/report)
    ↓
Mark scan complete (PUT /api/scan/{id}/complete)
    ↓
Results saved to database
    ↓
User views results in dashboard
```

### Database Storage

All vulnerabilities are stored with:
- **Scan Session Info**: Target URL, date, duration, browser
- **Vulnerability Details**: Type, URL, parameter, payload, severity
- **Timestamps**: For audit trail and trending

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/scan/start` | Create new scan session |
| POST | `/api/scan/{id}/report` | Report found vulnerability |
| PUT | `/api/scan/{id}/complete` | Mark scan as complete |
| GET | `/api/scans` | Get all scan sessions |
| GET | `/api/scan/{id}` | Get scan details |
| GET | `/api/stats` | Get vulnerability statistics |
| GET | `/health` | Check API health |

---

## 🔍 Vulnerability Detection

### SQL Injection
- Detects: SQL errors in response
- Payloads tested: `'`, `1' OR '1'='1`, `' OR 1=1--`
- Severity: Critical

### Cross-Site Scripting (XSS)
- Detects: Unescaped script tags in response
- Payloads tested: `<script>alert('XSS')</script>`, `<img onerror>`
- Severity: High

### Sensitive Information Exposure
- Detects: Email addresses, API keys, phone numbers, SSNs
- Uses regex patterns for detection
- Severity: Medium/High

---

## 🗄️ Database Setup

### PostgreSQL (Recommended)

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian
brew install postgresql                              # macOS

# Create database
createdb security_scanner

# Update .env
DATABASE_URL=postgresql://user:password@localhost:5432/security_scanner
```

### SQLite (Simple, No Setup)

Uncomment in `backend_api.py`:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_scanner.db'
```

### Verify Tables

```bash
# PostgreSQL
psql security_scanner

# SQLite
sqlite3 security_scanner.db
.tables
```

---

## 📊 Using Results

### Via API

```bash
# Get all scans
curl http://localhost:5000/api/scans

# Get specific scan
curl http://localhost:5000/api/scan/1

# Get statistics
curl http://localhost:5000/api/stats
```

### Via Dashboard

Open in browser: `http://localhost:5000/dashboard`

Features:
- Overview stats (total scans, vulnerabilities)
- Charts by type and severity
- Recent vulnerability list
- Auto-refresh every 30 seconds

---

## ⚙️ Configuration

### Extension Settings

In popup.js:
- **API URL**: Backend endpoint (default: `http://localhost:5000`)
- **Max Depth**: How deep to crawl (default: 3)
- **Auto Report**: Auto-send findings to API (default: true)

### Backend Configuration

In `.env`:
```
DATABASE_URL=postgresql://user:pass@localhost:5432/security_scanner
FLASK_ENV=development
FLASK_DEBUG=True
API_PORT=5000
```

---

## 🔒 Security Considerations

### ⚠️ Important Notes

1. **Authorization**: Only scan websites you own or have permission to test
2. **Rate Limiting**: Be aware of server load and timeouts
3. **WAF Detection**: Some payloads may trigger security systems
4. **Legal**: Check local laws regarding penetration testing
5. **Data Privacy**: Store only necessary vulnerability details

### Best Practices

1. **Testing Environments**: Use staging servers, not production
2. **Disclosure**: Follow responsible disclosure if finding real issues
3. **Credentials**: Never log sensitive data to database
4. **Encryption**: Use HTTPS in production
5. **Access Control**: Restrict dashboard access

---

## 🐛 Troubleshooting

### Extension won't connect to API
```
✓ Backend running: python backend_api.py
✓ API URL in settings: http://localhost:5000
✓ Port 5000 not blocked
✓ CORS enabled (already in code)
```

### Database connection fails
```
✓ PostgreSQL installed and running
✓ Credentials correct in .env
✓ Database created: createdb security_scanner
✓ SQLAlchemy installed: pip install Flask-SQLAlchemy
```

### Extension doesn't load
```
✓ All files in correct folder
✓ manifest.json is valid JSON
✓ Refresh extension in chrome://extensions/
✓ Check console (F12) for errors
```

### Scans not saving
```
✓ API endpoint working: curl http://localhost:5000/health
✓ Database has tables: SELECT * FROM scan_sessions;
✓ Check Flask logs for errors
✓ Check browser console (F12)
```

---

## 🚦 Next Steps

### Phase 2: Enhancements

- [ ] **Advanced Scanning**
  - CSRF detection
  - JWT token analysis
  - Security header checks

- [ ] **Reporting**
  - PDF export
  - HTML reports
  - Email notifications

- [ ] **Dashboard**
  - Interactive charts
  - Filter by severity
  - Export capabilities

- [ ] **Collaboration**
  - Multi-user support
  - Scan sharing
  - Comments/notes

- [ ] **Automation**
  - Scheduled scans
  - Webhook notifications
  - CI/CD integration

### Phase 3: Enterprise

- [ ] Manage multiple projects
- [ ] API key authentication
- [ ] Role-based access control
- [ ] Vulnerability trends
- [ ] SLA tracking

---

## 📚 API Examples

### Create Scan

```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "browser": "Chrome"
  }'
```

Response:
```json
{
  "session_id": 1,
  "message": "Scan session created"
}
```

### Report Vulnerability

```bash
curl -X POST http://localhost:5000/api/scan/1/report \
  -H "Content-Type: application/json" \
  -d '{
    "type": "SQL Injection",
    "url": "https://example.com/search?q=test",
    "parameter": "q",
    "payload": "\' OR 1=1--",
    "severity": "critical"
  }'
```

### Get Statistics

```bash
curl http://localhost:5000/api/stats
```

Response:
```json
{
  "total_scans": 10,
  "total_vulnerabilities": 27,
  "vulnerabilities_by_type": {
    "SQL Injection": 8,
    "XSS": 12,
    "Sensitive Information Exposure": 7
  },
  "vulnerabilities_by_severity": {
    "critical": 3,
    "high": 10,
    "medium": 12,
    "low": 2
  }
}
```

---

## 📝 License

This project is provided as-is for educational and authorized security testing purposes.

---

## ❓ FAQ

**Q: Can I scan production websites?**
A: Only if you have explicit written authorization. Unauthorized testing is illegal.

**Q: How do I scan without an API?**
A: Modify `popup.js` to store results locally instead of sending to API.

**Q: Can I use this for commercial scanning services?**
A: Review licensing requirements and consider OWASP ZAP or Burp Suite for commercial use.

**Q: How do I scale this?**
A: Add load balancing, caching, queue system (Celery), and distributed scanning.

**Q: Is my data private?**
A: Data is stored locally on your database server. Use HTTPS and access controls in production.

---

## 📞 Support Resources

- **OWASP**: https://owasp.org/
- **CWE**: https://cwe.mitre.org/
- **Flask Docs**: https://flask.palletsprojects.com/
- **SQLAlchemy**: https://www.sqlalchemy.org/

---

**Happy Scanning! 🔒**

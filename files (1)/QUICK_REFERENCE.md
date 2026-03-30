# Quick Reference Guide

## 🎯 30-Second Overview

Your Python scanner is now a **browser extension** that:
1. ✅ Runs directly in Chrome/Firefox
2. ✅ Sends findings to a **REST API**
3. ✅ Stores results in **PostgreSQL/SQLite**
4. ✅ Provides statistics and dashboards

---

## 🚀 Installation (Copy-Paste Steps)

### Step 1: Terminal (Install Backend)
```bash
# Navigate to your project folder
cd /path/to/web-security-scanner

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env

# Start backend (keep terminal open!)
python backend_api.py

# You should see: "Running on http://0.0.0.0:5000"
```

### Step 2: Chrome/Firefox (Load Extension)

**Chrome:**
1. Open `chrome://extensions/`
2. Toggle **Developer mode** ON (top right)
3. Click **Load unpacked**
4. Select your extension folder
5. ✅ Icon appears in toolbar

**Firefox:**
1. Open `about:debugging`
2. Click **This Firefox**
3. Click **Load Temporary Add-on**
4. Select any file from extension folder
5. ✅ Icon appears in toolbar

### Step 3: Use Extension
1. Visit any website
2. Click scanner icon
3. Click **Start Scan**
4. Watch results appear
5. Click **View Dashboard** to see database

---

## 📂 File Organization

```
Create folder: web-security-scanner/

Add these files:
├── backend_api.py          # API Server (Python)
├── requirements.txt        # Dependencies
├── .env                    # Configuration
│
├── manifest.json           # Extension config
├── popup.html             # Popup window
├── popup.css              # Styling
├── popup.js               # Logic
├── content.js             # Page scanner
├── background.js          # Service worker
└── images/                # Icons (optional)
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 🔧 Configuration (One-Time Setup)

### .env File
```env
# PostgreSQL (recommended)
DATABASE_URL=postgresql://user:password@localhost:5432/security_scanner

# OR SQLite (no setup needed)
# DATABASE_URL=sqlite:///security_scanner.db

FLASK_ENV=development
API_PORT=5000
```

### Extension Settings (In-App)
1. Click scanner icon
2. Click ⚙️ (Settings)
3. Enter: `http://localhost:5000`
4. Save

---

## 📊 Database Locations

### View Results - Option 1: Via Browser
```
http://localhost:5000/dashboard
```

### View Results - Option 2: Via API
```bash
# All scans
curl http://localhost:5000/api/scans

# Specific scan
curl http://localhost:5000/api/scan/1

# Statistics
curl http://localhost:5000/api/stats
```

### View Results - Option 3: Direct Database
```bash
# PostgreSQL
psql security_scanner
SELECT * FROM scan_sessions;
SELECT * FROM vulnerabilities;

# SQLite
sqlite3 security_scanner.db
.tables
SELECT * FROM scan_sessions;
```

---

## 🔍 What Gets Scanned

| Type | Detection | Example |
|------|-----------|---------|
| **SQL Injection** | Error messages | `' OR '1'='1` |
| **XSS** | Unescaped HTML | `<script>alert('xss')</script>` |
| **Sensitive Info** | Patterns | Email, API keys, phone numbers |

---

## 📈 Data Flow

```
Browser Extension          Backend API           Database
     ↓                         ↓                      ↓
User clicks "Scan"
     ↓
Extracts links
     ↓
Tests each URL ──→ POST /scan/start ──→ Creates session
     ↓                                    ↓
Finds vulnerabilities ──→ POST /scan/{id}/report ──→ Stores findings
     ↓                                    ↓
Marks complete ──→ PUT /scan/{id}/complete ──→ Updates status
     ↓                                    ↓
Shows results ←─ GET /api/scan/{id} ←─ Returns data
```

---

## 🛠️ Troubleshooting

### "Can't connect to API"
```bash
# Check if backend is running
python backend_api.py

# Verify it's accessible
curl http://localhost:5000/health

# Check settings: Should be http://localhost:5000
```

### "Database error"
```bash
# PostgreSQL - create database first
createdb security_scanner

# Or use SQLite (automatic)
# - Just change DATABASE_URL in .env

# Check if tables exist
psql security_scanner -c "\dt"
```

### "Extension won't load"
```bash
# Refresh in chrome://extensions/
# Check manifest.json syntax (must be valid JSON)
# View console errors: F12 → Console tab
```

---

## 📝 File Descriptions

| File | Purpose |
|------|---------|
| `backend_api.py` | REST API + Database (main server) |
| `popup.html` | Extension interface |
| `popup.js` | Extension logic |
| `popup.css` | Extension styling |
| `content.js` | Extracts links from pages |
| `background.js` | Extension background service |
| `manifest.json` | Extension configuration |
| `requirements.txt` | Python packages |

---

## 🚦 Status Indicators

| Symbol | Meaning |
|--------|---------|
| 🔄 | Scanning in progress |
| ✅ | Scan completed |
| ⚠️ | Vulnerabilities found |
| ❌ | Error occurred |
| 🔒 | Secure (no vulns found) |

---

## 💡 Common Tasks

### Check if API is Running
```bash
curl http://localhost:5000/health
# Should return: {"status": "healthy"}
```

### Stop Scanning
Click **Stop Scan** button in extension popup

### Export Results
```bash
# Get all vulnerabilities as JSON
curl http://localhost:5000/api/scans > results.json
```

### Reset Database
```bash
# PostgreSQL
dropdb security_scanner
createdb security_scanner

# SQLite
rm security_scanner.db
```

---

## 📞 Quick Answers

**Q: Does this work offline?**
A: No, it needs the API server running locally.

**Q: Can I scan multiple sites at once?**
A: Not yet - scan one site, then another.

**Q: Are results saved if I close the extension?**
A: Yes! They're in the database permanently.

**Q: How do I share results?**
A: Export from API endpoint or view dashboard.

**Q: Is this legal to use?**
A: Only on sites you own or have permission to test.

---

## 🎓 Learning Resources

- **Security Testing**: https://owasp.org/www-community/attacks
- **API Design**: https://flask.palletsprojects.com/
- **Browser Extensions**: https://developer.chrome.com/docs/extensions/
- **Databases**: https://www.postgresql.org/docs/

---

## ✅ Verification Checklist

- [ ] Backend installed: `pip install -r requirements.txt`
- [ ] .env file created with database URL
- [ ] Backend running: `python backend_api.py`
- [ ] Extension files in correct folder
- [ ] Extension loaded in browser
- [ ] API URL set in extension settings: `http://localhost:5000`
- [ ] Test scan on a simple website
- [ ] Results visible in browser console
- [ ] Dashboard accessible: `http://localhost:5000/dashboard`

---

**You're all set! 🎉**

Next scan and check the database to see your findings!

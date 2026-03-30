# Web Security Scanner Browser Extension - Setup Guide

## Overview
This solution consists of:
- **Backend API**: Flask-based REST API for storing scan results
- **Browser Extension**: Chrome/Firefox extension for scanning websites
- **Database**: PostgreSQL (recommended) or SQLite for storing vulnerabilities

## Prerequisites
- Python 3.8+
- Chrome or Firefox browser
- PostgreSQL or SQLite (for database)
- pip (Python package manager)

---

## Part 1: Backend Setup

### 1.1 Install Dependencies
```bash
pip install -r requirements.txt
```

### 1.2 Configure Database

#### Option A: PostgreSQL (Recommended)

1. Install PostgreSQL:
   - Ubuntu/Debian: `sudo apt-get install postgresql postgresql-contrib`
   - macOS: `brew install postgresql`
   - Windows: Download from https://www.postgresql.org/download/windows/

2. Create database:
   ```bash
   createdb security_scanner
   ```

3. Update `.env` file with PostgreSQL credentials:
   ```
   DATABASE_URL=postgresql://user:password@localhost:5432/security_scanner
   ```

#### Option B: SQLite (Simple, No Setup Required)

Comment out PostgreSQL line in `backend_api.py` and uncomment:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_scanner.db'
```

### 1.3 Run Backend Server
```bash
python backend_api.py
```

You should see:
```
 * Running on http://0.0.0.0:5000
```

**Keep this terminal open!**

---

## Part 2: Browser Extension Setup

### 2.1 Prepare Extension Files

Create a folder structure:
```
web-security-scanner/
├── manifest.json
├── popup.html
├── popup.css
├── popup.js
├── content.js
├── background.js
└── images/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### 2.2 Create Icons (Optional)

You can create simple PNG icons or use online tools. Icons should be:
- icon16.png: 16x16 pixels
- icon48.png: 48x48 pixels
- icon128.png: 128x128 pixels

### 2.3 Load Extension in Chrome

1. Open Chrome and go to: `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `web-security-scanner` folder
5. The extension should appear in your extensions list

### 2.4 Load Extension in Firefox

1. Open Firefox and go to: `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select any file from the `web-security-scanner` folder
4. The extension should appear in your extensions list

---

## Part 3: Using the Extension

### 3.1 Initial Configuration

1. Click the extension icon in your browser toolbar
2. Click the ⚙️ settings icon
3. Configure:
   - **API URL**: `http://localhost:5000` (default)
   - **Max Crawl Depth**: 3 (adjust as needed)
   - **Auto-report**: Keep checked for automatic reporting
4. Click **Save Settings**

### 3.2 Run a Scan

1. Navigate to any website you want to scan
2. Click the extension icon
3. Click **Start Scan**
4. Monitor progress in the popup
5. View vulnerabilities found
6. Click **View Full Dashboard** to see detailed results

---

## Part 4: API Reference

### Start a Scan
```bash
POST /api/scan/start
Content-Type: application/json

{
    "target_url": "https://example.com",
    "browser": "Chrome"
}

Response:
{
    "session_id": 1,
    "message": "Scan session created"
}
```

### Report a Vulnerability
```bash
POST /api/scan/{session_id}/report
Content-Type: application/json

{
    "type": "SQL Injection",
    "url": "https://example.com/search?q=test",
    "parameter": "q",
    "payload": "' OR '1'='1",
    "severity": "critical"
}

Response:
{
    "message": "Vulnerability recorded"
}
```

### Complete a Scan
```bash
PUT /api/scan/{session_id}/complete
Content-Type: application/json

{
    "total_urls_scanned": 15,
    "duration_seconds": 45
}
```

### Get All Scans
```bash
GET /api/scans?page=1&per_page=20

Response:
{
    "total": 42,
    "pages": 3,
    "current_page": 1,
    "scans": [
        {
            "id": 1,
            "target_url": "https://example.com",
            "scan_date": "2024-01-15T10:30:00",
            "status": "completed",
            "total_urls_scanned": 15,
            "vulnerabilities_found": 3,
            "duration_seconds": 45
        }
        ...
    ]
}
```

### Get Scan Details
```bash
GET /api/scan/{session_id}

Response:
{
    "session": {
        "id": 1,
        "target_url": "https://example.com",
        "status": "completed",
        "vulnerabilities_found": 3
    },
    "vulnerabilities": [
        {
            "id": 1,
            "vulnerability_type": "SQL Injection",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "' OR '1'='1",
            "severity": "critical",
            "timestamp": "2024-01-15T10:30:15"
        }
        ...
    ]
}
```

### Get Statistics
```bash
GET /api/stats

Response:
{
    "total_scans": 42,
    "total_vulnerabilities": 156,
    "vulnerabilities_by_type": {
        "SQL Injection": 45,
        "XSS": 67,
        "Sensitive Information Exposure": 44
    },
    "vulnerabilities_by_severity": {
        "critical": 12,
        "high": 34,
        "medium": 89,
        "low": 21
    }
}
```

---

## Part 5: Database Schema

### Tables

#### scan_sessions
```sql
CREATE TABLE scan_sessions (
    id SERIAL PRIMARY KEY,
    target_url VARCHAR(500) NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'in_progress',
    total_urls_scanned INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    duration_seconds INTEGER,
    browser VARCHAR(50)
);
```

#### vulnerabilities
```sql
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES scan_sessions(id),
    vulnerability_type VARCHAR(100) NOT NULL,
    url VARCHAR(500) NOT NULL,
    parameter VARCHAR(255),
    payload TEXT,
    info_type VARCHAR(100),
    severity VARCHAR(50) DEFAULT 'medium',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Troubleshooting

### Extension can't connect to API
- Ensure backend is running: `python backend_api.py`
- Check API URL in settings matches your backend
- Make sure port 5000 is not blocked by firewall

### Database connection errors
- PostgreSQL: Check credentials in `.env`
- SQLite: Ensure write permissions in directory
- Run `python backend_api.py` to auto-create tables

### Cross-Origin (CORS) errors
- Backend already has CORS enabled
- Check that API URL matches exactly in settings

### Extension not loading
- Ensure all files are in the correct folder
- Refresh the extension in `chrome://extensions/`
- Check browser console for errors (F12)

---

## Security Notes

⚠️ **Important**: This scanner is for authorized testing only!

- Only scan websites you own or have explicit permission to test
- Some payload tests may trigger WAF/IDS systems
- Be aware of rate limiting and server load
- Use responsibly and legally

---

## Next Steps

1. **Create a Dashboard**: Build a web UI to visualize scan results
2. **Email Alerts**: Send alerts when vulnerabilities are found
3. **Scheduled Scans**: Implement periodic scanning of known targets
4. **Remediation Tracking**: Track when vulnerabilities are fixed
5. **Team Collaboration**: Multi-user support for scan results

---

## Support

For issues or questions:
1. Check browser console (F12) for errors
2. Check Flask server logs
3. Verify database connection
4. Review API responses in Network tab

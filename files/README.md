# SiteShield — Backend Setup

## Requirements
- Python 3.10+
- pip

## Quick Start (Local)

```bash
# 1. Clone / copy the backend folder
cd scanner-backend

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
uvicorn main:app --reload --port 8000
```

API is now live at: http://localhost:8000

## Test it
```bash
curl "http://localhost:8000/scan?url=https://example.com"
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /scan?url= | Run a full security scan |
| GET | /admin/stats | Aggregate dashboard stats |
| GET | /admin/scans | Recent scan history |
| GET | /health | Health check |
| GET | /docs | Auto-generated Swagger UI |

## Connect the Frontend

In `index.html`, replace the mock scan with a real API call:

```javascript
// Change this in the fetchAIReport / startScan functions:
const BACKEND = "http://localhost:8000";   // or your deployed URL

const res = await fetch(`${BACKEND}/scan?url=${encodeURIComponent(url)}`);
const scanData = await res.json();
```

## Deploy to Render (free tier)

1. Push this folder to a GitHub repo
2. Go to https://render.com → New Web Service
3. Connect your repo, set:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Your API will be live at `https://your-app.onrender.com`

## Deploy to Railway

```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DB_PATH | siteshield.db | SQLite database file path |
| PORT | 8000 | Server port (set automatically on Render/Railway) |

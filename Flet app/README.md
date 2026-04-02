# WebSec Scanner 🛡️

A decentralized, asynchronous web vulnerability scanner featuring a FastAPI backend and native Flet desktop clients for both customers and administrators.

## 📂 Project Structure
* `scanner.py` - FastAPI backend and asynchronous scanning engine.
* `database.py` - SQLite database layer using SQLAlchemy.
* `frontend.py` - Flet desktop application for customers (requires API key).
* `admin.py` - Flet desktop application for administrators (requires JWT login).
* `requirements.txt` - Python dependencies.
* `install.bat` - Automated dependency installer.
* `run_app.bat` - Automated launcher for all services.

## ⚙️ Prerequisites
* **Python 3.8+** must be installed and added to your system's PATH.

## 🚀 Installation & Setup

1. **Install Dependencies:**
   Double-click the `install.bat` file. This will automatically install all required packages via `pip`.

2. **Launch the Application:**
   Double-click `run_app.bat`. This script will:
   * Open a new terminal window to run the FastAPI backend (`scanner.py`).
   * Wait 5 seconds for the server to spin up and initialize the database.
   * Launch the Customer Portal desktop app (`frontend.py`).
   * Launch the Admin Dashboard desktop app (`admin.py`).

## 🔑 First-Time Setup (Crucial)

Because this architecture does not use customer accounts, it relies on API Keys. 

1. **Get Your API Key:**
   The very first time you run `run_app.bat`, the backend will generate a SQLite database (`websec.db`) and create a single "bootstrap" API key. 
   * Look at the terminal window labeled **"WebSec Backend Server"**.
   * Find the line that says: `[database] Bootstrap API key: wsk_...`
   * Copy this key. You will need it to use the Customer Portal.

2. **Admin Credentials:**
   The database also automatically creates a default administrator account. Use these credentials to log into the Admin Dashboard (`admin.py`):
   * **Username:** `admin`
   * **Password:** `changeme123!`

## 💻 Usage Instructions

### Customer Portal (`frontend.py`)
1. Paste your `wsk_...` API key into the top field.
2. Enter a valid target URL (e.g., `https://example.com` or `http://localhost:8000`).
3. Click **Quick Scan** or **Deep Scan**.
4. The scan will run asynchronously on the backend. The UI will poll the server and display real-time metrics when the scan completes.

### Admin Dashboard (`admin.py`)
1. Log in using your admin credentials.
2. The dashboard displays aggregated, anonymized statistics (Total Scans, Vulnerability counts).
3. It also displays a log of the most recent Client IP addresses to connect to the service.

## 🛑 Stopping the App
Closing the desktop app windows will stop the frontends. To stop the backend server, locate the **"WebSec Backend Server"** terminal window and press `Ctrl + C`, or simply close the window.
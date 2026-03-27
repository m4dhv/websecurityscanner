@echo off
title SiteShield Backend Server
color 0A

echo.
echo  ============================================
echo   SiteShield - Website Security Scanner
echo   Backend Server Launcher
echo  ============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Please install Python from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo  [OK] Python found:
python --version
echo.

:: Move to the folder where this .bat file lives
cd /d "%~dp0"

:: Install dependencies
echo  [INFO] Installing / checking dependencies...
echo.
pip install -r requirements.txt --quiet
if errorlevel 1 (
    color 0C
    echo.
    echo  [ERROR] Failed to install dependencies.
    echo  Try running this as Administrator.
    pause
    exit /b 1
)

echo.
echo  [OK] Dependencies ready.
echo.
echo  ============================================
echo   Server starting at http://localhost:8000
echo   Swagger docs at http://localhost:8000/docs
echo.
echo   Keep this window open while using the app.
echo   Press CTRL+C to stop the server.
echo  ============================================
echo.

:: Start the FastAPI server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload

:: If server stops
echo.
echo  [INFO] Server stopped.
pause

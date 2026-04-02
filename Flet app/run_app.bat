@echo off
title WebSec Scanner - Launcher
echo ===================================================
echo Starting WebSec Scanner Architecture...
echo ===================================================
echo.

echo [1/3] Starting FastAPI Backend (Port 8000)...
:: Starts the backend in a new, separate command prompt window
start "WebSec Backend Server" cmd /k "uvicorn scanner:app --host 0.0.0.0 --port 8000"

echo Waiting 5 seconds for the backend and database to initialize...
timeout /t 5 /nobreak >nul

echo [2/3] Launching Customer Portal...
:: Starts the Flet frontend in the background
start "WebSec Customer Portal" /b python frontend.py

echo [3/3] Launching Admin Dashboard...
:: Starts the Flet admin panel in the background
start "WebSec Admin Dashboard" /b python admin.py

echo.
echo ===================================================
echo All services have been launched!
echo.
echo IMPORTANT: If this is your first run, check the 
echo "WebSec Backend Server" window to copy your 
echo Bootstrap API Key.
echo ===================================================
pause
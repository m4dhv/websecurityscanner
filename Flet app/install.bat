@echo off
title WebSec Scanner - Installer
echo ===================================================
echo Installing WebSec Scanner Dependencies...
echo ===================================================
echo.
echo.

 Upgrade pip and install requirements
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ===================================================
echo Installation Complete!
echo You can now run the application using run_app.bat
echo ===================================================
pause
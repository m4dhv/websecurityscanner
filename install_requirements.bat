@echo off
title WebSec Scanner Setup
echo ===================================================
echo     Installing WebSec Scanner Dependencies...
echo ===================================================
echo.

:: Upgrade pip and install requirements
echo Updating pip...
python -m pip install --upgrade pip

echo.
echo Installing packages from requirements.txt...
pip install -r requirements.txt

echo.
echo ===================================================
echo     Installation Complete!
echo ===================================================
pause
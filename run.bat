@echo off
color 0B
title Antivirus Pro - Advanced Threat Protection
cls

echo.
echo ============================================
echo    Antivirus Pro - Advanced Threat Protection
echo ============================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.7+ from python.org
    echo.
    pause
    exit /b 1
)

echo [OK] Python found!
echo.
echo Installing/updating dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    color 0C
    echo ERROR: Failed to install dependencies.
    echo.
    pause
    exit /b 1
)

echo [OK] Dependencies ready!
echo.
echo Starting Antivirus Pro...
echo.

python antivirus.py
if errorlevel 1 (
    color 0C
    echo ERROR: Application failed to start.
    echo.
    pause
    exit /b 1
)

color 0B
echo.
echo Thank you for using Antivirus Pro!
echo.
pause

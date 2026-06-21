@echo off
title Vigilagent - Launching All Services
echo ========================================
echo  Vigilagent - Starting All Services
echo ========================================
echo.

echo [1/2] Starting Backend (port 8000)...
start "Vigilagent Backend" cmd /k "cd /d D:\Antigravity 2\penetration testing system copy\penetration testing system && call .venv_win\Scripts\activate.bat && set API_AUTH_KEY=dev-test-key-12345678901234567890 && echo Starting backend... && python -m backend.main --mode serve"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend (port 5173)...
start "Vigilagent Frontend" cmd /k "cd /d D:\Antigravity 2\penetration testing system copy\penetration testing system && echo Starting frontend... && npm run dev"

echo.
echo ========================================
echo  Both servers are launching!
echo  Backend:  http://127.0.0.1:8000
echo  Frontend: http://localhost:5173
echo ========================================
echo.
echo Close this window anytime. The servers run in their own windows.
pause

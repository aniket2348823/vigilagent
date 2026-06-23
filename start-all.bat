@echo off
title Vigilagent - Launching All Services
echo ========================================
echo  Vigilagent - Starting All Services
echo ========================================
echo.

echo [1/2] Starting Backend (port 8000)...
start "Vigilagent Backend" cmd /k "cd /d D:\Antigravity 2\penetration testing system copy\penetration testing system && call .venv_win\Scripts\activate.bat && set API_AUTH_KEY=dev-test-key-12345678901234567890 && set REDIS_URL=redis://:vigilagent-redis-secret@127.0.0.1:6379/0 && set VIGILAGENT_DEV_MODE=true && echo Starting backend... && python -m backend.main --mode serve"

echo Waiting for backend to start (this takes about 60 seconds)...
:wait_loop
timeout /t 5 /nobreak >nul
curl -s -o nul -w "%%{http_code}" http://127.0.0.1:8000/api/health >nul 2>&1
if errorlevel 1 (
    echo   Still waiting for backend...
    goto wait_loop
)
echo   Backend is ready!

echo [2/2] Starting Frontend (port 5173)...
start "Vigilagent Frontend" cmd /k "cd /d D:\Antigravity 2\penetration testing system copy\penetration testing system && set API_AUTH_KEY=dev-test-key-12345678901234567890 && echo Starting frontend... && npm run dev"

echo.
echo ========================================
echo  Both servers are running!
echo  Backend:  http://127.0.0.1:8000
echo  Frontend: http://localhost:5173
echo ========================================
echo.
echo Close this window anytime. The servers run in their own windows.
pause

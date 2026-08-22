@echo off
title Vigilagent - Launching All Services
echo ========================================
echo  Vigilagent - Starting All Services
echo ========================================
echo.

echo [1/2] Starting Backend (port 8000)...
:: Read API_AUTH_KEY from .env automatically. Both the backend (load_dotenv
:: override) and Vite (loadEnv) use .env as the single source of truth — a
:: manually typed key here would diverge and cause 401 key_present=True on
:: every /api request through the proxy.
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%a in (`findstr /b "API_AUTH_KEY=" ".env"`) do (
        set "API_AUTH_KEY=%%b"
        goto :key_loaded
    )
)
:key_loaded
if "%API_AUTH_KEY%"=="" (
    echo   ERROR: API_AUTH_KEY not found in .env and not set in the environment.
    goto :end
)

start "Vigilagent Backend" cmd /k "cd /d "%~dp0" && call .venv_win\Scripts\activate.bat && set API_AUTH_KEY=%API_AUTH_KEY% && set VIGILAGENT_DEV_MODE=true && echo Starting backend... && python -m backend.main --mode serve"

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
start "Vigilagent Frontend" cmd /k "cd /d "%~dp0" && set API_AUTH_KEY=%API_AUTH_KEY% && echo Starting frontend... && npm run dev"

echo.
echo ========================================
echo  Both servers are running!
echo  Backend:  http://127.0.0.1:8000
echo  Frontend: http://localhost:5173
echo ========================================
echo  Close this window anytime. The servers run in their own windows.
:end
pause

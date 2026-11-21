@echo off
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
start "" cmd /c "timeout /t 2 >nul & start http://localhost:8000"
%PY% server.py
pause

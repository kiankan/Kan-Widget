@echo off
setlocal
cd /d "%~dp0"

echo Installing runtime dependencies...
py -3 -m pip install PySide6 psutil requests
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo Starting Kan Widget...
py -3 kan_widget.py
set "APP_EXIT=%ERRORLEVEL%"
if not "%APP_EXIT%"=="0" (
    echo Kan Widget exited with code %APP_EXIT%.
)
pause
exit /b %APP_EXIT%

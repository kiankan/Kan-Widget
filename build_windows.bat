@echo off
setlocal
cd /d "%~dp0"

echo [1/2] Installing build dependencies...
py -3 -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo [2/2] Building Kan Widget...
py -3 -m PyInstaller --noconfirm --clean --windowed --name KanWidget kan_widget.py
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Build complete: dist\KanWidget\KanWidget.exe
pause
exit /b 0

@echo off
cd /d "%~dp0"
py -3 -m pip install -r requirements.txt
if errorlevel 1 pause & exit /b 1
py -3 -m PyInstaller --noconfirm --clean --windowed --name KanWidget --collect-all PySide6 kan_widget.py
if errorlevel 1 pause & exit /b 1
echo.
echo Build complete: dist\KanWidget\KanWidget.exe
pause

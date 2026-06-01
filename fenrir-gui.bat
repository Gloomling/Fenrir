@echo off
:: Fenrir Security Scanner — Windows Launcher
:: Double-click this file to launch the GUI, or pin it to the Start Menu.
::
:: Requirements:
::   - Python 3.10+ installed (https://python.org)
::   - fenrir-scanner package installed:  pip install fenrir-scanner
::   - Or run from source directory with:  pip install -e .

setlocal

:: Try to activate a local venv first
if exist "%~dp0.venv\Scripts\activate.bat" (
    call "%~dp0.venv\Scripts\activate.bat"
) else if exist "%USERPROFILE%\.fenrir\venv\Scripts\activate.bat" (
    call "%USERPROFILE%\.fenrir\venv\Scripts\activate.bat"
)

:: Launch GUI (pythonw = no console window)
where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw -m fenrir.fenrir_gui %*
) else (
    python -m fenrir.fenrir_gui %*
)

@echo off
set OUTPUT=python_inventory.txt

echo ========================================== > "%OUTPUT%"
echo Python Installation and Package Inventory >> "%OUTPUT%"
echo ========================================== >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- Check if Python is available ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH. >> "%OUTPUT%"
    echo Python is not installed or not in PATH.
    pause
    exit /b
)

REM --- Python version ---
echo [Python Version] >> "%OUTPUT%"
python --version >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- Python path ---
echo [Python Executable Path] >> "%OUTPUT%"
where python >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- Installed pip packages ---
echo [Installed Python Packages] >> "%OUTPUT%"
pip list >> "%OUTPUT%"
echo. >> "%OUTPUT%"

echo Python inventory saved to %OUTPUT%
pause


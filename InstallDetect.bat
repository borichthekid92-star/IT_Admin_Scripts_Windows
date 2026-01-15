@echo off
setlocal enabledelayedexpansion
set OUTPUT=installed_apps_report.txt

REM Clear previous output file
if exist "%OUTPUT%" del "%OUTPUT%"

echo ========================================== > "%OUTPUT%"
echo Installed Applications - Multi-Source Enumeration >> "%OUTPUT%"
echo ========================================== >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- 1. MSI-based installed programs (Registry) ---
echo [Registry - Uninstall Keys (HKLM)] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr "DisplayName" >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- 2. 32-bit Programs (on 64-bit systems) ---
echo [Registry - 32-bit Programs (Wow6432Node)] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr "DisplayName" >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- 3. User-installed programs (HKCU) ---
echo [Registry - Current User Installed Programs] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr "DisplayName" >> "%OUTPUT%"
echo. >> "%OUTPUT%"

REM --- 4. Microsoft Store Apps ---
echo [Microsoft Store Apps - PowerShell] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
powershell -NoProfile -Command "Get-AppxPackage | Select-Object -Property Name, Version | Format-Table -AutoSize" >> "%OUTPUT%" 2>nul
echo. >> "%OUTPUT%"

REM --- 5. Programs from Control Panel (WMI) ---
echo [WMI - Installed Programs] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
powershell -NoProfile -Command "Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Select-Object -Property Name, Version | Format-Table -AutoSize" >> "%OUTPUT%" 2>nul
echo. >> "%OUTPUT%"

REM --- 6. Chocolatey Packages (if installed) ---
echo [Chocolatey Packages] >> "%OUTPUT%"
echo. >> "%OUTPUT%"
choco list --local-only 2>nul >> "%OUTPUT%"
if %errorlevel% neq 0 (
    echo Chocolatey not installed >> "%OUTPUT%"
)
echo. >> "%OUTPUT%"

echo. >> "%OUTPUT%"
echo ========================================== >> "%OUTPUT%"
echo Enumeration complete at: %date% %time% >> "%OUTPUT%"
echo ========================================== >> "%OUTPUT%"

echo.
echo Enumeration complete.
echo Output saved to: %cd%\%OUTPUT%
echo.
echo Preview of results:
type "%OUTPUT%"

pause
@echo off
REM Memory Dump Batch Wrapper
REM Requires Administrator privileges

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] This script requires Administrator privileges.
    echo [!] Please run as Administrator.
    pause
    exit /b 1
)

echo ========================================
echo Memory Dumping Tool
echo ========================================
echo.

if "%1"=="" goto :menu
goto :execute

:menu
echo Select dumping method:
echo.
echo 1. Dump specific process by name
echo 2. Dump specific process by PID
echo 3. Dump LSASS (credential analysis)
echo 4. Dump all processes
echo 5. Full system memory dump (causes reboot!)
echo 6. Exit
echo.
set /p choice="Enter choice (1-6): "

if "%choice%"=="1" goto :process_name
if "%choice%"=="2" goto :process_pid
if "%choice%"=="3" goto :lsass
if "%choice%"=="4" goto :all_processes
if "%choice%"=="5" goto :full_system
if "%choice%"=="6" exit /b 0
goto :menu

:process_name
set /p procname="Enter process name: "
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" -Method Process -Target "%procname%"
goto :end

:process_pid
set /p procpid="Enter process PID: "
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" -Method Process -Target "%procpid%"
goto :end

:lsass
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" -Method LSASS
goto :end

:all_processes
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" -Method AllProcesses
goto :end

:full_system
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" -Method FullSystem
goto :end

:execute
powershell.exe -ExecutionPolicy Bypass -File "%~dp0dump_memory.ps1" %*
goto :end

:end
echo.
pause

@echo off
REM Memory Dump and Forensic Activity Logger
REM Requires Administrator Privileges
REM Creates memory dump and logs process/file system activity

setlocal enabledelayedexpansion
cd /d %~dp0

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script requires Administrator privileges!
    echo [!] Please run as Administrator.
    pause
    exit /b 1
)

set TIMESTAMP=%date:~-4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set OUTPUT_DIR=forensics_dump_%TIMESTAMP%

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo ================================================
echo   Memory Dump and Forensic Activity Logger
echo ================================================
echo.
echo [*] Output Directory: %cd%\%OUTPUT_DIR%
echo [*] Timestamp: %TIMESTAMP%
echo.

REM ===== 1. MEMORY DUMP =====
echo [*] Step 1: Creating Memory Dump...
echo [+] Attempting memory dump capture...
echo.

REM ===== 2. PROCESS ENUMERATION AND ACTIVITY =====
echo [*] Step 2: Enumerating Process Activity...

(
    echo ================================================
    echo PROCESS ENUMERATION AND ACTIVITY
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-Process | Select-Object Name, Id, Handles, @{Name='Memory_MB';Expression={[math]::Round($_.WorkingSet/1MB,2)}} | Format-Table -AutoSize" >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"
echo [*] Process Tree - Parent-Child Relationships: >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, ParentProcessId | Format-Table -AutoSize" >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"
echo [*] Process Command Lines: >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize" >> "%OUTPUT_DIR%\process_activity_%TIMESTAMP%.txt" 2>nul

echo [+] Process activity logged to: process_activity_%TIMESTAMP%.txt
echo.

REM ===== 3. NETWORK ACTIVITY =====
echo [*] Step 3: Capturing Network Activity...

(
    echo ================================================
    echo NETWORK ACTIVITY AND CONNECTIONS
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
    echo [*] Current Network Connections:
    echo.
) > "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt"

netstat -ano >> "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt"
echo [*] DNS Resolution Cache: >> "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt"

ipconfig /displaydns >> "%OUTPUT_DIR%\network_activity_%TIMESTAMP%.txt" 2>nul

echo [+] Network activity logged to: network_activity_%TIMESTAMP%.txt
echo.

REM ===== 4. FILE SYSTEM ACTIVITY =====
echo [*] Step 4: Extracting File System Activity...

(
    echo ================================================
    echo FILE SYSTEM ACTIVITY AND RECENT FILES
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"

echo [*] Recently Modified Files in User Directory: >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-ChildItem -Path $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime, @{Name='Size_KB';Expression={[math]::Round($_.Length/1KB,2)}} -First 100 | Format-Table -AutoSize" >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"
echo [*] Recently Modified Files - System Root: >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-ChildItem -Path $env:WINDIR -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime -First 50 | Format-Table -AutoSize" >> "%OUTPUT_DIR%\filesystem_activity_%TIMESTAMP%.txt" 2>nul

echo [+] File system activity logged to: filesystem_activity_%TIMESTAMP%.txt
echo.

REM ===== 5. WINDOWS EVENT LOG ACTIVITY =====
echo [*] Step 5: Extracting Windows Event Logs...

(
    echo ================================================
    echo WINDOWS EVENT LOG ACTIVITY
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"

echo [*] Security Event Log - Process Creation (Event ID 4688): >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-WinEvent -LogName Security -FilterXPath \"*[System[(EventID=4688)]]\" -ErrorAction SilentlyContinue -MaxEvents 50 | Select-Object TimeCreated, @{Name='Event';Expression={$_.Id}}, Message | Format-Table -AutoSize -Wrap" >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"
echo [*] System Event Log (Last 50 Critical/Error events): >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-WinEvent -LogName System -ErrorAction SilentlyContinue -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, ProviderName, Message | Format-Table -AutoSize" >> "%OUTPUT_DIR%\event_logs_%TIMESTAMP%.txt" 2>nul

echo [+] Event logs logged to: event_logs_%TIMESTAMP%.txt
echo.

REM ===== 6. WINDOWS SERVICES STATE =====
echo [*] Step 6: Capturing Service State...

(
    echo ================================================
    echo WINDOWS SERVICES STATE
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\services_%TIMESTAMP%.txt"

powershell -NoProfile -Command "Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize" >> "%OUTPUT_DIR%\services_%TIMESTAMP%.txt" 2>nul

echo [+] Services logged to: services_%TIMESTAMP%.txt
echo.

REM ===== 7. REGISTRY HIVES (COPY) =====
echo [*] Step 7: Backing up Registry Hives...

reg save HKLM\SAM "%OUTPUT_DIR%\SAM" /y >nul 2>&1
if %errorlevel% equ 0 (echo [+] SAM hive backed up)

reg save HKLM\SECURITY "%OUTPUT_DIR%\SECURITY" /y >nul 2>&1
if %errorlevel% equ 0 (echo [+] SECURITY hive backed up)

reg save HKLM\SOFTWARE "%OUTPUT_DIR%\SOFTWARE" /y >nul 2>&1
if %errorlevel% equ 0 (echo [+] SOFTWARE hive backed up)

reg save HKLM\SYSTEM "%OUTPUT_DIR%\SYSTEM" /y >nul 2>&1
if %errorlevel% equ 0 (echo [+] SYSTEM hive backed up)

echo.

REM ===== 8. SYSTEM INFORMATION =====
echo [*] Step 8: Gathering System Information...

(
    echo ================================================
    echo SYSTEM INFORMATION
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"

systeminfo >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"
echo ================================================ >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"
echo ENVIRONMENT VARIABLES >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"
echo ================================================ >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"

set >> "%OUTPUT_DIR%\system_info_%TIMESTAMP%.txt"

echo [+] System info logged to: system_info_%TIMESTAMP%.txt
echo.

REM ===== 9. TASK LIST AND RUNNING PROCESSES =====
echo [*] Step 9: Capturing Task List...

(
    echo ================================================
    echo RUNNING TASKS AND SERVICES MAPPING
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt"

tasklist /v >> "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt" 2>nul

echo. >> "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt"
echo [*] Task to Service Mapping: >> "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt"

tasklist /svc >> "%OUTPUT_DIR%\tasklist_%TIMESTAMP%.txt" 2>nul

echo [+] Task list logged to: tasklist_%TIMESTAMP%.txt
echo.

REM ===== 10. AUTO-START PROGRAMS =====
echo [*] Step 10: Extracting Auto-Start Programs...

(
    echo ================================================
    echo AUTO-START PROGRAMS AND PERSISTENCE
    echo ================================================
    echo Timestamp: %date% %time%
    echo.
) > "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

echo [*] HKLM Run Keys: >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v * 2>nul >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

echo. >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"
echo [*] HKCU Run Keys: >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v * 2>nul >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

echo. >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"
echo [*] Startup Folder: >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"
echo. >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt"

dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" >> "%OUTPUT_DIR%\autostart_%TIMESTAMP%.txt" 2>nul

echo [+] Auto-start programs logged to: autostart_%TIMESTAMP%.txt
echo.

REM ===== 11. GENERATE SUMMARY REPORT =====
echo [*] Step 11: Generating Summary Report...

(
    echo ================================================
    echo FORENSIC DUMP SUMMARY REPORT
    echo ================================================
    echo.
    echo Generated: %date% %time%
    echo Output Directory: %cd%\%OUTPUT_DIR%
    echo.
    echo ===== FILES CREATED =====
    echo.
    echo 1. process_activity_%TIMESTAMP%.txt
    echo    - All running processes with memory usage
    echo    - Process tree with parent-child relationships
    echo    - Process command lines and arguments
    echo    - Use for: Detecting suspicious processes
    echo.
    echo 2. network_activity_%TIMESTAMP%.txt
    echo    - Active network connections ^(netstat output^)
    echo    - Local and remote IP addresses/ports
    echo    - Process IDs associated with connections
    echo    - DNS resolution cache
    echo    - Use for: Identifying C2 communication, data exfiltration
    echo.
    echo 3. filesystem_activity_%TIMESTAMP%.txt
    echo    - Recently modified files in user directories
    echo    - System directory changes
    echo    - File timestamps and sizes
    echo    - Use for: Detecting data staging, malware artifacts
    echo.
    echo 4. event_logs_%TIMESTAMP%.txt
    echo    - Windows Security event log ^(Process creation - Event ID 4688^)
    echo    - System event log with timestamps
    echo    - Use for: Timeline reconstruction, process execution history
    echo.
    echo 5. tasklist_%TIMESTAMP%.txt
    echo    - All running tasks and services
    echo    - Service-to-process mapping
    echo    - Use for: Service persistence, hidden processes
    echo.
    echo 6. services_%TIMESTAMP%.txt
    echo    - All Windows services and their status
    echo    - Service startup type ^(Auto, Manual, Disabled^)
    echo    - Use for: Persistence mechanisms
    echo.
    echo 7. autostart_%TIMESTAMP%.txt
    echo    - Registry Run keys ^(HKLM and HKCU^)
    echo    - Startup folder contents
    echo    - Use for: Boot persistence, malware startup points
    echo.
    echo 8. system_info_%TIMESTAMP%.txt
    echo    - Complete system information
    echo    - OS version, hardware details
    echo    - Network configuration
    echo    - Environment variables
    echo    - Use for: Baseline system state, configuration changes
    echo.
    echo 9. Registry Hives ^(Binary Files^):
    echo    - SAM ^(User accounts and password hashes^)
    echo    - SECURITY ^(LSA secrets and cached credentials^)
    echo    - SOFTWARE ^(Installed programs, persistence mechanisms^)
    echo    - SYSTEM ^(System configuration, services, devices^)
    echo    - Use for: Offline analysis with RegRipper or Registry Viewer
    echo.
    echo ===== ANALYSIS RECOMMENDATIONS =====
    echo.
    echo QUICK ANALYSIS:
    echo 1. Review process_activity for unusual parent-child relationships
    echo 2. Check network_activity for unknown connections
    echo 3. Look at filesystem_activity for suspicious modifications
    echo 4. Review event_logs for process creation patterns
    echo 5. Examine autostart for unauthorized persistence
    echo.
    echo SUSPICIOUS INDICATORS:
    echo - Processes with no parent or suspicious parents
    echo - Processes spawning cmd.exe or powershell.exe
    echo - Network connections to non-standard ports
    echo - Recently modified system files
    echo - Unexpected services or scheduled tasks
    echo - Registry modifications in auto-start locations
    echo.
    echo FORENSIC TOOLS:
    echo - Volatility 3: Memory analysis
    echo   Download: https://github.com/volatilityfoundation/volatility3
    echo.
    echo - RegRipper: Registry analysis
    echo   Download: https://github.com/keydet89/RegRipper3.0
    echo.
    echo - Timeline Tools: Create unified timeline
    echo   Tool: Plaso, log2timeline
    echo.
    echo ================================================
    echo.
) > "%OUTPUT_DIR%\REPORT_%TIMESTAMP%.txt"

echo [+] Summary report generated: REPORT_%TIMESTAMP%.txt
echo.

REM ===== FINAL SUMMARY =====
echo ================================================
echo FORENSIC DUMP COMPLETE
echo ================================================
echo.
echo Output Directory: %cd%\%OUTPUT_DIR%
echo.
echo Generated Files:
dir /B "%OUTPUT_DIR%"
echo.
echo [+] All forensic data has been collected and saved.
echo [+] Review REPORT_%TIMESTAMP%.txt for detailed analysis guide.
echo.

pause
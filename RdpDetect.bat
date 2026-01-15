@echo off
REM Remote Desktop Application Detection Script
REM Searches for all remote desktop and remote access applications on Windows system

setlocal enabledelayedexpansion
cd /d %~dp0

set TIMESTAMP=%date:~-4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set OUTPUT_FILE=remote_desktop_apps_%TIMESTAMP%.txt

echo ================================================
echo   Remote Desktop Application Detection
echo ================================================
echo.
echo [*] Scanning for remote desktop/remote access apps...
echo [*] This may take a few moments...
echo.

(
    echo ================================================
    echo Remote Desktop Application Detection Report
    echo ================================================
    echo Scan Date: %date% %time%
    echo.
) > "%OUTPUT_FILE%"

REM ===== 1. REGISTRY SEARCH - INSTALLED PROGRAMS =====
echo [*] Step 1: Searching Registry for Remote Desktop Apps...
echo [*] Checking HKLM installed programs...

(
    echo.
    echo ================================================
    echo REMOTE DESKTOP APPS - REGISTRY SEARCH
    echo ================================================
    echo.
    echo [*] Installed Applications:
    echo.
) >> "%OUTPUT_FILE%"

REM Create list of remote desktop related keywords to search
setlocal enabledelayedexpansion
set RDP_KEYWORDS=TeamViewer AnyDesk Chrome Remote Desktop VNC RealVNC UltraVNC Citrix Remote Desktop Jump Desktop ScreenConnect Ammyy Radmin Zoho Assist Supremo Splashtop LogMeIn GoToMyPC ConnectWise Parsec Moonlight Remmina MRemoteNG mstsc Remote Utilities Screenium Skype TemRem Huawei WeLink DingTalk Tencent Meeting QQ Meeting Xunfei UnityConnect rustdesktop

for %%K in (%RDP_KEYWORDS%) do (
    reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /I "%%K" >> "%OUTPUT_FILE%"
)

echo.
echo [*] Checking 32-bit applications (Wow6432Node)...

reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /I "Remote TeamViewer AnyDesk VNC UltraVNC Citrix Jump ScreenConnect Ammyy Radmin Zoho Supremo Splashtop LogMeIn GoToMyPC ConnectWise" >> "%OUTPUT_FILE%"

echo [+] Registry search complete
echo.

REM ===== 2. PROGRAM FILES SEARCH =====
echo [*] Step 2: Searching Program Files Directories...

(
    echo.
    echo ================================================
    echo REMOTE DESKTOP APPS - INSTALLED LOCATIONS
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

echo [*] Checking Program Files for remote desktop applications... >> "%OUTPUT_FILE%"
echo. >> "%OUTPUT_FILE%"

REM Search in Program Files (64-bit)
if exist "C:\Program Files" (
    echo [*] Program Files ^(64-bit^): >> "%OUTPUT_FILE%"
    for /d %%D in ("C:\Program Files\*Remote*" "C:\Program Files\TeamViewer*" "C:\Program Files\AnyDesk*" "C:\Program Files\VNC*" "C:\Program Files\UltraVNC*" "C:\Program Files\Citrix*" "C:\Program Files\Jump*" "C:\Program Files\ScreenConnect*" "C:\Program Files\Ammyy*" "C:\Program Files\Radmin*" "C:\Program Files\Zoho*" "C:\Program Files\Supremo*" "C:\Program Files\Splashtop*" "C:\Program Files\LogMeIn*" "C:\Program Files\GoToMyPC*" "C:\Program Files\ConnectWise*" "C:\Program Files\Parsec*" "C:\Program Files\Moonlight*" "C:\Program Files\Remmina*" "C:\Program Files\mRemoteNG*") do (
        echo   Found: %%D >> "%OUTPUT_FILE%"
    )
    echo. >> "%OUTPUT_FILE%"
)

REM Search in Program Files (x86)
if exist "C:\Program Files (x86)" (
    echo [*] Program Files ^(x86^): >> "%OUTPUT_FILE%"
    for /d %%D in ("C:\Program Files (x86)\*Remote*" "C:\Program Files (x86)\TeamViewer*" "C:\Program Files (x86)\AnyDesk*" "C:\Program Files (x86)\VNC*" "C:\Program Files (x86)\UltraVNC*" "C:\Program Files (x86)\Citrix*" "C:\Program Files (x86)\Jump*" "C:\Program Files (x86)\ScreenConnect*" "C:\Program Files (x86)\Ammyy*" "C:\Program Files (x86)\Radmin*" "C:\Program Files (x86)\Zoho*" "C:\Program Files (x86)\Supremo*" "C:\Program Files (x86)\Splashtop*" "C:\Program Files (x86)\LogMeIn*" "C:\Program Files (x86)\GoToMyPC*" "C:\Program Files (x86)\ConnectWise*") do (
        echo   Found: %%D >> "%OUTPUT_FILE%"
    )
    echo. >> "%OUTPUT_FILE%"
)

REM Search in AppData
echo [*] Checking AppData directory: >> "%OUTPUT_FILE%"
for /d %%D in ("%APPDATA%\*Remote*" "%APPDATA%\TeamViewer*" "%APPDATA%\AnyDesk*" "%APPDATA%\VNC*" "%APPDATA%\Citrix*" "%APPDATA%\Splashtop*") do (
    echo   Found: %%D >> "%OUTPUT_FILE%"
)
echo. >> "%OUTPUT_FILE%"

echo [+] File system search complete
echo.

REM ===== 3. RUNNING PROCESSES =====
echo [*] Step 3: Checking for Running Remote Desktop Processes...

(
    echo.
    echo ================================================
    echo RUNNING REMOTE DESKTOP APPLICATIONS
    echo ================================================
    echo.
    echo [*] Processes Currently Running:
    echo.
) >> "%OUTPUT_FILE%"

REM Check for running remote desktop related processes
tasklist | findstr /I "TeamViewer AnyDesk chrome VNC radmin supremo splashtop LogMeIn ConnectWise mstsc rdcman rdpclip Parsec moonlight remmina mRemoteNG TemRem Xunfei DingTalk WeLink QQMeeting TencentMeeting" >> "%OUTPUT_FILE%"

if %errorlevel% neq 0 (
    echo [*] No remote desktop processes currently running >> "%OUTPUT_FILE%"
)

echo [+] Process check complete
echo.

REM ===== 4. SERVICES =====
echo [*] Step 4: Checking for Remote Desktop Services...

(
    echo.
    echo ================================================
    echo REMOTE DESKTOP SERVICES
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

echo [*] Built-in RDP Service Status: >> "%OUTPUT_FILE%"
sc query TermService >> "%OUTPUT_FILE%" 2>&1
echo. >> "%OUTPUT_FILE%"

echo [*] Remote Registry Service Status: >> "%OUTPUT_FILE%"
sc query RemoteRegistry >> "%OUTPUT_FILE%" 2>&1
echo. >> "%OUTPUT_FILE%"

REM Check for remote desktop related services
echo [*] Third-party Remote Access Services: >> "%OUTPUT_FILE%"
powershell -NoProfile -Command "Get-Service | Where-Object {$_.Name -like '*team*' -or $_.Name -like '*any*' -or $_.Name -like '*vnc*' -or $_.Name -like '*radmin*' -or $_.Name -like '*splashtop*' -or $_.DisplayName -like '*Remote*' -or $_.DisplayName -like '*TeamViewer*' -or $_.DisplayName -like '*AnyDesk*'} | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize" >> "%OUTPUT_FILE%" 2>nul

echo. >> "%OUTPUT_FILE%"
echo [+] Service check complete
echo.

REM ===== 5. MICROSOFT STORE APPS =====
echo [*] Step 5: Checking Microsoft Store Applications...

(
    echo.
    echo ================================================
    echo MICROSOFT STORE REMOTE DESKTOP APPS
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

powershell -NoProfile -Command "Get-AppxPackage | Where-Object {$_.Name -like '*Remote*' -or $_.Name -like '*TeamViewer*' -or $_.Name -like '*Chrome*' -or $_.Name -like '*VNC*'} | Select-Object Name, Version, PackageFullName | Format-Table -AutoSize" >> "%OUTPUT_FILE%" 2>nul

echo [+] Store apps check complete
echo.

REM ===== 6. BROWSER EXTENSIONS =====
echo [*] Step 6: Searching for Chrome Remote Desktop Extension...

(
    echo.
    echo ================================================
    echo BROWSER EXTENSIONS - CHROME REMOTE DESKTOP
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

REM Check Chrome user data directory for CRD extension
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions" (
    echo [*] Chrome Extensions Directory Found >> "%OUTPUT_FILE%"
    dir "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions" /B | findstr /I "gbchcllhbilhmodmhabl3e7c" >> "%OUTPUT_FILE%"
    if %errorlevel% equ 0 (
        echo [+] Chrome Remote Desktop extension detected >> "%OUTPUT_FILE%"
    )
) else (
    echo [-] Chrome extensions directory not found >> "%OUTPUT_FILE%"
)

echo. >> "%OUTPUT_FILE%"
echo [+] Browser extension check complete
echo.

REM ===== 7. RECENT CONNECTIONS =====
echo [*] Step 7: Checking Recent Remote Desktop Connections...

(
    echo.
    echo ================================================
    echo RECENT REMOTE DESKTOP CONNECTIONS
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

REM Check RDP connection history
echo [*] RDP Connection History ^(HKEY_CURRENT_USER^): >> "%OUTPUT_FILE%"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" /v * 2>nul >> "%OUTPUT_FILE%"

echo. >> "%OUTPUT_FILE%"
echo [*] RDP Server Addresses: >> "%OUTPUT_FILE%"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>nul >> "%OUTPUT_FILE%"

echo. >> "%OUTPUT_FILE%"
echo [+] Recent connections check complete
echo.

REM ===== 8. NETWORK LISTENERS =====
echo [*] Step 8: Checking Network Listeners (Ports associated with Remote Desktop)...

(
    echo.
    echo ================================================
    echo NETWORK LISTENERS - REMOTE ACCESS PORTS
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

echo [*] Active Listeners on Common Remote Desktop Ports: >> "%OUTPUT_FILE%"
echo. >> "%OUTPUT_FILE%"

netstat -ano -p TCP | findstr /E "3389 5900 5800 6200 8080 10000" >> "%OUTPUT_FILE%"

echo. >> "%OUTPUT_FILE%"
echo [+] Network listener check complete
echo.

REM ===== 9. SUMMARY AND RECOMMENDATIONS =====
echo [*] Step 9: Generating Analysis Summary...

(
    echo.
    echo ================================================
    echo REMOTE DESKTOP APPS SUMMARY
    echo ================================================
    echo.
    echo COMMON REMOTE DESKTOP APPLICATIONS TO CHECK FOR:
    echo.
    echo [Built-in]:
    echo  - Remote Desktop Connection ^(mstsc.exe^) - Port 3389
    echo  - Remote Registry Service
    echo.
    echo [Commercial]:
    echo  - TeamViewer - Communication tool, remote support
    echo  - AnyDesk - Remote access and support
    echo  - Splashtop - Business remote access
    echo  - Citrix - Enterprise remote workspace
    echo  - LogMeIn - Cloud-based remote access
    echo  - ConnectWise ScreenConnect - IT support tool
    echo  - GoToMyPC - Remote desktop access
    echo.
    echo [Free/Open Source]:
    echo  - VNC ^(RealVNC, UltraVNC, TightVNC^) - Port 5900
    echo  - Chrome Remote Desktop - Browser-based
    echo  - Jump Desktop - Cross-platform remote access
    echo  - Remmina - Linux remote desktop client
    echo  - mRemoteNG - Multi-protocol remote management
    echo.
    echo [Potentially Malicious]:
    echo  - Ammyy Admin - Often used for support fraud
    echo  - Radmin - Can be misused for unauthorized access
    echo  - Supremo - Remote control tool
    echo  - TemRem - Remote access tool
    echo.
    echo [Collaboration Tools ^(with remote capabilities^)]:
    echo  - Skype
    echo  - Xunfei Intelligent Cloud
    echo  - DingTalk ^(Alibaba^)
    echo  - WeChat
    echo  - QQ
    echo  - Tencent Meeting
    echo.
    echo FORENSIC INDICATORS:
    echo  - Unexpected remote desktop applications
    echo  - Services running with elevated privileges
    echo  - Recent connection history in registry
    echo  - Network listeners on unusual ports
    echo  - Background remote access services
    echo  - Chrome extensions for remote access
    echo.
    echo INCIDENT RESPONSE NOTES:
    echo  - Document all remote access tools found
    echo  - Check installation dates and versions
    echo  - Review process hierarchy and parent-child relationships
    echo  - Analyze network traffic on remote access ports
    echo  - Check event logs for RDP connection attempts
    echo  - Review firewall rules for remote access exceptions
    echo.
    echo ================================================
    echo.
) >> "%OUTPUT_FILE%"

REM ===== FINAL SUMMARY =====
echo ================================================
echo REMOTE DESKTOP SCAN COMPLETE
echo ================================================
echo.
echo Output File: %cd%\%OUTPUT_FILE%
echo.
echo Scan Summary:
type "%OUTPUT_FILE%" | findstr /C:"Found:" /C:"Running" /C:"Port 3389" /C:"Status"
echo.
echo [+] Full report saved to: %OUTPUT_FILE%
echo [+] Review the report for all detected remote desktop applications
echo.

REM Display the full report
echo.
echo ================================================
echo FULL REPORT:
echo ================================================
type "%OUTPUT_FILE%"

pause
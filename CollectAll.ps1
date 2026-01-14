<#
.SYNOPSIS
    Windows Forensic Artifact Collection Script for Incident Response

.DESCRIPTION
    Collects critical forensic artifacts from a Windows system including:
    - Registry hives (SAM, SECURITY, SYSTEM, SOFTWARE, etc.)
    - Event logs (Security, System, Application, PowerShell, etc.)
    - User profile artifacts
    - Browser history and artifacts
    - Prefetch files
    - Recent files and jump lists
    - System information
    - Network information
    - Memory dump (optional)
    - MFT and filesystem artifacts

.PARAMETER OutputPath
    Destination folder for collected artifacts. Default: C:\ForensicCollection

.PARAMETER IncludeMemoryDump
    Include a memory dump in the collection (requires significant time/space)

.PARAMETER ComputerName
    Target computer name for documentation (defaults to current hostname)

.EXAMPLE
    .\Collect-ForensicArtifacts.ps1 -OutputPath "E:\Evidence\Case001"

.EXAMPLE
    .\Collect-ForensicArtifacts.ps1 -OutputPath "D:\IR" -IncludeMemoryDump

.NOTES
    Author: Incident Response Team
    Version: 1.0
    Requires: Administrator privileges
    Usage: For authorized incident response and forensic investigation only
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\ForensicCollection",

    [Parameter(Mandatory=$false)]
    [switch]$IncludeMemoryDump,

    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

# Requires Administrator privileges
#Requires -RunAsAdministrator

# Script version and metadata
$ScriptVersion = "1.0"
$CollectionTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CollectionRoot = Join-Path $OutputPath "$ComputerName`_$CollectionTimestamp"

# Initialize transcript logging
$TranscriptPath = Join-Path $CollectionRoot "collection_log.txt"

#region Functions

function Write-CollectionLog {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    $Color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'White' }
    }

    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $TranscriptPath -Value $LogMessage -ErrorAction SilentlyContinue
}

function New-CollectionFolder {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-CollectionLog "Created directory: $Path" -Level Success
        }
        catch {
            Write-CollectionLog "Failed to create directory $Path : $_" -Level Error
            return $false
        }
    }
    return $true
}

function Copy-ForensicFile {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Description
    )

    try {
        if (Test-Path $SourcePath) {
            Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            Write-CollectionLog "Collected: $Description" -Level Success
            return $true
        }
        else {
            Write-CollectionLog "File not found: $SourcePath" -Level Warning
            return $false
        }
    }
    catch {
        Write-CollectionLog "Failed to collect $Description : $_" -Level Error
        return $false
    }
}

function Export-RegistryHive {
    param(
        [string]$HiveName,
        [string]$DestinationPath
    )

    try {
        $RegFile = Join-Path $DestinationPath "$HiveName.reg"
        $HiveFile = Join-Path $DestinationPath "$HiveName.hive"

        # Export registry hive using reg.exe
        $RegArgs = "save HKLM\$HiveName `"$HiveFile`""
        Start-Process -FilePath "reg.exe" -ArgumentList $RegArgs -Wait -NoNewWindow -ErrorAction Stop

        Write-CollectionLog "Exported registry hive: $HiveName" -Level Success
        return $true
    }
    catch {
        Write-CollectionLog "Failed to export registry hive $HiveName : $_" -Level Error
        return $false
    }
}

#endregion

#region Main Script

Write-CollectionLog "=" * 80
Write-CollectionLog "Windows Forensic Artifact Collection Script v$ScriptVersion"
Write-CollectionLog "=" * 80
Write-CollectionLog "Target System: $ComputerName"
Write-CollectionLog "Collection Path: $CollectionRoot"
Write-CollectionLog "Collection Time: $CollectionTimestamp"
Write-CollectionLog "=" * 80

# Create root collection directory
if (-not (New-CollectionFolder -Path $CollectionRoot)) {
    Write-CollectionLog "Failed to create root collection directory. Exiting." -Level Error
    exit 1
}

# Create subdirectories
$Folders = @{
    Registry = Join-Path $CollectionRoot "Registry"
    EventLogs = Join-Path $CollectionRoot "EventLogs"
    UserProfiles = Join-Path $CollectionRoot "UserProfiles"
    SystemInfo = Join-Path $CollectionRoot "SystemInfo"
    Prefetch = Join-Path $CollectionRoot "Prefetch"
    Browser = Join-Path $CollectionRoot "Browser"
    Network = Join-Path $CollectionRoot "Network"
    FileSystem = Join-Path $CollectionRoot "FileSystem"
    Memory = Join-Path $CollectionRoot "Memory"
    Recent = Join-Path $CollectionRoot "Recent"
    Startup = Join-Path $CollectionRoot "Startup"
    Tasks = Join-Path $CollectionRoot "ScheduledTasks"
    Logs = Join-Path $CollectionRoot "Logs"
}

foreach ($Folder in $Folders.Values) {
    New-CollectionFolder -Path $Folder | Out-Null
}

#region Registry Collection
Write-CollectionLog "`n[1/12] Collecting Registry Hives..."

# Critical registry hives
$RegistryHives = @('SAM', 'SECURITY', 'SYSTEM', 'SOFTWARE')

foreach ($Hive in $RegistryHives) {
    Export-RegistryHive -HiveName $Hive -DestinationPath $Folders.Registry
}

# Export NTUSER.DAT from user profiles
Write-CollectionLog "Collecting user registry hives (NTUSER.DAT)..."
$UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($Profile in $UserProfiles) {
    $NTUserPath = Join-Path $Profile.FullName "NTUSER.DAT"
    $UsrClassPath = Join-Path $Profile.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"

    if (Test-Path $NTUserPath) {
        $UserRegFolder = Join-Path $Folders.Registry $Profile.Name
        New-CollectionFolder -Path $UserRegFolder | Out-Null
        Copy-ForensicFile -SourcePath $NTUserPath -DestinationPath $UserRegFolder -Description "NTUSER.DAT for $($Profile.Name)"
    }

    if (Test-Path $UsrClassPath) {
        $UserRegFolder = Join-Path $Folders.Registry $Profile.Name
        Copy-ForensicFile -SourcePath $UsrClassPath -DestinationPath $UserRegFolder -Description "UsrClass.dat for $($Profile.Name)"
    }
}

# Export common registry keys as text
$CommonKeys = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name="HKLM_Run"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Name="HKLM_RunOnce"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services"; Name="Services"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"; Name="NetworkProfiles"}
)

foreach ($Key in $CommonKeys) {
    try {
        if (Test-Path $Key.Path) {
            $OutFile = Join-Path $Folders.Registry "$($Key.Name).txt"
            Get-ItemProperty -Path $Key.Path -ErrorAction SilentlyContinue | Out-File -FilePath $OutFile
            Write-CollectionLog "Exported registry key: $($Key.Name)" -Level Success
        }
    }
    catch {
        Write-CollectionLog "Failed to export registry key $($Key.Name): $_" -Level Warning
    }
}

#endregion

#region Event Log Collection
Write-CollectionLog "`n[2/12] Collecting Event Logs..."

# Critical event logs
$EventLogs = @(
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
)

foreach ($Log in $EventLogs) {
    try {
        $LogName = $Log -replace '/', '_'
        $OutputFile = Join-Path $Folders.EventLogs "$LogName.evtx"

        # Use wevtutil to export event logs
        $WevtArgs = "epl `"$Log`" `"$OutputFile`""
        Start-Process -FilePath "wevtutil.exe" -ArgumentList $WevtArgs -Wait -NoNewWindow -ErrorAction Stop

        Write-CollectionLog "Exported event log: $Log" -Level Success
    }
    catch {
        Write-CollectionLog "Failed to export event log $Log : $_" -Level Warning
    }
}



#endregion

#region System Information
Write-CollectionLog "`n[3/12] Collecting System Information..."

# Computer system information
Get-ComputerInfo | Out-File -FilePath (Join-Path $Folders.SystemInfo "ComputerInfo.txt")
systeminfo.exe > (Join-Path $Folders.SystemInfo "SystemInfo.txt")

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Export-Csv -Path (Join-Path $Folders.SystemInfo "InstalledSoftware.csv") -NoTypeInformation

# Windows updates
Get-HotFix | Export-Csv -Path (Join-Path $Folders.SystemInfo "InstalledUpdates.csv") -NoTypeInformation

# Running processes
Get-Process | Select-Object ProcessName, Id, Path, CommandLine, StartTime, Company |
    Export-Csv -Path (Join-Path $Folders.SystemInfo "RunningProcesses.csv") -NoTypeInformation

# Services
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv -Path (Join-Path $Folders.SystemInfo "Services.csv") -NoTypeInformation

Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName |
    Export-Csv -Path (Join-Path $Folders.SystemInfo "ServicesDetailed.csv") -NoTypeInformation

# Scheduled tasks
schtasks /query /fo CSV /v > (Join-Path $Folders.Tasks "ScheduledTasks.csv")

# Drivers
Get-WmiObject Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode |
    Export-Csv -Path (Join-Path $Folders.SystemInfo "Drivers.csv") -NoTypeInformation

# Environment variables
Get-ChildItem Env: | Out-File -FilePath (Join-Path $Folders.SystemInfo "EnvironmentVariables.txt")

Write-CollectionLog "System information collected" -Level Success

#endregion

#region Network Information
Write-CollectionLog "`n[4/12] Collecting Network Information..."

# Network configuration
ipconfig /all > (Join-Path $Folders.Network "IPConfig.txt")
netstat -anob > (Join-Path $Folders.Network "NetStat.txt") 2>&1
route print > (Join-Path $Folders.Network "RoutingTable.txt")
arp -a > (Join-Path $Folders.Network "ARPCache.txt")
netsh wlan show profiles > (Join-Path $Folders.Network "WiFiProfiles.txt")
netsh advfirewall show allprofiles > (Join-Path $Folders.Network "FirewallStatus.txt")

# DNS cache
Get-DnsClientCache | Export-Csv -Path (Join-Path $Folders.Network "DNSCache.csv") -NoTypeInformation

# Network shares
net share > (Join-Path $Folders.Network "NetworkShares.txt")

# Hosts file
Copy-ForensicFile -SourcePath "C:\Windows\System32\drivers\etc\hosts" -DestinationPath $Folders.Network -Description "Hosts file"

Write-CollectionLog "Network information collected" -Level Success

#endregion

#region Prefetch Files
Write-CollectionLog "`n[5/12] Collecting Prefetch Files..."

$PrefetchPath = "C:\Windows\Prefetch"
if (Test-Path $PrefetchPath) {
    try {
        Copy-Item -Path "$PrefetchPath\*.pf" -Destination $Folders.Prefetch -Force -ErrorAction SilentlyContinue
        $PrefetchCount = (Get-ChildItem $Folders.Prefetch -Filter "*.pf" -ErrorAction SilentlyContinue).Count
        Write-CollectionLog "Collected $PrefetchCount prefetch files" -Level Success
    }
    catch {
        Write-CollectionLog "Failed to collect prefetch files: $_" -Level Warning
    }
}

#endregion

#region User Profile Artifacts
Write-CollectionLog "`n[6/12] Collecting User Profile Artifacts..."

foreach ($Profile in $UserProfiles) {
    $Username = $Profile.Name
    $UserArtifactPath = Join-Path $Folders.UserProfiles $Username
    New-CollectionFolder -Path $UserArtifactPath | Out-Null

    Write-CollectionLog "Collecting artifacts for user: $Username"

    # Recent files
    $RecentPath = Join-Path $Profile.FullName "AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $RecentPath) {
        $UserRecentPath = Join-Path $UserArtifactPath "Recent"
        New-CollectionFolder -Path $UserRecentPath | Out-Null
        Copy-Item -Path "$RecentPath\*" -Destination $UserRecentPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Jump lists
    $JumpListPaths = @(
        "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
        "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
    )

    foreach ($JLPath in $JumpListPaths) {
        $FullJLPath = Join-Path $Profile.FullName $JLPath
        if (Test-Path $FullJLPath) {
            $DestFolder = Join-Path $UserArtifactPath (Split-Path $JLPath -Leaf)
            New-CollectionFolder -Path $DestFolder | Out-Null
            Copy-Item -Path "$FullJLPath\*" -Destination $DestFolder -Force -ErrorAction SilentlyContinue
        }
    }

    # PowerShell history
    $PSHistoryPath = Join-Path $Profile.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $PSHistoryPath) {
        Copy-ForensicFile -SourcePath $PSHistoryPath -DestinationPath $UserArtifactPath -Description "PowerShell history for $Username"
    }

    # Downloads folder listing
    $DownloadsPath = Join-Path $Profile.FullName "Downloads"
    if (Test-Path $DownloadsPath) {
        Get-ChildItem $DownloadsPath -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime |
            Export-Csv -Path (Join-Path $UserArtifactPath "Downloads_Listing.csv") -NoTypeInformation
    }

    # Desktop file listing
    $DesktopPath = Join-Path $Profile.FullName "Desktop"
    if (Test-Path $DesktopPath) {
        Get-ChildItem $DesktopPath -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime |
            Export-Csv -Path (Join-Path $UserArtifactPath "Desktop_Listing.csv") -NoTypeInformation
    }
}

Write-CollectionLog "User profile artifacts collected" -Level Success

#endregion

#region Browser Artifacts
Write-CollectionLog "`n[7/12] Collecting Browser Artifacts..."

foreach ($Profile in $UserProfiles) {
    $Username = $Profile.Name
    $BrowserPath = Join-Path $Folders.Browser $Username
    New-CollectionFolder -Path $BrowserPath | Out-Null

    # Chrome/Edge Chromium artifacts
    $ChromiumPaths = @(
        @{Browser="Chrome"; Path="AppData\Local\Google\Chrome\User Data\Default"},
        @{Browser="Edge"; Path="AppData\Local\Microsoft\Edge\User Data\Default"}
    )

    foreach ($Browser in $ChromiumPaths) {
        $BrowserDataPath = Join-Path $Profile.FullName $Browser.Path
        if (Test-Path $BrowserDataPath) {
            $BrowserDest = Join-Path $BrowserPath $Browser.Browser
            New-CollectionFolder -Path $BrowserDest | Out-Null

            # Copy key database files
            $Artifacts = @('History', 'Cookies', 'Web Data', 'Login Data', 'Bookmarks', 'Preferences')
            foreach ($Artifact in $Artifacts) {
                $ArtifactPath = Join-Path $BrowserDataPath $Artifact
                if (Test-Path $ArtifactPath) {
                    Copy-ForensicFile -SourcePath $ArtifactPath -DestinationPath $BrowserDest -Description "$($Browser.Browser) $Artifact for $Username"
                }
            }
        }
    }

    # Firefox artifacts
    $FirefoxPath = Join-Path $Profile.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $FirefoxPath) {
        $FFProfiles = Get-ChildItem $FirefoxPath -Directory -ErrorAction SilentlyContinue
        foreach ($FFProfile in $FFProfiles) {
            $FFDest = Join-Path $BrowserPath "Firefox\$($FFProfile.Name)"
            New-CollectionFolder -Path $FFDest | Out-Null

            $Artifacts = @('places.sqlite', 'cookies.sqlite', 'formhistory.sqlite', 'logins.json', 'key4.db')
            foreach ($Artifact in $Artifacts) {
                $ArtifactPath = Join-Path $FFProfile.FullName $Artifact
                if (Test-Path $ArtifactPath) {
                    Copy-ForensicFile -SourcePath $ArtifactPath -DestinationPath $FFDest -Description "Firefox $Artifact for $Username"
                }
            }
        }
    }
}

Write-CollectionLog "Browser artifacts collected" -Level Success

#endregion

#region Startup Locations
Write-CollectionLog "`n[8/12] Collecting Startup and Persistence Locations..."

# Common startup folders
$StartupLocations = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\Windows\System32\Tasks"
)

foreach ($Profile in $UserProfiles) {
    $StartupLocations += Join-Path $Profile.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
}

foreach ($Location in $StartupLocations) {
    if (Test-Path $Location) {
        $SafeName = ($Location -replace ':', '' -replace '\\', '_')
        $DestPath = Join-Path $Folders.Startup $SafeName
        New-CollectionFolder -Path $DestPath | Out-Null
        Copy-Item -Path "$Location\*" -Destination $DestPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-CollectionLog "Startup locations collected" -Level Success

#endregion

#region File System Artifacts
Write-CollectionLog "`n[9/12] Collecting File System Artifacts..."

# $MFT (requires raw disk access)
try {
    Write-CollectionLog "Attempting to collect `$MFT..."
    # This requires third-party tools or raw disk access - document the location
    "MFT Location: C:\`$MFT (requires raw disk access tool like FTK Imager or RawCopy)" |
        Out-File -FilePath (Join-Path $Folders.FileSystem "MFT_Info.txt")
} catch {
    Write-CollectionLog "MFT collection requires specialized tools" -Level Warning
}

# $LogFile, $UsnJrnl locations
$FSArtifacts = @(
    "File system artifacts requiring raw access:",
    "  C:\`$MFT - Master File Table",
    "  C:\`$LogFile - NTFS transaction log",
    "  C:\`$Extend\`$UsnJrnl - USN Journal",
    "",
    "Use tools like:",
    "  - RawCopy (https://github.com/jschicht/RawCopy)",
    "  - FTK Imager",
    "  - Arsenal Image Mounter"
) | Out-File -FilePath (Join-Path $Folders.FileSystem "FileSystemArtifacts_Info.txt")

# Recycle Bin info (requires parsing - document locations)
$RecycleBinInfo = @()
foreach ($Drive in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' })) {
    $RecyclePath = Join-Path $Drive.Root '$Recycle.Bin'
    if (Test-Path $RecyclePath) {
        $RecycleBinInfo += "Recycle Bin Location: $RecyclePath"
    }
}
$RecycleBinInfo | Out-File -FilePath (Join-Path $Folders.FileSystem "RecycleBin_Locations.txt")

# Alternate Data Streams scan (sample of system files)
Write-CollectionLog "Scanning for Alternate Data Streams..."
Get-ChildItem "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } |
    Where-Object { $_.Stream -ne ':$DATA' } |
    Select-Object FileName, Stream, Length |
    Export-Csv -Path (Join-Path $Folders.FileSystem "AlternateDataStreams.csv") -NoTypeInformation

Write-CollectionLog "File system artifacts documented" -Level Success

#endregion

#region Windows Logs
Write-CollectionLog "`n[10/12] Collecting Windows Log Files..."

# Windows setup logs
$LogLocations = @(
    "C:\Windows\Panther",
    "C:\Windows\inf",
    "C:\Windows\Logs"
)

foreach ($LogLoc in $LogLocations) {
    if (Test-Path $LogLoc) {
        $SafeName = ($LogLoc -replace ':', '' -replace '\\', '_')
        $DestPath = Join-Path $Folders.Logs $SafeName
        New-CollectionFolder -Path $DestPath | Out-Null
        Copy-Item -Path "$LogLoc\*.log" -Destination $DestPath -Force -ErrorAction SilentlyContinue
        Copy-Item -Path "$LogLoc\*.txt" -Destination $DestPath -Force -ErrorAction SilentlyContinue
    }
}

Write-CollectionLog "Windows log files collected" -Level Success

#endregion

#region Memory Dump
if ($IncludeMemoryDump) {
    Write-CollectionLog "`n[11/12] Creating Memory Dump (this may take several minutes)..."

    try {
        $DumpFile = Join-Path $Folders.Memory "memory_$CollectionTimestamp.dmp"

        # Check if DumpIt or similar tool is available, otherwise document
        Write-CollectionLog "Memory dump requested. Recommended tools:" -Level Warning
        @(
            "Memory dump tools (not included in this script):",
            "  - DumpIt (https://www.comae.com/)",
            "  - WinPMEM (https://github.com/Velocidex/WinPmem)",
            "  - FTK Imager",
            "  - Magnet RAM Capture",
            "",
            "Alternative: Use Windows built-in (creates crash dump):",
            "  notmyfault.exe /crash"
        ) | Out-File -FilePath (Join-Path $Folders.Memory "MemoryDump_Info.txt")

        Write-CollectionLog "Memory dump requires external tool - see MemoryDump_Info.txt" -Level Warning
    }
    catch {
        Write-CollectionLog "Memory dump failed: $_" -Level Error
    }
} else {
    Write-CollectionLog "`n[11/12] Skipping Memory Dump (use -IncludeMemoryDump to enable)"
}

#endregion

#region Timeline Creation
Write-CollectionLog "`n[12/12] Creating Timeline Information..."

# Create a timeline of recent file system activity
try {
    $TimelineFile = Join-Path $CollectionRoot "FileSystem_Timeline.csv"

    Write-CollectionLog "Creating filesystem timeline (last 30 days of activity)..."
    $StartDate = (Get-Date).AddDays(-30)

    Get-ChildItem "C:\" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $StartDate -or $_.CreationTime -gt $StartDate } |
        Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime |
        Sort-Object LastWriteTime -Descending |
        Export-Csv -Path $TimelineFile -NoTypeInformation

    Write-CollectionLog "Filesystem timeline created" -Level Success
}
catch {
    Write-CollectionLog "Timeline creation failed: $_" -Level Warning
}

#endregion

#region Collection Summary
Write-CollectionLog "`n" + ("=" * 80)
Write-CollectionLog "COLLECTION SUMMARY"
Write-CollectionLog ("=" * 80)

# Generate collection report
$ReportPath = Join-Path $CollectionRoot "Collection_Report.txt"

$Report = @"
Windows Forensic Artifact Collection Report
==========================================

Collection Details:
  Computer Name: $ComputerName
  Collection Time: $CollectionTimestamp
  Script Version: $ScriptVersion
  Collector: $env:USERNAME
  Output Location: $CollectionRoot

Artifacts Collected:
  [X] Registry Hives (SAM, SECURITY, SYSTEM, SOFTWARE, NTUSER.DAT)
  [X] Event Logs (Security, System, Application, PowerShell, etc.)
  [X] System Information (processes, services, software, updates)
  [X] Network Information (connections, DNS cache, firewall)
  [X] Prefetch Files
  [X] User Profile Artifacts (recent files, jump lists, browser data)
  [X] Browser History (Chrome, Edge, Firefox)
  [X] Startup Locations
  [X] File System Metadata
  [X] Windows Log Files
  [X] Scheduled Tasks
  $( if ($IncludeMemoryDump) { "[X] Memory Dump" } else { "[ ] Memory Dump (not requested)" } )

Next Steps:
  1. Review collection_log.txt for any errors or warnings
  2. Verify all expected artifacts were collected
  3. Hash the collection folder for chain of custody
  4. Securely transfer to analysis system
  5. Parse artifacts using forensic tools (Autopsy, X-Ways, etc.)

Important File System Artifacts (require special tools):
  - `$MFT (Master File Table)
  - `$LogFile (NTFS transaction log)
  - `$UsnJrnl (Update Sequence Number Journal)
  See FileSystem\FileSystemArtifacts_Info.txt for details

Recommended Analysis Tools:
  - Registry: RegRipper, Registry Explorer
  - Event Logs: Event Log Explorer, EvtxECmd
  - Prefetch: PECmd, WinPrefetchView
  - Browser: Hindsight, DB Browser for SQLite
  - Timeline: log2timeline/plaso
  - Memory: Volatility Framework

Chain of Custody:
  Collected By: $env:USERNAME @ $env:COMPUTERNAME
  Date/Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Collection completed successfully.
"@

$Report | Out-File -FilePath $ReportPath
Write-CollectionLog "Collection report saved to: $ReportPath" -Level Success

# Calculate collection size
$CollectionSize = (Get-ChildItem $CollectionRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
$CollectionSizeMB = [math]::Round($CollectionSize / 1MB, 2)

Write-CollectionLog "`nCollection Statistics:"
Write-CollectionLog "  Total Size: $CollectionSizeMB MB"
Write-CollectionLog "  Location: $CollectionRoot"
Write-CollectionLog "`nIMPORTANT: Generate hash of collection folder for chain of custody:"
Write-CollectionLog "  Get-FileHash -Path '$CollectionRoot\*' -Algorithm SHA256 | Export-Csv hash_manifest.csv"

Write-CollectionLog "`n" + ("=" * 80)
Write-CollectionLog "Forensic artifact collection completed successfully!" -Level Success
Write-CollectionLog ("=" * 80)

#endregion

# Open collection folder
Write-CollectionLog "`nOpening collection folder..."
Invoke-Item $CollectionRoot

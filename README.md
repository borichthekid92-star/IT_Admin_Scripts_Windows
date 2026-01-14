# IT_Admin_Scripts_Windows
AI generated scripts for IT admin work

#CollectAll 
#.SYNOPSIS
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

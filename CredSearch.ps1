# Find-CredentialFiles.ps1
# Script to search for potential credential files on Windows systems
# USE ONLY ON SYSTEMS YOU OWN OR HAVE AUTHORIZATION TO AUDIT

<#
.SYNOPSIS
    Searches for files that may contain credentials.

.DESCRIPTION
    This script searches specified directories for files with names commonly
    associated with credentials, passwords, and sensitive information.

.PARAMETER SearchPath
    The root path to search. Defaults to C:\

.PARAMETER OutputFile
    Optional path to save results to a CSV file.

.PARAMETER MaxDepth
    Maximum directory depth to search. Use -1 for unlimited.

.EXAMPLE
    .\Find-CredentialFiles.ps1 -SearchPath "C:\Users" -OutputFile results.csv
#>

param(
    [string]$SearchPath = "C:\",
    [string]$OutputFile = "",
    [int]$MaxDepth = -1
)

# File name patterns to search for
$FilePatterns = @(
    "*password*",
	"*username**",
    "*passwd*",
    "*credential*",
    "*cred*",
    "*secret*",
    "*auth*",
    "*token*",
    "*key*",
    "*.pem",
    "*.key",
    "*.ppk",
    "*id_rsa*",
    "*id_dsa*",
    "*.pfx",
    "*.p12",
    "*shadow*",
    "*htpasswd*",
    "*login*",
    "*account*",
    "*.env",
    ".git-credentials",
    "*config*.txt",
    "*database*.txt",
    "*backup*.txt",
    "*dump*.sql",
    "*.kdbx",
    "*vault*"
)

# File extensions commonly containing credentials
$Extensions = @(
    "*.log",
	"*.key",
    "*.xml",
    "*.config",
    "*.cfg",
    "*.ini",
    "*.yml",
    "*.yaml",
    "*.conf",
    "*.properties"
)

# File extensions to exclude from all searches
$ExcludedExtensions = @(".exe", ".dll", ".manifest")

# Directories to exclude from searches
$ExcludedPaths = @(
    "C:\Windows\WinSxS\"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Credential File Search Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Search Path: $SearchPath" -ForegroundColor Yellow
Write-Host "Started: $(Get-Date)" -ForegroundColor Yellow
Write-Host ""

$Results = @()
$FileCount = 0

try {
    Write-Host "[*] Searching for potential credential files..." -ForegroundColor Green

    foreach ($pattern in $FilePatterns) {
        Write-Host "[+] Searching for pattern: $pattern" -ForegroundColor Gray

        $SearchParams = @{
            Path = $SearchPath
            Filter = $pattern
            File = $true
            Recurse = $true
            ErrorAction = 'SilentlyContinue'
        }

        $Files = Get-ChildItem @SearchParams | Where-Object { 
            ($_.Extension -notin $ExcludedExtensions) -and 
            -not ($ExcludedPaths | Where-Object { $_.FullName -like "$_*" })
        }

        foreach ($file in $Files) {
            $FileCount++

            $FileInfo = [PSCustomObject]@{
                FileName = $file.Name
                FullPath = $file.FullName
                Directory = $file.DirectoryName
                Size = $file.Length
                Extension = $file.Extension
                Created = $file.CreationTime
                Modified = $file.LastWriteTime
                Accessed = $file.LastAccessTime
            }

            $Results += $FileInfo

            Write-Host "    [!] Found: $($file.FullName)" -ForegroundColor Yellow
        }
    }

    # Additional search by extension with credential-related content
    Write-Host "`n[*] Searching by extension for credential-related content..." -ForegroundColor Green

    foreach ($ext in $Extensions) {
        $SearchParams = @{
            Path = $SearchPath
            Filter = $ext
            File = $true
            Recurse = $true
            ErrorAction = 'SilentlyContinue'
        }

        $Files = Get-ChildItem @SearchParams | Where-Object { 
            ($_.Length -lt 10MB) -and 
            ($_.Extension -notin $ExcludedExtensions) -and
            -not ($ExcludedPaths | Where-Object { $_.FullName -like "$_*" })
        }

        foreach ($file in $Files) {
            # Skip if already found
            if ($Results.FullPath -contains $file.FullName) {
                continue
            }

            # Quick content scan for credential keywords
            try {
                $Content = Get-Content -Path $file.FullName -TotalCount 100 -ErrorAction SilentlyContinue | Out-String

                if ($Content -match 'user|password|passwd|credential|secret|api[_-]?key|access[_-]?token|private[_-]?key') {
                    $FileCount++

                    $FileInfo = [PSCustomObject]@{
                        FileName = $file.Name
                        FullPath = $file.FullName
                        Directory = $file.DirectoryName
                        Size = $file.Length
                        Extension = $file.Extension
                        Created = $file.CreationTime
                        Modified = $file.LastWriteTime
                        Accessed = $file.LastAccessTime
                    }

                    $Results += $FileInfo
                    Write-Host "    [!] Found (content match): $($file.FullName)" -ForegroundColor Yellow
                }
            }
            catch {
                # Skip files that can't be read
                continue
            }
        }
    }

}
catch {
    Write-Host "[!] Error during search: $_" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Search Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total files found: $FileCount" -ForegroundColor Green
Write-Host "Finished: $(Get-Date)" -ForegroundColor Yellow

# Display summary
if ($Results.Count -gt 0) {
    Write-Host "`nResults Summary:" -ForegroundColor Cyan
    $Results | Format-Table FileName, Directory, Size, Modified -AutoSize

    # Save to CSV if output file specified
    if ($OutputFile) {
        $Results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "`n[+] Results saved to: $OutputFile" -ForegroundColor Green
    }
}
else {
    Write-Host "`n[*] No potential credential files found." -ForegroundColor Yellow
}

Write-Host "`n[!] REMINDER: Review these files manually and secure any that contain actual credentials!" -ForegroundColor Red
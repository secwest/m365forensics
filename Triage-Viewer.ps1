# INCIDENT RESPONSE RESULTS VIEWER v1.0
# Usage: powershell -ExecutionPolicy Bypass -File .\IR_Viewer.ps1 [-Path "C:\incident_20241125_123456"]

param(
    [string]$Path = "",
    [int]$PageSize = 20,
    [switch]$ExportReport = $false
)

# Console setup
$Host.UI.RawUI.WindowTitle = "Incident Response Viewer"
$ErrorActionPreference = "SilentlyContinue"

# Color definitions
$colors = @{
    Critical = "Red"
    High = "Magenta"
    Medium = "Yellow"
    Low = "Green"
    Info = "Cyan"
    Header = "White"
    Menu = "Gray"
    Data = "DarkGray"
}

# Find incident directories if path not specified
function Find-IncidentDirs {
    $dirs = Get-ChildItem -Path "C:\" -Filter "incident_*" -Directory -ErrorAction SilentlyContinue | 
            Sort-Object CreationTime -Descending
    
    if ($dirs.Count -eq 0) {
        Write-Host "No incident directories found in C:\" -ForegroundColor Red
        return $null
    }
    
    Write-Host "`nAvailable incident collections:" -ForegroundColor $colors.Header
    for ($i = 0; $i -lt $dirs.Count; $i++) {
        $summary = Get-Content "$($dirs[$i].FullName)\SUMMARY.txt" -ErrorAction SilentlyContinue | 
                   Select-String "THREAT LEVEL:" | ForEach-Object { $_.Line.Split(":")[1].Trim() }
        
        $threatColor = switch -Regex ($summary) {
            "CRITICAL" { $colors.Critical }
            "HIGH" { $colors.High }
            "MEDIUM" { $colors.Medium }
            "LOW" { $colors.Low }
            default { $colors.Info }
        }
        
        Write-Host "$($i+1). " -NoNewline -ForegroundColor $colors.Menu
        Write-Host "$($dirs[$i].Name) " -NoNewline
        Write-Host "[$summary]" -ForegroundColor $threatColor
    }
    
    $choice = Read-Host "`nSelect incident (1-$($dirs.Count)) or Q to quit"
    if ($choice -eq 'Q') { return $null }
    
    $index = [int]$choice - 1
    if ($index -ge 0 -and $index -lt $dirs.Count) {
        return $dirs[$index].FullName
    }
    return $null
}

# Paging function
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title = "Results",
        [switch]$NoFormat
    )
    
    Clear-Host
    Write-Host "=== $Title ===" -ForegroundColor $colors.Header
    Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
    Write-Host ("-" * 80) -ForegroundColor $colors.Menu
    
    $currentPage = 0
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    
    while ($true) {
        $startIndex = $currentPage * $PageSize
        $endIndex = [Math]::Min($startIndex + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIndex; $i -lt $endIndex; $i++) {
            if ($NoFormat) {
                Write-Host $Content[$i]
            } else {
                Write-Host "[$($i+1)] " -NoNewline -ForegroundColor $colors.Menu
                Write-Host $Content[$i] -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host "`n" -NoNewline
        Write-Host "Page $($currentPage + 1)/$totalPages" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit [#] Jump to item: " -NoNewline -ForegroundColor $colors.Menu
        
        $nav = Read-Host
        
        switch -Regex ($nav) {
            "^[Nn]" { 
                if ($currentPage -lt $totalPages - 1) { 
                    $currentPage++
                    Clear-Host
                    Write-Host "=== $Title ===" -ForegroundColor $colors.Header
                    Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
                    Write-Host ("-" * 80) -ForegroundColor $colors.Menu
                }
            }
            "^[Pp]" { 
                if ($currentPage -gt 0) { 
                    $currentPage--
                    Clear-Host
                    Write-Host "=== $Title ===" -ForegroundColor $colors.Header
                    Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
                    Write-Host ("-" * 80) -ForegroundColor $colors.Menu
                }
            }
            "^[Ff]" { 
                $currentPage = 0
                Clear-Host
                Write-Host "=== $Title ===" -ForegroundColor $colors.Header
                Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
                Write-Host ("-" * 80) -ForegroundColor $colors.Menu
            }
            "^[Ll]" { 
                $currentPage = $totalPages - 1
                Clear-Host
                Write-Host "=== $Title ===" -ForegroundColor $colors.Header
                Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
                Write-Host ("-" * 80) -ForegroundColor $colors.Menu
            }
            "^[Qq]" { return }
            "^\d+$" {
                $itemNum = [int]$nav - 1
                if ($itemNum -ge 0 -and $itemNum -lt $Content.Count) {
                    Clear-Host
                    Write-Host "=== Item Detail ===" -ForegroundColor $colors.Header
                    Write-Host $Content[$itemNum] -ForegroundColor $colors.Data
                    Write-Host "`nPress Enter to continue..." -ForegroundColor $colors.Menu
                    Read-Host
                    Clear-Host
                    Write-Host "=== $Title ===" -ForegroundColor $colors.Header
                    Write-Host "Total items: $($Content.Count)" -ForegroundColor $colors.Info
                    Write-Host ("-" * 80) -ForegroundColor $colors.Menu
                }
            }
        }
    }
}

# CSV viewer with formatting
function Show-CsvData {
    param(
        [string]$FilePath,
        [string]$Title
    )
    
    if (!(Test-Path $FilePath)) {
        Write-Host "File not found: $FilePath" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $data = Import-Csv $FilePath
    if ($data.Count -eq 0) {
        Write-Host "No data in file" -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        return
    }
    
    # Format for display
    $formatted = @()
    foreach ($row in $data) {
        $props = $row.PSObject.Properties
        $line = ""
        foreach ($prop in $props) {
            if ($prop.Value) {
                $val = if ($prop.Value.Length -gt 50) { 
                    $prop.Value.Substring(0, 47) + "..." 
                } else { 
                    $prop.Value 
                }
                $line += "$($prop.Name): $val | "
            }
        }
        $formatted += $line.TrimEnd(" | ")
    }
    
    Show-PagedContent -Content $formatted -Title $Title
}

# Main viewer function
function Show-IncidentData {
    param([string]$IncidentPath)
    
    while ($true) {
        Clear-Host
        
        # Header
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $colors.Header
        Write-Host "║                          INCIDENT RESPONSE VIEWER                            ║" -ForegroundColor $colors.Header
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $colors.Header
        
        Write-Host "`nIncident: " -NoNewline
        Write-Host (Split-Path $IncidentPath -Leaf) -ForegroundColor $colors.Info
        
        # Quick summary
        $summaryFile = "$IncidentPath\SUMMARY.txt"
        if (Test-Path $summaryFile) {
            $threatLevel = Get-Content $summaryFile | Select-String "THREAT LEVEL:" | 
                          ForEach-Object { $_.Line.Split(":")[1].Trim() }
            $totalAlerts = Get-Content $summaryFile | Select-String "TOTAL ALERTS:" | 
                          ForEach-Object { $_.Line.Split(":")[1].Trim() }
            
            $threatColor = switch -Regex ($threatLevel) {
                "CRITICAL" { $colors.Critical }
                "HIGH" { $colors.High }
                "MEDIUM" { $colors.Medium }
                "LOW" { $colors.Low }
                default { $colors.Info }
            }
            
            Write-Host "Threat Level: " -NoNewline
            Write-Host $threatLevel -ForegroundColor $threatColor
            Write-Host "Total Alerts: " -NoNewline
            Write-Host $totalAlerts -ForegroundColor $colors.Info
        }
        
        # Menu
        Write-Host "`n═══ MAIN MENU ═══" -ForegroundColor $colors.Header
        Write-Host "1.  View Summary Report" -ForegroundColor $colors.Menu
        Write-Host "2.  ALERTS - Critical Findings" -ForegroundColor $colors.Critical
        Write-Host "3.  Network Connections" -ForegroundColor $colors.Menu
        Write-Host "4.  Process Analysis" -ForegroundColor $colors.Menu
        Write-Host "5.  Persistence Mechanisms" -ForegroundColor $colors.Menu
        Write-Host "6.  System Information" -ForegroundColor $colors.Menu
        Write-Host "7.  IOCs (Indicators of Compromise)" -ForegroundColor $colors.Menu
        Write-Host "8.  Raw File Browser" -ForegroundColor $colors.Menu
        Write-Host "9.  Export Full Report" -ForegroundColor $colors.Menu
        Write-Host "Q.  Quit" -ForegroundColor $colors.Menu
        
        $choice = Read-Host "`nSelect option"
        
        switch ($choice) {
            "1" { # Summary
                Clear-Host
                if (Test-Path $summaryFile) {
                    Get-Content $summaryFile | ForEach-Object {
                        if ($_ -match "CRITICAL|HIGH") {
                            Write-Host $_ -ForegroundColor $colors.Critical
                        } elseif ($_ -match "MEDIUM") {
                            Write-Host $_ -ForegroundColor $colors.Medium
                        } elseif ($_ -match "LOW") {
                            Write-Host $_ -ForegroundColor $colors.Low
                        } elseif ($_ -match "^=+|^-+|^\*+|^!+") {
                            Write-Host $_ -ForegroundColor $colors.Header
                        } else {
                            Write-Host $_
                        }
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            
            "2" { # Alerts
                $alertFiles = Get-ChildItem "$IncidentPath\ALERTS" -Filter "*.*" -ErrorAction SilentlyContinue
                if ($alertFiles) {
                    Clear-Host
                    Write-Host "═══ ALERT FILES ═══" -ForegroundColor $colors.Critical
                    for ($i = 0; $i -lt $alertFiles.Count; $i++) {
                        Write-Host "$($i+1). $($alertFiles[$i].Name)" -ForegroundColor $colors.Menu
                    }
                    
                    $fileChoice = Read-Host "`nSelect file (1-$($alertFiles.Count)) or B for back"
                    if ($fileChoice -ne 'B' -and $fileChoice -match '^\d+$') {
                        $index = [int]$fileChoice - 1
                        if ($index -ge 0 -and $index -lt $alertFiles.Count) {
                            $file = $alertFiles[$index]
                            
                            switch ($file.Extension) {
                                ".csv" { Show-CsvData -FilePath $file.FullName -Title $file.Name }
                                ".txt" { 
                                    $content = Get-Content $file.FullName
                                    Show-PagedContent -Content $content -Title $file.Name -NoFormat
                                }
                                ".json" {
                                    $json = Get-Content $file.FullName | ConvertFrom-Json
                                    $formatted = $json | ConvertTo-Json -Depth 5 | Out-String -Width 120
                                    Show-PagedContent -Content $formatted.Split("`n") -Title $file.Name -NoFormat
                                }
                            }
                        }
                    }
                }
            }
            
            "3" { # Network
                Clear-Host
                Write-Host "═══ NETWORK ANALYSIS ═══" -ForegroundColor $colors.Header
                Write-Host "1. Active Connections (CSV)" -ForegroundColor $colors.Menu
                Write-Host "2. External IPs" -ForegroundColor $colors.Menu
                Write-Host "3. DNS Cache" -ForegroundColor $colors.Menu
                Write-Host "4. Active Sessions" -ForegroundColor $colors.Menu
                Write-Host "5. Network Configuration" -ForegroundColor $colors.Menu
                
                $netChoice = Read-Host "`nSelect option"
                
                switch ($netChoice) {
                    "1" { Show-CsvData -FilePath "$IncidentPath\Network\connections_basic.csv" -Title "Network Connections" }
                    "2" { 
                        $ips = Get-Content "$IncidentPath\Network\external_ips.txt" -ErrorAction SilentlyContinue
                        if ($ips) { Show-PagedContent -Content $ips -Title "External IPs" }
                    }
                    "3" { Show-CsvData -FilePath "$IncidentPath\Network\dns_cache.csv" -Title "DNS Cache" }
                    "4" {
                        $sessions = Get-Content "$IncidentPath\Network\active_sessions.txt" -ErrorAction SilentlyContinue
                        if ($sessions) { Show-PagedContent -Content $sessions -Title "Active Sessions" -NoFormat }
                    }
                    "5" {
                        $ipconfig = Get-Content "$IncidentPath\Network\ipconfig.txt" -ErrorAction SilentlyContinue
                        if ($ipconfig) { Show-PagedContent -Content $ipconfig -Title "Network Configuration" -NoFormat }
                    }
                }
            }
            
            "4" { # Processes
                Clear-Host
                Write-Host "═══ PROCESS ANALYSIS ═══" -ForegroundColor $colors.Header
                
                $procFiles = @(
                    @{Name="Process List"; Path="$IncidentPath\Processes\process_list_basic.csv"},
                    @{Name="Suspicious Locations"; Path="$IncidentPath\ALERTS\suspicious_process_locations.csv"},
                    @{Name="Suspicious Names"; Path="$IncidentPath\ALERTS\suspicious_process_names.csv"},
                    @{Name="Shells with Network"; Path="$IncidentPath\ALERTS\shells_with_network.csv"}
                )
                
                for ($i = 0; $i -lt $procFiles.Count; $i++) {
                    if (Test-Path $procFiles[$i].Path) {
                        Write-Host "$($i+1). $($procFiles[$i].Name)" -ForegroundColor $colors.Menu
                    }
                }
                
                $procChoice = Read-Host "`nSelect option"
                $index = [int]$procChoice - 1
                if ($index -ge 0 -and $index -lt $procFiles.Count) {
                    Show-CsvData -FilePath $procFiles[$index].Path -Title $procFiles[$index].Name
                }
            }
            
            "5" { # Persistence
                Clear-Host
                Write-Host "═══ PERSISTENCE MECHANISMS ═══" -ForegroundColor $colors.Header
                
                $persFiles = @(
                    @{Name="Registry Autoruns"; Path="$IncidentPath\Persistence\registry_autoruns.csv"},
                    @{Name="Scheduled Tasks"; Path="$IncidentPath\ALERTS\recent_scheduled_tasks.csv"},
                    @{Name="Suspicious Services"; Path="$IncidentPath\ALERTS\suspicious_services.csv"}
                )
                
                for ($i = 0; $i -lt $persFiles.Count; $i++) {
                    if (Test-Path $persFiles[$i].Path) {
                        Write-Host "$($i+1). $($persFiles[$i].Name)" -ForegroundColor $colors.Menu
                    }
                }
                
                $persChoice = Read-Host "`nSelect option"
                $index = [int]$persChoice - 1
                if ($index -ge 0 -and $index -lt $persFiles.Count) {
                    Show-CsvData -FilePath $persFiles[$index].Path -Title $persFiles[$index].Name
                }
            }
            
            "6" { # System Info
                $sysFiles = Get-ChildItem "$IncidentPath\System" -Filter "*.*" -ErrorAction SilentlyContinue
                if ($sysFiles) {
                    Clear-Host
                    Write-Host "═══ SYSTEM FILES ═══" -ForegroundColor $colors.Header
                    for ($i = 0; $i -lt $sysFiles.Count; $i++) {
                        Write-Host "$($i+1). $($sysFiles[$i].Name)" -ForegroundColor $colors.Menu
                    }
                    
                    $sysChoice = Read-Host "`nSelect file"
                    $index = [int]$sysChoice - 1
                    if ($index -ge 0 -and $index -lt $sysFiles.Count) {
                        $file = $sysFiles[$index]
                        if ($file.Extension -eq ".csv") {
                            Show-CsvData -FilePath $file.FullName -Title $file.Name
                        } else {
                            $content = Get-Content $file.FullName
                            Show-PagedContent -Content $content -Title $file.Name -NoFormat
                        }
                    }
                }
            }
            
            "7" { # IOCs
                $iocFile = "$IncidentPath\ALERTS\quick_iocs.json"
                if (Test-Path $iocFile) {
                    Clear-Host
                    Write-Host "═══ INDICATORS OF COMPROMISE ═══" -ForegroundColor $colors.Header
                    
                    $iocs = Get-Content $iocFile | ConvertFrom-Json
                    
                    if ($iocs.SuspiciousIPs) {
                        Write-Host "`nSuspicious IPs:" -ForegroundColor $colors.Critical
                        $iocs.SuspiciousIPs | ForEach-Object { Write-Host "  - $_" -ForegroundColor $colors.Data }
                    }
                    
                    if ($iocs.SuspiciousProcesses) {
                        Write-Host "`nSuspicious Processes:" -ForegroundColor $colors.Critical
                        $iocs.SuspiciousProcesses | ForEach-Object { Write-Host "  - $_" -ForegroundColor $colors.Data }
                    }
                    
                    if ($iocs.PersistenceLocations) {
                        Write-Host "`nPersistence Locations:" -ForegroundColor $colors.Critical
                        $iocs.PersistenceLocations | ForEach-Object { 
                            Write-Host "  - $($_.Name) at $($_.Location)" -ForegroundColor $colors.Data 
                        }
                    }
                    
                    Read-Host "`nPress Enter to continue"
                }
            }
            
            "8" { # Raw browser
                $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
                $fileList = $allFiles | ForEach-Object {
                    $relPath = $_.FullName.Replace($IncidentPath, "").TrimStart("\")
                    "$relPath ($([Math]::Round($_.Length/1KB, 2))KB)"
                }
                Show-PagedContent -Content $fileList -Title "All Files"
            }
            
            "9" { # Export report
                Export-HtmlReport -IncidentPath $IncidentPath
            }
            
            "Q" { return }
        }
    }
}

# HTML Report Generator
function Export-HtmlReport {
    param([string]$IncidentPath)
    
    Write-Host "`nGenerating HTML report..." -ForegroundColor $colors.Info
    
    $reportPath = "$IncidentPath\IncidentReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $summary = Get-Content "$IncidentPath\SUMMARY.txt" -Raw -ErrorAction SilentlyContinue
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Incident Response Report</title>
    <style>
        body { font-family: Consolas, monospace; background: #1e1e1e; color: #d4d4d4; margin: 20px; }
        h1, h2, h3 { color: #569cd6; }
        .critical { color: #f44747; font-weight: bold; }
        .high { color: #c586c0; }
        .medium { color: #dcdcaa; }
        .low { color: #4ec9b0; }
        .section { margin: 20px 0; padding: 10px; background: #252526; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #464647; padding: 8px; text-align: left; }
        th { background: #2d2d30; color: #569cd6; }
        tr:nth-child(even) { background: #2d2d30; }
        pre { background: #1e1e1e; padding: 10px; overflow-x: auto; }
        .alert-box { background: #5a1e1e; border: 2px solid #f44747; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Incident Response Report</h1>
    <div class="section">
        <h2>Summary</h2>
        <pre>$summary</pre>
    </div>
"@

    # Add alerts section
    $alertFiles = Get-ChildItem "$IncidentPath\ALERTS" -Filter "*.csv" -ErrorAction SilentlyContinue
    if ($alertFiles) {
        $html += "<div class='section'><h2>Critical Alerts</h2>"
        foreach ($file in $alertFiles) {
            $data = Import-Csv $file.FullName -ErrorAction SilentlyContinue
            if ($data) {
                $html += "<h3>$($file.BaseName)</h3><table>"
                $html += "<tr>"
                $data[0].PSObject.Properties.Name | ForEach-Object { $html += "<th>$_</th>" }
                $html += "</tr>"
                
                $data | Select-Object -First 10 | ForEach-Object {
                    $html += "<tr>"
                    $_.PSObject.Properties.Value | ForEach-Object { 
                        $val = if ($_.Length -gt 100) { $_.Substring(0,97) + "..." } else { $_ }
                        $html += "<td>$val</td>" 
                    }
                    $html += "</tr>"
                }
                $html += "</table>"
                if ($data.Count -gt 10) {
                    $html += "<p><i>... and $($data.Count - 10) more entries</i></p>"
                }
            }
        }
        $html += "</div>"
    }

    $html += @"
    <div class="section">
        <p>Generated: $(Get-Date)</p>
        <p>Full evidence: $IncidentPath</p>
    </div>
</body>
</html>
"@

    $html | Out-File $reportPath -Encoding UTF8
    Write-Host "Report saved to: $reportPath" -ForegroundColor $colors.Success
    Read-Host "Press Enter to continue"
}

# Main execution
Clear-Host
Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    INCIDENT RESPONSE RESULTS VIEWER v1.0                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $colors.Header

# Get incident path
$incidentPath = $Path
if (!$incidentPath -or !(Test-Path $incidentPath)) {
    $incidentPath = Find-IncidentDirs
}

if (!$incidentPath) {
    Write-Host "`nNo valid incident directory selected. Exiting." -ForegroundColor Red
    exit
}

# Start viewer
Show-IncidentData -IncidentPath $incidentPath

Write-Host "`nViewer closed." -ForegroundColor $colors.Info

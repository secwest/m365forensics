# INCIDENT RESPONSE DATA VIEWER v1.0
# Purpose: View and export data collected by the IR triage script
# No live data collection - only reads existing incident directories
# Usage: powershell -ExecutionPolicy Bypass -File .\IR_Viewer.ps1

param(
    [string]$Path = "",
    [int]$PageSize = 25
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "IR Data Viewer"

# Colors
$colors = @{
    Header = "Cyan"
    Critical = "Red"
    High = "Magenta"
    Medium = "Yellow" 
    Low = "Green"
    Info = "White"
    Data = "Gray"
    Menu = "DarkCyan"
}

# Display header
function Show-Header {
    param([string]$Title = "INCIDENT RESPONSE DATA VIEWER")
    Clear-Host
    Write-Host ("=" * 80) -ForegroundColor $colors.Header
    Write-Host $Title.PadLeft(40 + ($Title.Length / 2)) -ForegroundColor $colors.Header
    Write-Host ("=" * 80) -ForegroundColor $colors.Header
    Write-Host ""
}

# Find incident directories
function Select-IncidentDirectory {
    Show-Header "SELECT INCIDENT DIRECTORY"
    
    # Look for incident directories in current path and common locations
    $searchPaths = @(
        (Get-Location).Path,
        "C:\",
        "D:\",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents"
    )
    
    $allIncidents = @()
    Write-Host "Searching for incident directories..." -ForegroundColor $colors.Info
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $incidents = Get-ChildItem -Path $searchPath -Filter "incident_*" -Directory -ErrorAction SilentlyContinue
            if ($incidents) {
                $allIncidents += $incidents
            }
        }
    }
    
    if ($allIncidents.Count -eq 0) {
        Write-Host "`nNo incident directories found!" -ForegroundColor $colors.Critical
        Write-Host "Please ensure you're in the correct location or specify path with -Path parameter" -ForegroundColor $colors.Info
        Read-Host "`nPress Enter to exit"
        return $null
    }
    
    # Remove duplicates and sort by date
    $allIncidents = $allIncidents | Sort-Object -Property FullName -Unique | Sort-Object CreationTime -Descending
    
    Write-Host "`nFound $($allIncidents.Count) incident directories:" -ForegroundColor $colors.Info
    Write-Host ""
    
    # Display incidents
    for ($i = 0; $i -lt $allIncidents.Count; $i++) {
        $inc = $allIncidents[$i]
        
        # Get threat level from summary if available
        $threatLevel = "Unknown"
        $summaryPath = Join-Path $inc.FullName "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $threatLine = Get-Content $summaryPath | Select-String "THREAT LEVEL:" | Select-Object -First 1
            if ($threatLine) {
                $threatLevel = $threatLine.Line.Split(":")[1].Trim()
            }
        }
        
        $threatColor = switch ($threatLevel) {
            "CRITICAL" { $colors.Critical }
            "HIGH" { $colors.High }
            "MEDIUM" { $colors.Medium }
            "LOW" { $colors.Low }
            default { $colors.Data }
        }
        
        Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline
        Write-Host ("{0,-30}" -f $inc.Name) -NoNewline
        Write-Host " [$threatLevel]" -ForegroundColor $threatColor
        Write-Host ("     Path: {0}" -f $inc.FullName) -ForegroundColor $colors.Data
    }
    
    Write-Host ""
    $selection = Read-Host "Select incident number (1-$($allIncidents.Count)) or Q to quit"
    
    if ($selection -match '^[Qq]') {
        return $null
    }
    
    if ($selection -match '^\d+$') {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $allIncidents.Count) {
            return $allIncidents[$index].FullName
        }
    }
    
    Write-Host "Invalid selection!" -ForegroundColor $colors.Critical
    Start-Sleep -Seconds 2
    return Select-IncidentDirectory
}

# Read and format CSV files
function Show-CsvFile {
    param([string]$FilePath)
    
    try {
        Write-Host "Loading CSV data..." -ForegroundColor $colors.Info
        $data = Import-Csv $FilePath
        
        if ($data.Count -eq 0) {
            return @("No data in CSV file")
        }
        
        $output = @()
        $output += "CSV File: $(Split-Path $FilePath -Leaf)"
        $output += "Total Records: $($data.Count)"
        $output += "Columns: $($data[0].PSObject.Properties.Name -join ', ')"
        $output += ("=" * 60)
        $output += ""
        
        # Ask if user wants to filter
        if ($data.Count -gt 50) {
            Write-Host "Large dataset detected. Options:" -ForegroundColor $colors.Info
            Write-Host "1. View all records" -ForegroundColor $colors.Menu
            Write-Host "2. View first 50 records" -ForegroundColor $colors.Menu
            Write-Host "3. Search/filter records" -ForegroundColor $colors.Menu
            Write-Host "4. View summary only" -ForegroundColor $colors.Menu
            
            $viewChoice = Read-Host "Select option (1-4)"
            
            switch ($viewChoice) {
                "2" { $data = $data | Select-Object -First 50 }
                "3" {
                    Write-Host "Available columns:" -ForegroundColor $colors.Info
                    $data[0].PSObject.Properties.Name | ForEach-Object { Write-Host "  - $_" -ForegroundColor $colors.Data }
                    
                    $column = Read-Host "Enter column name to search"
                    $searchValue = Read-Host "Enter search value (supports wildcards)"
                    
                    $data = $data | Where-Object { $_.$column -like "*$searchValue*" }
                    $output += "Filtered Results: $($data.Count) records matching '$searchValue' in column '$column'"
                    $output += ""
                }
                "4" {
                    # Just show summary statistics
                    $output += "Summary Statistics:"
                    foreach ($prop in $data[0].PSObject.Properties.Name) {
                        $values = $data.$prop | Where-Object { $_ -ne "" }
                        $unique = $values | Select-Object -Unique
                        $output += ""
                        $output += "Column: $prop"
                        $output += "  - Non-empty values: $($values.Count)"
                        $output += "  - Unique values: $($unique.Count)"
                        if ($unique.Count -le 10 -and $unique.Count -gt 0) {
                            $output += "  - Values: $($unique -join ', ')"
                        }
                    }
                    return $output
                }
            }
        }
        
        # Format each record
        $recordNum = 1
        foreach ($record in $data) {
            $output += "───── Record #$recordNum ─────"
            foreach ($prop in $record.PSObject.Properties) {
                if ($prop.Value) {
                    # Truncate long values
                    $value = if ($prop.Value.Length -gt 100) {
                        $prop.Value.Substring(0, 97) + "..."
                    } else {
                        $prop.Value
                    }
                    $output += "  $($prop.Name): $value"
                }
            }
            $output += ""
            $recordNum++
        }
        
        if ($viewChoice -eq "2") {
            $output += "... Showing first 50 records of $($data.Count) total"
        }
        
        return $output
    }
    catch {
        return @("Error reading CSV: $_")
    }
}

# Read and format JSON files
function Show-JsonFile {
    param([string]$FilePath)
    
    try {
        $jsonContent = Get-Content $FilePath -Raw
        $jsonObject = $jsonContent | ConvertFrom-Json
        
        # Convert to formatted string
        $formatted = $jsonObject | ConvertTo-Json -Depth 10
        return $formatted -split "`n"
    }
    catch {
        return @("Error reading JSON: $_")
    }
}

# Parse event log files (.evtx)
function Show-EventLog {
    param([string]$FilePath)
    
    Write-Host "Loading event log..." -ForegroundColor $colors.Info
    
    try {
        # Get total event count first
        $totalEvents = (Get-WinEvent -Path $FilePath -MaxEvents 1 -Oldest -ErrorAction Stop | Measure-Object).Count
        
        # Ask user how many events to load
        Write-Host "Event log contains events. How many would you like to view?" -ForegroundColor $colors.Info
        Write-Host "1. First 100 events (newest)" -ForegroundColor $colors.Menu
        Write-Host "2. Last 100 events (oldest)" -ForegroundColor $colors.Menu
        Write-Host "3. First 500 events" -ForegroundColor $colors.Menu
        Write-Host "4. All events (may take time for large logs)" -ForegroundColor $colors.Menu
        Write-Host "5. Custom range" -ForegroundColor $colors.Menu
        
        $choice = Read-Host "Select option (1-5)"
        
        $events = switch ($choice) {
            "1" { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
            "2" { Get-WinEvent -Path $FilePath -MaxEvents 100 -Oldest -ErrorAction Stop }
            "3" { Get-WinEvent -Path $FilePath -MaxEvents 500 -ErrorAction Stop }
            "4" { 
                Write-Host "WARNING: Loading all events may use significant memory for large logs!" -ForegroundColor $colors.High
                $confirm = Read-Host "Continue? (Y/N)"
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    Write-Host "Loading all events... This may take several minutes." -ForegroundColor $colors.Info
                    Get-WinEvent -Path $FilePath -ErrorAction Stop 
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            "5" {
                $maxEvents = Read-Host "Enter number of events to load"
                if ($maxEvents -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            $lineNum = "{0,6}: " -f ($i + 1)
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Low
            }
            elseif ($line -match "===== Event #\d+ =====") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Header
            }
            elseif ($line -match "^Time:|^Level:|^Source:|^ID:|^Computer:|^User:") {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Info
            }
            else {
                Write-Host $lineNum -NoNewline -ForegroundColor $colors.Menu
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]rev [F]irst [L]ast [G]oto page [J]ump to line [S]earch [E]xport [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "G" {
                $goto = Read-Host "Enter page number (1-$totalPages)"
                if ($goto -match '^\d+

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. View IOCs (if available)" -ForegroundColor $colors.Menu
        Write-Host "9. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "0. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Show-IOCs -IncidentPath $IncidentPath }
            "9" { Browse-Files -IncidentPath $IncidentPath }
            "0" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view, A for analysis summary, or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^[Aa]') {
            # Quick analysis of all event logs
            Show-EventLogSummary -LogsPath $logsPath
        }
        elseif ($choice -match '^\d+

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Show IOCs
function Show-IOCs {
    param([string]$IncidentPath)
    
    $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
    
    if (!(Test-Path $iocFile)) {
        Write-Host "No IOC file found (quick_iocs.json)" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    try {
        $iocContent = Get-Content $iocFile -Raw
        $iocs = $iocContent | ConvertFrom-Json
        
        $output = @()
        $output += "INDICATORS OF COMPROMISE (IOCs)"
        $output += "="*60
        $output += ""
        
        if ($iocs.SuspiciousIPs -and $iocs.SuspiciousIPs.Count -gt 0) {
            $output += "SUSPICIOUS IP ADDRESSES:"
            $output += "-"*40
            foreach ($ip in $iocs.SuspiciousIPs) {
                $output += "  • $ip"
            }
            $output += ""
        }
        
        if ($iocs.SuspiciousProcesses -and $iocs.SuspiciousProcesses.Count -gt 0) {
            $output += "SUSPICIOUS PROCESSES:"
            $output += "-"*40
            foreach ($proc in $iocs.SuspiciousProcesses) {
                $output += "  • $proc"
            }
            $output += ""
        }
        
        if ($iocs.SuspiciousFiles -and $iocs.SuspiciousFiles.Count -gt 0) {
            $output += "SUSPICIOUS FILES:"
            $output += "-"*40
            foreach ($file in $iocs.SuspiciousFiles) {
                $output += "  • $file"
            }
            $output += ""
        }
        
        if ($iocs.PersistenceLocations -and $iocs.PersistenceLocations.Count -gt 0) {
            $output += "PERSISTENCE LOCATIONS:"
            $output += "-"*40
            foreach ($pers in $iocs.PersistenceLocations) {
                if ($pers.Location -and $pers.Name) {
                    $output += "  • Location: $($pers.Location)"
                    $output += "    Name: $($pers.Name)"
                    if ($pers.Value) {
                        $output += "    Value: $($pers.Value)"
                    }
                    $output += ""
                }
            }
        }
        
        Show-PagedContent -Content $output -Title "IOCs"
    }
    catch {
        Write-Host "Error parsing IOC file: $_" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all readable data to a comprehensive text file." -ForegroundColor $colors.Info
    Write-Host "Large event logs will be summarized to prevent excessive file size." -ForegroundColor $colors.Info
    Write-Host ""
    
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "Export Tool: IR Data Viewer v1.0"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    $totalFiles = 0
    $skippedFiles = 0
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
                $totalFiles++
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "SIZE: $([Math]::Round($file.Length/1KB, 2)) KB"
                    $output += "-"*60
                    
                    # Special handling for event logs
                    if ($file.Extension -eq ".evtx") {
                        $output += "Event log file - Summary only (full parsing requires Windows Event Log service)"
                        $output += "To view full events, use the interactive viewer on a Windows system"
                        $skippedFiles++
                    }
                    else {
                        $content = Show-FileContent -FilePath $file.FullName
                        $output += $content
                        $totalFiles++
                    }
                }
            }
        }
    }
    
    # Add file inventory
    $output += ""
    $output += "="*80
    $output += "FILE INVENTORY"
    $output += "="*80
    
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    $output += "Total Files: $($allFiles.Count)"
    $output += "Total Size: $([Math]::Round((($allFiles | Measure-Object Length -Sum).Sum/1MB), 2)) MB"
    $output += ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.FullName.Replace($IncidentPath, "").TrimStart("\")
        $output += "$relPath ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "Files exported: $totalFiles" -ForegroundColor $colors.Info
    Write-Host "Files skipped: $skippedFiles (event logs)" -ForegroundColor $colors.Info
    Write-Host "Export saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Export size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info
Write-Host ""
Write-Host "Features used:" -ForegroundColor $colors.Header
Write-Host "  • View collected incident response data" -ForegroundColor $colors.Data
Write-Host "  • Parse CSV, JSON, TXT, and LOG files" -ForegroundColor $colors.Data
Write-Host "  • Navigate event logs (Windows systems)" -ForegroundColor $colors.Data
Write-Host "  • Search and filter large datasets" -ForegroundColor $colors.Data
Write-Host "  • Export comprehensive text reports" -ForegroundColor $colors.Data
Write-Host "") {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    $pageNum = [int]$goto - 1
                    if ($pageNum -ge 0 -and $pageNum -lt $totalPages) {
                        $currentPage = $pageNum
                    }
                }
            }
            "J" {
                $jumpLine = Read-Host "Enter line number (1-$($Content.Count))"
                if ($jumpLine -match '^\d+
                $searchTerm = Read-Host "Enter search term"
                if ($searchTerm) {
                    Write-Host "Searching..." -ForegroundColor $colors.Info
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        if ($Content[$i] -match [regex]::Escape($searchTerm)) {
                            $matches += "Line $($i+1): $($Content[$i])"
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Write-Host "Found $($matches.Count) matches" -ForegroundColor $colors.Info
                        Read-Host "Press Enter to view"
                        Show-PagedContent -Content $matches -Title "Search Results: '$searchTerm'"
                    } else {
                        Write-Host "No matches found" -ForegroundColor $colors.High
                        Start-Sleep -Seconds 2
                    }
                }
            }
            "E" {
                $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $Content | Out-File $exportPath -Encoding UTF8
                Write-Host "Exported to: $exportPath" -ForegroundColor $colors.Low
                Start-Sleep -Seconds 2
            }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Event log summary analysis
function Show-EventLogSummary {
    param([string]$LogsPath)
    
    Write-Host "Analyzing event logs..." -ForegroundColor $colors.Info
    $summary = @()
    $summary += "EVENT LOG SUMMARY ANALYSIS"
    $summary += "="*60
    $summary += ""
    
    $evtxFiles = Get-ChildItem $LogsPath -Filter "*.evtx"
    
    foreach ($file in $evtxFiles) {
        $summary += "Log: $($file.Name)"
        $summary += "Size: $([Math]::Round($file.Length/1MB, 2)) MB"
        
        try {
            # Try to get basic stats
            $events = Get-WinEvent -Path $file.FullName -MaxEvents 1000 -ErrorAction Stop
            
            $errorCount = ($events | Where-Object { $_.Level -eq 2 }).Count
            $warningCount = ($events | Where-Object { $_.Level -eq 3 }).Count
            $infoCount = ($events | Where-Object { $_.Level -eq 4 }).Count
            
            $summary += "Sample of 1000 events:"
            $summary += "  - Errors: $errorCount"
            $summary += "  - Warnings: $warningCount"
            $summary += "  - Information: $infoCount"
            
            # Get time range
            $oldest = $events | Select-Object -Last 1
            $newest = $events | Select-Object -First 1
            $summary += "  - Time range: $($oldest.TimeCreated) to $($newest.TimeCreated)"
            
            # Common event IDs
            $commonIds = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
            $summary += "  - Common Event IDs:"
            foreach ($id in $commonIds) {
                $summary += "    - ID $($id.Name): $($id.Count) occurrences"
            }
        }
        catch {
            $summary += "  - Unable to parse on this system"
        }
        
        $summary += ""
    }
    
    Show-PagedContent -Content $summary -Title "EVENT LOG SUMMARY"
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    $pageNum = [int]$goto - 1
                    if ($pageNum -ge 0 -and $pageNum -lt $totalPages) {
                        $currentPage = $pageNum
                    }
                }
            }
            "S" {
                $searchTerm = Read-Host "Enter search term"
                if ($searchTerm) {
                    Write-Host "Searching..." -ForegroundColor $colors.Info
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        if ($Content[$i] -match [regex]::Escape($searchTerm)) {
                            $matches += "Line $($i+1): $($Content[$i])"
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Write-Host "Found $($matches.Count) matches" -ForegroundColor $colors.Info
                        Read-Host "Press Enter to view"
                        Show-PagedContent -Content $matches -Title "Search Results: '$searchTerm'"
                    } else {
                        Write-Host "No matches found" -ForegroundColor $colors.High
                        Start-Sleep -Seconds 2
                    }
                }
            }
            "E" {
                $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $Content | Out-File $exportPath -Encoding UTF8
                Write-Host "Exported to: $exportPath" -ForegroundColor $colors.Low
                Start-Sleep -Seconds 2
            }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    $lineNum = [int]$jumpLine - 1
                    if ($lineNum -ge 0 -and $lineNum -lt $Content.Count) {
                        # Calculate which page contains this line
                        $currentPage = [Math]::Floor($lineNum / $PageSize)
                    }
                }
            }
            "S" {
                $searchTerm = Read-Host "Enter search term"
                if ($searchTerm) {
                    Write-Host "Searching..." -ForegroundColor $colors.Info
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        if ($Content[$i] -match [regex]::Escape($searchTerm)) {
                            $matches += "Line $($i+1): $($Content[$i])"
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Write-Host "Found $($matches.Count) matches" -ForegroundColor $colors.Info
                        Read-Host "Press Enter to view"
                        Show-PagedContent -Content $matches -Title "Search Results: '$searchTerm'"
                    } else {
                        Write-Host "No matches found" -ForegroundColor $colors.High
                        Start-Sleep -Seconds 2
                    }
                }
            }
            "E" {
                $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $Content | Out-File $exportPath -Encoding UTF8
                Write-Host "Exported to: $exportPath" -ForegroundColor $colors.Low
                Start-Sleep -Seconds 2
            }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Event log summary analysis
function Show-EventLogSummary {
    param([string]$LogsPath)
    
    Write-Host "Analyzing event logs..." -ForegroundColor $colors.Info
    $summary = @()
    $summary += "EVENT LOG SUMMARY ANALYSIS"
    $summary += "="*60
    $summary += ""
    
    $evtxFiles = Get-ChildItem $LogsPath -Filter "*.evtx"
    
    foreach ($file in $evtxFiles) {
        $summary += "Log: $($file.Name)"
        $summary += "Size: $([Math]::Round($file.Length/1MB, 2)) MB"
        
        try {
            # Try to get basic stats
            $events = Get-WinEvent -Path $file.FullName -MaxEvents 1000 -ErrorAction Stop
            
            $errorCount = ($events | Where-Object { $_.Level -eq 2 }).Count
            $warningCount = ($events | Where-Object { $_.Level -eq 3 }).Count
            $infoCount = ($events | Where-Object { $_.Level -eq 4 }).Count
            
            $summary += "Sample of 1000 events:"
            $summary += "  - Errors: $errorCount"
            $summary += "  - Warnings: $warningCount"
            $summary += "  - Information: $infoCount"
            
            # Get time range
            $oldest = $events | Select-Object -Last 1
            $newest = $events | Select-Object -First 1
            $summary += "  - Time range: $($oldest.TimeCreated) to $($newest.TimeCreated)"
            
            # Common event IDs
            $commonIds = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
            $summary += "  - Common Event IDs:"
            foreach ($id in $commonIds) {
                $summary += "    - ID $($id.Name): $($id.Count) occurrences"
            }
        }
        catch {
            $summary += "  - Unable to parse on this system"
        }
        
        $summary += ""
    }
    
    Show-PagedContent -Content $summary -Title "EVENT LOG SUMMARY"
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    $pageNum = [int]$goto - 1
                    if ($pageNum -ge 0 -and $pageNum -lt $totalPages) {
                        $currentPage = $pageNum
                    }
                }
            }
            "S" {
                $searchTerm = Read-Host "Enter search term"
                if ($searchTerm) {
                    Write-Host "Searching..." -ForegroundColor $colors.Info
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        if ($Content[$i] -match [regex]::Escape($searchTerm)) {
                            $matches += "Line $($i+1): $($Content[$i])"
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Write-Host "Found $($matches.Count) matches" -ForegroundColor $colors.Info
                        Read-Host "Press Enter to view"
                        Show-PagedContent -Content $matches -Title "Search Results: '$searchTerm'"
                    } else {
                        Write-Host "No matches found" -ForegroundColor $colors.High
                        Start-Sleep -Seconds 2
                    }
                }
            }
            "E" {
                $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $Content | Out-File $exportPath -Encoding UTF8
                Write-Host "Exported to: $exportPath" -ForegroundColor $colors.Low
                Start-Sleep -Seconds 2
            }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                    Get-WinEvent -Path $FilePath -MaxEvents ([int]$maxEvents) -ErrorAction Stop
                } else {
                    Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop
                }
            }
            default { Get-WinEvent -Path $FilePath -MaxEvents 100 -ErrorAction Stop }
        }
        
        Write-Host "Processing $($events.Count) events..." -ForegroundColor $colors.Info
        
        $output = @()
        $output += "Event Log: $(Split-Path $FilePath -Leaf)"
        $output += "Total Events Loaded: $($events.Count)"
        $output += ("=" * 60)
        $output += ""
        
        # Add filter option
        Write-Host "Filter events? (Y/N)" -NoNewline -ForegroundColor $colors.Info
        $filter = Read-Host
        
        if ($filter -eq 'Y' -or $filter -eq 'y') {
            Write-Host "Filter by:" -ForegroundColor $colors.Menu
            Write-Host "1. Error/Critical only" -ForegroundColor $colors.Menu
            Write-Host "2. Specific Event ID" -ForegroundColor $colors.Menu
            Write-Host "3. Time range" -ForegroundColor $colors.Menu
            Write-Host "4. No filter" -ForegroundColor $colors.Menu
            
            $filterChoice = Read-Host "Select filter (1-4)"
            
            $events = switch ($filterChoice) {
                "1" { $events | Where-Object { $_.Level -le 2 } }
                "2" {
                    $eventId = Read-Host "Enter Event ID"
                    if ($eventId -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $events | Where-Object { $_.Id -eq [int]$eventId }
                    } else { $events }
                }
                "3" {
                    $hours = Read-Host "Events from last X hours"
                    if ($hours -match '^\d+

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info) {
                        $cutoff = (Get-Date).AddHours(-[int]$hours)
                        $events | Where-Object { $_.TimeCreated -gt $cutoff }
                    } else { $events }
                }
                default { $events }
            }
            
            $output += "Filtered Events: $($events.Count)"
            $output += ""
        }
        
        # Format events
        $eventNum = 1
        foreach ($event in $events) {
            $output += "===== Event #$eventNum ====="
            $output += "Time: $($event.TimeCreated)"
            $output += "Level: $($event.LevelDisplayName) | ID: $($event.Id)"
            $output += "Source: $($event.ProviderName)"
            $output += "Computer: $($event.MachineName)"
            
            if ($event.UserId) {
                $output += "User: $($event.UserId)"
            }
            
            if ($event.Message) {
                # Option to show full or truncated messages
                $output += "Message:"
                $output += $event.Message -split "`n" | ForEach-Object { "  $_" }
            }
            
            $output += ""
            $eventNum++
        }
        
        return $output
    }
    catch {
        $output = @()
        $output += "Unable to parse event log on this system."
        $output += "Event logs can only be viewed on Windows systems with appropriate permissions."
        $output += ""
        $output += "Error: $_"
        $output += ""
        $output += "Raw file location: $FilePath"
        $output += "File size: $([Math]::Round((Get-Item $FilePath).Length/1MB, 2)) MB"
        
        return $output
    }
}

# Display file content based on type
function Show-FileContent {
    param([string]$FilePath)
    
    if (!(Test-Path $FilePath)) {
        return @("File not found: $FilePath")
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        ".csv" { return Show-CsvFile -FilePath $FilePath }
        ".json" { return Show-JsonFile -FilePath $FilePath }
        ".evtx" { return Show-EventLog -FilePath $FilePath }
        ".txt" { return Get-Content $FilePath }
        ".log" { return Get-Content $FilePath }
        default { return @("Cannot display file type: $extension") }
    }
}

# Paged display
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title
    )
    
    if ($Content.Count -eq 0) {
        Write-Host "No content to display" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    $currentPage = 0
    
    while ($true) {
        Show-Header $Title
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display page content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            $line = $Content[$i]
            
            # Color coding based on content
            if ($line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS") {
                Write-Host $line -ForegroundColor $colors.Low
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]revious [F]irst [L]ast [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch ($key.ToUpper()) {
            "N" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "P" { if ($currentPage -gt 0) { $currentPage-- } }
            "F" { $currentPage = 0 }
            "L" { $currentPage = $totalPages - 1 }
            "Q" { return }
        }
    }
}

# Main menu for incident data
function Show-IncidentMenu {
    param([string]$IncidentPath)
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident info
        $incidentName = Split-Path $IncidentPath -Leaf
        Write-Host "Incident: $incidentName" -ForegroundColor $colors.Info
        Write-Host "Path: $IncidentPath" -ForegroundColor $colors.Data
        
        # Get summary info if available
        $summaryPath = Join-Path $IncidentPath "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryLines = Get-Content $summaryPath | Select-String "THREAT LEVEL:|TOTAL ALERTS:"
            foreach ($line in $summaryLines) {
                if ($line -match "THREAT LEVEL:") {
                    $level = $line.Line.Split(":")[1].Trim()
                    $color = switch ($level) {
                        "CRITICAL" { $colors.Critical }
                        "HIGH" { $colors.High }
                        "MEDIUM" { $colors.Medium }
                        "LOW" { $colors.Low }
                        default { $colors.Data }
                    }
                    Write-Host $line.Line -ForegroundColor $color
                }
                else {
                    Write-Host $line.Line -ForegroundColor $colors.Info
                }
            }
        }
        
        Write-Host ""
        Write-Host "MAIN MENU" -ForegroundColor $colors.Header
        Write-Host "1. View Summary" -ForegroundColor $colors.Menu
        Write-Host "2. View Alerts" -ForegroundColor $colors.Menu
        Write-Host "3. Network Data" -ForegroundColor $colors.Menu
        Write-Host "4. Process Data" -ForegroundColor $colors.Menu
        Write-Host "5. Persistence Data" -ForegroundColor $colors.Menu
        Write-Host "6. System Information" -ForegroundColor $colors.Menu
        Write-Host "7. Event Logs" -ForegroundColor $colors.Menu
        Write-Host "8. Browse All Files" -ForegroundColor $colors.Menu
        Write-Host "9. Export All to Text" -ForegroundColor $colors.Menu
        Write-Host "Q. Back to Directory Selection" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Show-Alerts -IncidentPath $IncidentPath }
            "3" { Show-NetworkData -IncidentPath $IncidentPath }
            "4" { Show-ProcessData -IncidentPath $IncidentPath }
            "5" { Show-PersistenceData -IncidentPath $IncidentPath }
            "6" { Show-SystemInfo -IncidentPath $IncidentPath }
            "7" { Show-EventLogs -IncidentPath $IncidentPath }
            "8" { Browse-Files -IncidentPath $IncidentPath }
            "9" { Export-AllData -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
        }
    }
}

# Show summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        Show-PagedContent -Content $content -Title "INCIDENT SUMMARY"
    }
    else {
        Write-Host "Summary file not found" -ForegroundColor $colors.Critical
        Read-Host "Press Enter to continue"
    }
}

# Show alerts
function Show-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-Host "No alerts directory found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "ALERTS"
        
        $files = Get-ChildItem $alertsPath -File | Sort-Object Name
        if ($files.Count -eq 0) {
            Write-Host "No alert files found" -ForegroundColor $colors.Info
            Read-Host "Press Enter to continue"
            return
        }
        
        Write-Host "Alert Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.High
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "ALERT: $($files[$index].Name)"
            }
        }
    }
}

# Show network data
function Show-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-Host "No network data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK DATA"
        
        $files = Get-ChildItem $networkPath -File | Sort-Object Name
        
        Write-Host "Network Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "NETWORK: $($files[$index].Name)"
            }
        }
    }
}

# Show process data
function Show-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    $files = @()
    
    # Check both Processes folder and ALERTS for process files
    if (Test-Path $processPath) {
        $files += Get-ChildItem $processPath -File
    }
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*process*" -File
        $files += Get-ChildItem $alertsPath -Filter "*pid*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No process data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PROCESS DATA"
        
        Write-Host "Process Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PROCESS: $($files[$index].Name)"
            }
        }
    }
}

# Show persistence data
function Show-PersistenceData {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    $files = @()
    
    if (Test-Path $persistPath) {
        $files += Get-ChildItem $persistPath -File
    }
    
    # Also check ALERTS for persistence files
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $files += Get-ChildItem $alertsPath -Filter "*autorun*" -File
        $files += Get-ChildItem $alertsPath -Filter "*service*" -File
        $files += Get-ChildItem $alertsPath -Filter "*task*" -File
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No persistence data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "PERSISTENCE DATA"
        
        Write-Host "Persistence Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].DirectoryName -match "ALERTS") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "PERSISTENCE: $($files[$index].Name)"
            }
        }
    }
}

# Show system info
function Show-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    if (!(Test-Path $systemPath)) {
        Write-Host "No system data found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $files = Get-ChildItem $systemPath -File | Sort-Object Name
        
        Write-Host "System Files:" -ForegroundColor $colors.Header
        for ($i = 0; $i -lt $files.Count; $i++) {
            Write-Host ("{0,3}. {1}" -f ($i + 1), $files[$i].Name) -ForegroundColor $colors.Menu
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "SYSTEM: $($files[$index].Name)"
            }
        }
    }
}

# Show event logs
function Show-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-Host "No event logs found" -ForegroundColor $colors.Info
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOGS"
        
        $files = Get-ChildItem $logsPath -File | Sort-Object Name
        
        Write-Host "Event Log Files:" -ForegroundColor $colors.Header
        Write-Host "(Note: .evtx files can only be parsed on Windows systems)" -ForegroundColor $colors.Data
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $color = if ($files[$i].Extension -eq ".evtx") { $colors.High } else { $colors.Menu }
            Write-Host ("{0,3}. {1} ({2:N2} MB)" -f ($i + 1), $files[$i].Name, ($files[$i].Length/1MB)) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^[Qq]') { return }
        
        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                $content = Show-FileContent -FilePath $files[$index].FullName
                Show-PagedContent -Content $content -Title "LOG: $($files[$index].Name)"
            }
        }
    }
}

# Browse all files
function Browse-Files {
    param([string]$IncidentPath)
    
    Show-Header "FILE BROWSER"
    
    Write-Host "Building file list..." -ForegroundColor $colors.Info
    $allFiles = Get-ChildItem $IncidentPath -Recurse -File | Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $relPath = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        
        if ($relPath -ne $currentDir) {
            $fileList += ""
            $fileList += "[$relPath]"
            $currentDir = $relPath
        }
        
        $fileList += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Export all data to text
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT ALL DATA"
    
    Write-Host "This will export all data to a single text file." -ForegroundColor $colors.Info
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $output = @()
    
    # Header
    $output += "="*80
    $output += "INCIDENT RESPONSE DATA EXPORT"
    $output += "="*80
    $output += "Generated: $(Get-Date)"
    $output += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $output += "Path: $IncidentPath"
    $output += "="*80
    $output += ""
    
    Write-Host "Exporting data..." -ForegroundColor $colors.Info
    
    # Process each directory
    $directories = @(
        @{Name="SUMMARY"; Path="SUMMARY.txt"; Type="File"},
        @{Name="ALERTS"; Path="ALERTS"; Type="Directory"},
        @{Name="NETWORK"; Path="Network"; Type="Directory"},
        @{Name="PROCESSES"; Path="Processes"; Type="Directory"},
        @{Name="PERSISTENCE"; Path="Persistence"; Type="Directory"},
        @{Name="SYSTEM"; Path="System"; Type="Directory"},
        @{Name="LOGS"; Path="Logs"; Type="Directory"}
    )
    
    foreach ($dir in $directories) {
        Write-Host "  Exporting $($dir.Name)..." -ForegroundColor $colors.Data
        
        $fullPath = Join-Path $IncidentPath $dir.Path
        
        if (Test-Path $fullPath) {
            $output += ""
            $output += "="*80
            $output += $dir.Name
            $output += "="*80
            
            if ($dir.Type -eq "File") {
                $output += Get-Content $fullPath
            }
            else {
                $files = Get-ChildItem $fullPath -File | Sort-Object Name
                foreach ($file in $files) {
                    $output += ""
                    $output += "-"*60
                    $output += "FILE: $($file.Name)"
                    $output += "-"*60
                    
                    $content = Show-FileContent -FilePath $file.FullName
                    $output += $content
                }
            }
        }
    }
    
    # Save export
    $output | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor $colors.Low
    Write-Host "File saved to: $exportFile" -ForegroundColor $colors.Info
    Write-Host "Size: $([Math]::Round((Get-Item $exportFile).Length/1MB, 2)) MB" -ForegroundColor $colors.Data
    Write-Host ""
    
    $open = Read-Host "Open file now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    Read-Host "Press Enter to continue"
}

# Main execution
Show-Header

Write-Host "This viewer displays data collected by the Incident Response Triage Script" -ForegroundColor $colors.Info
Write-Host "No live data collection will be performed" -ForegroundColor $colors.Info
Write-Host ""

# Main loop
while ($true) {
    $incidentPath = $Path
    
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    Show-IncidentMenu -IncidentPath $incidentPath
    
    # Reset path to show selection menu again
    $Path = ""
}

Write-Host ""
Write-Host "Thank you for using IR Data Viewer" -ForegroundColor $colors.Info

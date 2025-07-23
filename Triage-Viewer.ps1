# COMPREHENSIVE INCIDENT RESPONSE VIEWER v3.0
# Combines all features: Event log parsing, JSON formatting, HTML reports, detailed alerts
# Usage: powershell -ExecutionPolicy Bypass -File .\IR_Viewer.ps1

param(
    [string]$Path = "",
    [int]$PageSize = 20,
    [switch]$AutoExport = $false,
    [switch]$GenerateHTML = $false
)

# Initialize
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "Incident Response Viewer v3.0"
$global:exportContent = @()
$global:currentIncident = ""

# Enhanced color scheme
$colors = @{
    Title = "Cyan"
    Critical = "Red"
    High = "Magenta"
    Medium = "Yellow"
    Low = "Green"
    Success = "Green"
    Info = "Cyan"
    Menu = "White"
    Data = "Gray"
    Header = "Yellow"
    Progress = "DarkCyan"
    Alert = "Red"
    Warning = "DarkYellow"
}

# Header function with box drawing
function Show-Header {
    param([string]$Title = "INCIDENT RESPONSE VIEWER v3.0")
    Clear-Host
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $colors.Title
    Write-Host "║$(' ' * 79)║" -ForegroundColor $colors.Title
    Write-Host "║$($Title.PadLeft(40 + ($Title.Length / 2)).PadRight(79))║" -ForegroundColor $colors.Title
    Write-Host "║$(' ' * 79)║" -ForegroundColor $colors.Title
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $colors.Title
    Write-Host ""
}

# Enhanced color output helper
function Write-ColorOutput {
    param($Message, $Type = "Info", $NoNewLine = $false)
    
    $color = switch ($Type) {
        "Success" { $colors.Success }
        "Error" { $colors.Critical }
        "Warning" { $colors.Warning }
        "Alert" { $colors.Alert }
        "Info" { $colors.Info }
        "Progress" { $colors.Progress }
        "Menu" { $colors.Menu }
        "Data" { $colors.Data }
        default { "White" }
    }
    
    if ($NoNewLine) {
        Write-Host $Message -ForegroundColor $color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $color
    }
}

# Find and list incident directories with detailed info
function Select-IncidentDirectory {
    Show-Header "SELECT INCIDENT DIRECTORY"
    
    # Search multiple locations
    $searchPaths = @("C:\", "D:\", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:TEMP")
    $allIncidents = @()
    
    Write-ColorOutput "Searching for incident directories..." "Progress"
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            Write-Host "." -NoNewline -ForegroundColor $colors.Progress
            $incidents = Get-ChildItem -Path $searchPath -Filter "incident_*" -Directory -ErrorAction SilentlyContinue -Depth 2
            if ($incidents) {
                $allIncidents += $incidents
            }
        }
    }
    
    Write-Host ""
    
    if ($allIncidents.Count -eq 0) {
        Write-ColorOutput "`nNo incident directories found!" "Error"
        Write-ColorOutput "Searched in: $($searchPaths -join ', ')" "Data"
        Read-Host "`nPress Enter to exit"
        return $null
    }
    
    # Sort by date (newest first) and remove duplicates
    $allIncidents = $allIncidents | Sort-Object CreationTime -Descending | Select-Object -Unique
    
    Write-ColorOutput "`nFound $($allIncidents.Count) incident directories:" "Success"
    Write-Host ""
    
    # Create detailed incident list
    $incidentDetails = @()
    
    foreach ($inc in $allIncidents) {
        Write-Host "." -NoNewline -ForegroundColor $colors.Progress
        
        $details = [PSCustomObject]@{
            Path = $inc.FullName
            Name = $inc.Name
            Created = $inc.CreationTime
            ThreatLevel = "Unknown"
            AlertCount = 0
            SizeMB = 0
            HasAlerts = $false
            HasNetwork = $false
            HasLogs = $false
        }
        
        # Get threat level and alerts from summary
        $summaryPath = Join-Path $inc.FullName "SUMMARY.txt"
        if (Test-Path $summaryPath) {
            $summaryContent = Get-Content $summaryPath -ErrorAction SilentlyContinue
            $threatLine = $summaryContent | Select-String "THREAT LEVEL:" | Select-Object -First 1
            if ($threatLine) {
                $details.ThreatLevel = $threatLine.Line.Split(":")[1].Trim()
            }
            $alertLine = $summaryContent | Select-String "TOTAL ALERTS:" | Select-Object -First 1
            if ($alertLine) {
                $details.AlertCount = [int]($alertLine.Line.Split(":")[1].Trim())
            }
        }
        
        # Check for key directories
        $details.HasAlerts = Test-Path (Join-Path $inc.FullName "ALERTS")
        $details.HasNetwork = Test-Path (Join-Path $inc.FullName "Network")
        $details.HasLogs = Test-Path (Join-Path $inc.FullName "Logs")
        
        # Calculate size
        try {
            $details.SizeMB = [Math]::Round((Get-ChildItem $inc.FullName -Recurse -File | Measure-Object Length -Sum).Sum/1MB, 2)
        } catch {
            $details.SizeMB = 0
        }
        
        $incidentDetails += $details
    }
    
    Write-Host "`n"
    
    # Display incidents with enhanced formatting
    Write-Host "  #  Incident Name                    Threat     Alerts  Size      Created" -ForegroundColor $colors.Header
    Write-Host "  ─  ────────────────────────────────  ─────────  ──────  ────────  ────────────────" -ForegroundColor $colors.Menu
    
    for ($i = 0; $i -lt $incidentDetails.Count; $i++) {
        $inc = $incidentDetails[$i]
        
        # Determine color based on threat level
        $threatColor = switch ($inc.ThreatLevel) {
            "CRITICAL" { $colors.Critical }
            "HIGH" { $colors.High }
            "MEDIUM" { $colors.Medium }
            "LOW" { $colors.Low }
            default { $colors.Data }
        }
        
        # Format line
        Write-Host ("{0,3}  " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
        Write-Host ("{0,-32}  " -f $inc.Name) -NoNewline -ForegroundColor $colors.Info
        Write-Host ("{0,-9}  " -f $inc.ThreatLevel) -NoNewline -ForegroundColor $threatColor
        Write-Host ("{0,6}  " -f $inc.AlertCount) -NoNewline -ForegroundColor $(if($inc.AlertCount -gt 0){$colors.Warning}else{$colors.Data})
        Write-Host ("{0,6}MB  " -f $inc.SizeMB) -NoNewline -ForegroundColor $colors.Data
        Write-Host ("{0}" -f $inc.Created.ToString("yyyy-MM-dd HH:mm")) -ForegroundColor $colors.Data
        
        # Show indicators
        if ($inc.HasAlerts -or $inc.HasNetwork -or $inc.HasLogs) {
            Write-Host "     └─ " -NoNewline -ForegroundColor $colors.Menu
            if ($inc.HasAlerts) { Write-Host "[ALERTS]" -NoNewline -ForegroundColor $colors.Alert }
            if ($inc.HasNetwork) { Write-Host "[NETWORK]" -NoNewline -ForegroundColor $colors.Info }
            if ($inc.HasLogs) { Write-Host "[LOGS]" -NoNewline -ForegroundColor $colors.Warning }
            Write-Host ""
        }
    }
    
    Write-Host "`n" -NoNewline
    $selection = Read-Host "Select incident number (1-$($incidentDetails.Count)) or Q to quit"
    
    if ($selection -eq 'Q' -or $selection -eq 'q') {
        return $null
    }
    
    $index = 0
    if ([int]::TryParse($selection, [ref]$index)) {
        $index--
        if ($index -ge 0 -and $index -lt $incidentDetails.Count) {
            return $incidentDetails[$index].Path
        }
    }
    
    Write-ColorOutput "Invalid selection!" "Error"
    Start-Sleep -Seconds 2
    return Select-IncidentDirectory
}

# Parse event log files with enhanced error handling
function Get-EventLogData {
    param([string]$EventFile)
    
    try {
        $events = @()
        Write-ColorOutput "Parsing event log: $(Split-Path $EventFile -Leaf)..." "Progress"
        
        # Try to read with Get-WinEvent
        $eventData = Get-WinEvent -Path $EventFile -MaxEvents 200 -ErrorAction Stop
        
        foreach ($event in $eventData) {
            $msg = if ($event.Message) {
                if ($event.Message.Length -gt 300) { 
                    $event.Message.Substring(0, 297) + "..." 
                } else { 
                    $event.Message 
                }
            } else {
                "No message available"
            }
            
            $events += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id = $event.Id
                Level = $event.LevelDisplayName
                Source = $event.ProviderName
                Message = $msg -replace "`r`n", " " -replace "`n", " "
                User = if($event.UserId) { $event.UserId.Value } else { "N/A" }
                Computer = $event.MachineName
            }
        }
        
        return $events
    }
    catch {
        # Try alternative method using wevtutil
        try {
            $tempXml = "$env:TEMP\temp_evt_$(Get-Random).xml"
            $null = wevtutil qe /lf:$EventFile /f:XML /e:Events /c:50 > $tempXml
            
            if (Test-Path $tempXml) {
                [xml]$xmlContent = Get-Content $tempXml
                Remove-Item $tempXml -Force
                
                $events = @()
                foreach ($evt in $xmlContent.Events.Event) {
                    $events += [PSCustomObject]@{
                        TimeCreated = $evt.System.TimeCreated.SystemTime
                        Id = $evt.System.EventID
                        Level = $evt.System.Level
                        Source = $evt.System.Provider.Name
                        Message = "Event data available in XML format"
                        User = "N/A"
                        Computer = $evt.System.Computer
                    }
                }
                return $events
            }
        }
        catch {
            # Final fallback
            return @([PSCustomObject]@{
                TimeCreated = "N/A"
                Id = "N/A"
                Level = "Error"
                Source = "Parser"
                Message = "Unable to parse event log file. Error: $_"
                User = "N/A"
                Computer = "N/A"
            })
        }
    }
}

# Format JSON for display with syntax highlighting
function Format-JsonData {
    param([string]$JsonFile)
    
    try {
        $jsonContent = Get-Content $JsonFile -Raw
        $jsonObject = $jsonContent | ConvertFrom-Json
        
        # Convert to formatted string with proper indentation
        $formatted = $jsonObject | ConvertTo-Json -Depth 10 | Out-String
        
        # Split into lines for paging
        return $formatted -split "`n"
    }
    catch {
        return @("Error parsing JSON: $_")
    }
}

# Enhanced CSV viewer with sorting and filtering
function Show-CsvData {
    param(
        [string]$FilePath,
        [string]$Title
    )
    
    if (!(Test-Path $FilePath)) {
        Write-ColorOutput "File not found: $FilePath" "Error"
        Read-Host "Press Enter to continue"
        return
    }
    
    $data = Import-Csv $FilePath -ErrorAction SilentlyContinue
    if (!$data -or $data.Count -eq 0) {
        Write-ColorOutput "No data in file or unable to parse CSV" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    # Get column names
    $columns = $data[0].PSObject.Properties.Name
    
    while ($true) {
        Show-Header "$Title - CSV Viewer"
        
        Write-ColorOutput "Total Records: $($data.Count)" "Info"
        Write-ColorOutput "Columns: $($columns -join ', ')" "Data"
        Write-Host ""
        
        # Format for display
        $formatted = @()
        $index = 1
        foreach ($row in $data) {
            $line = "[$index] "
            foreach ($col in $columns) {
                $val = $row.$col
                if ($val) {
                    $displayVal = if ($val.Length -gt 30) { $val.Substring(0, 27) + "..." } else { $val }
                    $line += "$col`: $displayVal | "
                }
            }
            $formatted += $line.TrimEnd(" | ")
            $index++
        }
        
        # Show paged content
        Show-PagedContent -Content $formatted -Title $Title -NoLineNumbers
        break
    }
}

# Enhanced paging function with search and export
function Show-PagedContent {
    param(
        [array]$Content,
        [string]$Title = "Content Viewer",
        [switch]$NoLineNumbers,
        [switch]$ColorCode
    )
    
    if ($Content.Count -eq 0) {
        Write-ColorOutput "No content to display" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    $currentPage = 0
    $totalPages = [Math]::Ceiling($Content.Count / $PageSize)
    
    while ($true) {
        Show-Header $Title
        
        Write-ColorOutput "Total items: $($Content.Count) | Page size: $PageSize" "Info"
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        
        $startIdx = $currentPage * $PageSize
        $endIdx = [Math]::Min($startIdx + $PageSize, $Content.Count)
        
        # Display content
        for ($i = $startIdx; $i -lt $endIdx; $i++) {
            if (!$NoLineNumbers) {
                Write-Host ("{0,4}: " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            }
            
            # Apply color coding based on content
            $line = $Content[$i]
            if ($ColorCode -or $line -match "CRITICAL|ERROR|FAIL") {
                Write-Host $line -ForegroundColor $colors.Critical
            }
            elseif ($line -match "WARNING|ALERT|SUSPICIOUS") {
                Write-Host $line -ForegroundColor $colors.High
            }
            elseif ($line -match "SUCCESS|PASS|ENABLED") {
                Write-Host $line -ForegroundColor $colors.Success
            }
            elseif ($line -match "INFO|INFORMATION") {
                Write-Host $line -ForegroundColor $colors.Info
            }
            else {
                Write-Host $line -ForegroundColor $colors.Data
            }
        }
        
        # Navigation bar
        Write-Host ""
        Write-Host ("-" * 80) -ForegroundColor $colors.Menu
        Write-Host "Page $($currentPage + 1) of $totalPages | " -NoNewline -ForegroundColor $colors.Info
        Write-Host "Showing items $($startIdx + 1)-$endIdx of $($Content.Count)" -ForegroundColor $colors.Info
        Write-Host "[N]ext [P]rev [F]irst [L]ast [G]oto [S]earch [E]xport [D]etails [Q]uit: " -NoNewline -ForegroundColor $colors.Menu
        
        $key = Read-Host
        
        switch -Regex ($key.ToUpper()) {
            "^N" { 
                if ($currentPage -lt $totalPages - 1) { 
                    $currentPage++ 
                } else {
                    Write-ColorOutput "Already on last page" "Warning"
                    Start-Sleep -Seconds 1
                }
            }
            "^P" { 
                if ($currentPage -gt 0) { 
                    $currentPage-- 
                } else {
                    Write-ColorOutput "Already on first page" "Warning"
                    Start-Sleep -Seconds 1
                }
            }
            "^F" { $currentPage = 0 }
            "^L" { $currentPage = $totalPages - 1 }
            "^G" {
                $goto = Read-Host "Go to page (1-$totalPages)"
                if ($goto -match '^\d+$') {
                    $pageNum = [int]$goto - 1
                    if ($pageNum -ge 0 -and $pageNum -lt $totalPages) {
                        $currentPage = $pageNum
                    } else {
                        Write-ColorOutput "Invalid page number" "Error"
                        Start-Sleep -Seconds 1
                    }
                }
            }
            "^S" {
                $search = Read-Host "Search for (regex supported)"
                if ($search) {
                    $matches = @()
                    for ($i = 0; $i -lt $Content.Count; $i++) {
                        if ($Content[$i] -match $search) {
                            $matches += "Line $($i + 1): $($Content[$i])"
                        }
                    }
                    if ($matches.Count -gt 0) {
                        Show-PagedContent -Content $matches -Title "Search Results for '$search' ($($matches.Count) matches)"
                    } else {
                        Write-ColorOutput "No matches found" "Warning"
                        Read-Host "Press Enter to continue"
                    }
                }
            }
            "^E" {
                $exportPath = "$env:TEMP\IR_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                @"
$Title
Exported: $(Get-Date)
Total Items: $($Content.Count)
$('='*80)

"@ + ($Content -join "`r`n") | Out-File $exportPath -Encoding UTF8
                Write-ColorOutput "Exported to: $exportPath" "Success"
                $open = Read-Host "Open in notepad? (Y/N)"
                if ($open -eq 'Y' -or $open -eq 'y') {
                    notepad.exe $exportPath
                }
            }
            "^D" {
                $detail = Read-Host "Enter line number for details"
                if ($detail -match '^\d+$') {
                    $lineNum = [int]$detail - 1
                    if ($lineNum -ge 0 -and $lineNum -lt $Content.Count) {
                        Show-Header "Line Detail"
                        Write-ColorOutput "Line $($lineNum + 1):" "Info"
                        Write-Host ""
                        Write-Host $Content[$lineNum] -ForegroundColor $colors.Data
                        Write-Host ""
                        
                        # If it's a path, offer to view the file
                        if ($Content[$lineNum] -match '([A-Z]:\\[^|]+\.(txt|csv|log|json))') {
                            $filePath = $matches[1]
                            if (Test-Path $filePath) {
                                $view = Read-Host "This appears to be a file path. View it? (Y/N)"
                                if ($view -eq 'Y' -or $view -eq 'y') {
                                    Show-FileContent -FilePath $filePath -Title "File Content"
                                    continue
                                }
                            }
                        }
                        
                        Read-Host "`nPress Enter to continue"
                    }
                }
            }
            "^Q" { return }
            "^\d+$" {
                # Direct line jump
                $lineNum = [int]$key - 1
                if ($lineNum -ge 0 -and $lineNum -lt $Content.Count) {
                    # Calculate which page this line is on
                    $targetPage = [Math]::Floor($lineNum / $PageSize)
                    $currentPage = $targetPage
                }
            }
        }
    }
}

# Display file content with appropriate formatting
function Show-FileContent {
    param(
        [string]$FilePath,
        [string]$Title,
        [switch]$ReturnContent
    )
    
    if (!(Test-Path $FilePath)) {
        Write-ColorOutput "File not found: $FilePath" "Error"
        if (!$ReturnContent) { Read-Host "Press Enter to continue" }
        return @()
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    $content = @()
    
    Write-ColorOutput "Processing $fileName..." "Progress"
    
    switch ($extension) {
        ".csv" {
            if ($ReturnContent) {
                # For export, return raw CSV data
                $content = Get-Content $FilePath
            } else {
                # For display, use the enhanced CSV viewer
                Show-CsvData -FilePath $FilePath -Title $Title
                return
            }
        }
        
        ".json" {
            $content = Format-JsonData -JsonFile $FilePath
        }
        
        ".evtx" {
            $events = Get-EventLogData -EventFile $FilePath
            $content = @()
            $content += "Event Log: $fileName"
            $content += "Total Events Shown: $($events.Count) (limited to most recent)"
            $content += "="*80
            $content += ""
            
            foreach ($evt in $events) {
                $content += "Time: $($evt.TimeCreated) | ID: $($evt.Id) | Level: $($evt.Level)"
                $content += "Source: $($evt.Source) | Computer: $($evt.Computer)"
                if ($evt.User -ne "N/A") {
                    $content += "User: $($evt.User)"
                }
                $content += "Message: $($evt.Message)"
                $content += "-"*60
            }
        }
        
        ".txt", ".log" {
            $content = Get-Content $FilePath -ErrorAction SilentlyContinue
        }
        
        ".xml" {
            try {
                [xml]$xmlContent = Get-Content $FilePath
                $content = $xmlContent.OuterXml -split "`n"
            } catch {
                $content = Get-Content $FilePath
            }
        }
        
        default {
            $content = @("Binary or unsupported file type: $extension")
            if (!$ReturnContent) {
                $size = (Get-Item $FilePath).Length
                $content += "File size: $([Math]::Round($size/1KB, 2)) KB"
            }
        }
    }
    
    if ($ReturnContent) {
        return $content
    }
    
    Show-PagedContent -Content $content -Title "$Title [$fileName]" -ColorCode
}

# Main incident browser with all features
function Browse-IncidentData {
    param([string]$IncidentPath)
    
    $global:currentIncident = $IncidentPath
    $incidentName = Split-Path $IncidentPath -Leaf
    
    # Load incident details once
    $incidentInfo = Get-IncidentInfo -Path $IncidentPath
    
    while ($true) {
        Show-Header "INCIDENT DATA BROWSER"
        
        # Display incident summary
        Write-Host "┌─ Incident Information ─────────────────────────────────────────────────────┐" -ForegroundColor $colors.Menu
        Write-Host "│ " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Name: $incidentName" "Info" -NoNewLine
        Write-Host (" " * (75 - $incidentName.Length)) -NoNewline
        Write-Host "│" -ForegroundColor $colors.Menu
        
        Write-Host "│ " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Threat Level: " "Menu" -NoNewLine
        $threatColor = switch ($incidentInfo.ThreatLevel) {
            "CRITICAL" { $colors.Critical }
            "HIGH" { $colors.High }
            "MEDIUM" { $colors.Medium }
            "LOW" { $colors.Low }
            default { $colors.Data }
        }
        Write-Host "$($incidentInfo.ThreatLevel)" -ForegroundColor $threatColor -NoNewline
        Write-Host (" " * (63 - $incidentInfo.ThreatLevel.Length)) -NoNewline
        Write-Host "│" -ForegroundColor $colors.Menu
        
        Write-Host "│ " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Total Alerts: $($incidentInfo.AlertCount)" "Data" -NoNewLine
        Write-Host (" " * (63 - $incidentInfo.AlertCount.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor $colors.Menu
        
        Write-Host "│ " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Collection Time: $($incidentInfo.CollectionTime)" "Data" -NoNewLine
        Write-Host (" " * (59 - $incidentInfo.CollectionTime.Length)) -NoNewline
        Write-Host "│" -ForegroundColor $colors.Menu
        
        Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor $colors.Menu
        Write-Host ""
        
        # Key findings if available
        if ($incidentInfo.KeyFindings.Count -gt 0) {
            Write-ColorOutput "Key Findings:" "Warning"
            $incidentInfo.KeyFindings | Select-Object -First 5 | ForEach-Object {
                Write-Host "  • $_" -ForegroundColor $colors.High
            }
            Write-Host ""
        }
        
        # Main menu
        Write-ColorOutput "MAIN MENU" "Header"
        Write-Host ("-" * 40) -ForegroundColor $colors.Menu
        Write-Host " 1. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "View Summary Report" "Menu"
        
        Write-Host " 2. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Browse ALERTS " "Critical" -NoNewLine
        Write-ColorOutput "(Critical Findings)" "Menu"
        
        Write-Host " 3. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Network Analysis" "Menu"
        
        Write-Host " 4. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Process Information" "Menu"
        
        Write-Host " 5. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Persistence Mechanisms" "Menu"
        
        Write-Host " 6. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Event Logs" "Menu"
        
        Write-Host " 7. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "System Information" "Menu"
        
        Write-Host " 8. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "IOCs (Indicators of Compromise)" "Menu"
        
        Write-Host " 9. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Browse All Files" "Menu"
        
        Write-Host "10. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Search Across All Files" "Menu"
        
        Write-Host "11. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Export Complete Report (Text)" "Success"
        
        Write-Host "12. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Generate HTML Report" "Success"
        
        Write-Host " Q. " -NoNewline -ForegroundColor $colors.Menu
        Write-ColorOutput "Back to Directory Selection" "Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-Summary -IncidentPath $IncidentPath }
            "2" { Browse-Alerts -IncidentPath $IncidentPath }
            "3" { Browse-NetworkData -IncidentPath $IncidentPath }
            "4" { Browse-ProcessData -IncidentPath $IncidentPath }
            "5" { Browse-Persistence -IncidentPath $IncidentPath }
            "6" { Browse-EventLogs -IncidentPath $IncidentPath }
            "7" { Browse-SystemInfo -IncidentPath $IncidentPath }
            "8" { Show-IOCs -IncidentPath $IncidentPath }
            "9" { Browse-AllFiles -RootPath $IncidentPath }
            "10" { Search-AllFiles -RootPath $IncidentPath }
            "11" { Export-AllData -IncidentPath $IncidentPath }
            "12" { Export-HtmlReport -IncidentPath $IncidentPath }
            "Q" { return }
            "q" { return }
            default {
                Write-ColorOutput "Invalid option" "Error"
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Get incident information
function Get-IncidentInfo {
    param([string]$Path)
    
    $info = [PSCustomObject]@{
        ThreatLevel = "Unknown"
        AlertCount = 0
        CollectionTime = "Unknown"
        KeyFindings = @()
        RemoteAccess = $false
        SuspiciousProcesses = 0
        NetworkConnections = 0
    }
    
    # Parse summary
    $summaryPath = Join-Path $Path "SUMMARY.txt"
    if (Test-Path $summaryPath) {
        $summary = Get-Content $summaryPath
        
        # Extract threat level
        $threatLine = $summary | Select-String "THREAT LEVEL:"
        if ($threatLine) {
            $info.ThreatLevel = $threatLine.Line.Split(":")[1].Trim()
        }
        
        # Extract alert count
        $alertLine = $summary | Select-String "TOTAL ALERTS:"
        if ($alertLine) {
            $info.AlertCount = [int]($alertLine.Line.Split(":")[1].Trim())
        }
        
        # Extract collection time
        $timeLine = $summary | Select-String "Collection Time:"
        if ($timeLine) {
            $info.CollectionTime = $timeLine.Line.Split(":", 2)[1].Trim()
        }
        
        # Extract key findings
        $findingsStart = ($summary | Select-String -Pattern "KEY FINDINGS:").LineNumber
        if ($findingsStart) {
            $findings = $summary[$findingsStart..($findingsStart + 20)] | Where-Object { $_ -match "^>" }
            $info.KeyFindings = $findings | ForEach-Object { $_.TrimStart(">").Trim() }
        }
    }
    
    return $info
}

# Show detailed summary
function Show-Summary {
    param([string]$IncidentPath)
    
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile
        
        # Color-code the summary
        $coloredContent = @()
        foreach ($line in $content) {
            $coloredContent += $line
        }
        
        Show-PagedContent -Content $coloredContent -Title "INCIDENT SUMMARY" -ColorCode
    } else {
        Write-ColorOutput "Summary file not found" "Error"
        Read-Host "Press Enter to continue"
    }
}

# Browse alerts with categorization
function Browse-Alerts {
    param([string]$IncidentPath)
    
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (!(Test-Path $alertsPath)) {
        Write-ColorOutput "No alerts directory found" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "CRITICAL ALERTS AND FINDINGS"
        
        $alertFiles = Get-ChildItem -Path $alertsPath -File -ErrorAction SilentlyContinue | Sort-Object Name
        
        if ($alertFiles.Count -eq 0) {
            Write-ColorOutput "No alert files found" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        # Categorize alerts
        $categories = @{
            "Suspicious Processes" = @()
            "Network Alerts" = @()
            "Persistence" = @()
            "Remote Access" = @()
            "IOCs" = @()
            "Other" = @()
        }
        
        foreach ($file in $alertFiles) {
            if ($file.Name -match "process|proc") { $categories["Suspicious Processes"] += $file }
            elseif ($file.Name -match "network|connection|ip") { $categories["Network Alerts"] += $file }
            elseif ($file.Name -match "persistence|autorun|service|task") { $categories["Persistence"] += $file }
            elseif ($file.Name -match "remote|rdp|teamviewer") { $categories["Remote Access"] += $file }
            elseif ($file.Name -match "ioc") { $categories["IOCs"] += $file }
            else { $categories["Other"] += $file }
        }
        
        # Display categorized alerts
        $fileIndex = 1
        $fileMap = @{}
        
        foreach ($category in $categories.Keys | Sort-Object) {
            if ($categories[$category].Count -gt 0) {
                Write-Host ""
                Write-ColorOutput "═══ $category ═══" "High"
                
                foreach ($file in $categories[$category]) {
                    $sizeKB = [Math]::Round($file.Length / 1KB, 2)
                    
                    Write-Host ("{0,3}. " -f $fileIndex) -NoNewline -ForegroundColor $colors.Menu
                    Write-Host ("{0,-40}" -f $file.Name) -NoNewline -ForegroundColor $colors.Alert
                    Write-Host (" {0,8} KB" -f $sizeKB) -ForegroundColor $colors.Data
                    
                    $fileMap[$fileIndex] = $file
                    $fileIndex++
                }
            }
        }
        
        Write-Host ""
        Write-Host "Enter file number to view (1-$($fileIndex-1)), A for all, or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -eq 'A' -or $selection -eq 'a') {
            # View all alerts in sequence
            foreach ($file in $alertFiles) {
                Show-FileContent -FilePath $file.FullName -Title "ALERT: $($file.Name)"
            }
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection
            if ($fileMap.ContainsKey($index)) {
                Show-FileContent -FilePath $fileMap[$index].FullName -Title "ALERT FILE"
            }
        }
    }
}

# Browse network data with analysis
function Browse-NetworkData {
    param([string]$IncidentPath)
    
    $networkPath = Join-Path $IncidentPath "Network"
    if (!(Test-Path $networkPath)) {
        Write-ColorOutput "No network data found" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "NETWORK ANALYSIS"
        
        # Quick network summary
        $connFile = Join-Path $networkPath "connections_basic.csv"
        if (Test-Path $connFile) {
            $connections = Import-Csv $connFile -ErrorAction SilentlyContinue
            if ($connections) {
                $established = @($connections | Where-Object {$_.State -eq "Established"})
                $listening = @($connections | Where-Object {$_.State -eq "Listen"})
                $external = @($established | Where-Object {
                    $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
                })
                
                Write-ColorOutput "Network Summary:" "Info"
                Write-Host "  Total Connections: $($connections.Count)" -ForegroundColor $colors.Data
                Write-Host "  Established: $($established.Count)" -ForegroundColor $colors.Data
                Write-Host "  Listening: $($listening.Count)" -ForegroundColor $colors.Data
                Write-Host "  External: $($external.Count)" -ForegroundColor $(if($external.Count -gt 0){$colors.Warning}else{$colors.Data})
                Write-Host ""
            }
        }
        
        Write-ColorOutput "Available Data:" "Header"
        Write-Host " 1. Network Connections (CSV)" -ForegroundColor $colors.Menu
        Write-Host " 2. External IPs List" -ForegroundColor $colors.Menu
        Write-Host " 3. DNS Cache" -ForegroundColor $colors.Menu
        Write-Host " 4. Active Sessions" -ForegroundColor $colors.Menu
        Write-Host " 5. Network Configuration" -ForegroundColor $colors.Menu
        Write-Host " 6. ARP Table" -ForegroundColor $colors.Menu
        Write-Host " 7. Routing Table" -ForegroundColor $colors.Menu
        Write-Host " 8. Open Ports (netstat)" -ForegroundColor $colors.Menu
        Write-Host " 9. View All Network Files" -ForegroundColor $colors.Menu
        Write-Host " Q. Back to Main Menu" -ForegroundColor $colors.Menu
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Show-FileContent -FilePath (Join-Path $networkPath "connections_basic.csv") -Title "Network Connections" }
            "2" { Show-FileContent -FilePath (Join-Path $networkPath "external_ips.txt") -Title "External IPs" }
            "3" { Show-FileContent -FilePath (Join-Path $networkPath "dns_cache.csv") -Title "DNS Cache" }
            "4" { Show-FileContent -FilePath (Join-Path $networkPath "active_sessions.txt") -Title "Active Sessions" }
            "5" { Show-FileContent -FilePath (Join-Path $networkPath "ipconfig.txt") -Title "Network Configuration" }
            "6" { Show-FileContent -FilePath (Join-Path $networkPath "arp.txt") -Title "ARP Table" }
            "7" { Show-FileContent -FilePath (Join-Path $networkPath "routes.txt") -Title "Routing Table" }
            "8" { Show-FileContent -FilePath (Join-Path $networkPath "netstat_full.txt") -Title "Open Ports (netstat)" }
            "9" { Browse-Directory -Path $networkPath -Title "ALL NETWORK FILES" }
            "Q" { return }
            "q" { return }
        }
    }
}

# Browse process data
function Browse-ProcessData {
    param([string]$IncidentPath)
    
    $processPath = Join-Path $IncidentPath "Processes"
    
    while ($true) {
        Show-Header "PROCESS ANALYSIS"
        
        # Check for process data in both locations
        $processFiles = @()
        if (Test-Path $processPath) {
            $processFiles += Get-ChildItem -Path $processPath -Filter "*.csv" -ErrorAction SilentlyContinue
        }
        
        # Also check ALERTS for process-related files
        $alertsPath = Join-Path $IncidentPath "ALERTS"
        if (Test-Path $alertsPath) {
            $processFiles += Get-ChildItem -Path $alertsPath -Filter "*process*.csv" -ErrorAction SilentlyContinue
            $processFiles += Get-ChildItem -Path $alertsPath -Filter "*shell*.csv" -ErrorAction SilentlyContinue
            $processFiles += Get-ChildItem -Path $alertsPath -Filter "*pid*.csv" -ErrorAction SilentlyContinue
        }
        
        if ($processFiles.Count -eq 0) {
            Write-ColorOutput "No process data found" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        Write-ColorOutput "Available Process Data:" "Header"
        for ($i = 0; $i -lt $processFiles.Count; $i++) {
            $file = $processFiles[$i]
            $location = if ($file.DirectoryName -match "ALERTS") { "[ALERT]" } else { "[DATA]" }
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            Write-Host ("{0,-40}" -f $file.Name) -NoNewline
            Write-Host (" {0}" -f $location) -ForegroundColor $(if($location -eq "[ALERT]"){$colors.Alert}else{$colors.Info})
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $processFiles.Count) {
                Show-FileContent -FilePath $processFiles[$index].FullName -Title "PROCESS DATA"
            }
        }
    }
}

# Browse persistence mechanisms
function Browse-Persistence {
    param([string]$IncidentPath)
    
    $persistPath = Join-Path $IncidentPath "Persistence"
    
    while ($true) {
        Show-Header "PERSISTENCE MECHANISMS"
        
        $persFiles = @()
        
        # Check main persistence folder
        if (Test-Path $persistPath) {
            $persFiles += Get-ChildItem -Path $persistPath -File -ErrorAction SilentlyContinue
        }
        
        # Check alerts for persistence-related files
        $alertsPath = Join-Path $IncidentPath "ALERTS"
        if (Test-Path $alertsPath) {
            $persFiles += Get-ChildItem -Path $alertsPath -Filter "*autorun*.csv" -ErrorAction SilentlyContinue
            $persFiles += Get-ChildItem -Path $alertsPath -Filter "*task*.csv" -ErrorAction SilentlyContinue
            $persFiles += Get-ChildItem -Path $alertsPath -Filter "*service*.csv" -ErrorAction SilentlyContinue
        }
        
        if ($persFiles.Count -eq 0) {
            Write-ColorOutput "No persistence data found" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        # Categorize persistence mechanisms
        Write-ColorOutput "Detected Persistence Mechanisms:" "Header"
        Write-Host ""
        
        $categories = @{
            "Registry Autoruns" = $persFiles | Where-Object {$_.Name -match "autorun|registry"}
            "Scheduled Tasks" = $persFiles | Where-Object {$_.Name -match "task"}
            "Services" = $persFiles | Where-Object {$_.Name -match "service"}
            "Other" = $persFiles | Where-Object {$_.Name -notmatch "autorun|registry|task|service"}
        }
        
        $fileIndex = 1
        $fileMap = @{}
        
        foreach ($cat in $categories.Keys | Sort-Object) {
            if ($categories[$cat].Count -gt 0) {
                Write-ColorOutput "─ $cat ─" "Warning"
                foreach ($file in $categories[$cat]) {
                    Write-Host ("{0,3}. " -f $fileIndex) -NoNewline -ForegroundColor $colors.Menu
                    Write-Host $file.Name -ForegroundColor $colors.High
                    $fileMap[$fileIndex] = $file
                    $fileIndex++
                }
                Write-Host ""
            }
        }
        
        Write-Host "Enter file number to view or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection
            if ($fileMap.ContainsKey($index)) {
                Show-FileContent -FilePath $fileMap[$index].FullName -Title "PERSISTENCE DATA"
            }
        }
    }
}

# Browse event logs
function Browse-EventLogs {
    param([string]$IncidentPath)
    
    $logsPath = Join-Path $IncidentPath "Logs"
    if (!(Test-Path $logsPath)) {
        Write-ColorOutput "No event logs found" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header "EVENT LOG ANALYSIS"
        
        $logFiles = Get-ChildItem -Path $logsPath -Filter "*.evtx" -ErrorAction SilentlyContinue | Sort-Object Name
        
        if ($logFiles.Count -eq 0) {
            Write-ColorOutput "No event log files found" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        Write-ColorOutput "Available Event Logs:" "Header"
        Write-Host ""
        
        for ($i = 0; $i -lt $logFiles.Count; $i++) {
            $file = $logFiles[$i]
            $sizeMB = [Math]::Round($file.Length / 1MB, 2)
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            Write-Host ("{0,-30}" -f $file.Name) -NoNewline
            
            # Color based on log type
            $color = switch ($file.Name) {
                "Security.evtx" { $colors.High }
                "System.evtx" { $colors.Warning }
                "Application.evtx" { $colors.Info }
                "PowerShell.evtx" { $colors.Alert }
                default { $colors.Data }
            }
            
            Write-Host (" {0,8} MB" -f $sizeMB) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter log number to view, A for analysis summary, or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -eq 'A' -or $selection -eq 'a') {
            # Quick analysis of all logs
            Show-EventLogSummary -LogsPath $logsPath
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $logFiles.Count) {
                Show-FileContent -FilePath $logFiles[$index].FullName -Title "EVENT LOG"
            }
        }
    }
}

# Show event log summary
function Show-EventLogSummary {
    param([string]$LogsPath)
    
    Show-Header "EVENT LOG SUMMARY ANALYSIS"
    Write-ColorOutput "Analyzing event logs..." "Progress"
    
    $summary = @()
    $logFiles = Get-ChildItem -Path $LogsPath -Filter "*.evtx"
    
    foreach ($logFile in $logFiles) {
        Write-Host "." -NoNewline -ForegroundColor $colors.Progress
        
        $events = Get-EventLogData -EventFile $logFile.FullName
        
        $summary += ""
        $summary += "═══ $($logFile.Name) ═══"
        $summary += "Total Events Analyzed: $($events.Count)"
        
        # Group by level
        $levels = $events | Group-Object Level | Sort-Object Name
        $summary += "Event Levels:"
        foreach ($level in $levels) {
            $summary += "  - $($level.Name): $($level.Count)"
        }
        
        # Find critical events
        $critical = $events | Where-Object {$_.Level -match "Error|Critical|Warning"}
        if ($critical) {
            $summary += ""
            $summary += "Critical Events (last 5):"
            $critical | Select-Object -Last 5 | ForEach-Object {
                $summary += "  [$($_.TimeCreated)] $($_.Source): $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))"
            }
        }
        
        # Security specific analysis
        if ($logFile.Name -eq "Security.evtx") {
            $logons = $events | Where-Object {$_.Id -eq 4624}
            $failedLogons = $events | Where-Object {$_.Id -eq 4625}
            $summary += ""
            $summary += "Security Analysis:"
            $summary += "  - Successful Logons: $($logons.Count)"
            $summary += "  - Failed Logons: $($failedLogons.Count)"
        }
    }
    
    Write-Host ""
    Show-PagedContent -Content $summary -Title "EVENT LOG SUMMARY" -ColorCode
}

# Browse system information
function Browse-SystemInfo {
    param([string]$IncidentPath)
    
    $systemPath = Join-Path $IncidentPath "System"
    
    while ($true) {
        Show-Header "SYSTEM INFORMATION"
        
        $sysFiles = @()
        if (Test-Path $systemPath) {
            $sysFiles = Get-ChildItem -Path $systemPath -File -ErrorAction SilentlyContinue | Sort-Object Name
        }
        
        if ($sysFiles.Count -eq 0) {
            Write-ColorOutput "No system information found" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        Write-ColorOutput "Available System Information:" "Header"
        Write-Host ""
        
        for ($i = 0; $i -lt $sysFiles.Count; $i++) {
            $file = $sysFiles[$i]
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            
            # Add descriptions
            $description = switch -Wildcard ($file.Name) {
                "basic_info.txt" { "System Overview" }
                "defender_status.csv" { "Windows Defender Status" }
                "firewall_status.csv" { "Firewall Configuration" }
                default { "" }
            }
            
            Write-Host ("{0,-30}" -f $file.Name) -NoNewline
            if ($description) {
                Write-Host (" - $description") -ForegroundColor $colors.Data
            } else {
                Write-Host ""
            }
        }
        
        Write-Host ""
        Write-Host "Enter file number to view or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $sysFiles.Count) {
                Show-FileContent -FilePath $sysFiles[$index].FullName -Title "SYSTEM INFO"
            }
        }
    }
}

# Show IOCs
function Show-IOCs {
    param([string]$IncidentPath)
    
    $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
    
    if (!(Test-Path $iocFile)) {
        Write-ColorOutput "No IOC file found" "Warning"
        Read-Host "Press Enter to continue"
        return
    }
    
    Show-Header "INDICATORS OF COMPROMISE (IOCs)"
    
    try {
        $iocs = Get-Content $iocFile | ConvertFrom-Json
        $content = @()
        
        if ($iocs.SuspiciousIPs -and $iocs.SuspiciousIPs.Count -gt 0) {
            $content += "═══ SUSPICIOUS IP ADDRESSES ═══"
            foreach ($ip in $iocs.SuspiciousIPs) {
                $content += "  • $ip"
            }
            $content += ""
        }
        
        if ($iocs.SuspiciousProcesses -and $iocs.SuspiciousProcesses.Count -gt 0) {
            $content += "═══ SUSPICIOUS PROCESSES ═══"
            foreach ($proc in $iocs.SuspiciousProcesses) {
                $content += "  • $proc"
            }
            $content += ""
        }
        
        if ($iocs.SuspiciousFiles -and $iocs.SuspiciousFiles.Count -gt 0) {
            $content += "═══ SUSPICIOUS FILES ═══"
            foreach ($file in $iocs.SuspiciousFiles) {
                $content += "  • $file"
            }
            $content += ""
        }
        
        if ($iocs.PersistenceLocations -and $iocs.PersistenceLocations.Count -gt 0) {
            $content += "═══ PERSISTENCE LOCATIONS ═══"
            foreach ($pers in $iocs.PersistenceLocations) {
                $content += "  • $($pers.Name) at $($pers.Location)"
                if ($pers.Value) {
                    $content += "    Value: $($pers.Value)"
                }
            }
            $content += ""
        }
        
        Show-PagedContent -Content $content -Title "INDICATORS OF COMPROMISE" -ColorCode
        
    } catch {
        Write-ColorOutput "Error parsing IOC file: $_" "Error"
        Read-Host "Press Enter to continue"
    }
}

# Browse all files recursively
function Browse-AllFiles {
    param([string]$RootPath)
    
    Show-Header "FILE BROWSER"
    Write-ColorOutput "Building file tree..." "Progress"
    
    $allFiles = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | 
                Sort-Object DirectoryName, Name
    
    $fileList = @()
    $currentDir = ""
    
    foreach ($file in $allFiles) {
        $dir = $file.DirectoryName.Replace($RootPath, "").TrimStart("\")
        if ($dir -ne $currentDir) {
            $fileList += ""
            $fileList += "[$dir]"
            $currentDir = $dir
        }
        
        $sizeKB = [Math]::Round($file.Length / 1KB, 2)
        $fileList += "  $($file.Name) ($sizeKB KB)"
    }
    
    Show-PagedContent -Content $fileList -Title "ALL FILES ($($allFiles.Count) total)"
}

# Enhanced search across all files
function Search-AllFiles {
    param([string]$RootPath)
    
    Show-Header "SEARCH ALL FILES"
    
    Write-Host "Search Options:" -ForegroundColor $colors.Header
    Write-Host "1. Search file contents (text files only)" -ForegroundColor $colors.Menu
    Write-Host "2. Search file names" -ForegroundColor $colors.Menu
    Write-Host "3. Search by file extension" -ForegroundColor $colors.Menu
    Write-Host "4. Search by date modified" -ForegroundColor $colors.Menu
    Write-Host "Q. Cancel" -ForegroundColor $colors.Menu
    Write-Host ""
    
    $searchType = Read-Host "Select search type"
    
    switch ($searchType) {
        "1" {
            $searchTerm = Read-Host "Enter search term (regex supported)"
            if (!$searchTerm) { return }
            
            Write-ColorOutput "Searching file contents..." "Progress"
            $results = @()
            $fileCount = 0
            
            Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_
                $fileCount++
                
                if ($fileCount % 10 -eq 0) {
                    Write-Host "." -NoNewline -ForegroundColor $colors.Progress
                }
                
                # Skip binary files
                if ($file.Extension -match "\.(exe|dll|sys|evtx|bin|zip)$") { return }
                
                try {
                    $matches = Select-String -Path $file.FullName -Pattern $searchTerm -ErrorAction Stop
                    foreach ($match in $matches) {
                        $relativePath = $file.FullName.Replace($RootPath, "").TrimStart("\")
                        $results += "$relativePath : Line $($match.LineNumber) : $($match.Line.Trim())"
                    }
                }
                catch {
                    # Skip files that can't be read
                }
            }
            
            Write-Host ""
            
            if ($results.Count -eq 0) {
                Write-ColorOutput "No matches found" "Warning"
                Read-Host "Press Enter to continue"
            } else {
                Show-PagedContent -Content $results -Title "SEARCH RESULTS: '$searchTerm' ($($results.Count) matches)"
            }
        }
        
        "2" {
            $searchTerm = Read-Host "Enter file name pattern (wildcards supported)"
            if (!$searchTerm) { return }
            
            $files = Get-ChildItem -Path $RootPath -Recurse -Filter $searchTerm -File -ErrorAction SilentlyContinue
            
            if ($files.Count -eq 0) {
                Write-ColorOutput "No files found matching '$searchTerm'" "Warning"
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | ForEach-Object {
                    $relativePath = $_.FullName.Replace($RootPath, "").TrimStart("\")
                    "$relativePath ($([Math]::Round($_.Length/1KB, 2)) KB) - Modified: $($_.LastWriteTime)"
                }
                Show-PagedContent -Content $results -Title "FILES MATCHING: '$searchTerm' ($($files.Count) found)"
            }
        }
        
        "3" {
            $extension = Read-Host "Enter file extension (e.g., csv, txt, log)"
            if (!$extension) { return }
            
            $extension = if ($extension.StartsWith(".")) { $extension } else { ".$extension" }
            
            $files = Get-ChildItem -Path $RootPath -Recurse -Filter "*$extension" -File -ErrorAction SilentlyContinue
            
            if ($files.Count -eq 0) {
                Write-ColorOutput "No files found with extension '$extension'" "Warning"
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | ForEach-Object {
                    $relativePath = $_.FullName.Replace($RootPath, "").TrimStart("\")
                    "$relativePath ($([Math]::Round($_.Length/1KB, 2)) KB)"
                }
                Show-PagedContent -Content $results -Title "FILES WITH EXTENSION: '$extension' ($($files.Count) found)"
            }
        }
        
        "4" {
            $days = Read-Host "Files modified in the last X days"
            if (!$days -or !($days -match '^\d+$')) { return }
            
            $cutoffDate = (Get-Date).AddDays(-[int]$days)
            
            $files = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | 
                     Where-Object { $_.LastWriteTime -gt $cutoffDate }
            
            if ($files.Count -eq 0) {
                Write-ColorOutput "No files modified in the last $days days" "Warning"
                Read-Host "Press Enter to continue"
            } else {
                $results = $files | Sort-Object LastWriteTime -Descending | ForEach-Object {
                    $relativePath = $_.FullName.Replace($RootPath, "").TrimStart("\")
                    "$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) - $relativePath"
                }
                Show-PagedContent -Content $results -Title "FILES MODIFIED IN LAST $days DAYS ($($files.Count) found)"
            }
        }
        
        "Q", "q" { return }
    }
}

# Export all data to comprehensive text file
function Export-AllData {
    param([string]$IncidentPath)
    
    Show-Header "EXPORT COMPLETE REPORT"
    
    Write-ColorOutput "This will export all readable incident data to a comprehensive text report." "Info"
    Write-ColorOutput "The process may take several minutes for large incidents." "Warning"
    Write-Host ""
    
    $confirm = Read-Host "Continue with export? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') { return }
    
    $exportFile = Join-Path $IncidentPath "IR_Complete_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $exportContent = @()
    
    # Header
    $exportContent += "="*80
    $exportContent += "COMPREHENSIVE INCIDENT RESPONSE REPORT"
    $exportContent += "="*80
    $exportContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $exportContent += "Incident: $(Split-Path $IncidentPath -Leaf)"
    $exportContent += "Full Path: $IncidentPath"
    $exportContent += "Report Generator: IR Viewer v3.0"
    $exportContent += "="*80
    $exportContent += ""
    
    # Progress tracking
    $totalSteps = 10
    $currentStep = 0
    
    # Function to update progress
    $updateProgress = {
        param($step, $message)
        $script:currentStep++
        $percent = [Math]::Round(($script:currentStep / $totalSteps) * 100)
        Write-Host "`r[$percent%] $message" -NoNewline -ForegroundColor $colors.Progress
    }
    
    # 1. Summary
    & $updateProgress 1 "Exporting summary..."
    $summaryFile = Join-Path $IncidentPath "SUMMARY.txt"
    if (Test-Path $summaryFile) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "EXECUTIVE SUMMARY"
        $exportContent += "="*80
        $exportContent += Get-Content $summaryFile
    }
    
    # 2. Critical Alerts
    & $updateProgress 2 "Exporting alerts..."
    $alertsPath = Join-Path $IncidentPath "ALERTS"
    if (Test-Path $alertsPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "CRITICAL ALERTS AND FINDINGS"
        $exportContent += "="*80
        
        $alertFiles = Get-ChildItem -Path $alertsPath -File -ErrorAction SilentlyContinue | Sort-Object Name
        foreach ($file in $alertFiles) {
            $exportContent += ""
            $exportContent += "-"*60
            $exportContent += "ALERT FILE: $($file.Name)"
            $exportContent += "-"*60
            
            $content = Show-FileContent -FilePath $file.FullName -Title "Export" -ReturnContent
            $exportContent += $content
        }
    }
    
    # 3. Network Analysis
    & $updateProgress 3 "Exporting network data..."
    $networkPath = Join-Path $IncidentPath "Network"
    if (Test-Path $networkPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "NETWORK ANALYSIS"
        $exportContent += "="*80
        
        # Key network files
        $netFiles = @(
            @{Name="connections_basic.csv"; Title="Network Connections"},
            @{Name="external_ips.txt"; Title="External IP Addresses"},
            @{Name="dns_cache.csv"; Title="DNS Cache"},
            @{Name="active_sessions.txt"; Title="Active Sessions"},
            @{Name="ipconfig.txt"; Title="Network Configuration"}
        )
        
        foreach ($netFile in $netFiles) {
            $filePath = Join-Path $networkPath $netFile.Name
            if (Test-Path $filePath) {
                $exportContent += ""
                $exportContent += "-"*60
                $exportContent += $netFile.Title
                $exportContent += "-"*60
                $content = Show-FileContent -FilePath $filePath -Title "Export" -ReturnContent
                $exportContent += $content
            }
        }
    }
    
    # 4. Process Information
    & $updateProgress 4 "Exporting process data..."
    $processPath = Join-Path $IncidentPath "Processes"
    if (Test-Path $processPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "PROCESS ANALYSIS"
        $exportContent += "="*80
        
        $procFiles = Get-ChildItem -Path $processPath -File -ErrorAction SilentlyContinue
        foreach ($file in $procFiles) {
            $exportContent += ""
            $exportContent += "-"*60
            $exportContent += "PROCESS FILE: $($file.Name)"
            $exportContent += "-"*60
            $content = Show-FileContent -FilePath $file.FullName -Title "Export" -ReturnContent
            $exportContent += $content
        }
    }
    
    # 5. Persistence Mechanisms
    & $updateProgress 5 "Exporting persistence data..."
    $persistPath = Join-Path $IncidentPath "Persistence"
    if (Test-Path $persistPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "PERSISTENCE MECHANISMS"
        $exportContent += "="*80
        
        $persFiles = Get-ChildItem -Path $persistPath -File -ErrorAction SilentlyContinue
        foreach ($file in $persFiles) {
            $exportContent += ""
            $exportContent += "-"*60
            $exportContent += "PERSISTENCE: $($file.Name)"
            $exportContent += "-"*60
            $content = Show-FileContent -FilePath $file.FullName -Title "Export" -ReturnContent
            $exportContent += $content
        }
    }
    
    # 6. System Information
    & $updateProgress 6 "Exporting system info..."
    $systemPath = Join-Path $IncidentPath "System"
    if (Test-Path $systemPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "SYSTEM INFORMATION"
        $exportContent += "="*80
        
        $sysFiles = Get-ChildItem -Path $systemPath -File -ErrorAction SilentlyContinue
        foreach ($file in $sysFiles) {
            $exportContent += ""
            $exportContent += "-"*60
            $exportContent += "SYSTEM: $($file.Name)"
            $exportContent += "-"*60
            $content = Show-FileContent -FilePath $file.FullName -Title "Export" -ReturnContent
            $exportContent += $content
        }
    }
    
    # 7. Event Logs Summary
    & $updateProgress 7 "Parsing event logs..."
    $logsPath = Join-Path $IncidentPath "Logs"
    if (Test-Path $logsPath) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "EVENT LOG ANALYSIS"
        $exportContent += "="*80
        
        $logFiles = Get-ChildItem -Path $logsPath -Filter "*.evtx" -ErrorAction SilentlyContinue
        foreach ($logFile in $logFiles) {
            Write-Host "." -NoNewline -ForegroundColor $colors.Progress
            
            $exportContent += ""
            $exportContent += "-"*60
            $exportContent += "EVENT LOG: $($logFile.Name)"
            $exportContent += "-"*60
            
            $events = Get-EventLogData -EventFile $logFile.FullName
            $exportContent += "Total Events Parsed: $($events.Count) (showing most recent)"
            $exportContent += ""
            
            # Group by criticality
            $critical = $events | Where-Object {$_.Level -match "Error|Critical"}
            $warning = $events | Where-Object {$_.Level -eq "Warning"}
            
            if ($critical) {
                $exportContent += "CRITICAL/ERROR Events:"
                $critical | Select-Object -First 20 | ForEach-Object {
                    $exportContent += "[$($_.TimeCreated)] ID:$($_.Id) - $($_.Source): $($_.Message)"
                }
                $exportContent += ""
            }
            
            if ($warning) {
                $exportContent += "WARNING Events:"
                $warning | Select-Object -First 10 | ForEach-Object {
                    $exportContent += "[$($_.TimeCreated)] ID:$($_.Id) - $($_.Source): $($_.Message)"
                }
            }
        }
    }
    
    # 8. IOCs
    & $updateProgress 8 "Exporting IOCs..."
    $iocFile = Join-Path $IncidentPath "ALERTS\quick_iocs.json"
    if (Test-Path $iocFile) {
        $exportContent += ""
        $exportContent += "="*80
        $exportContent += "INDICATORS OF COMPROMISE (IOCs)"
        $exportContent += "="*80
        
        try {
            $iocs = Get-Content $iocFile | ConvertFrom-Json
            $exportContent += $iocs | ConvertTo-Json -Depth 10
        }
        catch {
            $exportContent += "Error parsing IOCs: $_"
        }
    }
    
    # 9. File listing
    & $updateProgress 9 "Creating file inventory..."
    $exportContent += ""
    $exportContent += "="*80
    $exportContent += "COMPLETE FILE INVENTORY"
    $exportContent += "="*80
    
    $allFiles = Get-ChildItem -Path $IncidentPath -Recurse -File -ErrorAction SilentlyContinue | 
                Sort-Object DirectoryName, Name
    
    $exportContent += "Total Files Collected: $($allFiles.Count)"
    $exportContent += "Total Size: $([Math]::Round((($allFiles | Measure-Object Length -Sum).Sum / 1MB), 2)) MB"
    $exportContent += ""
    
    $currentDir = ""
    foreach ($file in $allFiles) {
        $dir = $file.DirectoryName.Replace($IncidentPath, "").TrimStart("\")
        if ($dir -ne $currentDir) {
            $exportContent += ""
            $exportContent += "[$dir]"
            $currentDir = $dir
        }
        $exportContent += "  $($file.Name) ($([Math]::Round($file.Length/1KB, 2)) KB) - Modified: $($file.LastWriteTime)"
    }
    
    # 10. Save the export
    & $updateProgress 10 "Saving report..."
    Write-Host ""
    
    $exportContent | Out-File -FilePath $exportFile -Encoding UTF8
    
    # Summary
    $fileInfo = Get-Item $exportFile
    Write-Host ""
    Write-ColorOutput "Export completed successfully!" "Success"
    Write-ColorOutput "Report saved to: $exportFile" "Info"
    Write-ColorOutput "Report size: $([Math]::Round($fileInfo.Length / 1MB, 2)) MB" "Info"
    Write-ColorOutput "Total lines: $($exportContent.Count)" "Info"
    Write-Host ""
    
    $open = Read-Host "Open the report now? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        notepad.exe $exportFile
    }
    
    $compress = Read-Host "Create compressed archive? (Y/N)"
    if ($compress -eq 'Y' -or $compress -eq 'y') {
        $zipPath = "$exportFile.zip"
        Compress-Archive -Path $exportFile -DestinationPath $zipPath -Force
        Write-ColorOutput "Archive created: $zipPath" "Success"
    }
    
    Read-Host "`nPress Enter to continue"
}

# Generate HTML report
function Export-HtmlReport {
    param([string]$IncidentPath)
    
    Show-Header "GENERATE HTML REPORT"
    
    Write-ColorOutput "Generating interactive HTML report..." "Progress"
    
    $reportPath = Join-Path $IncidentPath "IR_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    # Load incident info
    $info = Get-IncidentInfo -Path $IncidentPath
    $summary = Get-Content (Join-Path $IncidentPath "SUMMARY.txt") -Raw -ErrorAction SilentlyContinue
    
    # Determine threat color
    $threatColor = switch ($info.ThreatLevel) {
        "CRITICAL" { "#f44747" }
        "HIGH" { "#c586c0" }
        "MEDIUM" { "#dcdcaa" }
        "LOW" { "#4ec9b0" }
        default { "#d4d4d4" }
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Response Report - $(Split-Path $IncidentPath -Leaf)</title>
    <style>
        :root {
            --bg-primary: #1e1e1e;
            --bg-secondary: #252526;
            --bg-tertiary: #2d2d30;
            --text-primary: #d4d4d4;
            --text-secondary: #969696;
            --border: #464647;
            --critical: #f44747;
            --high: #c586c0;
            --medium: #dcdcaa;
            --low: #4ec9b0;
            --info: #569cd6;
            --success: #4ec9b0;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Courier New', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1, h2, h3 {
            color: var(--info);
            margin-bottom: 15px;
        }
        
        h1 {
            font-size: 2.5em;
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid var(--border);
            margin-bottom: 30px;
        }
        
        .threat-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 20px;
            background: $threatColor;
            color: #000;
        }
        
        .summary-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--info);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: var(--info);
        }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .section h2 {
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        th, td {
            text-align: left;
            padding: 10px;
            border: 1px solid var(--border);
        }
        
        th {
            background: var(--bg-tertiary);
            color: var(--info);
            font-weight: bold;
        }
        
        tr:nth-child(even) {
            background: var(--bg-tertiary);
        }
        
        .alert-box {
            background: rgba(244, 71, 71, 0.1);
            border: 2px solid var(--critical);
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .alert-box h3 {
            color: var(--critical);
        }
        
        pre {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        
        .collapsible {
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-left: 25px;
        }
        
        .collapsible:before {
            content: '▼';
            position: absolute;
            left: 0;
            transition: transform 0.2s;
        }
        
        .collapsible.collapsed:before {
            transform: rotate(-90deg);
        }
        
        .collapsible-content {
            margin-top: 15px;
            padding-left: 25px;
        }
        
        .collapsed + .collapsible-content {
            display: none;
        }
        
        .critical { color: var(--critical); }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }
        .info { color: var(--info); }
        .success { color: var(--success); }
        
        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
        }
        
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>
            Incident Response Report
            <span class="threat-badge">$($info.ThreatLevel)</span>
        </h1>
        
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p><strong>Incident ID:</strong> $(Split-Path $IncidentPath -Leaf)</p>
            <p><strong>Collection Time:</strong> $($info.CollectionTime)</p>
            <p><strong>Threat Level:</strong> <span class="$($info.ThreatLevel.ToLower())">$($info.ThreatLevel)</span></p>
            <p><strong>Total Alerts:</strong> $($info.AlertCount)</p>
        </div>
        
        <div class="stats-grid">
"@

    # Add statistics
    $stats = @(
        @{Name="Total Alerts"; Value=$info.AlertCount; Icon="⚠️"},
        @{Name="Suspicious Processes"; Value=(Get-ChildItem "$IncidentPath\ALERTS\*process*.csv" -ErrorAction SilentlyContinue).Count; Icon="🔍"},
        @{Name="Network Connections"; Value="Check"; Icon="🌐"},
        @{Name="Persistence Items"; Value=(Get-ChildItem "$IncidentPath\Persistence" -ErrorAction SilentlyContinue).Count; Icon="🔒"}
    )
    
    foreach ($stat in $stats) {
        $html += @"
            <div class="stat-card">
                <div style="font-size: 2em;">$($stat.Icon)</div>
                <div class="stat-number">$($stat.Value)</div>
                <div>$($stat.Name)</div>
            </div>
"@
    }
    
    $html += @"
        </div>
        
        <div class="section">
            <h2>Summary Details</h2>
            <pre>$([System.Web.HttpUtility]::HtmlEncode($summary))</pre>
        </div>
"@

    # Add alerts section
    $alertFiles = Get-ChildItem "$IncidentPath\ALERTS" -Filter "*.csv" -ErrorAction SilentlyContinue
    if ($alertFiles) {
        $html += @"
        <div class="section alert-box">
            <h2 class="collapsible">Critical Alerts ($($alertFiles.Count) files)</h2>
            <div class="collapsible-content">
"@
        
        foreach ($file in $alertFiles | Select-Object -First 10) {
            $data = Import-Csv $file.FullName -ErrorAction SilentlyContinue | Select-Object -First 5
            if ($data) {
                $html += "<h3>$($file.BaseName)</h3><table>"
                
                # Headers
                $html += "<tr>"
                $data[0].PSObject.Properties.Name | ForEach-Object { 
                    $html += "<th>$([System.Web.HttpUtility]::HtmlEncode($_))</th>" 
                }
                $html += "</tr>"
                
                # Data rows
                foreach ($row in $data) {
                    $html += "<tr>"
                    $row.PSObject.Properties.Value | ForEach-Object { 
                        $val = if ($_ -and $_.ToString().Length -gt 100) { 
                            $_.ToString().Substring(0,97) + "..." 
                        } else { 
                            $_ 
                        }
                        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($val))</td>" 
                    }
                    $html += "</tr>"
                }
                
                $html += "</table>"
            }
        }
        
        $html += @"
            </div>
        </div>
"@
    }

    # Add network section
    $netFile = "$IncidentPath\Network\connections_basic.csv"
    if (Test-Path $netFile) {
        $connections = Import-Csv $netFile -ErrorAction SilentlyContinue
        $external = @($connections | Where-Object {
            $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
        })
        
        $html += @"
        <div class="section">
            <h2 class="collapsible">Network Analysis</h2>
            <div class="collapsible-content">
                <p><strong>Total Connections:</strong> $($connections.Count)</p>
                <p><strong>External Connections:</strong> <span class="$(if($external.Count -gt 0){'high'}else{'success'})">$($external.Count)</span></p>
                
                $(if($external.Count -gt 0) {
                    "<h3>External IP Addresses</h3><ul>" + 
                    ($external | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 10 | ForEach-Object {
                        "<li>$_</li>"
                    }) -join "" +
                    "</ul>"
                })
            </div>
        </div>
"@
    }

    # Add IOCs
    $iocFile = "$IncidentPath\ALERTS\quick_iocs.json"
    if (Test-Path $iocFile) {
        try {
            $iocs = Get-Content $iocFile | ConvertFrom-Json
            $html += @"
        <div class="section">
            <h2 class="collapsible">Indicators of Compromise (IOCs)</h2>
            <div class="collapsible-content">
"@
            
            if ($iocs.SuspiciousIPs) {
                $html += "<h3>Suspicious IPs</h3><ul>"
                $iocs.SuspiciousIPs | ForEach-Object { $html += "<li>$_</li>" }
                $html += "</ul>"
            }
            
            if ($iocs.SuspiciousProcesses) {
                $html += "<h3>Suspicious Processes</h3><ul>"
                $iocs.SuspiciousProcesses | ForEach-Object { $html += "<li>$_</li>" }
                $html += "</ul>"
            }
            
            $html += @"
            </div>
        </div>
"@
        }
        catch {
            # Skip if can't parse
        }
    }

    # Footer
    $html += @"
        <div class="footer">
            <p>Generated by IR Viewer v3.0 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>Full evidence location: <code>$IncidentPath</code></p>
        </div>
    </div>
    
    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(el => {
            el.addEventListener('click', function() {
                this.classList.toggle('collapsed');
            });
        });
        
        // Auto-expand critical sections
        document.querySelectorAll('.alert-box .collapsible').forEach(el => {
            el.classList.remove('collapsed');
        });
    </script>
</body>
</html>
"@

    # Save report
    $html | Out-File $reportPath -Encoding UTF8
    
    Write-Host ""
    Write-ColorOutput "HTML report generated successfully!" "Success"
    Write-ColorOutput "Report saved to: $reportPath" "Info"
    Write-Host ""
    
    $open = Read-Host "Open in browser? (Y/N)"
    if ($open -eq 'Y' -or $open -eq 'y') {
        Start-Process $reportPath
    }
    
    Read-Host "Press Enter to continue"
}

# Browse directory helper
function Browse-Directory {
    param(
        [string]$Path,
        [string]$Title,
        [string]$Filter = "*.*"
    )
    
    if (!(Test-Path $Path)) {
        Write-ColorOutput "Directory not found: $Path" "Error"
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Header $Title
        
        $files = Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object Name
        
        if ($files.Count -eq 0) {
            Write-ColorOutput "No files found in this directory" "Warning"
            Read-Host "Press Enter to return"
            return
        }
        
        Write-ColorOutput "Files in directory:" "Info"
        Write-Host ""
        
        for ($i = 0; $i -lt $files.Count; $i++) {
            $file = $files[$i]
            $sizeKB = [Math]::Round($file.Length / 1KB, 2)
            
            Write-Host ("{0,3}. " -f ($i + 1)) -NoNewline -ForegroundColor $colors.Menu
            Write-Host ("{0,-40}" -f $file.Name) -NoNewline
            
            # Color based on file type
            $color = switch ($file.Extension.ToLower()) {
                ".csv" { $colors.Info }
                ".txt" { $colors.Data }
                ".log" { $colors.Data }
                ".json" { $colors.Success }
                ".evtx" { $colors.High }
                ".xml" { $colors.Warning }
                default { $colors.Menu }
            }
            
            Write-Host (" {0,10} KB" -f $sizeKB) -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "Enter file number to view, A for all, or Q to go back: " -NoNewline -ForegroundColor $colors.Menu
        $selection = Read-Host
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            return
        }
        elseif ($selection -eq 'A' -or $selection -eq 'a') {
            # View all files in sequence
            foreach ($file in $files) {
                Show-FileContent -FilePath $file.FullName -Title "$Title - $($file.Name)"
                
                $continue = Read-Host "`nContinue to next file? (Y/N)"
                if ($continue -ne 'Y' -and $continue -ne 'y') {
                    break
                }
            }
        }
        elseif ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $files.Count) {
                Show-FileContent -FilePath $files[$index].FullName -Title $Title
            }
        }
    }
}

# Main execution
Show-Header "INCIDENT RESPONSE VIEWER v3.0"

Write-ColorOutput "Welcome to the Comprehensive Incident Response Viewer" "Info"
Write-ColorOutput "This tool helps analyze and export incident response data" "Info"
Write-Host ""

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    Write-ColorOutput "Note: Running without admin rights. Some event logs may not be accessible." "Warning"
    Write-Host ""
}

# Main loop
while ($true) {
    # Select incident directory
    $incidentPath = $Path
    if (!$incidentPath -or !(Test-Path $incidentPath)) {
        $incidentPath = Select-IncidentDirectory
    }
    
    if (!$incidentPath) {
        Write-Host "`nNo incident selected. Exiting..." -ForegroundColor $colors.Info
        break
    }
    
    # Auto-export if specified
    if ($AutoExport) {
        Export-AllData -IncidentPath $incidentPath
        break
    }
    
    # Browse the selected incident
    Browse-IncidentData -IncidentPath $incidentPath
    
    # Clear the path so we go back to selection
    $Path = ""
}

Write-ColorOutput "`nThank you for using IR Viewer!" "Success"
Write-ColorOutput "Stay vigilant, stay secure." "Info"

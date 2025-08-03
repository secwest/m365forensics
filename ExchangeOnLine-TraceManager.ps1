<#
.SYNOPSIS
    Exchange Mail Trace Manager - Comprehensive mail trace extraction and analysis tool
    
.DESCRIPTION
    This script provides a complete solution for extracting Exchange Online mail trace logs
    with hourly execution, state management, HTML reporting, and both console and scheduled
    operation modes. Features include:
    - Hourly mail trace extraction with deduplication
    - Real-time HTML dashboard updates
    - Console mode with interactive options
    - Scheduled mode for automated execution
    - UTC-based log rollover at midnight
    - Comprehensive error handling and retry logic
    - State persistence to prevent duplicate entries
    - Browser-based authentication with token refresh
    - Automatic tenant discovery 
    
.PARAMETER Mode
    Operation mode: 'Console' for interactive or 'Scheduled' for automated execution
    
.PARAMETER Action
    Action to perform: 'Run' for extraction, 'Setup' for initial configuration,
    'Status' to check current state, 'Analyze' to generate reports
    
.PARAMETER OutputPath
    Base directory for all output files (logs, CSVs, HTML reports)
    
.PARAMETER ConfigFile
    Path to configuration file (auto-created if not exists)
    
.PARAMETER TenantName
    Default tenant name (e.g., contoso) - will auto-discover full domain including country TLDs
    
.PARAMETER UseDeviceCode
    Use device code flow for authentication (default for initial setup)
    
.EXAMPLE
    # Initial setup with Canadian company
    .\ExchangeTraceManager.ps1 -Action Setup -TenantName "mapleleaf"
    # Will automatically try: mapleleaf.ca, mapleleaf.com, mapleleaf.onmicrosoft.com, etc.
    
.EXAMPLE
    # Run in console mode
    .\ExchangeTraceManager.ps1 -Mode Console -Action Run
    
.EXAMPLE
    # Run in scheduled mode
    .\ExchangeTraceManager.ps1 -Mode Scheduled -Action Run
    
.NOTES
    Author: Dragos Ruiu
    Version: 3.0
    Requires: Internet connectivity, Exchange Online subscription
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Console', 'Scheduled')]
    [string]$Mode = 'Console',
    
    [Parameter()]
    [ValidateSet('Run', 'Setup', 'Status', 'Analyze', 'Auth')]
    [string]$Action = 'Run',
    
    [Parameter()]
    [string]$OutputPath = "$env:ProgramData\ExchangeTraceManager",
    
    [Parameter()]
    [string]$ConfigFile = "$env:ProgramData\ExchangeTraceManager\config.json",
    
    [Parameter()]
    [string]$TenantName = "",
    
    [Parameter()]
    [switch]$UseDeviceCode = $false,
    
    [Parameter()]
    [switch]$ForceReauth = $false
)

#region Global Configuration
$Script:Config = @{
    Version = "3.0"
    Paths = @{
        Base = $OutputPath
        Logs = Join-Path $OutputPath "Logs"
        Data = Join-Path $OutputPath "Data"
        Html = Join-Path $OutputPath "HTML"
        State = Join-Path $OutputPath "State"
        Archive = Join-Path $OutputPath "Archive"
    }
    Files = @{
        Config = $ConfigFile
        LastRun = Join-Path $OutputPath "State\lastrun.json"
        CurrentState = Join-Path $OutputPath "State\current.json"
        PidFile = Join-Path $OutputPath "State\running.pid"
        TokenCache = Join-Path $OutputPath "State\token.secure"
    }
    Extraction = @{
        IntervalMinutes = 60
        PageSize = 1000
        MaxResultsPerRun = 50000
        RetryAttempts = 3
        RetryDelaySeconds = 30
        LookbackMinutes = 65  # Slight overlap to catch edge cases
    }
    Logging = @{
        MaxLogSizeMB = 100
        MaxLogAgeDays = 90
        LogLevel = "INFO"  # DEBUG, INFO, WARNING, ERROR
    }
    Html = @{
        RefreshIntervalSeconds = 300
        MaxRowsPerTable = 1000
        EnableCharts = $true
    }
    OAuth = @{
        ClientId = "00000002-0000-0ff1-ce00-000000000000"  # Exchange Online
        RedirectUri = "http://localhost:8400"
        Scope = "https://outlook.office365.com/.default"
        TokenEndpoint = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token"
        AuthorizeEndpoint = "https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize"
        DeviceCodeEndpoint = "https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode"
    }
}

# Ensure all paths exist
foreach ($path in $Script:Config.Paths.Values) {
    if (!(Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Add .NET types for OAuth
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security;

public class SecureStringHelper {
    public static SecureString ConvertToSecureString(string plainText) {
        var secureString = new SecureString();
        foreach (char c in plainText) {
            secureString.AppendChar(c);
        }
        secureString.MakeReadOnly();
        return secureString;
    }
    
    public static string ConvertToString(SecureString secureString) {
        IntPtr ptr = IntPtr.Zero;
        try {
            ptr = Marshal.SecureStringToBSTR(secureString);
            return Marshal.PtrToStringBSTR(ptr);
        } finally {
            Marshal.ZeroFreeBSTR(ptr);
        }
    }
}
"@
#endregion

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',
        [switch]$NoConsole,
        [switch]$Raw
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $utcTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff UTC")
    
    # Construct log entry
    $logEntry = if ($Raw) {
        $Message
    } else {
        "[$timestamp] [$Level] $Message (UTC: $utcTimestamp)"
    }
    
    # Console output with colors
    if (!$NoConsole -and ($Mode -eq 'Console' -or $Level -in @('ERROR', 'WARNING'))) {
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARNING' { 'Yellow' }
            'SUCCESS' { 'Green' }
            'DEBUG' { 'Gray' }
            default { 'White' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    
    # File logging with rotation check
    $logDate = (Get-Date).ToUniversalTime().Date
    $logFile = Join-Path $Script:Config.Paths.Logs "ExchangeTrace_$($logDate.ToString('yyyy-MM-dd')).log"
    
    # Check log rotation
    if (Test-Path $logFile) {
        $logInfo = Get-Item $logFile
        if ($logInfo.Length -gt ($Script:Config.Logging.MaxLogSizeMB * 1MB)) {
            $archiveName = "ExchangeTrace_$($logDate.ToString('yyyy-MM-dd'))_$(Get-Date -Format 'HHmmss').log"
            Move-Item $logFile (Join-Path $Script:Config.Paths.Archive $archiveName) -Force
            Write-Log "Log file rotated to $archiveName" -Level INFO -NoConsole
        }
    }
    
    # Append to log file
    Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
}
#endregion

#region OAuth Authentication Functions
function Get-TenantInfo {
    param([string]$TenantIdentifier)
    
    Write-Log "Discovering tenant information for: $TenantIdentifier" -Level DEBUG
    
    try {
        # Try OpenID configuration endpoint
        $discoveryUrl = "https://login.microsoftonline.com/$TenantIdentifier/v2.0/.well-known/openid-configuration"
        $response = Invoke-RestMethod -Uri $discoveryUrl -Method Get -ErrorAction Stop -TimeoutSec 5
        
        # Extract tenant ID from issuer
        if ($response.issuer -match '/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/') {
            $tenantId = $matches[1]
            
            # Get tenant details
            $tenantUrl = "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
            $tenantResponse = Invoke-RestMethod -Uri $tenantUrl -Method Get -ErrorAction Stop -TimeoutSec 5
            
            return @{
                TenantId = $tenantId
                TenantName = $TenantIdentifier
                TokenEndpoint = $tenantResponse.token_endpoint
                AuthorizeEndpoint = $tenantResponse.authorization_endpoint
                Issuer = $tenantResponse.issuer
            }
        }
    } catch {
        Write-Log "Tenant discovery failed for $TenantIdentifier : $_" -Level DEBUG
    }
    
    return $null
}

function Start-DeviceCodeFlow {
    param($TenantInfo)
    
    Write-Log "Starting device code authentication flow" -Level INFO
    
    $deviceCodeUrl = $TenantInfo.TokenEndpoint -replace '/token$', '/devicecode'
    
    $body = @{
        client_id = $Script:Config.OAuth.ClientId
        scope = $Script:Config.OAuth.Scope
    }
    
    try {
        $response = Invoke-RestMethod -Uri $deviceCodeUrl -Method Post -Body $body -ErrorAction Stop
        
        # Display code to user
        Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
        Write-Host "To sign in, use a web browser to open the page:" -ForegroundColor Yellow
        Write-Host $response.verification_uri -ForegroundColor Green
        Write-Host "`nEnter the code:" -ForegroundColor Yellow
        Write-Host $response.user_code -ForegroundColor Green -BackgroundColor Black
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
        
        # Copy to clipboard if possible
        try {
            $response.user_code | Set-Clipboard
            Write-Host "Code copied to clipboard!" -ForegroundColor Green
        } catch {
            # Clipboard not available
        }
        
        # Poll for completion
        $interval = $response.interval
        if (!$interval) { $interval = 5 }
        
        Write-Host "Waiting for authentication..." -ForegroundColor Yellow
        
        while ($true) {
            Start-Sleep -Seconds $interval
            
            $tokenBody = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                client_id = $Script:Config.OAuth.ClientId
                device_code = $response.device_code
            }
            
            try {
                $tokenResponse = Invoke-RestMethod -Uri $TenantInfo.TokenEndpoint -Method Post -Body $tokenBody -ErrorAction Stop
                Write-Log "Authentication successful!" -Level SUCCESS
                return $tokenResponse
            } catch {
                $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                
                if ($errorDetail.error -eq "authorization_pending") {
                    Write-Host "." -NoNewline -ForegroundColor Yellow
                } elseif ($errorDetail.error -eq "authorization_declined") {
                    Write-Log "Authentication declined by user" -Level ERROR
                    return $null
                } elseif ($errorDetail.error -eq "expired_token") {
                    Write-Log "Authentication code expired" -Level ERROR
                    return $null
                } else {
                    Write-Log "Authentication error: $_" -Level ERROR
                    return $null
                }
            }
        }
    } catch {
        Write-Log "Error initiating device code flow: $_" -Level ERROR
        return $null
    }
}

function Start-BrowserAuth {
    param($TenantInfo)
    
    Write-Log "Starting browser authentication flow" -Level INFO
    
    # Create local HTTP listener
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Script:Config.OAuth.RedirectUri + "/")
    
    try {
        $listener.Start()
        
        # Generate state for security
        $state = [Guid]::NewGuid().ToString()
        
        # Build auth URL
        $authUrl = "$($TenantInfo.AuthorizeEndpoint)?" + 
                   "client_id=$($Script:Config.OAuth.ClientId)&" +
                   "response_type=code&" +
                   "redirect_uri=$([Uri]::EscapeDataString($Script:Config.OAuth.RedirectUri))&" +
                   "response_mode=query&" +
                   "scope=$([Uri]::EscapeDataString($Script:Config.OAuth.Scope))&" +
                   "state=$state"
        
        # Open browser
        Write-Host "`nOpening browser for authentication..." -ForegroundColor Yellow
        Start-Process $authUrl
        
        # Wait for callback
        Write-Host "Waiting for authentication response..." -ForegroundColor Yellow
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        # Extract code from query string
        $queryParams = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
        $code = $queryParams["code"]
        $returnedState = $queryParams["state"]
        
        # Validate state
        if ($returnedState -ne $state) {
            throw "Invalid state returned"
        }
        
        # Send response to browser
        $responseHtml = @"
<html>
<head><title>Authentication Complete</title></head>
<body style="font-family: Arial; text-align: center; padding: 50px;">
    <h1 style="color: #0078d4;">Authentication Successful!</h1>
    <p>You can close this window and return to the PowerShell console.</p>
    <script>window.setTimeout(function(){window.close();}, 3000);</script>
</body>
</html>
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        
        # Exchange code for token
        if ($code) {
            $tokenBody = @{
                client_id = $Script:Config.OAuth.ClientId
                scope = $Script:Config.OAuth.Scope
                code = $code
                redirect_uri = $Script:Config.OAuth.RedirectUri
                grant_type = "authorization_code"
            }
            
            $tokenResponse = Invoke-RestMethod -Uri $TenantInfo.TokenEndpoint -Method Post -Body $tokenBody -ErrorAction Stop
            Write-Log "Authentication successful!" -Level SUCCESS
            return $tokenResponse
        }
        
    } catch {
        Write-Log "Browser authentication error: $_" -Level ERROR
        return $null
    } finally {
        if ($listener.IsListening) {
            $listener.Stop()
            $listener.Dispose()
        }
    }
}

function Get-StoredToken {
    if (Test-Path $Script:Config.Files.TokenCache) {
        try {
            $encryptedData = Get-Content $Script:Config.Files.TokenCache -Raw
            $secureString = ConvertTo-SecureString $encryptedData
            $tokenJson = [SecureStringHelper]::ConvertToString($secureString)
            $token = $tokenJson | ConvertFrom-Json
            
            # Check if token is expired
            if ([DateTime]$token.ExpiresAt -gt (Get-Date).AddMinutes(5)) {
                Write-Log "Using cached authentication token" -Level DEBUG
                return $token
            } else {
                Write-Log "Cached token expired, refreshing..." -Level INFO
                return Refresh-Token -Token $token
            }
        } catch {
            Write-Log "Error reading token cache: $_" -Level WARNING
        }
    }
    return $null
}

function Save-Token {
    param($TokenResponse, $TenantInfo)
    
    try {
        # Add expiration time
        $token = @{
            AccessToken = $TokenResponse.access_token
            RefreshToken = $TokenResponse.refresh_token
            ExpiresIn = $TokenResponse.expires_in
            ExpiresAt = (Get-Date).AddSeconds($TokenResponse.expires_in).ToString('o')
            TokenType = $TokenResponse.token_type
            Scope = $TokenResponse.scope
            TenantId = $TenantInfo.TenantId
            TenantName = $TenantInfo.TenantName
        }
        
        # Encrypt and save
        $tokenJson = $token | ConvertTo-Json
        $secureString = [SecureStringHelper]::ConvertToSecureString($tokenJson)
        $encryptedData = ConvertFrom-SecureString $secureString
        $encryptedData | Set-Content $Script:Config.Files.TokenCache -Force
        
        Write-Log "Authentication token saved securely" -Level DEBUG
    } catch {
        Write-Log "Error saving token: $_" -Level ERROR
    }
}

function Refresh-Token {
    param($Token)
    
    if (!$Token.RefreshToken) {
        Write-Log "No refresh token available" -Level WARNING
        return $null
    }
    
    try {
        $config = Get-Configuration
        $tenantInfo = Get-TenantInfo -TenantIdentifier $config.TenantId
        
        $body = @{
            client_id = $Script:Config.OAuth.ClientId
            scope = $Script:Config.OAuth.Scope
            refresh_token = $Token.RefreshToken
            grant_type = "refresh_token"
        }
        
        $response = Invoke-RestMethod -Uri $tenantInfo.TokenEndpoint -Method Post -Body $body -ErrorAction Stop
        Write-Log "Token refreshed successfully" -Level DEBUG
        
        # Save new token
        Save-Token -TokenResponse $response -TenantInfo $tenantInfo
        
        return Get-StoredToken
    } catch {
        Write-Log "Error refreshing token: $_" -Level ERROR
        return $null
    }
}
#endregion

#region Exchange Online REST API Functions
function Invoke-ExchangeAPI {
    param(
        [string]$Endpoint,
        [hashtable]$Body,
        [string]$Method = "POST"
    )
    
    $token = Get-StoredToken
    if (!$token) {
        throw "No valid authentication token available"
    }
    
    $headers = @{
        "Authorization" = "$($token.TokenType) $($token.AccessToken)"
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }
    
    $uri = "https://outlook.office365.com/adminapi/beta/$($token.TenantId)/$Endpoint"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method $Method -Body ($Body | ConvertTo-Json) -ErrorAction Stop
        return $response
    } catch {
        if ($_.Exception.Response.StatusCode -eq 401) {
            Write-Log "Authentication failed, attempting token refresh" -Level WARNING
            
            # Try to refresh token
            $token = Refresh-Token -Token $token
            if ($token) {
                $headers["Authorization"] = "$($token.TokenType) $($token.AccessToken)"
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method $Method -Body ($Body | ConvertTo-Json) -ErrorAction Stop
                return $response
            }
        }
        throw
    }
}

function Get-MessageTraceViaAPI {
    param(
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [int]$Page = 1
    )
    
    $body = @{
        MessageTraceDetailAction = @{
            StartDate = $StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            EndDate = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            Page = $Page
            PageSize = $Script:Config.Extraction.PageSize
        }
    }
    
    try {
        $response = Invoke-ExchangeAPI -Endpoint "MessageTrace/MessageTrace" -Body $body -Method POST
        return $response.value
    } catch {
        Write-Log "Error calling Message Trace API: $_" -Level ERROR
        throw
    }
}
#endregion

#region State Management Functions
function Get-CurrentState {
    if (Test-Path $Script:Config.Files.CurrentState) {
        try {
            return Get-Content $Script:Config.Files.CurrentState -Raw | ConvertFrom-Json
        } catch {
            Write-Log "Error reading state file: $_" -Level WARNING
        }
    }
    
    # Return default state
    return @{
        LastRunTime = $null
        LastSuccessfulRun = $null
        LastProcessedMessageId = $null
        ProcessedRanges = @()
        Statistics = @{
            TotalMessagesProcessed = 0
            TotalRunsCompleted = 0
            ConsecutiveFailures = 0
        }
    }
}

function Save-CurrentState {
    param($State)
    
    try {
        $State | ConvertTo-Json -Depth 10 | Set-Content $Script:Config.Files.CurrentState -Force
        Write-Log "State saved successfully" -Level DEBUG
    } catch {
        Write-Log "Error saving state: $_" -Level ERROR
    }
}

function Add-ProcessedRange {
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime,
        [int]$MessageCount
    )
    
    $state = Get-CurrentState
    
    # Add new range
    $state.ProcessedRanges += @{
        Start = $StartTime.ToString('o')
        End = $EndTime.ToString('o')
        Count = $MessageCount
        ProcessedAt = (Get-Date).ToString('o')
    }
    
    # Keep only last 7 days of ranges for performance
    $cutoff = (Get-Date).AddDays(-7)
    $state.ProcessedRanges = $state.ProcessedRanges | Where-Object {
        [DateTime]$_.ProcessedAt -gt $cutoff
    }
    
    Save-CurrentState -State $state
}

function Test-RangeProcessed {
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )
    
    $state = Get-CurrentState
    
    foreach ($range in $state.ProcessedRanges) {
        $rangeStart = [DateTime]$range.Start
        $rangeEnd = [DateTime]$range.End
        
        # Check if this range overlaps with any processed range
        if ($StartTime -lt $rangeEnd -and $EndTime -gt $rangeStart) {
            return $true
        }
    }
    
    return $false
}
#endregion

#region Data Processing Functions
function Get-MessageTraceResilient {
    param(
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )
    
    Write-Log "Retrieving messages from $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -Level INFO
    
    # Check if this range was already processed
    if (Test-RangeProcessed -StartTime $StartDate -EndTime $EndDate) {
        Write-Log "Range already processed, skipping to avoid duplicates" -Level WARNING
        return @()
    }
    
    $allMessages = @()
    $page = 1
    $hasMore = $true
    
    while ($hasMore -and $allMessages.Count -lt $Script:Config.Extraction.MaxResultsPerRun) {
        try {
            Write-Progress -Activity "Retrieving messages" -Status "Page $page (Total: $($allMessages.Count))"
            
            $messages = @(Get-MessageTraceViaAPI -StartDate $StartDate -EndDate $EndDate -Page $page)
            
            if ($messages.Count -eq 0) {
                $hasMore = $false
            } else {
                $allMessages += $messages
                
                if ($messages.Count -lt $Script:Config.Extraction.PageSize) {
                    $hasMore = $false
                } else {
                    $page++
                }
            }
            
        } catch {
            Write-Log "Error retrieving page $page: $_" -Level ERROR
            
            # If we have some messages, return what we got
            if ($allMessages.Count -gt 0) {
                Write-Log "Returning partial results: $($allMessages.Count) messages" -Level WARNING
                break
            }
            
            throw
        }
    }
    
    # Record this range as processed
    if ($allMessages.Count -gt 0) {
        Add-ProcessedRange -StartTime $StartDate -EndTime $EndDate -MessageCount $allMessages.Count
    }
    
    Write-Log "Retrieved $($allMessages.Count) messages" -Level INFO
    return $allMessages
}

function Export-MessageTraceData {
    param(
        [array]$Messages,
        [DateTime]$RunTime
    )
    
    if ($Messages.Count -eq 0) {
        Write-Log "No messages to export" -Level DEBUG
        return
    }
    
    # Determine file paths based on UTC date
    $utcDate = $RunTime.ToUniversalTime().Date
    $localDate = $RunTime.Date
    
    $csvFileName = "MailTrace_$($utcDate.ToString('yyyy-MM-dd'))_UTC.csv"
    $csvPath = Join-Path $Script:Config.Paths.Data $csvFileName
    
    $htmlFileName = "MailTrace_$($utcDate.ToString('yyyy-MM-dd'))_UTC.html"
    $htmlPath = Join-Path $Script:Config.Paths.Html $htmlFileName
    
    try {
        # Prepare message data with additional fields
        $exportData = $Messages | Select-Object @(
            @{N='MessageId'; E={$_.MessageId}},
            @{N='MessageTraceId'; E={$_.MessageTraceId}},
            @{N='ReceivedUTC'; E={[DateTime]$_.Received}},
            @{N='ReceivedLocal'; E={[DateTime]$_.Received}},
            @{N='SenderAddress'; E={$_.SenderAddress}},
            @{N='RecipientAddress'; E={$_.RecipientAddress}},
            @{N='Subject'; E={$_.Subject}},
            @{N='Status'; E={$_.Status}},
            @{N='FromIP'; E={$_.FromIP}},
            @{N='ToIP'; E={$_.ToIP}},
            @{N='Size'; E={$_.Size}},
            @{N='ProcessedAtUTC'; E={$RunTime.ToUniversalTime()}},
            @{N='ProcessedAtLocal'; E={$RunTime}}
        )
        
        # Export to CSV (append if exists)
        $isNewFile = !(Test-Path $csvPath)
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Append
        
        Write-Log "Exported $($Messages.Count) messages to $csvFileName" -Level SUCCESS
        
        # Update HTML report
        Update-HtmlReport -DataPath $csvPath -HtmlPath $htmlPath -RunTime $RunTime
        
        # Update state statistics
        $state = Get-CurrentState
        $state.Statistics.TotalMessagesProcessed += $Messages.Count
        $state.LastProcessedMessageId = $Messages[-1].MessageId
        Save-CurrentState -State $state
        
    } catch {
        Write-Log "Error exporting data: $_" -Level ERROR
        throw
    }
}

function Update-HtmlReport {
    param(
        [string]$DataPath,
        [string]$HtmlPath,
        [DateTime]$RunTime
    )
    
    Write-Log "Updating HTML report: $(Split-Path $HtmlPath -Leaf)" -Level DEBUG
    
    try {
        # Load all data for the day
        $allData = @(Import-Csv $DataPath -ErrorAction Stop)
        
        # Calculate statistics
        $stats = @{
            TotalMessages = $allData.Count
            UniqueRecipients = @($allData.RecipientAddress | Sort-Object -Unique).Count
            UniqueSenders = @($allData.SenderAddress | Sort-Object -Unique).Count
            LastUpdate = $RunTime.ToString('yyyy-MM-dd HH:mm:ss')
            LastUpdateUTC = $RunTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
        }
        
        # Group data for analysis
        $statusBreakdown = $allData | Group-Object Status | 
            Sort-Object Count -Descending | 
            Select-Object Name, Count
        
        $topSenders = $allData | Group-Object SenderAddress | 
            Sort-Object Count -Descending | 
            Select-Object -First 20 @{N='Sender';E={$_.Name}}, Count
        
        $topRecipients = $allData | Group-Object RecipientAddress | 
            Sort-Object Count -Descending | 
            Select-Object -First 20 @{N='Recipient';E={$_.Name}}, Count
        
        $hourlyDistribution = $allData | ForEach-Object { 
            [DateTime]$_.ReceivedLocal 
        } | Group-Object Hour | Sort-Object Name
        
        # Generate HTML
        $html = Get-HtmlReportTemplate -Stats $stats -StatusBreakdown $statusBreakdown `
            -TopSenders $topSenders -TopRecipients $topRecipients `
            -HourlyDistribution $hourlyDistribution -Messages $allData
        
        # Save HTML
        $html | Out-File -FilePath $HtmlPath -Encoding UTF8 -Force
        
        Write-Log "HTML report updated successfully" -Level DEBUG
        
    } catch {
        Write-Log "Error updating HTML report: $_" -Level ERROR
    }
}

function Get-HtmlReportTemplate {
    param($Stats, $StatusBreakdown, $TopSenders, $TopRecipients, $HourlyDistribution, $Messages)
    
    # Calculate additional metrics
    $failedMessages = @($Messages | Where-Object { $_.Status -notin @('Delivered', 'Sent', 'Received') })
    $failureRate = if ($Stats.TotalMessages -gt 0) { 
        [Math]::Round(($failedMessages.Count / $Stats.TotalMessages) * 100, 2) 
    } else { 0 }
    
    # Recent messages (last 100)
    $recentMessages = $Messages | 
        Sort-Object ReceivedLocal -Descending | 
        Select-Object -First 100
    
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="300">
    <title>Exchange Mail Trace Report - $(Split-Path $Stats.LastUpdate -Leaf)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { 
            color: #0078d4;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #e1e5ea;
        }
        .update-info {
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
            font-size: 0.9em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.12);
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #0078d4;
            margin: 10px 0;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .warning { 
            background: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        table {
            width: 100%;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
        }
        th {
            background: #0078d4;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        tr:nth-child(even) { background: #f8f9fa; }
        tr:hover { background: #e9ecef; }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            margin-bottom: 30px;
            overflow-x: auto;
        }
        .bar {
            display: inline-block;
            background: #0078d4;
            margin-right: 2px;
            vertical-align: bottom;
            min-width: 20px;
            text-align: center;
            color: white;
            font-size: 0.8em;
            padding: 5px 0;
        }
        .recent-messages {
            max-height: 600px;
            overflow-y: auto;
        }
        .status-delivered { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-pending { color: #ffc107; font-weight: bold; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
            table { font-size: 0.9em; }
            th, td { padding: 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Exchange Mail Trace Report</h1>
            <div class="update-info">
                <strong>Last Updated:</strong> $($Stats.LastUpdate) (Local) | $($Stats.LastUpdateUTC)
                <br><strong>Auto-refresh:</strong> Every 5 minutes
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Messages</div>
                <div class="stat-value">$("{0:N0}" -f $Stats.TotalMessages)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Senders</div>
                <div class="stat-value">$("{0:N0}" -f $Stats.UniqueSenders)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Recipients</div>
                <div class="stat-value">$("{0:N0}" -f $Stats.UniqueRecipients)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Failure Rate</div>
                <div class="stat-value" style="color: $(if ($failureRate -gt 5) {'#dc3545'} else {'#28a745'})">
                    $failureRate%
                </div>
            </div>
        </div>

        $(if ($failedMessages.Count -gt 0) {
            "<div class='warning'>
                <strong>Warning:</strong> $($failedMessages.Count) messages failed delivery ($failureRate% failure rate)
            </div>"
        })

        <h2>Message Status Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Visual</th>
                </tr>
            </thead>
            <tbody>
$(foreach ($status in $StatusBreakdown) {
    $percentage = [Math]::Round(($status.Count / $Stats.TotalMessages) * 100, 2)
    $barWidth = [Math]::Max(1, [Math]::Round($percentage))
    $statusClass = switch ($status.Name) {
        'Delivered' { 'status-delivered' }
        'Sent' { 'status-delivered' }
        'Failed' { 'status-failed' }
        default { 'status-pending' }
    }
    "                <tr>
                    <td class='$statusClass'>$($status.Name)</td>
                    <td>$("{0:N0}" -f $status.Count)</td>
                    <td>$percentage%</td>
                    <td><div class='bar' style='width: $($barWidth * 3)px;'>$percentage%</div></td>
                </tr>"
})
            </tbody>
        </table>

        <h2>Hourly Message Distribution</h2>
        <div class="chart-container">
            <div style="display: flex; align-items: flex-end; height: 200px;">
$(foreach ($hour in 0..23) {
    $hourData = $HourlyDistribution | Where-Object { [int]$_.Name -eq $hour }
    $count = if ($hourData) { $hourData.Count } else { 0 }
    $maxCount = ($HourlyDistribution | Measure-Object Count -Maximum).Maximum
    $height = if ($maxCount -gt 0) { [Math]::Round(($count / $maxCount) * 180) } else { 0 }
    "                <div class='bar' style='height: $($height)px; margin: 0 1px;' title='$hour:00 - $count messages'>
                    <div style='margin-top: -20px;'>$count</div>
                    <div style='position: absolute; bottom: -20px; width: 100%;'>$hour</div>
                </div>"
})
            </div>
        </div>

        <h2>Top 20 Senders</h2>
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Sender</th>
                    <th>Message Count</th>
                </tr>
            </thead>
            <tbody>
$(foreach ($i in 0..($TopSenders.Count - 1)) {
    $sender = $TopSenders[$i]
    "                <tr>
                    <td>$($i + 1)</td>
                    <td>$($sender.Sender)</td>
                    <td>$("{0:N0}" -f $sender.Count)</td>
                </tr>"
})
            </tbody>
        </table>

        <h2>Top 20 Recipients</h2>
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Recipient</th>
                    <th>Message Count</th>
                </tr>
            </thead>
            <tbody>
$(foreach ($i in 0..($TopRecipients.Count - 1)) {
    $recipient = $TopRecipients[$i]
    "                <tr>
                    <td>$($i + 1)</td>
                    <td>$($recipient.Recipient)</td>
                    <td>$("{0:N0}" -f $recipient.Count)</td>
                </tr>"
})
            </tbody>
        </table>

        <h2>Recent Messages (Last 100)</h2>
        <div class="recent-messages">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Subject</th>
                        <th>Status</th>
                        <th>Size</th>
                    </tr>
                </thead>
                <tbody>
$(foreach ($msg in $recentMessages) {
    $statusClass = switch ($msg.Status) {
        'Delivered' { 'status-delivered' }
        'Sent' { 'status-delivered' }
        'Failed' { 'status-failed' }
        default { 'status-pending' }
    }
    $sizeKB = if ($msg.Size) { [Math]::Round([int]$msg.Size / 1024, 1) } else { 0 }
    "                    <tr>
                        <td>$(([DateTime]$msg.ReceivedLocal).ToString('HH:mm:ss'))</td>
                        <td title='$($msg.SenderAddress)'>$($msg.SenderAddress.Substring(0, [Math]::Min(30, $msg.SenderAddress.Length)))</td>
                        <td title='$($msg.RecipientAddress)'>$($msg.RecipientAddress.Substring(0, [Math]::Min(30, $msg.RecipientAddress.Length)))</td>
                        <td title='$($msg.Subject)'>$(if ($msg.Subject) { $msg.Subject.Substring(0, [Math]::Min(50, $msg.Subject.Length)) } else { '(No Subject)' })</td>
                        <td class='$statusClass'>$($msg.Status)</td>
                        <td>$sizeKB KB</td>
                    </tr>"
})
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by Exchange Mail Trace Manager v$($Script:Config.Version)</p>
            <p>Report Date: $(Get-Date -Format 'yyyy-MM-dd') | Next update in <span id="countdown">300</span> seconds</p>
        </div>
    </div>

    <script>
        // Countdown timer
        let seconds = 300;
        setInterval(() => {
            seconds--;
            document.getElementById('countdown').textContent = seconds;
            if (seconds <= 0) {
                location.reload();
            }
        }, 1000);

        // Highlight new rows (placeholder for future enhancement)
        document.addEventListener('DOMContentLoaded', () => {
            const tables = document.querySelectorAll('table');
            tables.forEach(table => {
                table.addEventListener('click', (e) => {
                    if (e.target.tagName === 'TD') {
                        e.target.parentElement.style.backgroundColor = '#fffacd';
                        setTimeout(() => {
                            e.target.parentElement.style.backgroundColor = '';
                        }, 2000);
                    }
                });
            });
        });
    </script>
</body>
</html>
"@
}
#endregion

#region Configuration Management
function Get-Configuration {
    if (Test-Path $Script:Config.Files.Config) {
        try {
            $config = Get-Content $Script:Config.Files.Config -Raw | ConvertFrom-Json
            
            # Merge with defaults
            foreach ($key in $Script:Config.Keys) {
                if (!$config.PSObject.Properties[$key]) {
                    $config | Add-Member -NotePropertyName $key -NotePropertyValue $Script:Config[$key]
                }
            }
            
            return $config
        } catch {
            Write-Log "Error reading configuration: $_" -Level WARNING
        }
    }
    
    # Return defaults
    return $Script:Config
}

function Save-Configuration {
    param($Config)
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Set-Content $Script:Config.Files.Config -Force
        Write-Log "Configuration saved successfully" -Level SUCCESS
    } catch {
        Write-Log "Error saving configuration: $_" -Level ERROR
        throw
    }
}

function Initialize-Configuration {
    Write-Log "Initializing configuration..." -Level INFO
    
    # Get tenant information
    $tenantInfo = $null
    
    if ($TenantName) {
        Write-Log "Using provided tenant name: $TenantName" -Level INFO
        
        # Try common patterns including country domains
        $patterns = @(
            "$TenantName.onmicrosoft.com",
            "$TenantName.com",
            "$TenantName.ca",
            "$TenantName.co.uk",
            "$TenantName.co.nz",
            "$TenantName.com.au",
            "$TenantName.de",
            "$TenantName.fr",
            "$TenantName.it",
            "$TenantName.es",
            "$TenantName.nl",
            "$TenantName.be",
            "$TenantName.ch",
            "$TenantName.at",
            "$TenantName.dk",
            "$TenantName.se",
            "$TenantName.no",
            "$TenantName.fi",
            "$TenantName.ie",
            "$TenantName.pt",
            "$TenantName.pl",
            "$TenantName.cz",
            "$TenantName.hu",
            "$TenantName.ro",
            "$TenantName.gr",
            "$TenantName.co.za",
            "$TenantName.ae",
            "$TenantName.sa",
            "$TenantName.in",
            "$TenantName.co.in",
            "$TenantName.jp",
            "$TenantName.co.jp",
            "$TenantName.cn",
            "$TenantName.com.cn",
            "$TenantName.kr",
            "$TenantName.co.kr",
            "$TenantName.sg",
            "$TenantName.com.sg",
            "$TenantName.my",
            "$TenantName.com.my",
            "$TenantName.hk",
            "$TenantName.com.hk",
            "$TenantName.tw",
            "$TenantName.com.tw",
            "$TenantName.mx",
            "$TenantName.com.mx",
            "$TenantName.br",
            "$TenantName.com.br",
            "$TenantName.ar",
            "$TenantName.com.ar",
            "$TenantName.cl",
            "$TenantName.co",
            "$TenantName.com.co",
            "$TenantName.pe",
            "$TenantName.com.pe",
            "$TenantName.org",
            "$TenantName.net",
            "$TenantName.edu",
            "$TenantName.gov",
            "$TenantName.mil",
            "$TenantName.int",
            "$TenantName.eu",
            "$TenantName.asia",
            "$TenantName.info",
            "$TenantName.biz",
            "$TenantName.io",
            "$TenantName.ai",
            "$TenantName.app",
            "$TenantName.cloud",
            "$TenantName.tech",
            $TenantName
        )
        
        # Try discovery with progress indication
        $total = $patterns.Count
        $current = 0
        
        Write-Host "Attempting tenant discovery..." -ForegroundColor Yellow
        
        foreach ($pattern in $patterns) {
            $current++
            Write-Progress -Activity "Discovering tenant" -Status "Trying: $pattern" -PercentComplete (($current / $total) * 100)
            
            $info = Get-TenantInfo -TenantIdentifier $pattern
            if ($info) {
                $tenantInfo = $info
                Write-Progress -Activity "Discovering tenant" -Completed
                Write-Log "Successfully discovered tenant using: $pattern" -Level SUCCESS
                Write-Log "Tenant ID: $($info.TenantId)" -Level SUCCESS
                break
            }
        }
        
        Write-Progress -Activity "Discovering tenant" -Completed
        
        if (!$tenantInfo) {
            Write-Log "Could not discover tenant automatically" -Level WARNING
            Write-Host "`nAutomatic discovery failed. Common reasons:" -ForegroundColor Yellow
            Write-Host "  - Tenant uses a custom domain not in our list" -ForegroundColor Gray
            Write-Host "  - Tenant name might be different from domain name" -ForegroundColor Gray
            Write-Host "  - Network connectivity issues" -ForegroundColor Gray
            
            $domain = Read-Host "`nEnter your full tenant domain (e.g., contoso.onmicrosoft.com or contoso.ca)"
            $tenantInfo = Get-TenantInfo -TenantIdentifier $domain
        }
    } else {
        # Interactive tenant discovery
        Write-Host "`nTenant Discovery" -ForegroundColor Cyan
        Write-Host "Enter one of the following:" -ForegroundColor Yellow
        Write-Host "  - Tenant name (e.g., contoso)" -ForegroundColor Gray
        Write-Host "  - Full domain (e.g., contoso.com, contoso.ca, contoso.co.uk)" -ForegroundColor Gray
        Write-Host "  - Microsoft domain (e.g., contoso.onmicrosoft.com)" -ForegroundColor Gray
        Write-Host "  - Tenant ID (GUID)" -ForegroundColor Gray
        Write-Host "`nSupported country domains: .ca, .co.uk, .com.au, .de, .fr, .jp, .in, etc." -ForegroundColor DarkGray
        
        $identifier = Read-Host "`nTenant identifier"
        
        # If user entered just a name without domain, try common patterns
        if ($identifier -notmatch '\.' -and $identifier -notmatch '-') {
            Write-Host "`nTrying common domain patterns for '$identifier'..." -ForegroundColor Yellow
            $TenantName = $identifier
            
            # Use the same pattern list
            $patterns = @(
                "$TenantName.onmicrosoft.com",
                "$TenantName.com",
                "$TenantName.ca",
                "$TenantName.co.uk",
                "$TenantName.co.nz",
                "$TenantName.com.au",
                "$TenantName.de",
                "$TenantName.fr",
                "$TenantName.org",
                "$TenantName.net"
            )
            
            foreach ($pattern in $patterns) {
                Write-Host "  Trying: $pattern" -ForegroundColor Gray -NoNewline
                $info = Get-TenantInfo -TenantIdentifier $pattern
                if ($info) {
                    Write-Host " ✓" -ForegroundColor Green
                    $tenantInfo = $info
                    Write-Log "Successfully discovered tenant using: $pattern" -Level SUCCESS
                    break
                } else {
                    Write-Host " ✗" -ForegroundColor Red
                }
            }
        } else {
            # User provided full domain or tenant ID
            $tenantInfo = Get-TenantInfo -TenantIdentifier $identifier
        }
    }
    
    if (!$tenantInfo) {
        throw "Failed to discover tenant information"
    }
    
    # Authenticate
    Write-Host "`nAuthentication Method" -ForegroundColor Cyan
    Write-Host "1. Device Code (recommended for first setup)" -ForegroundColor Yellow
    Write-Host "2. Browser Authentication" -ForegroundColor Yellow
    
    $authChoice = Read-Host "`nSelect method (1 or 2)"
    
    $tokenResponse = $null
    if ($authChoice -eq "2") {
        $tokenResponse = Start-BrowserAuth -TenantInfo $tenantInfo
    } else {
        $tokenResponse = Start-DeviceCodeFlow -TenantInfo $tenantInfo
    }
    
    if (!$tokenResponse) {
        throw "Authentication failed"
    }
    
    # Save token
    Save-Token -TokenResponse $tokenResponse -TenantInfo $tenantInfo
    
    # Create configuration
    $config = @{
        Version = $Script:Config.Version
        TenantId = $tenantInfo.TenantId
        TenantName = $tenantInfo.TenantName
        AuthMethod = if ($authChoice -eq "2") { "Browser" } else { "DeviceCode" }
        Paths = $Script:Config.Paths
        Extraction = $Script:Config.Extraction
        Logging = $Script:Config.Logging
        Html = $Script:Config.Html
        Schedule = @{
            Enabled = $false
            IntervalMinutes = 60
            TaskName = "ExchangeMailTraceManager"
        }
    }
    
    Save-Configuration -Config $config
    return $config
}
#endregion

#region Scheduling Functions
function Enable-ScheduledExecution {
    Write-Log "Setting up scheduled execution..." -Level INFO
    
    $taskName = "ExchangeMailTraceManager"
    $scriptPath = $MyInvocation.MyCommand.Path
    
    # Create scheduled task XML for more control
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>$env:USERNAME</Author>
    <Description>Exchange Mail Trace Manager - Hourly mail trace extraction with deduplication</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT5M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$scriptPath" -Mode Scheduled -Action Run</Arguments>
      <WorkingDirectory>$OutputPath</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
    
    try {
        # Save XML to temp file
        $tempXml = [System.IO.Path]::GetTempFileName()
        $taskXml | Out-File -FilePath $tempXml -Encoding Unicode
        
        # Register the task
        $result = schtasks.exe /Create /TN $taskName /XML $tempXml /F 2>&1
        
        # Clean up temp file
        Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Scheduled task created successfully" -Level SUCCESS
            Write-Log "Task will run every hour starting from next hour" -Level INFO
            
            # Update configuration
            $config = Get-Configuration
            $config.Schedule.Enabled = $true
            $config.Schedule.TaskName = $taskName
            Save-Configuration -Config $config
            
            # Prompt to run now
            if ($Mode -eq 'Console') {
                $runNow = Read-Host "`nRun task immediately? (Y/N)"
                if ($runNow -eq 'Y') {
                    Write-Log "Starting scheduled task..." -Level INFO
                    schtasks.exe /Run /TN $taskName
                }
            }
        } else {
            throw "Failed to create scheduled task: $result"
        }
        
    } catch {
        Write-Log "Error setting up scheduled execution: $_" -Level ERROR
        throw
    }
}
#endregion

#region Main Execution Functions
function Start-MailTraceExtraction {
    param(
        [switch]$SingleRun
    )
    
    Write-Log "Starting mail trace extraction (Mode: $Mode)" -Level INFO
    
    # Check for running instance
    if (Test-Path $Script:Config.Files.PidFile) {
        $pidInfo = Get-Content $Script:Config.Files.PidFile -Raw | ConvertFrom-Json
        $existingProcess = Get-Process -Id $pidInfo.Pid -ErrorAction SilentlyContinue
        
        if ($existingProcess -and $existingProcess.StartTime -eq [DateTime]$pidInfo.StartTime) {
            Write-Log "Another instance is already running (PID: $($pidInfo.Pid))" -Level WARNING
            
            if ($Mode -eq 'Console') {
                $force = Read-Host "Force start anyway? (Y/N)"
                if ($force -ne 'Y') {
                    return
                }
            } else {
                return
            }
        }
    }
    
    # Create PID file
    @{
        Pid = $PID
        StartTime = (Get-Process -Id $PID).StartTime.ToString('o')
        Mode = $Mode
    } | ConvertTo-Json | Set-Content $Script:Config.Files.PidFile -Force
    
    try {
        # Verify authentication
        $token = Get-StoredToken
        if (!$token) {
            if ($Mode -eq 'Console') {
                Write-Log "No valid authentication found. Running setup..." -Level WARNING
                Initialize-Configuration
                $token = Get-StoredToken
            } else {
                throw "No valid authentication token available"
            }
        }
        
        do {
            $runStartTime = Get-Date
            $state = Get-CurrentState
            
            # Calculate time range
            $endTime = $runStartTime
            $startTime = if ($state.LastSuccessfulRun) {
                # Start from last successful run with small overlap
                ([DateTime]$state.LastSuccessfulRun).AddMinutes(-5)
            } else {
                # Default to last 65 minutes for first run
                $endTime.AddMinutes(-$Script:Config.Extraction.LookbackMinutes)
            }
            
            # Ensure we don't go too far back
            $maxLookback = $endTime.AddDays(-10)
            if ($startTime -lt $maxLookback) {
                $startTime = $maxLookback
                Write-Log "Limiting lookback to 10 days" -Level WARNING
            }
            
            Write-Log "=" * 60 -Level INFO -Raw
            Write-Log "Extraction Run Started: $($runStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level INFO
            Write-Log "Time Range: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level INFO
            
            try {
                # Get messages
                $messages = Get-MessageTraceResilient -StartDate $startTime -EndDate $endTime
                
                if ($messages.Count -gt 0) {
                    # Export data
                    Export-MessageTraceData -Messages $messages -RunTime $runStartTime
                    
                    # Update state
                    $state.LastSuccessfulRun = $endTime.ToString('o')
                    $state.Statistics.TotalRunsCompleted++
                    $state.Statistics.ConsecutiveFailures = 0
                } else {
                    Write-Log "No messages found in time range" -Level INFO
                }
                
                # Always update last run time
                $state.LastRunTime = $runStartTime.ToString('o')
                Save-CurrentState -State $state
                
                # Display summary
                if ($Mode -eq 'Console') {
                    Write-Host "`n" -NoNewline
                    Write-Log "Run Summary:" -Level SUCCESS
                    Write-Log "  Messages Processed: $($messages.Count)" -Level INFO
                    Write-Log "  Total Messages Today: $($state.Statistics.TotalMessagesProcessed)" -Level INFO
                    Write-Log "  Run Duration: $((Get-Date) - $runStartTime)" -Level INFO
                }
                
            } catch {
                Write-Log "Error during extraction: $_" -Level ERROR
                
                $state.Statistics.ConsecutiveFailures++
                Save-CurrentState -State $state
                
                if ($state.Statistics.ConsecutiveFailures -gt 5) {
                    Write-Log "Too many consecutive failures, stopping" -Level ERROR
                    break
                }
            }
            
            # Handle continuation
            if (!$SingleRun -and $Mode -eq 'Console') {
                Write-Host "`n" -NoNewline
                Write-Log "Next run scheduled for: $($runStartTime.AddHours(1).ToString('HH:mm:ss'))" -Level INFO
                Write-Host "`nOptions: [R]un now, [Q]uit, or wait for next scheduled run" -ForegroundColor Yellow
                
                $waitUntil = $runStartTime.AddHours(1)
                $keypressed = $false
                
                while ((Get-Date) -lt $waitUntil -and !$keypressed) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        switch ($key.Key) {
                            'R' { 
                                Write-Log "Manual run triggered" -Level INFO
                                $keypressed = $true
                            }
                            'Q' { 
                                Write-Log "User requested exit" -Level INFO
                                return
                            }
                        }
                    }
                    
                    # Update countdown
                    $remaining = $waitUntil - (Get-Date)
                    Write-Host "`rNext run in: $($remaining.ToString('hh\:mm\:ss'))  " -NoNewline -ForegroundColor Cyan
                    
                    Start-Sleep -Seconds 1
                }
                
                Write-Host "`n" -NoNewline
            }
            
        } while (!$SingleRun -and $Mode -eq 'Console')
        
    } finally {
        # Cleanup
        Remove-Item $Script:Config.Files.PidFile -Force -ErrorAction SilentlyContinue
    }
}

function Show-Status {
    Write-Log "Exchange Mail Trace Manager Status" -Level INFO
    Write-Log "=" * 50 -Level INFO -Raw
    
    # Check configuration
    $config = Get-Configuration
    Write-Log "Configuration:" -Level INFO
    Write-Log "  Version: $($config.Version)" -Level INFO
    Write-Log "  Output Path: $($config.Paths.Base)" -Level INFO
    Write-Log "  Tenant: $($config.TenantName) ($($config.TenantId))" -Level INFO
    Write-Log "  Auth Method: $($config.AuthMethod)" -Level INFO
    
    # Check token
    $token = Get-StoredToken
    if ($token) {
        Write-Log "  Token Status: Valid until $([DateTime]$token.ExpiresAt)" -Level SUCCESS
    } else {
        Write-Log "  Token Status: Not authenticated" -Level WARNING
    }
    
    # Check state
    $state = Get-CurrentState
    if ($state.LastRunTime) {
        $lastRun = [DateTime]$state.LastRunTime
        Write-Log "  Last Run: $($lastRun.ToString('yyyy-MM-dd HH:mm:ss')) ($((Get-Date) - $lastRun) ago)" -Level INFO
    } else {
        Write-Log "  Last Run: Never" -Level INFO
    }
    
    Write-Log "  Total Messages: $($state.Statistics.TotalMessagesProcessed)" -Level INFO
    Write-Log "  Total Runs: $($state.Statistics.TotalRunsCompleted)" -Level INFO
    
    # Check scheduled task
    Write-Log "`nScheduled Task:" -Level INFO
    $task = Get-ScheduledTask -TaskName "ExchangeMailTraceManager" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Log "  Status: $($task.State)" -Level INFO
        $nextRun = ($task | Get-ScheduledTaskInfo).NextRunTime
        if ($nextRun) {
            Write-Log "  Next Run: $($nextRun.ToString('yyyy-MM-dd HH:mm:ss'))" -Level INFO
        }
    } else {
        Write-Log "  Status: Not configured" -Level WARNING
    }
    
    # Check running instance
    if (Test-Path $Script:Config.Files.PidFile) {
        $pidInfo = Get-Content $Script:Config.Files.PidFile -Raw | ConvertFrom-Json
        $process = Get-Process -Id $pidInfo.Pid -ErrorAction SilentlyContinue
        
        if ($process) {
            Write-Log "`nRunning Instance:" -Level WARNING
            Write-Log "  PID: $($pidInfo.Pid)" -Level WARNING
            Write-Log "  Mode: $($pidInfo.Mode)" -Level WARNING
            Write-Log "  Started: $($pidInfo.StartTime)" -Level WARNING
        }
    }
    
    # Check today's files
    $utcDate = (Get-Date).ToUniversalTime().Date
    $todaysCsv = Join-Path $Script:Config.Paths.Data "MailTrace_$($utcDate.ToString('yyyy-MM-dd'))_UTC.csv"
    $todaysHtml = Join-Path $Script:Config.Paths.Html "MailTrace_$($utcDate.ToString('yyyy-MM-dd'))_UTC.html"
    
    Write-Log "`nToday's Files (UTC):" -Level INFO
    if (Test-Path $todaysCsv) {
        $csvInfo = Get-Item $todaysCsv
        $rowCount = (Import-Csv $todaysCsv | Measure-Object).Count
        Write-Log "  CSV: $($csvInfo.Name) ($rowCount messages, $([Math]::Round($csvInfo.Length / 1MB, 2)) MB)" -Level INFO
    } else {
        Write-Log "  CSV: Not created yet" -Level INFO
    }
    
    if (Test-Path $todaysHtml) {
        Write-Log "  HTML: $(Split-Path $todaysHtml -Leaf)" -Level INFO
        Write-Log "  URL: file:///$($todaysHtml.Replace('\', '/'))" -Level INFO
    } else {
        Write-Log "  HTML: Not created yet" -Level INFO
    }
}
#endregion

#region Main Script Entry Point
try {
    # Load required assemblies
    Add-Type -AssemblyName System.Web
    
    # Header
    if ($Mode -eq 'Console') {
        Clear-Host
        Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          Exchange Mail Trace Manager v$($Script:Config.Version)          ║
║                                                           ║
║  Comprehensive mail trace extraction and analysis tool    ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    }
    
    # Load configuration
    $config = if (Test-Path $Script:Config.Files.Config) {
        Get-Configuration
    } else {
        $null
    }
    
    # Execute based on action
    switch ($Action) {
        'Setup' {
            Write-Log "Running setup wizard..." -Level INFO
            
            # Initialize configuration
            $config = Initialize-Configuration
            
            # Set up scheduled task
            if ($Mode -eq 'Console') {
                $setupSchedule = Read-Host "`nSet up hourly scheduled execution? (Y/N)"
                if ($setupSchedule -eq 'Y') {
                    Enable-ScheduledExecution
                }
            }
            
            Write-Log "`nSetup completed successfully!" -Level SUCCESS
            Write-Log "Run with -Action Run to start extraction" -Level INFO
        }
        
        'Auth' {
            Write-Log "Re-authenticating..." -Level INFO
            
            if (!$config) {
                Write-Log "No configuration found. Run with -Action Setup first" -Level ERROR
                exit 1
            }
            
            $tenantInfo = Get-TenantInfo -TenantIdentifier $config.TenantId
            
            if ($UseDeviceCode) {
                $tokenResponse = Start-DeviceCodeFlow -TenantInfo $tenantInfo
            } else {
                $tokenResponse = Start-BrowserAuth -TenantInfo $tenantInfo
            }
            
            if ($tokenResponse) {
                Save-Token -TokenResponse $tokenResponse -TenantInfo $tenantInfo
                Write-Log "Authentication successful!" -Level SUCCESS
            } else {
                Write-Log "Authentication failed" -Level ERROR
                exit 1
            }
        }
        
        'Run' {
            # Validate configuration
            if (!$config) {
                Write-Log "No configuration found. Run with -Action Setup first" -Level ERROR
                exit 1
            }
            
            # Run extraction
            if ($Mode -eq 'Scheduled') {
                Start-MailTraceExtraction -SingleRun
            } else {
                Start-MailTraceExtraction
            }
        }
        
        'Status' {
            Show-Status
        }
        
        'Analyze' {
            Write-Log "Analysis feature coming soon..." -Level INFO
            # TODO: Implement analysis features
        }
    }
    
} catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level DEBUG
    
    if ($Mode -eq 'Console') {
        Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
} finally {
    # Cleanup
    if ($Mode -eq 'Console' -and $Action -ne 'Status') {
        Write-Log "`nExecution completed" -Level INFO
    }
}
#endregion

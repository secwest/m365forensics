<#
.SYNOPSIS
    Enhanced end-to-end Microsoft 365 tenant forensic sweep (E3-compatible) with persistence detection.
.DESCRIPTION
    • Reads Exchange Online + Microsoft Graph artefacts without modifying tenant state.
    • Installs required modules only when absent.
    • Detects sophisticated persistence mechanisms that might survive credential resets.
    • Raises on‑screen alerts for suspicious configurations and persistence mechanisms.
    • Exports every surface to CSV under a timestamped report directory and creates HTML summary.
.PARAMETER ReportPath
    Base directory to hold CSV (and optional ZIP). Default: .\Report_<yyyyMMdd_HHmm>.
.PARAMETER InternalDomains
    One or more accepted domains – used to decide if a forwarding target is external.
.PARAMETER IncludeBeta
    Switch – collect preview/beta Graph artefacts (PrivilegedAccessGroup, ManagedTenant).
.PARAMETER Scopes
    Extra Graph delegated scopes appended to the baseline minimal set.
.PARAMETER SkipEXO / SkipGraph
    Switches to bypass EXO or Graph phases.
.PARAMETER CollectSignInLogs
    Switch – pull last 7 days of Entra ID sign‑in events (requires AuditLog.Read.All).
.PARAMETER ZipOutput
    Switch – compress *.csv into a ZIP at the end.
.PARAMETER EchoRaw
    Switch – write every collected object to the console (default = on).
.PARAMETER MaxConsoleRows
    Integer – maximum rows to emit per object (default = 50). Head 25 / Tail 25 when exceeded.
.PARAMETER StartDate
    DateTime – optional start date for filtering changes by date.
.PARAMETER EndDate
    DateTime – optional end date for filtering changes by date.
.PARAMETER FocusOnRecent
    Switch – focuses on changes in the last 30 days (sets StartDate to 30 days ago).
.EXAMPLE
    .\TenantForensicSweep.ps1 -InternalDomains contoso.com -ZipOutput -FocusOnRecent -Verbose
#>
[CmdletBinding()]
param(
    [string]   $ReportPath      = (Join-Path $PWD ("Report_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmm'))),
    [string[]] $InternalDomains = @(),
    [switch]   $IncludeBeta,
    [string[]] $Scopes          = @(),
    [switch]   $SkipEXO,
    [switch]   $SkipGraph,
    [switch]   $CollectSignInLogs,
    [switch]   $ZipOutput,
    [switch]   $EchoRaw         = $true,
    [int]      $MaxConsoleRows  = 50,
    [datetime] $StartDate,      # Add temporal filtering
    [datetime] $EndDate,        # Add temporal filtering  
    [switch]   $FocusOnRecent   # If set, focuses on changes in the last 30 days
)

# Apply time-based filtering if specified
if ($FocusOnRecent) {
    $StartDate = (Get-Date).AddDays(-30)
    $EndDate = Get-Date
    Write-Verbose "Focusing on changes in the last 30 days (since $($StartDate.ToString('yyyy-MM-dd')))"
}

# ================= helper utilities =================
function Write-Alert {
    param([string]$Message, [string]$Category = "General")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$timestamp ALERT [$Category]: $Message" -ForegroundColor Red
    
    # Track alerts for summary
    $script:Alerts += [PSCustomObject]@{
        Timestamp = $timestamp
        Category = $Category
        Message = $Message
    }
}

function Echo-Object {
    param($Object)
    if (-not $EchoRaw -or $null -eq $Object) { return }
    try {
        $rows = @($Object).Count
        if ($rows -eq 0) { return }
        if ($rows -le $MaxConsoleRows) {
            $Object | Format-Table -AutoSize | Out-Host
        } else {
            ($Object | Select-Object -First ([int]($MaxConsoleRows/2))) | Format-Table -AutoSize | Out-Host
            Write-Host "... ($($rows - $MaxConsoleRows)) rows skipped ..." -ForegroundColor DarkGray
            ($Object | Select-Object -Last ([int]($MaxConsoleRows/2)))  | Format-Table -AutoSize | Out-Host
        }
    } catch { Write-Warning "Echo failed: $_" }
}

function Export-Result {
    param($Object, [string]$Name, [switch]$NoEcho)
    if ($null -eq $Object) { return }
    $csv = Join-Path $ReportPath "$Name.csv"
    try {
        $Object | Export-Csv -NoTypeInformation -Path $csv -Encoding UTF8
        Write-Verbose "Saved -> $csv"
        
        # Add entry to file register for summary
        $script:FileRegister += [PSCustomObject]@{
            Name = $Name
            Path = $csv
            Count = @($Object).Count
            Size = (Get-Item $csv).Length
        }
    } catch { Write-Warning "Failed to export $Name : $_" }
    
    if (-not $NoEcho) {
        Echo-Object $Object
    }
}

function Ensure-Module {
    param([string]$Name, [string]$MinVersion='0', [string]$Scope='CurrentUser')
    if (-not (Get-Module -ListAvailable -Name $Name -MinimumVersion $MinVersion)) {
        Write-Verbose "Installing module $Name (scope=$Scope)…"
        try { Install-Module $Name -Scope $Scope -MinimumVersion $MinVersion -Force -ErrorAction Stop }
        catch { Throw "Unable to install $Name : $_" }
    }
}

# Function to run heavy operations in parallel jobs
function Start-ParallelOperation {
    param(
        [ScriptBlock]$ScriptBlock,
        [string]$Name,
        [int]$ThrottleLimit = 5
    )
    
    Start-Job -ScriptBlock $ScriptBlock -Name $Name
}

# Function to create HTML summary report
function Create-HTMLSummary {
    param([string]$OutputPath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Tenant Forensic Sweep Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .alert { color: red; font-weight: bold; }
        .summary { margin-bottom: 30px; }
        .summary h2 { border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        .chart { height: 250px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Microsoft 365 Tenant Forensic Sweep Summary</h1>
    <p>Generated: $(Get-Date)</p>
    
    <div class="summary">
        <h2>Alerts Summary</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
"@

    # Get alert counts by category
    $alertCategories = $script:Alerts | Group-Object -Property Category | Sort-Object -Property Count -Descending
    
    foreach ($category in $alertCategories) {
        $html += "<tr><td>$($category.Name)</td><td>$($category.Count)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
    
    <div class="summary">
        <h2>Files Generated</h2>
        <table>
            <tr><th>File</th><th>Size</th><th>Record Count</th></tr>
"@

    foreach ($file in $script:FileRegister | Sort-Object -Property Name) {
        $sizeKB = [math]::Round($file.Size/1KB, 2)
        $html += "<tr><td>$($file.Name)</td><td>$sizeKB KB</td><td>$($file.Count)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
    
    <div class="summary">
        <h2>All Alerts</h2>
        <table>
            <tr><th>Timestamp</th><th>Category</th><th>Alert</th></tr>
"@

    foreach ($alert in $script:Alerts | Sort-Object -Property Timestamp) {
        $html += "<tr><td>$($alert.Timestamp)</td><td>$($alert.Category)</td><td class='alert'>$($alert.Message)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath (Join-Path $OutputPath 'summary.html') -Encoding UTF8
    Write-Host "HTML Summary report generated: $(Join-Path $OutputPath 'summary.html')"
}

# Initialize global tracking variables
$script:Alerts = @()
$script:FileRegister = @()

$ErrorActionPreference = 'Stop'
$VerbosePreference     = $PSCmdlet.MyInvocation.BoundParameters['Verbose'] ? 'Continue' : 'SilentlyContinue'

# ==================== bootstrap =====================
New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
Start-Transcript -Path (Join-Path $ReportPath 'run.log') -Append

# =============== 1.  Exchange Online pass =============
if (-not $SkipEXO) {
    Write-Host "==== Starting Exchange Online collection phase ====" -ForegroundColor Cyan
    
    Ensure-Module 'ExchangeOnlineManagement' '3.4.0'
    Import-Module ExchangeOnlineManagement
    if (-not (Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' })) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }

    $outbound = Get-HostedOutboundSpamFilterPolicy
    Export-Result $outbound 'HostedOutboundSpamPolicy'
    foreach ($p in $outbound) {
        $mode = $p.AutoForwardingMode; if (-not $mode) { $mode = $p.AutoForwardEnabled ? 'On' : 'Off' }
        if ($mode -ne 'Off') { Write-Alert "Outbound spam policy '$($p.Name)' permits external auto-forward ($mode)" -Category "EmailForwarding" }
    }

    $remote = Get-RemoteDomain
    Export-Result $remote 'RemoteDomain'
    $remote | Where-Object { $_.AutoForwardEnabled } | ForEach-Object { 
        Write-Alert "RemoteDomain '$($_.DomainName)' re‑enables auto-forward" -Category "EmailForwarding"
    }

    $tr = Get-TransportRule
    Export-Result $tr 'TransportRule'
    $fwd = 'RedirectMessage','ForwardTo','BlindCopyTo','SendTo'
    $tr | Where-Object { $_.Actions.ActionType -match ($fwd -join '|') } | ForEach-Object { 
        Write-Alert "Transport rule '$($_.Name)' forwards/BCCs (priority $($_.Priority))" -Category "EmailForwarding"
    }

    $mbxFwd = Get-EXOMailbox -ResultSize Unlimited -Properties DeliverToMailboxAndForward,ForwardingSMTPAddress,ForwardingAddress
    Export-Result $mbxFwd 'MailboxForwarding'
    $mbxFwd | Where-Object { $_.ForwardingSMTPAddress -or $_.ForwardingAddress } | ForEach-Object {
        $t = $_.ForwardingSMTPAddress ?? $_.ForwardingAddress.PrimarySmtpAddress
        $external = ($InternalDomains.Count -eq 0) -or ($InternalDomains -notcontains ($t -split '@')[-1])
        if ($external) { 
            Write-Alert "Mailbox '$($_.UserPrincipalName)' forwards to EXTERNAL '$t'" -Category "EmailForwarding" 
        }
    }

    # Get list of mailboxes for inbox rule check
    Write-Host "Retrieving mailbox list..." -ForegroundColor Yellow
    $mbxList = Get-EXOMailbox -ResultSize Unlimited | Select-Object -ExpandProperty UserPrincipalName
    Write-Host "Found $($mbxList.Count) mailboxes" -ForegroundColor Yellow
    
    # Check inbox rules - could take time for large environments
    Write-Host "Checking inbox rules (this may take some time)..." -ForegroundColor Yellow
    $inboxOut = @()
    $processedCount = 0
    $totalCount = $mbxList.Count
    
    foreach ($upn in $mbxList) {
        $processedCount++
        $percentComplete = [math]::Round(($processedCount / $totalCount) * 100, 0)
        Write-Progress -Activity "Checking Inbox Rules" -Status "Processing mailbox $processedCount of $totalCount" -PercentComplete $percentComplete
        
        try {
            $rules = Get-InboxRule -Mailbox $upn -ErrorAction SilentlyContinue
            $inboxOut += $rules
            $rules | Where-Object { $_.RedirectTo -or $_.ForwardTo -or $_.ForwardAsAttachment } | ForEach-Object { 
                Write-Alert "Inbox rule '$($_.Name)' in '$upn' redirects/forwards" -Category "EmailForwarding"
            }
        }
        catch {
            Write-Verbose "Error getting inbox rules for $upn : $_"
        }
    }
    Write-Progress -Activity "Checking Inbox Rules" -Completed
    Export-Result $inboxOut 'InboxRules'

    # Check mailbox permissions - focusing on non-standard delegations
    Write-Host "Checking mailbox permissions..." -ForegroundColor Yellow
    $permOut = @()
    $processedCount = 0
    
    foreach ($m in $mbxList) {
        $processedCount++
        $percentComplete = [math]::Round(($processedCount / $totalCount) * 100, 0)
        Write-Progress -Activity "Checking Mailbox Permissions" -Status "Processing mailbox $processedCount of $totalCount" -PercentComplete $percentComplete
        
        try {
            $permOut += Get-MailboxPermission $m -ErrorAction SilentlyContinue | Where-Object { -not $_.IsInherited }
            $permOut += Get-RecipientPermission $m -ErrorAction SilentlyContinue | Where-Object { -not $_.IsInherited }
        }
        catch {
            Write-Verbose "Error getting permissions for $m : $_"
        }
    }
    Write-Progress -Activity "Checking Mailbox Permissions" -Completed
    Export-Result $permOut 'MailboxPermissions'
    
    $permOut | Where-Object { $_.AccessRights -match 'FullAccess|SendAs' } | ForEach-Object {
        $principal = $_.User ?? $_.Trustee
        if ($principal -match '@') {
            $ext = ($InternalDomains.Count -eq 0) -or ($InternalDomains -notcontains ($principal -split '@')[-1])
            if ($ext) { 
                Write-Alert "Mailbox '$($_.Identity)' delegated $($_.AccessRights) to EXTERNAL '$principal'" -Category "MailboxDelegation"
            }
        }
    }

    # Check for suspicious connectors
    $outConn = Get-OutboundConnector; $inConn = Get-InboundConnector
    Export-Result $outConn 'OutboundConnector'; Export-Result $inConn 'InboundConnector'
    $outConn | Where-Object { $_.SmartHosts -and ($_.SmartHosts -notmatch 'mail\.protection\.outlook\.com$') } | ForEach-Object { 
        Write-Alert "Outbound connector '$($_.Name)' smart-hosts to $($_.SmartHosts -join ',')" -Category "MailFlow"
    }

    # Check for Journaling rules (possible BCC exfiltration mechanism)
    try {
        $journalRules = Get-JournalRule
        Export-Result $journalRules 'JournalRules'
        $journalRules | ForEach-Object {
            Write-Alert "Journal rule '$($_.Name)' sends to '$($_.RecipientEmail)'" -Category "MailFlow"
        }
    } catch {
        Write-Verbose "Unable to get journal rules: $_"
    }
    
    # Check for advanced delivery settings (sometimes used for bypassing security)
    try {
        $safeAttachmentPolicy = Get-SafeAttachmentPolicy
        $safeLinksPolicy = Get-SafeLinksPolicy
        Export-Result $safeAttachmentPolicy 'SafeAttachmentPolicy'
        Export-Result $safeLinksPolicy 'SafeLinksPolicy'
        
        $safeAttachmentPolicy | Where-Object { -not $_.Enable } | ForEach-Object {
            Write-Alert "Safe Attachment Policy '$($_.Name)' is disabled" -Category "SecurityBypass"
        }
        
        $safeLinksPolicy | Where-Object { -not $_.Enable } | ForEach-Object {
            Write-Alert "Safe Links Policy '$($_.Name)' is disabled" -Category "SecurityBypass"
        }
    } catch {
        Write-Verbose "Unable to get safe attachment/links policies: $_"
    }
    
    Write-Host "Disconnecting from Exchange Online..." -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false
}

# =============== 2.  Microsoft Graph pass ============
if (-not $SkipGraph) {
    Write-Host "==== Starting Microsoft Graph collection phase ====" -ForegroundColor Cyan
    
    Ensure-Module 'Microsoft.Graph' '2.0.0'
    Import-Module Microsoft.Graph

    $base = 'Directory.Read.All','User.Read.All','Policy.Read.All','RoleManagement.Read.Directory',
            'MailboxSettings.Read','Mail.ReadBasic.All','DeviceManagementConfiguration.Read.All',
            'Application.Read.All','AppRoleAssignment.ReadWrite.All','Domain.Read.All'
    
    if ($CollectSignInLogs) { $base += 'AuditLog.Read.All' }
    if ($Scopes) { $base += $Scopes }

    Write-Host "Connecting to Microsoft Graph with scopes: $($base -join ', ')" -ForegroundColor Yellow
    if (-not (Get-MgContext)) { Connect-MgGraph -Scopes $base }

    # Get basic user information
    Write-Host "Retrieving user accounts..." -ForegroundColor Yellow
    Select-MgProfile 'v1.0'
    $allUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,OnPremisesSyncEnabled,CreatedDateTime,LastPasswordChangeDateTime
    Export-Result $allUsers 'AllUsers'
    
    # Check for recently created/modified users
    if ($FocusOnRecent -or $StartDate) {
        $filterDate = $StartDate ?? (Get-Date).AddDays(-30)
        $recentUsers = $allUsers | Where-Object { $_.CreatedDateTime -ge $filterDate }
        Export-Result $recentUsers 'RecentlyCreatedUsers'
        
        if ($recentUsers) {
            Write-Alert "Found $(($recentUsers).Count) user accounts created since $($filterDate.ToString('yyyy-MM-dd'))" -Category "RecentChanges"
        }
    }
    
    # Get role memberships
    Write-Host "Retrieving directory role memberships..." -ForegroundColor Yellow
    $roles = @()
    $roleDefinitions = Get-MgDirectoryRoleDefinition -All
    $roleActivations = Get-MgDirectoryRole -All
    
    foreach ($r in $roleActivations) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All
        foreach ($member in $members) {
            # Get more details about the member
            $memberDetails = $null
            try {
                # Try to get user details if it's a user
                $memberDetails = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
                $memberType = "User"
            } catch {
                try {
                    # Try to get service principal details if it's a service principal
                    $memberDetails = Get-MgServicePrincipal -ServicePrincipalId $member.Id -ErrorAction SilentlyContinue
                    $memberType = "ServicePrincipal"
                } catch {
                    $memberType = "Unknown"
                }
            }
            
            $roleEntry = [PSCustomObject]@{
                RoleId = $r.Id
                RoleName = $r.DisplayName
                MemberId = $member.Id
                MemberType = $memberType
                DisplayName = $memberDetails ? $memberDetails.DisplayName : $member.Id
                UserPrincipalName = $memberDetails ? $memberDetails.UserPrincipalName : ""
                CreatedDateTime = $memberDetails ? $memberDetails.CreatedDateTime : $null
            }
            
            $roles += $roleEntry
        }
    }
    Export-Result $roles 'RoleMembers'
    
    # Check for critical role assignments 
    $criticalRoles = @('Global Administrator', 'Privileged Role Administrator', 'Application Administrator', 
                       'Cloud Application Administrator', 'User Administrator', 'Exchange Administrator',
                       'Hybrid Identity Administrator', 'Directory Synchronization Accounts')
    
    $criticalRoleMembers = $roles | Where-Object { $criticalRoles -contains $_.RoleName }
    Export-Result $criticalRoleMembers 'CriticalRoleMembers'
    
    # Alert on service principals with critical roles
    $criticalRoleMembers | Where-Object { $_.MemberType -eq "ServicePrincipal" } | ForEach-Object {
        Write-Alert "Service Principal '$($_.DisplayName)' has critical role '$($_.RoleName)'" -Category "PrivilegedAccess"
    }
    
    # Check for suspicious email forwarding via Graph
    Write-Host "Checking for suspicious email forwarding..." -ForegroundColor Yellow
    $suspFwd = @()
    foreach ($u in $allUsers) {
        try { 
            $mbx = Get-MgUserMailboxSetting -UserId $u.Id
            if ($mbx.ForwardingSmtpAddress) { 
                $suspFwd += [pscustomobject]@{
                    User = $u.UserPrincipalName
                    ForwardingAddress = $mbx.ForwardingSmtpAddress
                    ForwardAndKeep = $mbx.ForwardingSettings.ForwardingSmtpAddress ? $true : $false 
                }
                
                $external = ($InternalDomains.Count -eq 0) -or ($InternalDomains -notcontains (($mbx.ForwardingSmtpAddress -split '@')[-1]))
                if ($external) {
                    Write-Alert "User '$($u.UserPrincipalName)' has Graph-level forwarding to EXTERNAL '$($mbx.ForwardingSmtpAddress)'" -Category "EmailForwarding"
                }
            }
        } catch {}
        
        # Check message rules via Graph
        try {
            Get-MgUserMessageRule -UserId $u.Id -All -ErrorAction SilentlyContinue | Where-Object { $_.ForwardToRecipients -or $_.RedirectToRecipients } | ForEach-Object {
                $rule = $_
                $suspFwd += [pscustomobject]@{
                    User = $u.UserPrincipalName
                    Rule = $rule.DisplayName
                    ForwardTo = ($rule.ForwardToRecipients -join ';')
                    RedirectTo = ($rule.RedirectToRecipients -join ';')
                    Enabled = $rule.IsEnabled
                }
                
                # Check if any forwarding is to external domains
                $externalForward = $false
                $rule.ForwardToRecipients | ForEach-Object {
                    if (($InternalDomains.Count -eq 0) -or ($InternalDomains -notcontains (($_ -split '@')[-1]))) {
                        $externalForward = $true
                    }
                }
                
                $rule.RedirectToRecipients | ForEach-Object {
                    if (($InternalDomains.Count -eq 0) -or ($InternalDomains -notcontains (($_ -split '@')[-1]))) {
                        $externalForward = $true
                    }
                }
                
                if ($externalForward) {
                    Write-Alert "User '$($u.UserPrincipalName)' has message rule '$($rule.DisplayName)' forwarding to external recipients" -Category "EmailForwarding"
                }
            }
        } catch {}
    }
    Export-Result $suspFwd 'SuspiciousForwarding_Graph'
    
    # Check application registrations and service principals
    Write-Host "Analyzing application registrations and service principals..." -ForegroundColor Yellow
    
    # Get all app registrations
    $appRegs = Get-MgApplication -All 
    Export-Result $appRegs 'AppRegistrations'
    
    # Get all service principals
    $servicePrincipals = Get-MgServicePrincipal -All
    Export-Result $servicePrincipals 'ServicePrincipals'
    
    # Find service principals with credentials
    $svcSecrets = $servicePrincipals | Where-Object { $_.PasswordCredentials -or $_.KeyCredentials } | Select-Object -Property Id, AppId, DisplayName, ServicePrincipalType
    Export-Result $svcSecrets 'ServicePrincipalsWithSecrets'
    
    # Detect credentials/secrets expiring soon (possible last-minute attacker additions)
    $threshold = (Get-Date).AddDays(90)
    $suspiciousSecrets = @()
    
    # Check app registration secrets/certs
    foreach ($app in $appRegs) {
        # Alert on very recently created apps
        if ($app.CreatedDateTime -gt (Get-Date).AddDays(-7)) {
            Write-Alert "Recently created app registration '$($app.DisplayName)' ($(($app.CreatedDateTime).ToString('yyyy-MM-dd')))" -Category "ApplicationSecurity"
        }
        
        # Track all credentials
        foreach ($cred in $app.PasswordCredentials) {
            $suspiciousSecrets += [PSCustomObject]@{
                Type = "AppRegistration"
                ObjectId = $app.Id
                DisplayName = $app.DisplayName
                CredentialType = "Secret"
                EndDateTime = $cred.EndDateTime
                CreatedDateTime = $cred.StartDateTime
                KeyId = $cred.KeyId
                RecentlyCreated = $cred.StartDateTime -gt (Get-Date).AddDays(-30)
            }
        }
        
        foreach ($cert in $app.KeyCredentials) {
            $suspiciousSecrets += [PSCustomObject]@{
                Type = "AppRegistration"
                ObjectId = $app.Id
                DisplayName = $app.DisplayName
                CredentialType = "Certificate"
                EndDateTime = $cert.EndDateTime
                CreatedDateTime = $cert.StartDateTime
                KeyId = $cert.KeyId
                RecentlyCreated = $cert.StartDateTime -gt (Get-Date).AddDays(-30)
            }
        }
    }
    
    # Check service principal secrets/certs
    foreach ($sp in $servicePrincipals) {
        foreach ($cred in $sp.PasswordCredentials) {
            $suspiciousSecrets += [PSCustomObject]@{
                Type = "ServicePrincipal"
                ObjectId = $sp.Id
                DisplayName = $sp.DisplayName
                CredentialType = "Secret"
                EndDateTime = $cred.EndDateTime
                CreatedDateTime = $cred.StartDateTime
                KeyId = $cred.KeyId
                RecentlyCreated = $cred.StartDateTime -gt (Get-Date).AddDays(-30)
            }
        }
        
        foreach ($cert in $sp.KeyCredentials) {
            $suspiciousSecrets += [PSCustomObject]@{
                Type = "ServicePrincipal"
                ObjectId = $sp.Id
                DisplayName = $sp.DisplayName
                CredentialType = "Certificate"
                EndDateTime = $cert.EndDateTime
                CreatedDateTime = $cert.StartDateTime
                KeyId = $cert.KeyId
                RecentlyCreated = $cert.StartDateTime -gt (Get-Date).AddDays(-30)
            }
        }
    }
    
    Export-Result $suspiciousSecrets 'CredentialsInventory'
    
    # Alert on recently created credentials
    $recentCredentials = $suspiciousSecrets | Where-Object { $_.RecentlyCreated -eq $true }
    Export-Result $recentCredentials 'RecentlyCreatedCredentials'
    
    $recentCredentials | ForEach-Object {
        Write-Alert "Recently added $($_.CredentialType) for $($_.Type) '$($_.DisplayName)' on $(($_.CreatedDateTime).ToString('yyyy-MM-dd'))" -Category "ApplicationSecurity"
    }
    
    # Get OAuth permission grants
    Write-Host "Retrieving OAuth permission grants..." -ForegroundColor Yellow
    $grants = Get-MgOauth2PermissionGrant -All
    Export-Result $grants 'OAuthGrants'
    
    # Get high-risk permissions
    $highRiskPermissions = @(
        'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
        'User.ReadWrite.All', 'Group.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite'
    )
    
    # Process grants to extract readable information
    $processedGrants = @()
    foreach ($grant in $grants) {
        $clientApp = $servicePrincipals | Where-Object { $_.Id -eq $grant.ClientId }
        $resourceApp = $servicePrincipals | Where-Object { $_.Id -eq $grant.ResourceId }
        
        # Parse scopes
        $scopesList = $grant.Scope -split ' '
        $hasHighRiskScope = $false
        
        foreach ($scope in $scopesList) {
            if ($highRiskPermissions -contains $scope) {
                $hasHighRiskScope = $true
            }
        }
        
        $processedGrants += [PSCustomObject]@{
            GrantId = $grant.Id
            ClientAppId = $grant.ClientId
            ClientAppName = $clientApp ? $clientApp.DisplayName : "Unknown"
            ResourceAppId = $grant.ResourceId
            ResourceAppName = $resourceApp ? $resourceApp.DisplayName : "Unknown"
            ConsentType = $grant.ConsentType
            PrincipalId = $grant.PrincipalId
            Scopes = $grant.Scope
            HasHighRiskScope = $hasHighRiskScope
        }
        
        if ($hasHighRiskScope) {
            Write-Alert "OAuth grant to '$($clientApp ? $clientApp.DisplayName : $grant.ClientId)' has high-risk permissions" -Category "PermissionsRisk"
        }
    }
    
    Export-Result $processedGrants 'ProcessedOAuthGrants'
    
    # Check for administrative units (often overlooked for privilege escalation)
    Write-Host "Checking Administrative Units..." -ForegroundColor Yellow
    try {
        $adminUnits = Get-MgDirectoryAdministrativeUnit -All
        Export-Result $adminUnits 'AdministrativeUnits'
        
        $adminUnitMembers = @()
        foreach ($au in $adminUnits) {
            try {
                $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
                foreach ($member in $members) {
                    $adminUnitMembers += [PSCustomObject]@{
                        AdminUnitId = $au.Id
                        AdminUnitName = $au.DisplayName
                        MemberId = $member.Id
                        MemberOdataType = $member.AdditionalProperties.'@odata.type'
                    }
                }
            } catch {
                Write-Verbose "Error getting members for Administrative Unit $($au.DisplayName): $_"
            }
        }
        Export-Result $adminUnitMembers 'AdministrativeUnitMembers'
        
        if ($adminUnits) {
            Write-Host "Found $($adminUnits.Count) Administrative Units" -ForegroundColor Yellow
        }
    } catch {
        Write-Verbose "Error retrieving Administrative Units: $_"
    }
    
    # Examine domain federation settings
    Write-Host "Checking domain federation settings..." -ForegroundColor Yellow
    $domains = Get-MgDomain -All
    $federatedDomains = $domains | Where-Object { $_.AuthenticationType -eq 'Federated' }
    Export-Result $domains 'AllDomains'
    Export-Result $federatedDomains 'FederatedDomains'
    
    # Report on federated domains
    if ($federatedDomains) {
        Write-Alert "Found $($federatedDomains.Count) federated domains" -Category "Federation"
        
        # Get federation settings for each federated domain
        $federationSettings = @()
        foreach ($domain in $federatedDomains) {
            try {
                $fedSettings = Get-MgDomainFederationConfiguration -DomainId $domain.Id
                
                $federationSettings += [PSCustomObject]@{
                    Domain = $domain.Id
                    IssuerUri = $fedSettings.IssuerUri 
                    ActiveSignInUri = $fedSettings.ActiveSignInUri
                    PassiveSignInUri = $fedSettings.PassiveSignInUri
                    MetadataExchangeUri = $fedSettings.MetadataExchangeUri
                    SigningCertificate = $fedSettings.SigningCertificate ? "Present" : "Missing"
                }
                
                Write-Alert "Domain '$($domain.Id)' federated with '$($fedSettings.IssuerUri)'" -Category "Federation"
            } catch {
                Write-Verbose "Federation details error for $($domain.Id): $_"
            }
        }
        Export-Result $federationSettings 'FederationSettings'
    }
    
    # Check conditional access policies
    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Yellow
    $ca = Get-MgIdentityConditionalAccessPolicy -All
    Export-Result $ca 'CAPolicies'
    
    # Flag disabled CA policies
    $disabledCAPolicies = $ca | Where-Object { $_.State -eq 'disabled' }
    if ($disabledCAPolicies) {
        Export-Result $disabledCAPolicies 'DisabledCAPolicies'
        $disabledCAPolicies | ForEach-Object {
            Write-Alert "Conditional Access policy '$($_.DisplayName)' is disabled" -Category "IdentitySecurity"
        }
    }
    
    # Check named locations for CA
    $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
    Export-Result $namedLocations 'NamedLocations'
    
    # Check tenant relationship information
    try {
        $partnerRelationships = Get-MgContract -All
        Export-Result $partnerRelationships 'PartnerRelationships'
        
        if ($partnerRelationships) {
            Write-Alert "Found $($partnerRelationships.Count) partner relationships" -Category "PartnerAccess"
        }
    } catch {
        Write-Verbose "Failed to get partner relationships: $_"
    }
    
    # Examine authentication methods (especially FIDO keys, phone numbers that could be backdoors)
    Write-Host "Checking authentication methods..." -ForegroundColor Yellow
    try {
        Select-MgProfile 'beta'
        $authMethods = @()
        $processedCount = 0
        $totalCount = $allUsers.Count
        
        foreach ($user in $allUsers) {
            $processedCount++
            $percentComplete = [math]::Round(($processedCount / $totalCount) * 100, 0)
            Write-Progress -Activity "Checking Authentication Methods" -Status "Processing user $processedCount of $totalCount" -PercentComplete $percentComplete
            
            try {
                $methods = Get-MgBetaUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                foreach ($method in $methods) {
                    $methodInfo = [PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        MethodId = $method.Id
                        MethodType = $method.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                    }
                    
                    # Add specific details based on method type
                    switch -Regex ($method.AdditionalProperties.'@odata.type') {
                        'phoneAuthenticationMethod {
                            $methodInfo | Add-Member -NotePropertyName PhoneNumber -NotePropertyValue $method.AdditionalProperties.phoneNumber
                            $methodInfo | Add-Member -NotePropertyName PhoneType -NotePropertyValue $method.AdditionalProperties.phoneType
                        }
                        'fido2AuthenticationMethod {
                            $methodInfo | Add-Member -NotePropertyName Model -NotePropertyValue $method.AdditionalProperties.model
                            $methodInfo | Add-Member -NotePropertyName CreatedDateTime -NotePropertyValue $method.AdditionalProperties.createdDateTime
                        }
                        'microsoftAuthenticatorAuthenticationMethod {
                            $methodInfo | Add-Member -NotePropertyName DeviceTag -NotePropertyValue $method.AdditionalProperties.deviceTag
                            $methodInfo | Add-Member -NotePropertyName DisplayName -NotePropertyValue $method.AdditionalProperties.displayName
                        }
                        'emailAuthenticationMethod {
                            $methodInfo | Add-Member -NotePropertyName EmailAddress -NotePropertyValue $method.AdditionalProperties.emailAddress
                        }
                    }
                    
                    $authMethods += $methodInfo
                }
            } catch {
                Write-Verbose "Could not get auth methods for $($user.UserPrincipalName): $_"
            }
        }
        Write-Progress -Activity "Checking Authentication Methods" -Completed
        Export-Result $authMethods 'AuthenticationMethods'
        
        # Check for recently added authentication methods
        if ($StartDate -or $FocusOnRecent) {
            $filterDate = $StartDate ?? (Get-Date).AddDays(-30)
            $recentAuthMethods = $authMethods | Where-Object { 
                $_.MethodType -eq 'fido2AuthenticationMethod' -and 
                $_.CreatedDateTime -and 
                [datetime]$_.CreatedDateTime -gt $filterDate 
            }
            
            if ($recentAuthMethods) {
                Export-Result $recentAuthMethods 'RecentlyAddedFIDOKeys'
                Write-Alert "Found $($recentAuthMethods.Count) FIDO keys added since $($filterDate.ToString('yyyy-MM-dd'))" -Category "AuthenticationMethods"
            }
        }
        
        # Check for authentication methods on privileged accounts
        $privUserUPNs = $criticalRoleMembers | Where-Object { $_.MemberType -eq "User" } | Select-Object -ExpandProperty UserPrincipalName -Unique
        $privUserAuthMethods = $authMethods | Where-Object { $privUserUPNs -contains $_.UserPrincipalName }
        Export-Result $privUserAuthMethods 'PrivilegedUserAuthMethods'
        
        Select-MgProfile 'v1.0'
    } catch {
        Write-Warning "Authentication methods collection failed: $_"
        Select-MgProfile 'v1.0'
    }
    
    # Check for devices
    Write-Host "Retrieving registered and joined devices..." -ForegroundColor Yellow
    $devices = Get-MgDevice -All
    Export-Result $devices 'AllDevices'
    
    # Focus on recently registered devices
    if ($StartDate -or $FocusOnRecent) {
        $filterDate = $StartDate ?? (Get-Date).AddDays(-30)
        $recentDevices = $devices | Where-Object { $_.RegistrationDateTime -gt $filterDate }
        
        if ($recentDevices) {
            Export-Result $recentDevices 'RecentlyRegisteredDevices'
            Write-Alert "Found $($recentDevices.Count) devices registered since $($filterDate.ToString('yyyy-MM-dd'))" -Category "DeviceSecurity"
        }
    }
    
    # Check sign-in logs if requested
    if ($CollectSignInLogs) {
        Write-Host "Retrieving sign-in logs (last 7 days)..." -ForegroundColor Yellow
        $since = (Get-Date).AddDays(-7).ToString('o')
        $signin = Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $since"
        Export-Result $signin 'SignInLogs_7d'
        
        # Check for sign-ins from unusual locations
        $signInsByLocation = $signin | Group-Object -Property Location
        $signInsByCountry = $signin | Group-Object -Property { $_.Location.CountryOrRegion }
        Export-Result $signInsByLocation 'SignInsByLocation'
        Export-Result $signInsByCountry 'SignInsByCountry'
        
        # Check for risky sign-ins
        Write-Host "Checking for risky sign-ins..." -ForegroundColor Yellow
        try {
            $riskySignins = Get-MgRiskyUser -All
            Export-Result $riskySignins 'RiskyUsers'
            
            if ($riskySignins) {
                Write-Alert "Found $($riskySignins.Count) users with risk detections" -Category "RiskDetection"
            }
        } catch {
            Write-Verbose "Unable to get risky users: $_"
        }
        
        # Get user sign-in activity to detect dormant privileged accounts
        Write-Host "Analyzing user sign-in activity..." -ForegroundColor Yellow
        $signInActivity = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,SignInActivity | 
                          Select-Object Id,DisplayName,UserPrincipalName,
                          @{n='LastSignInDateTime';e={$_.SignInActivity.LastSignInDateTime}},
                          @{n='LastNonInteractiveSignInDateTime';e={$_.SignInActivity.LastNonInteractiveSignInDateTime}}
        
        # Find users with no sign-in activity
        $noSignIn = $signInActivity | Where-Object { -not $_.LastSignInDateTime -and -not $_.LastNonInteractiveSignInDateTime }
        Export-Result $noSignIn 'NoSignInActivity'
        
        # Check which of these have privileges
        $noSignInWithRoles = @()
        foreach ($user in $noSignIn) {
            $userRoles = $roles | Where-Object { $_.MemberId -eq $user.Id }
            if ($userRoles) {
                $noSignInWithRoles += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    Roles = ($userRoles | Select-Object -ExpandProperty RoleName) -join '; '
                }
                
                Write-Alert "Privileged account '$($user.UserPrincipalName)' has no sign-in activity" -Category "DormantAccounts"
            }
        }
        Export-Result $noSignInWithRoles 'NoSignInPrivilegedAccounts'
    }
    
    # Check custom directory roles (preview feature in some tenants)
    Write-Host "Checking for custom directory roles..." -ForegroundColor Yellow
    try {
        $customRoles = Get-MgRoleManagementDirectoryRoleDefinition -All | Where-Object { -not $_.IsBuiltIn }
        Export-Result $customRoles 'CustomDirectoryRoles'
        
        if ($customRoles) {
            Write-Alert "Found $($customRoles.Count) custom directory roles" -Category "PrivilegedAccess"
            foreach ($role in $customRoles) {
                Write-Alert "Custom role '$($role.DisplayName)' detected" -Category "PrivilegedAccess"
            }
        }
    } catch {
        Write-Verbose "Custom roles not available: $_"
    }
    
    # Check for PIM eligible role assignments (time-bound privileged access)
    Write-Host "Checking PIM eligible assignments..." -ForegroundColor Yellow
    try {
        Select-MgProfile 'beta'
        $eligibleRoles = Get-MgBetaRoleManagementDirectoryRoleEligibilityScheduleInstance -All
        Export-Result $eligibleRoles 'PIMEligibleRoleAssignments'
        
        if ($eligibleRoles) {
            Write-Alert "Found $($eligibleRoles.Count) PIM eligible role assignments" -Category "PrivilegedAccess"
        }
        
        Select-MgProfile 'v1.0'
    } catch {
        Write-Verbose "PIM eligible roles not available: $_"
        Select-MgProfile 'v1.0'
    }
    
    # Get B2B guest information
    Write-Host "Retrieving B2B guest information..." -ForegroundColor Yellow
    try {
        $guests = $allUsers | Where-Object { $_.UserType -eq 'Guest' }
        Export-Result $guests 'GuestUsers'
        
        if ($FocusOnRecent -or $StartDate) {
            $filterDate = $StartDate ?? (Get-Date).AddDays(-30)
            $recentGuests = $guests | Where-Object { $_.CreatedDateTime -ge $filterDate }
            Export-Result $recentGuests 'RecentlyAddedGuests'
            
            if ($recentGuests) {
                Write-Alert "Found $($recentGuests.Count) guest accounts added since $($filterDate.ToString('yyyy-MM-dd'))" -Category "ExternalAccess"
            }
        }
        
        # Check for guest invitations
        $invitations = Get-MgInvitation -All
        Export-Result $invitations 'GuestInvitations'
        
        # Check if any guests have privileged roles
        $guestPrivileges = $roles | Where-Object { ($guests | Select-Object -ExpandProperty Id) -contains $_.MemberId }
        
        if ($guestPrivileges) {
            Export-Result $guestPrivileges 'PrivilegedGuestAccounts'
            Write-Alert "Found $($guestPrivileges.Count) roles assigned to guest accounts" -Category "PrivilegedAccess"
            
            $guestPrivileges | ForEach-Object {
                Write-Alert "Guest account has role '$($_.RoleName)'" -Category "PrivilegedAccess"
            }
        }
    } catch {
        Write-Verbose "Error retrieving guest information: $_"
    }
    
    # Check for B2B policy
    try {
        $b2bPolicy = Get-MgPolicyAuthorizationPolicy
        Export-Result $b2bPolicy 'B2BPolicy'
    } catch {
        Write-Verbose "B2B policy retrieval failed: $_"
    }
    
    if ($IncludeBeta) {
        Write-Host "Collecting beta API information..." -ForegroundColor Yellow
        Select-MgProfile 'beta'
        try { 
            $pag = Get-MgBetaPrivilegedAccessGroupAssignmentScheduleInstance -All
            Export-Result $pag 'PrivilegedAccessGroupAssignments_beta' 
            
            if ($pag) {
                Write-Alert "Found $($pag.Count) Privileged Access Group assignments" -Category "PrivilegedAccess"
            }
        } catch {
            Write-Verbose "Error getting privileged access group assignments: $_"
        }
        
        try { 
            $mnt = Get-MgBetaTenantRelationshipManagedTenant -All
            Export-Result $mnt 'ManagedTenantDelegations_beta' 
            
            if ($mnt) {
                Write-Alert "Found $($mnt.Count) managed tenant delegations" -Category "PartnerAccess"
            }
        } catch {
            Write-Verbose "Error getting managed tenant relationships: $_"
        }
        
        # Try to get tenant settings that might reveal security configurations
        try {
            $tenantSettings = Get-MgBetaOrganization -Select id,displayName,securityComplianceCenter,tenantBrandingProperties,mobileDeviceManagementAuthority,privacyProfile
            Export-Result $tenantSettings 'TenantSettings_beta'
        } catch {
            Write-Verbose "Error getting tenant settings: $_"
        }
        
        Select-MgProfile 'v1.0'
    }
    
    Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
    Disconnect-MgGraph
}

# =============== 3. Additional Security Checks ============
Write-Host "==== Running additional security checks ====" -ForegroundColor Cyan

# Check local reports for high risk indicators
Write-Host "Analyzing results for additional security insights..." -ForegroundColor Yellow

# Cross-reference findings for more sophisticated indicators
$securityInsights = @()

# Check if the same external domains are used across different forwarding mechanisms
$forwardingCSVs = @(
    (Join-Path $ReportPath 'MailboxForwarding.csv'),
    (Join-Path $ReportPath 'SuspiciousForwarding_Graph.csv'),
    (Join-Path $ReportPath 'InboxRules.csv')
)

$externalDomains = @()
foreach ($csv in $forwardingCSVs) {
    if (Test-Path $csv) {
        try {
            $data = Import-Csv $csv
            
            # Extract domains from potential forwarding addresses
            foreach ($row in $data) {
                if ($row.ForwardingSMTPAddress) {
                    $domain = ($row.ForwardingSMTPAddress -split '@')[-1]
                    if ($domain -and ($InternalDomains -notcontains $domain)) {
                        $externalDomains += $domain
                    }
                }
                
                if ($row.ForwardingAddress) {
                    $domain = ($row.ForwardingAddress -split '@')[-1]
                    if ($domain -and ($InternalDomains -notcontains $domain)) {
                        $externalDomains += $domain
                    }
                }
                
                if ($row.ForwardTo) {
                    $addresses = $row.ForwardTo -split ';'
                    foreach ($addr in $addresses) {
                        $domain = ($addr -split '@')[-1]
                        if ($domain -and ($InternalDomains -notcontains $domain)) {
                            $externalDomains += $domain
                        }
                    }
                }
                
                if ($row.RedirectTo) {
                    $addresses = $row.RedirectTo -split ';'
                    foreach ($addr in $addresses) {
                        $domain = ($addr -split '@')[-1]
                        if ($domain -and ($InternalDomains -notcontains $domain)) {
                            $externalDomains += $domain
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "Error analyzing $csv : $_"
        }
    }
}

$externalDomainStats = $externalDomains | Group-Object | Sort-Object -Property Count -Descending
Export-Result $externalDomainStats 'ExternalForwardingDomains'

# Alert on domains that appear more than once in forwarding rules
$frequentExternalDomains = $externalDomainStats | Where-Object { $_.Count -gt 1 }
if ($frequentExternalDomains) {
    foreach ($domain in $frequentExternalDomains) {
        $securityInsights += [PSCustomObject]@{
            Category = "DataExfiltration"
            Finding = "Multiple forwarding to same external domain"
            Detail = "Domain '$($domain.Name)' is used in $($domain.Count) different forwarding configurations"
            RiskLevel = "High"
        }
        
        Write-Alert "Multiple forwarding rules ($($domain.Count)) pointing to domain '$($domain.Name)'" -Category "DataExfiltration"
    }
}

# Check for potential backdoor signs
$potentialBackdoors = @()

# Check for disabled MFA on privileged accounts
if (Test-Path (Join-Path $ReportPath 'AuthenticationMethods.csv')) {
    try {
        $authMethods = Import-Csv (Join-Path $ReportPath 'AuthenticationMethods.csv')
        if (Test-Path (Join-Path $ReportPath 'CriticalRoleMembers.csv')) {
            $criticalMembers = Import-Csv (Join-Path $ReportPath 'CriticalRoleMembers.csv')
            
            # Group methods by user
            $methodsByUser = $authMethods | Group-Object -Property UserPrincipalName
            
            # Check critical users with no MFA
            foreach ($user in $criticalMembers) {
                $userMethods = $methodsByUser | Where-Object { $_.Name -eq $user.UserPrincipalName }
                
                $hasMFA = $false
                if ($userMethods) {
                    $hasMFA = $userMethods.Group | Where-Object { 
                        $_.MethodType -in @('microsoftAuthenticatorAuthenticationMethod', 'fido2AuthenticationMethod', 'phoneAuthenticationMethod') 
                    }
                }
                
                if (-not $hasMFA) {
                    $potentialBackdoors += [PSCustomObject]@{
                        Type = "NoMFA"
                        UserPrincipalName = $user.UserPrincipalName
                        Role = $user.RoleName
                        Detail = "Critical role without MFA protection"
                    }
                    
                    Write-Alert "Privileged account '$($user.UserPrincipalName)' with role '$($user.RoleName)' lacks MFA" -Category "AuthenticationSecurity"
                }
            }
        }
    } catch {
        Write-Verbose "Error analyzing authentication methods: $_"
    }
}

# Export potential backdoor indicators
Export-Result $potentialBackdoors 'PotentialBackdoors'
Export-Result $securityInsights 'SecurityInsights'

# =============== 4.  Persist / summary ==================
Write-Host "==== Generating final reports ====" -ForegroundColor Cyan

if ($ZipOutput) {
    Write-Host "Compressing results..." -ForegroundColor Yellow
    Compress-Archive -Path (Join-Path $ReportPath '*.csv') -DestinationPath "$ReportPath.zip" -Force
    Write-Host "Report compressed -> $ReportPath.zip" -ForegroundColor Green
}

# Generate HTML summary
Create-HTMLSummary -OutputPath $ReportPath

Write-Host "================= SUMMARY FILE LIST ================" -ForegroundColor Green
Get-ChildItem $ReportPath -Filter *.csv | ForEach-Object { Write-Host $_.FullName }
Write-Host "====================================================" -ForegroundColor Green

# Alert count by category
Write-Host "================= ALERT SUMMARY ===================" -ForegroundColor Yellow
$alertCategories = $script:Alerts | Group-Object -Property Category | Sort-Object -Property Count -Descending
foreach ($category in $alertCategories) {
    Write-Host "$($category.Name): $($category.Count) alerts" -ForegroundColor Yellow
}
Write-Host "====================================================" -ForegroundColor Yellow

# Completion message
Write-Host "Forensic sweep completed. Review 'summary.html' for detailed findings." -ForegroundColor Green
Write-Host "Time: $(Get-Date)" -ForegroundColor Green

Stop-Transcript

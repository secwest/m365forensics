<#
.SYNOPSIS
    Scans a Microsoft 365 E3 tenant for common attacker persistence techniques.
.DESCRIPTION
    This script checks various configurations across Exchange Online, Azure AD (Entra ID),
    SharePoint Online, Teams, Power Platform, and other services based on a predefined
    list of potential persistence points relevant for M365 E3 subscriptions.
    It outputs findings to the console and to text files in a timestamped report directory.
.NOTES
    Version: 3.24
    Author: Dragos Ruiu
    Requires: PowerShell 7.2+, ExchangeOnlineManagement module, Microsoft.Graph module. MSOnline module (for DAP check).
    Permissions: Global Administrator or equivalent read permissions across M365 services.

#>

#region Script Setup and Configuration

# --- Script Configuration ---
$ReportBaseDir = "C:\M365_Persistence_Reports" # Change if needed
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportDir = Join-Path -Path $ReportBaseDir -ChildPath "M365_Persistence_Check_$Timestamp"
$MainLogFile = Join-Path -Path $ReportDir -ChildPath "Main_Report_$Timestamp.txt"
$AlertLogFile = Join-Path -Path $ReportDir -ChildPath "Alerts_Summary_$Timestamp.txt"
$LookbackDays = 30 # For "recent" checks
$CertExpiryWarningDays = 30 # For certificate expiry warnings

# --- Create Report Directory ---
try {
    if (-not (Test-Path $ReportDir)) {
        New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
        Write-Host "Report directory created at $ReportDir" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to create report directory at $ReportDir. Please check permissions and path. Error: $($_.Exception.Message)"
    exit 1
}

# --- Logging Function ---
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Type = "INFO", # INFO, WARN, ERROR, ALERT, SECTION, SUBSECTION

        [Parameter(Mandatory = $false)]
        [string]$SpecificLogFile = $null,

        [Parameter(Mandatory = $false)]
        [switch]$IsAlert
    )

    $LogEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Type] $Message"

    # Console Output
    switch ($Type) {
        "INFO"       { Write-Host $LogEntry }
        "WARN"       { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"      { Write-Host $LogEntry -ForegroundColor Red }
        "ALERT"      { Write-Host $LogEntry -ForegroundColor Magenta }
        "SECTION"    { Write-Host "--------------------------------------------------" ; Write-Host $LogEntry -ForegroundColor Cyan; Write-Host "--------------------------------------------------" }
        "SUBSECTION" { Write-Host "--- $($LogEntry) ---" -ForegroundColor Cyan }
        default      { Write-Host $LogEntry }
    }

    # Main Log File Output
    Add-Content -Path $MainLogFile -Value $LogEntry

    # Specific Log File Output (if provided)
    if ($null -ne $SpecificLogFile) {
        try {
            $FullSpecificLogPath = Join-Path -Path $ReportDir -ChildPath $SpecificLogFile
            Add-Content -Path $FullSpecificLogPath -Value $LogEntry
        }
        catch {
            Add-Content -Path $MainLogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to write to specific log file $SpecificLogFile: $($_.Exception.Message)"
        }
    }

    # Alert Summary Log File
    if ($IsAlert.IsPresent) {
        Add-Content -Path $AlertLogFile -Value $LogEntry
    }
}

Write-Log -Message "Script execution started." -Type "INFO"
Write-Log -Message "Reports will be saved in: $ReportDir" -Type "INFO"
Write-Log -Message "Ensure you are running this script with appropriate administrative permissions." -Type "WARN"
Write-Log -Message "PowerShell 7.2+ is recommended." -Type "INFO"

# --- Module Installation and Import ---
function Install-Or-Import-Module {
    param (
        [string]$ModuleName,
        [string]$NeededFor,
        [switch]$Optional # If the module is optional and script can continue without it
    )
    Write-Log -Message "Checking for module: $ModuleName (Needed for: $NeededFor)"
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log -Message "Module $ModuleName not found. Attempting to install..." -Type "WARN"
        try {
            Install-Module $ModuleName -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -Confirm:$false
            Write-Log -Message "Module $ModuleName installed successfully." -Type "INFO"
        }
        catch {
            Write-Log -Message "Failed to install module $ModuleName. Error: $($_.Exception.Message). Please install it manually and re-run the script." -Type "ERROR"
            if (-not $Optional) { return $false } # Only return false if mandatory
            return $true # If optional, installation failure is not critical for this function's success criteria
        }
    }
    else {
         Write-Log -Message "Module $ModuleName is available."
    }

    try {
        Import-Module $ModuleName -ErrorAction Stop
        Write-Log -Message "Module $ModuleName imported successfully." -Type "INFO"
        return $true
    }
    catch {
        Write-Log -Message "Failed to import module $ModuleName. Error: $($_.Exception.Message)." -Type "ERROR"
        if (-not $Optional) { return $false }
        return $true # If optional, import failure is not critical for this function's success criteria
    }
}

$ModulesRequired = @(
    @{ Name = "ExchangeOnlineManagement"; NeededFor = "Exchange Online Checks"; Optional = $false },
    @{ Name = "Microsoft.Graph"; NeededFor = "Azure AD, SharePoint, Teams, and other Graph API checks"; Optional = $false },
    @{ Name = "MSOnline"; NeededFor = "DAP Partner Relationship Checks (Legacy)"; Optional = $true } # MSOnline is optional for DAP
)

foreach ($module in $ModulesRequired) {
    if (-not (Install-Or-Import-Module -ModuleName $module.Name -NeededFor $module.NeededFor -Optional $module.Optional)) {
        if (-not $module.Optional) {
             Write-Log -Message "A mandatory module ($($module.Name)) could not be installed or imported. Script might not function fully or may exit." -Type "ERROR"
             # Consider exiting if a truly critical module fails, e.g. exit 1
        }
    }
}

# --- Global Variables for Connections ---
$ExoConnected = $false
$GraphConnected = $false
$MSOnlineConnected = $false
$TenantDomain = $null 
$TenantId = $null # To store current tenant ID
$AcceptedDomains = @() 

#endregion Script Setup and Configuration

#region Connection Functions

function Connect-ToExchangeOnline {
    Write-Log -Message "Attempting to connect to Exchange Online..." -Type "INFO"
    try {
        $currentExoSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' }
        if ($currentExoSession.Count -gt 0) {
            Write-Log -Message "Already connected to Exchange Online." -Type "INFO"
            $script:ExoConnected = $true
        } else {
            Connect-ExchangeOnline -ShowBanner:$false
            Write-Log -Message "Successfully connected to Exchange Online." -Type "INFO"
            $script:ExoConnected = $true
        }

        if ($script:ExoConnected -and $script:AcceptedDomains.Count -eq 0) {
            $script:AcceptedDomains = (Get-AcceptedDomain).DomainName
            Write-Log -Message "Fetched $($script:AcceptedDomains.Count) accepted domains for the tenant." -Type "INFO"
        }
    }
    catch {
        Write-Log -Message "Failed to connect to Exchange Online or fetch accepted domains. Error: $($_.Exception.Message)" -Type "ERROR"
        $script:ExoConnected = $false
    }
}

function Connect-ToGraphAPI {
    param (
        [string[]]$Scopes = @(
            "Organization.Read.All", "User.Read.All", "RoleManagement.Read.Directory", "Application.Read.All",
            "Policy.Read.All", "Directory.Read.All", "Group.Read.All", "Sites.Read.All", "Team.ReadBasic.All",
            "AppCatalog.Read.All", "ChannelMessage.Read.All", "Chat.ReadBasic.All", "MailboxSettings.Read",
            "Reports.Read.All", "AuditLog.Read.All", "ServicePrincipalEndpoint.Read.All",
            "CrossTenantInformation.ReadBasic.All", "Domain.Read.All", "IdentityProvider.Read.All",
            "AdministrativeUnit.Read.All", "Device.Read.All",
            "Mail.ReadBasic.All", "Mail.Read", "User.ReadBasic.All",
            "UserAuthenticationMethod.Read.All", "RoleManagement.ReadWrite.Directory", 
            "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", 
            "Policy.Read.PermissionGrant", "Policy.Read.ConditionalAccess", "Policy.Read.Authorization", # Added Policy.Read.Authorization for B2B
            "DelegatedAdminRelationship.Read.All" 
        )
    )
    Write-Log -Message "Attempting to connect to Microsoft Graph API..." -Type "INFO"
    try {
        if (Get-MgContext -ErrorAction SilentlyContinue) {
             Write-Log -Message "Already connected to Microsoft Graph." -Type "INFO"
             $script:GraphConnected = $true
        } else {
            Connect-MgGraph -Scopes $Scopes
            Write-Log -Message "Successfully connected to Microsoft Graph." -Type "INFO"
            $script:GraphConnected = $true
        }
       
        if ($script:GraphConnected) {
            $MgContext = Get-MgContext
            if ($null -eq $script:TenantDomain) {
                $script:TenantDomain = $MgContext.Domain 
                if (-not $script:TenantDomain) { 
                    $orgDetails = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($orgDetails.VerifiedDomains) {
                        $primaryDomain = ($orgDetails.VerifiedDomains | Where-Object {$_.IsDefault -eq $true -or $_.IsInitial -eq $true} | Select-Object -First 1).Name
                        if ($primaryDomain) { $script:TenantDomain = $primaryDomain }
                    }
                }
                 Write-Log -Message "Primary tenant domain for Graph checks set to: $($script:TenantDomain)" -Type "INFO"
            }
            if ($null -eq $script:TenantId) {
                $script:TenantId = $MgContext.TenantId
                Write-Log -Message "Current Tenant ID set to: $($script:TenantId)" -Type "INFO"
            }
        }
    }
    catch {
        Write-Log -Message "Failed to connect to Microsoft Graph. Error: $($_.Exception.Message)" -Type "ERROR"
        $script:GraphConnected = $false
    }
}

function Connect-ToMSOnline {
    Write-Log -Message "Attempting to connect to MSOnline (for DAP checks)..." -Type "INFO"
    if (-not (Get-Module -Name MSOnline -ListAvailable)) {
        Write-Log -Message "MSOnline module not available. Skipping DAP checks." -Type "WARN"
        $script:MSOnlineConnected = $false
        return
    }
    try {
        if ($script:GraphConnected) { # Check if Graph connection exists to get current user
            $currentUserUPN = (Get-MgContext).Account
            if ($currentUserUPN) {
                Get-MsolUser -UserPrincipalName $currentUserUPN -ErrorAction SilentlyContinue | Out-Null
                if ($?) { 
                    Write-Log -Message "Already connected to MSOnline." -Type "INFO"
                    $script:MSOnlineConnected = $true
                    return
                }
            }
        }
    } catch {} 

    try {
        Connect-MsolService
        Write-Log -Message "Successfully connected to MSOnline." -Type "INFO"
        $script:MSOnlineConnected = $true
    }
    catch {
        Write-Log -Message "Failed to connect to MSOnline. Error: $($_.Exception.Message). DAP checks will be skipped." -Type "ERROR"
        $script:MSOnlineConnected = $false
    }
}


function Is-TrusteeExternal {
    param (
        [string]$TrusteeIdentity, 
        [string]$MailboxOwnerDomain 
    )
    if ($TrusteeIdentity -match "^S-1-5-21-" -or $TrusteeIdentity -match "NT AUTHORITY\\SELF" -or $TrusteeIdentity -match "NT AUTHORITY\\SYSTEM" -or $TrusteeIdentity -match "Everyone" -or $TrusteeIdentity -match "Authenticated Users") {
        return $false 
    }
    try {
        $recipient = Get-Recipient -Identity $TrusteeIdentity -ErrorAction SilentlyContinue
        if ($recipient) {
            if ($recipient.RecipientTypeDetails -in @("MailUser", "MailContact", "GuestMailUser")) { return $true }
            if ($recipient.ExternalEmailAddress -ne $null -and $recipient.ExternalEmailAddress.ToString().Trim() -ne [System.String]::Empty) {
                $externalDomain = ($recipient.ExternalEmailAddress.ToString() -split "@")[1]
                if ($script:AcceptedDomains -contains $externalDomain) { return $false }
                return $true
            }
            $userDomain = $null
            if ($recipient.PrimarySmtpAddress) { $userDomain = ($recipient.PrimarySmtpAddress.ToString() -split "@")[1] } 
            elseif ($recipient.UserPrincipalName) { $userDomain = ($recipient.UserPrincipalName.ToString() -split "@")[1] }
            if ($userDomain -and ($script:AcceptedDomains -notcontains $userDomain)) { return $true }
            return $false 
        } else {
            if ($TrusteeIdentity -match "@") {
                $trusteeDomain = ($TrusteeIdentity -split "@")[1]
                if ($script:AcceptedDomains -notcontains $trusteeDomain) { return $true }
            }
            Write-Log -Message "Could not resolve trustee '$TrusteeIdentity' with Get-Recipient. External status may be inaccurate." -Type "WARN"
            return $false 
        }
    } catch {
        Write-Log -Message "Error in Is-TrusteeExternal for '$TrusteeIdentity': $($_.Exception.Message)" -Type "ERROR"
        return $false 
    }
}
#endregion Connection Functions

#region Check Implementations

# ==================================================
# SECTION I: Exchange Online Checks
# ==================================================
function Invoke-ExchangeOnlineChecks {
    Write-Log -Message "Starting Exchange Online Checks" -Type "SECTION"
    Connect-ToGraphAPI # Ensure Graph is connected for potential domain lookups
    Connect-ToExchangeOnline 

    if (-not $ExoConnected -and -not $GraphConnected) { # Graph can sometimes help if EXO fails
        Write-Log -Message "Cannot perform Exchange Online checks. Not connected to EXO or Graph." -Type "ERROR"
        return
    }
   
    $ExoReportFile = "ExchangeOnline_Report.txt"

    # --- 1. Outbound Spam Policies ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Outbound Spam Policies (Auto-Forwarding)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-HostedOutboundSpamFilterPolicy | ForEach-Object {
                Write-Log -Message "Policy: $($_.Name), AutoForwardingMode: $($_.AutoForwardingMode)" -SpecificLogFile $ExoReportFile
                if ($_.AutoForwardingMode -ne "Off") {
                    Write-Log -Message "ALERT: Outbound Spam Policy '$($_.Name)' allows auto-forwarding (Mode: $($_.AutoForwardingMode))." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                }
            }
        }
        catch { Write-Log -Message "Error checking Outbound Spam Policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Outbound Spam Policies check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}


    # --- 2. Remote Domain Settings ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Remote Domain Settings (Auto-Forwarding/Replies)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-RemoteDomain | ForEach-Object {
                if ($_.AutoForwardEnabled -eq $true -or $_.AutoReplyEnabled -eq $true) {
                    Write-Log -Message "Domain: $($_.DomainName), AutoForwardEnabled: $($_.AutoForwardEnabled), AutoReplyEnabled: $($_.AutoReplyEnabled)" -SpecificLogFile $ExoReportFile
                    if ($_.AutoForwardEnabled -eq $true) {
                        Write-Log -Message "ALERT: Remote Domain '$($_.DomainName)' has AutoForwardEnabled." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                    }
                    if ($_.AutoReplyEnabled -eq $true -and $_.DomainName -ne "*") { # Default domain "*" often has AR enabled, less critical.
                        Write-Log -Message "ALERT: Remote Domain '$($_.DomainName)' has AutoReplyEnabled." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                    }
                }
            }
        }
        catch { Write-Log -Message "Error checking Remote Domains: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Remote Domain Settings check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 3. Transport Rules (Mail Flow Rules) ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Transport Rules..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-TransportRule | ForEach-Object {
                $rule = $_; $ruleName = $rule.Name; $ruleGuid = $rule.Guid
                Write-Log -Message "Rule: $ruleName (GUID: $ruleGuid, State: $($rule.State), Mode: $($rule.Mode))" -SpecificLogFile $ExoReportFile
                $ruleDetailsFile = Join-Path $ReportDir "TransportRule_Details_$($ruleGuid).txt"
                $rule | Select-Object * | Format-List | Out-File -FilePath $ruleDetailsFile -Encoding UTF8
                Write-Log -Message "Full details for rule '$ruleName' saved to $ruleDetailsFile" -SpecificLogFile $ExoReportFile

                if ($rule.Actions -match "RedirectMessage" -or $rule.Actions -match "BlindCopyTo" -or $rule.Actions -match "AddToRecipients") {
                    Write-Log -Message "ALERT: Transport Rule '$ruleName' contains a forwarding-related action: $($rule.ActionsToString)." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                    # Check for external recipients in AddToRecipients
                    $rule.Actions | Where-Object { $_.Name -eq "AddToRecipients" } | ForEach-Object {
                        $_.Addresses | ForEach-Object {
                            $addressString = $_.ToString(); $isExternal = $true
                            foreach ($domain in $script:AcceptedDomains) { if ($addressString -like "*@$domain") { $isExternal = $false; break } }
                            if ($addressString -match "@" -and $isExternal) { 
                                Write-Log -Message "ALERT: Transport Rule '$ruleName' action 'AddToRecipients' includes potentially external address: $addressString" -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                            }
                        }
                    }
                }
                $setHeaderActions = $rule.Actions | Where-Object { $_.Name -eq "SetHeader" }
                if ($setHeaderActions) {
                    foreach ($action in $setHeaderActions) {
                        Write-Log -Message "INFO: Transport Rule '$ruleName' uses 'SetHeader'. Header: '$($action.HeaderName)', Value: '$($action.HeaderValue)'" -SpecificLogFile $ExoReportFile
                        if ($action.HeaderName -match "X-MS-Exchange-Organization-AutoForward" -or $action.HeaderValue -match "http" -or $action.HeaderValue -match "script") {
                            Write-Log -Message "ALERT: Transport Rule '$ruleName' action 'SetHeader' has a potentially suspicious header/value. Header: '$($action.HeaderName)', Value: '$($action.HeaderValue)'" -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                        }
                    }
                }
                if ($rule.SentToScope -eq "NotInOrganization" -and ($rule.Actions -match "DeleteMessage" -or $rule.Actions -match "Quarantine")) {
                    Write-Log -Message "INFO: Transport Rule '$ruleName' acts on messages to 'NotInOrganization' with action: $($rule.ActionsToString). Verify legitimacy." -Type "INFO" -SpecificLogFile $ExoReportFile
                }
                # Check for complex regex in conditions
                $rule.Conditions | ForEach-Object {
                    if ($_.Name -in @("SubjectMatchesPatterns", "SenderDomainIs", "RecipientDomainIs", "AttachmentNameMatchesPatterns", "ContentMatchesPatterns") ) {
                        $patterns = $_.Patterns
                        if ($patterns) {
                            foreach ($pattern in $patterns) {
                                if (($pattern.ToString().Length -gt 50 -and $pattern.ToString() -match "[\\\[\]\(\)\*\+\?\^\$\{\}\.]"){2,}") { # Example: long string with many regex special chars
                                    Write-Log -Message "ALERT: Transport Rule '$ruleName' condition '$($_.Name)' uses a potentially complex/obfuscated pattern: '$pattern'. Review manually." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                                }
                            }
                        }
                    }
                }
            }
        }
        catch { Write-Log -Message "Error checking Transport Rules: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Transport Rules check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 4. Mailbox Forwarding (SMTP Forwarding & DeliverToMailboxAndForward) ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Mailbox Forwarding..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingSmtpAddress -ne $null -or $_.ForwardingAddress -ne $null} | ForEach-Object {
                $mailbox = $_
                Write-Log -Message "Mailbox: $($mailbox.PrimarySmtpAddress), ForwardingSmtpAddress: $($mailbox.ForwardingSmtpAddress), ForwardingAddress: $($mailbox.ForwardingAddress), DeliverToMailboxAndForward: $($mailbox.DeliverToMailboxAndForward)" -SpecificLogFile $ExoReportFile
                if ($mailbox.ForwardingSmtpAddress -ne $null) { 
                     $fwdSmtpAddress = $mailbox.ForwardingSmtpAddress.ToString(); $isExternalSmtp = $true
                     foreach($domain in $script:AcceptedDomains){ if($fwdSmtpAddress -like "*@$domain"){$isExternalSmtp = $false; break} }
                     if($fwdSmtpAddress -match "@" -and $isExternalSmtp){
                        Write-Log -Message "ALERT: Mailbox '$($mailbox.PrimarySmtpAddress)' has external SMTP forwarding to '$fwdSmtpAddress'." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                     } else { Write-Log -Message "INFO: Mailbox '$($mailbox.PrimarySmtpAddress)' has internal SMTP forwarding to '$fwdSmtpAddress'." -SpecificLogFile $ExoReportFile }
                }
                if ($mailbox.ForwardingAddress -ne $null) { 
                    $targetRecipient = Get-Recipient -Identity $mailbox.ForwardingAddress.ToString() -ErrorAction SilentlyContinue
                    if ($targetRecipient -and ($targetRecipient.RecipientTypeDetails -eq "MailUser" -or $targetRecipient.RecipientTypeDetails -eq "MailContact" -or ($targetRecipient.ExternalEmailAddress -ne $null -and $targetRecipient.ExternalEmailAddress.ToString().Trim() -ne [System.String]::Empty))) {
                        $externalAddress = $targetRecipient.ExternalEmailAddress.ToString()
                        if ($null -ne $externalAddress -and $externalAddress.Trim() -ne "") {
                             $isExternalFwdAddr = $true
                             foreach($domain in $script:AcceptedDomains){ if($externalAddress -like "*@$domain"){$isExternalFwdAddr=$false;break} }
                             if($isExternalFwdAddr){
                                Write-Log -Message "ALERT: Mailbox '$($mailbox.PrimarySmtpAddress)' has forwarding to external recipient '$($mailbox.ForwardingAddress)' (Target: $externalAddress)." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                             } else { Write-Log -Message "INFO: Mailbox '$($mailbox.PrimarySmtpAddress)' has forwarding to an internal recipient (via ExternalEmailAddress property) '$($mailbox.ForwardingAddress)' (Target: $externalAddress)." -SpecificLogFile $ExoReportFile }
                        } else { Write-Log -Message "INFO: Mailbox '$($mailbox.PrimarySmtpAddress)' has forwarding to recipient '$($mailbox.ForwardingAddress)' (Type: $($targetRecipient.RecipientTypeDetails), no direct external email address found, likely internal)." -SpecificLogFile $ExoReportFile }
                    } else { Write-Log -Message "INFO: Mailbox '$($mailbox.PrimarySmtpAddress)' has internal forwarding to '$($mailbox.ForwardingAddress)'." -SpecificLogFile $ExoReportFile }
                }
            }
        }
        catch { Write-Log -Message "Error checking Mailbox Forwarding: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Mailbox Forwarding check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 5. Inbox Rules ---
    Write-Log -Message "Checking Inbox Rules using Microsoft Graph API..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
    if (-not $GraphConnected) {
        Write-Log -Message "Skipping Inbox Rule checks (Graph API not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile
    } else {
        try {
            $users = Get-MgUser -All -Property "Id,UserPrincipalName" -Filter "assignedLicenses/any(x:x/skuId -ne null)" 
            Write-Log -Message "Found $($users.Count) users to check for Inbox Rules." -SpecificLogFile $ExoReportFile
            foreach ($user in $users) {
                Write-Log -Message "Checking Inbox Rules for $($user.UserPrincipalName)..." -SpecificLogFile $ExoReportFile
                try {
                    $inboxRules = Get-MgUserMessageRule -UserId $user.Id -All -ErrorAction SilentlyContinue
                    if ($null -eq $inboxRules -or $inboxRules.Count -eq 0) {
                        Write-Log -Message "  No inbox rules found or unable to retrieve for $($user.UserPrincipalName)." -Type "INFO" -SpecificLogFile $ExoReportFile
                        continue
                    }
                    foreach ($rule in $inboxRules) {
                        Write-Log -Message "  Rule: $($rule.DisplayName), Enabled: $($rule.IsEnabled), Sequence: $($rule.Sequence)" -SpecificLogFile $ExoReportFile
                        $isSuspiciousRule = $false; $suspiciousActions = New-Object System.Collections.Generic.List[string]; $ruleExternalTarget = $false
                        if ($rule.Actions.ForwardTo.Count -gt 0) {
                            $isSuspiciousRule = $true
                            $rule.Actions.ForwardTo | ForEach-Object {
                                $fwdToAddress = $_.EmailAddress.Address; $suspiciousActions.Add("ForwardTo: $fwdToAddress")
                                $isExternalAddr = $true; foreach($d in $script:AcceptedDomains){if($fwdToAddress -like "*@$d"){$isExternalAddr=$false;break}}
                                if ($fwdToAddress -match "@" -and $isExternalAddr) {
                                    Write-Log -Message "  ALERT: Inbox Rule '$($rule.DisplayName)' for '$($user.UserPrincipalName)' forwards to external address: $fwdToAddress." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                                    $ruleExternalTarget = $true
                                }
                            }
                        }
                        if ($rule.Actions.ForwardAsAttachmentTo.Count -gt 0) {
                            $isSuspiciousRule = $true
                             $rule.Actions.ForwardAsAttachmentTo | ForEach-Object {
                                $fwdAttAddress = $_.EmailAddress.Address; $suspiciousActions.Add("ForwardAsAttachmentTo: $fwdAttAddress")
                                $isExternalAddr = $true; foreach($d in $script:AcceptedDomains){if($fwdAttAddress -like "*@$d"){$isExternalAddr=$false;break}}
                                if ($fwdAttAddress -match "@" -and $isExternalAddr) {
                                    Write-Log -Message "  ALERT: Inbox Rule '$($rule.DisplayName)' for '$($user.UserPrincipalName)' forwards as attachment to external address: $fwdAttAddress." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                                    $ruleExternalTarget = $true
                                }
                            }
                        }
                        if ($rule.Actions.RedirectTo.Count -gt 0) {
                            $isSuspiciousRule = $true
                            $rule.Actions.RedirectTo | ForEach-Object {
                                $redirectToAddress = $_.EmailAddress.Address; $suspiciousActions.Add("RedirectTo: $redirectToAddress")
                                $isExternalAddr = $true; foreach($d in $script:AcceptedDomains){if($redirectToAddress -like "*@$d"){$isExternalAddr=$false;break}}
                                if ($redirectToAddress -match "@" -and $isExternalAddr) {
                                    Write-Log -Message "  ALERT: Inbox Rule '$($rule.DisplayName)' for '$($user.UserPrincipalName)' redirects to external address: $redirectToAddress." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                                    $ruleExternalTarget = $true
                                }
                            }
                        }
                        if ($rule.Actions.Delete -eq $true) {
                            $isSuspiciousRule = $true; $suspiciousActions.Add("Delete")
                            Write-Log -Message "  ALERT: Inbox Rule '$($rule.DisplayName)' for '$($user.UserPrincipalName)' contains a Delete action." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                        }
                        if ($null -ne $rule.Actions.MoveToFolder) {
                            $isSuspiciousRule = $true; $targetFolderId = $rule.Actions.MoveToFolder
                            $suspiciousActions.Add("MoveToFolder: $targetFolderId")
                            Write-Log -Message "  INFO: Inbox Rule '$($rule.DisplayName)' for '$($user.UserPrincipalName)' moves messages to folder ID '$targetFolderId'. Review destination manually." -Type "INFO" -SpecificLogFile $ExoReportFile
                        }
                        if ($isSuspiciousRule) {
                             Write-Log -Message "    Suspicious Actions: $($suspiciousActions -join ', ')" -SpecificLogFile $ExoReportFile
                             Write-Log -Message "    Conditions: SubjectContains: $($rule.Conditions.SubjectContains -join '; '), BodyContains: $($rule.Conditions.BodyContains -join '; '), SenderContains: $($rule.Conditions.SenderContains -join '; '), FromAddresses: $(($rule.Conditions.FromAddresses | %{$_.EmailAddress.Address}) -join '; ')" -SpecificLogFile $ExoReportFile
                        }
                    }
                } catch { Write-Log -Message "  Error retrieving inbox rules for $($user.UserPrincipalName): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
            }
        } catch { Write-Log -Message "Error checking Inbox Rules via Graph: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    }

    # --- 6. Mailbox Permissions ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Mailbox Permissions (FullAccess, SendAs, SendOnBehalfTo)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            $mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox,RoomMailbox,EquipmentMailbox 
            foreach ($mbx in $mailboxes) {
                $mailboxUPN = $mbx.UserPrincipalName; $mailboxPrimaryDomain = ($mailboxUPN -split "@")[1]
                Write-Log -Message "Processing permissions for mailbox: $mailboxUPN" -SpecificLogFile $ExoReportFile
                try {
                    Get-MailboxPermission -Identity $mailboxUPN -ErrorAction SilentlyContinue | Where-Object {
                        $_.IsInherited -eq $false -and $_.AccessRights -contains "FullAccess" -and 
                        $_.User -notlike "NT AUTHORITY\SELF" -and $_.User -notmatch "^S-1-5-21-" # Exclude common SIDs
                    } | ForEach-Object {
                        $trusteeIdentity = $_.User.ToString()
                        Write-Log -Message "  FullAccess on '$mailboxUPN' for User: '$trusteeIdentity', AccessRights: $($_.AccessRightsToString())" -SpecificLogFile $ExoReportFile
                        if (Is-TrusteeExternal -TrusteeIdentity $trusteeIdentity -MailboxOwnerDomain $mailboxPrimaryDomain) {
                            Write-Log -Message "  ALERT: External/Suspicious user '$trusteeIdentity' has FullAccess to mailbox '$mailboxUPN'." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                        }
                    }
                } catch { Write-Log -Message "  Error getting FullAccess permissions for $mailboxUPN: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
                try {
                    Get-RecipientPermission -Identity $mailboxUPN -ErrorAction SilentlyContinue | Where-Object {
                        $_.IsInherited -eq $false -and $_.Trustee -notlike "NT AUTHORITY\SELF"
                    } | ForEach-Object {
                        $trusteeIdentity = $_.Trustee.ToString()
                        Write-Log -Message "  SendAs on '$mailboxUPN' for Trustee: '$trusteeIdentity'" -SpecificLogFile $ExoReportFile
                        if (Is-TrusteeExternal -TrusteeIdentity $trusteeIdentity -MailboxOwnerDomain $mailboxPrimaryDomain) {
                            Write-Log -Message "  ALERT: External/Suspicious trustee '$trusteeIdentity' has SendAs permission on mailbox '$mailboxUPN'." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                        }
                    }
                } catch { Write-Log -Message "  Error getting SendAs permissions for $mailboxUPN: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
                try {
                    if ($mbx.GrantSendOnBehalfTo.Count -gt 0) {
                        foreach ($delegateIdentity in $mbx.GrantSendOnBehalfTo) {
                            $delegateRecipient = Get-Recipient -Identity $delegateIdentity.ToString() -ErrorAction SilentlyContinue
                            $delegateDisplayName = $delegateRecipient.DisplayName ?? $delegateIdentity.ToString()
                            Write-Log -Message "  SendOnBehalfTo for '$mailboxUPN' granted to: '$delegateDisplayName'" -SpecificLogFile $ExoReportFile
                            if (Is-TrusteeExternal -TrusteeIdentity $delegateIdentity.ToString() -MailboxOwnerDomain $mailboxPrimaryDomain) {
                                Write-Log -Message "  ALERT: External/Suspicious delegate '$delegateDisplayName' has SendOnBehalfTo permission for mailbox '$mailboxUPN'." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                            }
                        }
                    }
                } catch { Write-Log -Message "  Error getting SendOnBehalfTo permissions for $mailboxUPN: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
            }
        } catch { Write-Log -Message "Error retrieving mailboxes for permission checks: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Mailbox Permissions check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 7. Mail Connectors ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Mail Connectors..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-InboundConnector | ForEach-Object { Write-Log -Message "Inbound Connector: $($_.Name), Enabled: $($_.Enabled), ConnectorType: $($_.ConnectorType), SenderDomains: $($_.SenderDomainsToString())" -SpecificLogFile $ExoReportFile } 
            Get-OutboundConnector | ForEach-Object { Write-Log -Message "Outbound Connector: $($_.Name), Enabled: $($_.Enabled), ConnectorType: $($_.ConnectorType), SmartHosts: $($_.SmartHostsToString()), RecipientDomains: $($_.RecipientDomainsToString())" -SpecificLogFile $ExoReportFile 
                if ($_.UseMXRecord -eq $false -and ($_.SmartHosts -ne $null -and $_.SmartHosts.Count -gt 0)) {
                    Write-Log -Message "ALERT: Outbound Connector '$($_.Name)' uses SmartHosts: $($_.SmartHostsToString()). Verify these are legitimate." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                }
            }
        } catch { Write-Log -Message "Error checking Mail Connectors: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Mail Connectors check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 8. Journaling Rules ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Journaling Rules..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            $journalRules = Get-JournalRule -ErrorAction SilentlyContinue
            if ($journalRules) {
                foreach ($rule in $journalRules) {
                    Write-Log -Message "Journal Rule: $($rule.Name), Enabled: $($rule.Enabled), Recipient: $($rule.Recipient), JournalEmailAddress: $($rule.JournalEmailAddress)" -SpecificLogFile $ExoReportFile
                    if ($rule.Enabled) {
                        $journalEmail = $rule.JournalEmailAddress.ToString()
                        if ($journalEmail) {
                            $isExternalJournal = $true
                            foreach ($domain in $script:AcceptedDomains) { if ($journalEmail -like "*@$domain") { $isExternalJournal = $false; break } }
                            if ($journalEmail -match "@" -and $isExternalJournal) {
                                Write-Log -Message "ALERT: Journal Rule '$($rule.Name)' is enabled and journals to a potentially external address: $journalEmail." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                            } else { Write-Log -Message "INFO: Journal Rule '$($rule.Name)' journals to internal address: $journalEmail." -SpecificLogFile $ExoReportFile }
                        } else { Write-Log -Message "WARN: Journal Rule '$($rule.Name)' is enabled but JournalEmailAddress is empty or invalid." -Type "WARN" -SpecificLogFile $ExoReportFile }
                    }
                }
            } else { Write-Log -Message "No Journaling Rules found or error retrieving them." -Type "INFO" -SpecificLogFile $ExoReportFile }
        } catch { Write-Log -Message "Error checking Journaling Rules: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Journaling Rules check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 9. Email Security Bypass (Defender for Office 365) ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Email Security Bypass (Defender for Office 365 Policies - E3/P1 level)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            Get-SafeAttachmentPolicy | ForEach-Object {
                $policy = $_
                Write-Log -Message "Safe Attachment Policy: $($policy.Name), Enabled: $($policy.Enabled), Action: $($policy.Action), Redirect: $($policy.Redirect), RedirectAddress: $($policy.RedirectAddress)" -SpecificLogFile $ExoReportFile
                if ($policy.Enabled -eq $false -or $policy.Action -eq "Off" -or $policy.Action -eq "Allow") {
                    Write-Log -Message "ALERT: Safe Attachment Policy '$($policy.Name)' is disabled or has a weak action '$($policy.Action)'." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                }
                if ($policy.Redirect -eq $true -and $policy.RedirectAddress) {
                    $redirectEmail = $policy.RedirectAddress.ToString()
                    $isExternalRedirect = $true
                    foreach($domain in $script:AcceptedDomains){ if($redirectEmail -like "*@$domain"){$isExternalRedirect=$false;break} }
                    if($redirectEmail -match "@" -and $isExternalRedirect){
                        Write-Log -Message "ALERT: Safe Attachment Policy '$($policy.Name)' redirects attachments to a potentially external address: $redirectEmail." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                    }
                }
            }
            Get-SafeLinksPolicy | ForEach-Object {
                $policy = $_
                Write-Log -Message "Safe Links Policy: $($policy.Name), Enabled: $($policy.Enabled), DoNotRewriteUrls: $($policy.DoNotRewriteUrls -join '; ')" -SpecificLogFile $ExoReportFile 
                if ($policy.Enabled -eq $false) {
                    Write-Log -Message "ALERT: Safe Links Policy '$($policy.Name)' is disabled." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                }
                if ($policy.DoNotRewriteUrls -ne $null -and $policy.DoNotRewriteUrls.Count -gt 0) {
                     Write-Log -Message "ALERT: Safe Links Policy '$($policy.Name)' has URLs excluded from rewriting: $($policy.DoNotRewriteUrls -join '; '). Review these exclusions." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile
                }
            }
            Get-AntiPhishPolicy | ForEach-Object {
                $policy = $_
                Write-Log -Message "Anti-Phish Policy: $($policy.Name), Enabled: $($policy.Enabled), EnableSpoofIntelligence: $($policy.EnableSpoofIntelligence), EnableMailboxIntelligence: $($policy.EnableMailboxIntelligence), EnableImpersonationProtection: $($policy.EnableImpersonationProtection)" -SpecificLogFile $ExoReportFile
                if ($policy.Enabled -eq $false) { Write-Log -Message "ALERT: Anti-Phish Policy '$($policy.Name)' is disabled." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile }
                if ($policy.EnableSpoofIntelligence -eq $false) { Write-Log -Message "ALERT: Anti-Phish Policy '$($policy.Name)' has Spoof Intelligence disabled." -Type "ALERT" -IsAlert -SpecificLogFile $ExoReportFile }
                if ($policy.EnableMailboxIntelligence -eq $false) { Write-Log -Message "WARN: Anti-Phish Policy '$($policy.Name)' has Mailbox Intelligence disabled." -Type "WARN" -SpecificLogFile $ExoReportFile } # Less critical than spoof intelligence
                if ($policy.EnableImpersonationProtection -eq $false) { Write-Log -Message "WARN: Anti-Phish Policy '$($policy.Name)' has Impersonation Protection disabled." -Type "WARN" -SpecificLogFile $ExoReportFile }
                if ($policy.EnableTargetedUserProtection -eq $true -and ($policy.TargetedUsersToProtect -eq $null -or $policy.TargetedUsersToProtect.Count -eq 0)) { Write-Log -Message "WARN: Anti-Phish Policy '$($policy.Name)' has Targeted User Protection enabled but no users specified." -Type "WARN" -SpecificLogFile $ExoReportFile }
                if ($policy.EnableTargetedDomainsProtection -eq $true -and ($policy.TargetedDomainsToProtect -eq $null -or $policy.TargetedDomainsToProtect.Count -eq 0)) { Write-Log -Message "WARN: Anti-Phish Policy '$($policy.Name)' has Targeted Domain Protection enabled but no domains specified." -Type "WARN" -SpecificLogFile $ExoReportFile }
                Write-Log -Message "  Anti-Phish Policy '$($policy.Name)' - PhishThresholdLevel: $($policy.PhishThresholdLevel), ImpersonationAction: $($policy.ImpersonationAction), SpoofAction: $($policy.SpoofAction)" -SpecificLogFile $ExoReportFile
            }
            Write-Log -Message "INFO: Review any custom Defender for O365 policies manually. Use Get-MalwareFilterPolicy for anti-malware policies." -Type "INFO" -SpecificLogFile $ExoReportFile
        } catch { Write-Log -Message "Error checking Defender for O365 policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Defender for O365 policies check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 10. Exchange Server Hybrid Configuration (if applicable) ---
    if ($ExoConnected) {
        Write-Log -Message "Checking Exchange Server Hybrid Configuration (Informational)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
        try {
            $hybridConfig = Get-HybridConfiguration -ErrorAction SilentlyContinue
            if ($hybridConfig) {
                Write-Log -Message "Hybrid Configuration Found. Review its settings manually." -SpecificLogFile $ExoReportFile
                $hybridConfig | Format-List | Out-String | % { Write-Log -Message $_ -SpecificLogFile $ExoReportFile }
                Write-Log -Message "Checking Intra-Organization Connectors..." -SpecificLogFile $ExoReportFile
                Get-IntraOrganizationConnector | ForEach-Object {
                    Write-Log -Message "  IntraOrg Connector: $($_.Name), Enabled: $($_.Enabled), TargetAddressDomains: $($_.TargetAddressDomains -join '; '), DiscoveryEndpoint: $($_.DiscoveryEndpoint)" -SpecificLogFile $ExoReportFile
                }
                Write-Log -Message "Checking Organization Relationships..." -SpecificLogFile $ExoReportFile
                Get-OrganizationRelationship | ForEach-Object {
                    Write-Log -Message "  Org Relationship: $($_.Name), Enabled: $($_.Enabled), DomainNames: $($_.DomainNames -join '; '), FreeBusyAccessEnabled: $($_.FreeBusyAccessEnabled), MailboxMoveEnabled: $($_.MailboxMoveEnabled)" -SpecificLogFile $ExoReportFile
                    if ($_.Enabled -and ($_.FreeBusyAccessEnabled -or $_.MailboxMoveEnabled)) {
                        Write-Log -Message "  INFO: Org Relationship '$($_.Name)' is enabled with DomainNames: $($_.DomainNames -join '; '). Verify these are trusted." -Type "INFO" -SpecificLogFile $ExoReportFile
                    }
                }
            } else { Write-Log -Message "No Exchange Hybrid Configuration object found." -SpecificLogFile $ExoReportFile }
        } catch { Write-Log -Message "Error checking Hybrid Configuration details: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $ExoReportFile }
    } else { Write-Log -Message "Skipping Hybrid Configuration check (EXO not connected)." -Type "WARN" -SpecificLogFile $ExoReportFile}

    # --- 11. Exchange Mail Flow Rules with Scripts ---
    Write-Log -Message "Checking Exchange Mail Flow Rules for potential Script Payloads (Advanced)..." -Type "SUBSECTION" -SpecificLogFile $ExoReportFile
    Write-Log -Message "INFO: This check has been integrated into the main Transport Rule check (Point 3) by looking for suspicious SetHeader actions and complex regex patterns." -Type "INFO" -SpecificLogFile $ExoReportFile

    Write-Log -Message "Finished Exchange Online Checks." -Type "SECTION"
}

# ==================================================
# SECTION II: Azure Active Directory / Entra ID Checks
# ==================================================
function Invoke-AzureADChecks {
    Write-Log -Message "Starting Azure Active Directory / Entra ID Checks" -Type "SECTION"
    Connect-ToGraphAPI 
    if (-not $GraphConnected) {
        Write-Log -Message "Cannot perform Azure AD checks. Not connected to Graph API." -Type "ERROR"
        return
    }
    $AadReportFile = "AzureAD_Report.txt"

    # --- 12. User Accounts & Authentication Methods ---
    Write-Log -Message "Checking User Accounts & Authentication Methods..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime,UserType,AccountEnabled,SignInActivity,RefreshTokensValidFromDateTime" 
        foreach ($user in $users) {
            Write-Log -Message "User: $($user.UserPrincipalName), Created: $($user.CreatedDateTime), Type: $($user.UserType), Enabled: $($user.AccountEnabled), RefreshTokensValidFrom: $($user.RefreshTokensValidFromDateTime)" -SpecificLogFile $AadReportFile
            if ((New-TimeSpan -Start $user.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) { 
                Write-Log -Message "ALERT: User '$($user.UserPrincipalName)' created recently ($($user.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
            }
            Write-Log -Message "  Checking authentication methods for $($user.UserPrincipalName)..." -SpecificLogFile $AadReportFile
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction SilentlyContinue
                if ($authMethods) {
                    foreach ($method in $authMethods) {
                        $methodType = $method.AdditionalProperties.'@odata.type'
                        Write-Log -Message "    Auth Method Type: $methodType" -SpecificLogFile $AadReportFile
                        if ($methodType -eq "#microsoft.graph.phoneAuthenticationMethod") {
                            Write-Log -Message "      Phone Number: $($method.PhoneNumber), Type: $($method.PhoneType), SSPR Registered: $($method.SmsSignInState)" -SpecificLogFile $AadReportFile
                        } elseif ($methodType -eq "#microsoft.graph.fido2AuthenticationMethod") {
                            Write-Log -Message "      FIDO2 Key: DisplayName: $($method.DisplayName), Created: $($method.CreatedDateTime), AaGuid: $($method.AaGuid)" -SpecificLogFile $AadReportFile
                            Write-Log -Message "      ALERT: User '$($user.UserPrincipalName)' has a FIDO2 key registered. Verify if expected." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        } elseif ($methodType -eq "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod") {
                             Write-Log -Message "      MS Authenticator: DisplayName: $($method.DisplayName), Created: $($method.CreatedDateTime), DeviceTag: $($method.DeviceTag), PhoneAppVersion: $($method.PhoneAppVersion)" -SpecificLogFile $AadReportFile
                             if ($method.AdditionalProperties.clientAppName -eq "WindowsAzureMultiFactorAuthentication") { # Check for legacy MFA registration
                                 Write-Log -Message "        (Legacy MFA Registration type)" -SpecificLogFile $AadReportFile
                             }
                        } elseif ($methodType -eq "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod") {
                            Write-Log -Message "      Passwordless MS Authenticator: DisplayName: $($method.DisplayName), Created: $($method.CreatedDateTime)" -SpecificLogFile $AadReportFile
                            Write-Log -Message "      ALERT: User '$($user.UserPrincipalName)' has Passwordless Microsoft Authenticator configured. Verify if expected." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        } elseif ($methodType -eq "#microsoft.graph.emailAuthenticationMethod") {
                            Write-Log -Message "      Email Method: $($method.EmailAddress)" -SpecificLogFile $AadReportFile
                        } elseif ($methodType -eq "#microsoft.graph.softwareOathAuthenticationMethod") { 
                             Write-Log -Message "      Software OATH Token registered. SecretKey property is not readable." -SpecificLogFile $AadReportFile
                        }
                        # Add other method types as needed
                    }
                } else { Write-Log -Message "    No specific authentication methods found or unable to retrieve for $($user.UserPrincipalName)." -Type "INFO" -SpecificLogFile $AadReportFile }
            } catch { Write-Log -Message "    WARN: Could not retrieve authentication methods for $($user.UserPrincipalName). Error: $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $AadReportFile }
        }
        Write-Log -Message "INFO: Full MFA status check also requires analyzing Conditional Access Policies. Review RefreshTokensValidFromDateTime for mass token invalidation events. For 'recently added' auth methods, Azure AD Audit Logs are the definitive source." -Type "INFO" -SpecificLogFile $AadReportFile
    } catch { Write-Log -Message "Error checking User Accounts & Authentication Methods: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }

    # --- 13. Directory Role (Built-in & Custom) Memberships ---
    Write-Log -Message "Checking Directory Role Memberships..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $script:privilegedRoles = @( # Common high-privilege roles - made script-scoped for use in #23
            "Global Administrator", "Privileged Role Administrator", "Exchange Administrator", 
            "SharePoint Administrator", "User Administrator", "Authentication Administrator",
            "Conditional Access Administrator", "Security Administrator", "Application Administrator",
            "Cloud Application Administrator" 
        )
        $roleDefinitions = Get-MgDirectoryRole -All 
        foreach ($roleDef in $roleDefinitions) {
            if ($script:privilegedRoles -contains $roleDef.DisplayName -or $roleDef.DisplayName -match "Admin" -or $roleDef.IsBuiltIn -eq $false) { # Check privileged, "Admin" in name, or custom
                Write-Log -Message "Checking members for role: $($roleDef.DisplayName) (ID: $($roleDef.Id), IsBuiltIn: $($roleDef.IsBuiltIn))" -SpecificLogFile $AadReportFile
                if ($roleDef.IsBuiltIn -eq $false) {
                     Write-Log -Message "INFO: Custom directory role detected: '$($roleDef.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile
                     try {
                         $permissions = $roleDef.RolePermissions
                         if ($permissions) {
                             Write-Log -Message "  Custom Role Permissions for '$($roleDef.DisplayName)':" -SpecificLogFile $AadReportFile
                             $permissions | ForEach-Object { 
                                 if ($_.AllowedResourceActions) {
                                     Write-Log -Message "    Allowed: $($_.AllowedResourceActions -join '; ')" -SpecificLogFile $AadReportFile
                                 }
                             }
                         } else { Write-Log -Message "  No explicit permissions listed for custom role '$($roleDef.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile }
                     } catch { Write-Log -Message "  WARN: Could not retrieve permissions for custom role '$($roleDef.DisplayName)'. Error: $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $AadReportFile }
                }
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $roleDef.Id -ErrorAction SilentlyContinue -All
                if ($members) {
                    foreach ($member in $members) {
                        $memberType = $member.AdditionalProperties.'@odata.type'
                        $memberDisplayName = $member.AdditionalProperties.displayName 
                        $memberUpnOrAppId = $member.AdditionalProperties.userPrincipalName ?? $member.AdditionalProperties.appId ?? "N/A"
                        Write-Log -Message "  Member: $memberDisplayName ($memberType), UPN/AppId: $memberUpnOrAppId" -SpecificLogFile $AadReportFile
                        if ($memberType -eq "#microsoft.graph.servicePrincipal") {
                            Write-Log -Message "  ALERT: Service Principal '$memberDisplayName' (AppId: $memberUpnOrAppId) is a member of role '$($roleDef.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                        if ($memberUpnOrAppId -match "#EXT#") { # Guest user check
                            Write-Log -Message "  ALERT: Guest User '$memberUpnOrAppId' is a member of role '$($roleDef.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                } else { Write-Log -Message "  No members found for role '$($roleDef.DisplayName)' or error occurred." -Type "INFO" -SpecificLogFile $AadReportFile }
            }
        }
    } catch { Write-Log -Message "Error checking Directory Role Memberships: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }

    # --- 14. Application Registrations & Enterprise Applications (Service Principals) ---
    Write-Log -Message "Checking Application Registrations & Service Principals..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    $HighRiskApplicationPermissionStrings = @( # Common high-risk permission strings
        "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All",
        "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite", "User.ReadWrite.All", "Sites.FullControl.All",
        "Files.ReadWrite.All", "Policy.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "SecurityEvents.ReadWrite.All",
        "User.Invite.All", "ApplicationImpersonation", "User.ManageIdentities.All", "GroupMember.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All", "OAuth2PermissionGrant.ReadWrite.All", "ServicePrincipalEndpoint.ReadWrite.All"
    )
    try {
        $applications = Get-MgApplication -All -ErrorAction SilentlyContinue
        Write-Log -Message "Found $($applications.Count) application registrations." -SpecificLogFile $AadReportFile
        foreach ($app in $applications) {
            Write-Log -Message "App Registration: $($app.DisplayName) (AppId: $($app.AppId)), Created: $($app.CreatedDateTime), Publisher: $($app.PublisherDomain)" -SpecificLogFile $AadReportFile
            if ((New-TimeSpan -Start $app.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                Write-Log -Message "  ALERT: Application '$($app.DisplayName)' (AppId: $($app.AppId)) created recently ($($app.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
            }
            if ($app.PasswordCredentials.Count -gt 0) {
                Write-Log -Message "  Password Credentials for $($app.DisplayName):" -SpecificLogFile $AadReportFile
                $app.PasswordCredentials | ForEach-Object {
                    Write-Log -Message "    DisplayName: $($_.DisplayName), Start: $($_.StartDateTime), End: $($_.EndDateTime), KeyId: $($_.KeyId)" -SpecificLogFile $AadReportFile
                    if ($_.EndDateTime -lt (Get-Date).AddDays($script:CertExpiryWarningDays) -and $_.EndDateTime -gt (Get-Date)) {
                        Write-Log -Message "    WARN: Password credential '$($_.DisplayName)' for app '$($app.DisplayName)' is expiring soon ($($_.EndDateTime))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                    if ($_.StartDateTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                         Write-Log -Message "    INFO: Password credential '$($_.DisplayName)' for app '$($app.DisplayName)' started recently ($($_.StartDateTime)). Review if expected." -Type "INFO" -SpecificLogFile $AadReportFile
                    }
                }
            }
            if ($app.KeyCredentials.Count -gt 0) {
                Write-Log -Message "  Key Credentials (Certificates) for $($app.DisplayName):" -SpecificLogFile $AadReportFile
                $app.KeyCredentials | ForEach-Object {
                    Write-Log -Message "    DisplayName: $($_.DisplayName), Type: $($_.Type), Usage: $($_.Usage), Start: $($_.StartDateTime), End: $($_.EndDateTime), KeyId: $($_.KeyId)" -SpecificLogFile $AadReportFile
                     if ($_.EndDateTime -lt (Get-Date).AddDays($script:CertExpiryWarningDays) -and $_.EndDateTime -gt (Get-Date)) {
                        Write-Log -Message "    WARN: Key credential '$($_.DisplayName)' for app '$($app.DisplayName)' is expiring soon ($($_.EndDateTime))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                    if ($_.StartDateTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                         Write-Log -Message "    INFO: Key credential '$($_.DisplayName)' for app '$($app.DisplayName)' started recently ($($_.StartDateTime)). Review if expected." -Type "INFO" -SpecificLogFile $AadReportFile
                    }
                }
            }
            if ($app.RequiredResourceAccess.Count -gt 0) {
                Write-Log -Message "  API Permissions for $($app.DisplayName):" -SpecificLogFile $AadReportFile
                foreach ($resourceAccess in $app.RequiredResourceAccess) {
                    $resourceAppInfo = Get-MgServicePrincipal -Filter "appId eq '$($resourceAccess.ResourceAppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    $resourceAppName = $resourceAppInfo.DisplayName ?? $resourceAccess.ResourceAppId
                    Write-Log -Message "    Resource: $resourceAppName (AppId: $($resourceAccess.ResourceAppId))" -SpecificLogFile $AadReportFile
                    foreach ($permission in $resourceAccess.ResourceAccess) {
                        $permObject = $null; $permName = $permission.Id # Default to ID if name not found
                        if ($permission.Type -eq "Role") { # Application Permission
                            $permObject = $resourceAppInfo.AppRoles | Where-Object {$_.Id -eq $permission.Id} | Select-Object -First 1
                            if ($permObject) { $permName = $permObject.Value }
                            Write-Log -Message "      App Permission (Role): $permName (ID: $($permission.Id))" -SpecificLogFile $AadReportFile
                            if ($HighRiskApplicationPermissionStrings -contains $permName) {
                                Write-Log -Message "      ALERT: High-risk Application Permission '$permName' granted to app '$($app.DisplayName)' for resource '$resourceAppName'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                            }
                        } elseif ($permission.Type -eq "Scope") { # Delegated Permission
                            $permObject = $resourceAppInfo.Oauth2PermissionScopes | Where-Object {$_.Id -eq $permission.Id} | Select-Object -First 1
                            if ($permObject) { $permName = $permObject.Value }
                            Write-Log -Message "      Delegated Permission (Scope): $permName (ID: $($permission.Id))" -SpecificLogFile $AadReportFile
                             if ($HighRiskApplicationPermissionStrings -contains $permName) {
                                Write-Log -Message "      ALERT: High-risk Delegated Permission '$permName' granted to app '$($app.DisplayName)' for resource '$resourceAppName'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                            }
                        }
                    }
                }
            }
        }
    } catch { Write-Log -Message "Error checking Application Registrations: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }

    try {
        $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction SilentlyContinue
        Write-Log -Message "Found $($servicePrincipals.Count) service principals." -SpecificLogFile $AadReportFile
        foreach ($sp in $servicePrincipals) {
            Write-Log -Message "Service Principal: $($sp.DisplayName) (AppId: $($sp.AppId)), Type: $($sp.ServicePrincipalType), Enabled: $($sp.AccountEnabled), OwnerOrgId: $($sp.AppOwnerOrganizationId)" -SpecificLogFile $AadReportFile
            if ($sp.AppOwnerOrganizationId -ne $null -and $sp.AppOwnerOrganizationId -ne $script:TenantId) {
                 Write-Log -Message "  ALERT: Service Principal '$($sp.DisplayName)' (AppId: $($sp.AppId)) is from another tenant (OwnerOrgId: $($sp.AppOwnerOrganizationId)). Verify legitimacy." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
            }
            if ($sp.PasswordCredentials.Count -gt 0) {
                Write-Log -Message "  Password Credentials for SP $($sp.DisplayName):" -SpecificLogFile $AadReportFile
                $sp.PasswordCredentials | ForEach-Object {
                    Write-Log -Message "    DisplayName: $($_.DisplayName), Start: $($_.StartDateTime), End: $($_.EndDateTime), KeyId: $($_.KeyId)" -SpecificLogFile $AadReportFile
                    if ($_.EndDateTime -lt (Get-Date).AddDays($script:CertExpiryWarningDays) -and $_.EndDateTime -gt (Get-Date)) {
                        Write-Log -Message "    WARN: Password credential '$($_.DisplayName)' for SP '$($sp.DisplayName)' is expiring soon ($($_.EndDateTime))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                     if ($_.StartDateTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                         Write-Log -Message "    INFO: Password credential '$($_.DisplayName)' for SP '$($sp.DisplayName)' started recently ($($_.StartDateTime)). Review if expected." -Type "INFO" -SpecificLogFile $AadReportFile
                    }
                }
            }
            if ($sp.KeyCredentials.Count -gt 0) {
                Write-Log -Message "  Key Credentials (Certificates) for SP $($sp.DisplayName):" -SpecificLogFile $AadReportFile
                $sp.KeyCredentials | ForEach-Object {
                    Write-Log -Message "    DisplayName: $($_.DisplayName), Type: $($_.Type), Usage: $($_.Usage), Start: $($_.StartDateTime), End: $($_.EndDateTime), KeyId: $($_.KeyId)" -SpecificLogFile $AadReportFile
                     if ($_.EndDateTime -lt (Get-Date).AddDays($script:CertExpiryWarningDays) -and $_.EndDateTime -gt (Get-Date)) {
                        Write-Log -Message "    WARN: Key credential '$($_.DisplayName)' for SP '$($sp.DisplayName)' is expiring soon ($($_.EndDateTime))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                    if ($_.StartDateTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                         Write-Log -Message "    INFO: Key credential '$($_.DisplayName)' for SP '$($sp.DisplayName)' started recently ($($_.StartDateTime)). Review if expected." -Type "INFO" -SpecificLogFile $AadReportFile
                    }
                }
            }
        }
    } catch { Write-Log -Message "Error checking Service Principals: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 15. OAuth Permission Grants (Delegated & Application) ---
    Write-Log -Message "Checking OAuth Permission Grants (Tenant-wide Admin Consents)..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $oauthGrants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
        if ($oauthGrants) {
            Write-Log -Message "Found $($oauthGrants.Count) tenant-wide OAuth2 permission grants." -SpecificLogFile $AadReportFile
            foreach ($grant in $oauthGrants) {
                $clientSp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
                $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue
               
                $clientName = $clientSp.DisplayName ?? $grant.ClientId
                $resourceName = $resourceSp.DisplayName ?? $grant.ResourceId

                Write-Log -Message "Grant ID: $($grant.Id) | Client: '$clientName' (AppId: $($clientSp.AppId ?? 'N/A')) | Resource: '$resourceName' | ConsentType: $($grant.ConsentType) | Scope: '$($grant.Scope)'" -SpecificLogFile $AadReportFile

                if ($grant.ConsentType -eq "AllPrincipals") { # Admin consent for the whole tenant
                    $grantedPermissions = $grant.Scope -split " "
                    foreach ($perm in $grantedPermissions) {
                        if ($HighRiskApplicationPermissionStrings -contains $perm) {
                            Write-Log -Message "  ALERT: High-risk permission '$perm' granted tenant-wide to client '$clientName' (AppId: $($clientSp.AppId ?? 'N/A')) for resource '$resourceName'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                }
            }
        } else {
            Write-Log -Message "No tenant-wide OAuth2 permission grants found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
        }
    } catch { Write-Log -Message "Error checking OAuth2 Permission Grants: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 16. Administrative Units (AUs) ---
    Write-Log -Message "Checking Administrative Units..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $adminUnits = Get-MgDirectoryAdministrativeUnit -All -ErrorAction SilentlyContinue
        if ($adminUnits) {
            Write-Log -Message "Found $($adminUnits.Count) Administrative Units." -SpecificLogFile $AadReportFile
            foreach ($au in $adminUnits) {
                Write-Log -Message "Administrative Unit: $($au.DisplayName) (ID: $($au.Id)), Visibility: $($au.Visibility)" -SpecificLogFile $AadReportFile
                if ($au.Visibility -ne "Public" -and (-not [string]::IsNullOrEmpty($au.Visibility)) ){ # Hidden AUs can be suspicious
                     Write-Log -Message "  ALERT: Administrative Unit '$($au.DisplayName)' has non-public visibility: $($au.Visibility). Review purpose." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                }

                try {
                    $auMembers = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All -ErrorAction SilentlyContinue
                    if ($auMembers) {
                        Write-Log -Message "  Members of AU '$($au.DisplayName)':" -SpecificLogFile $AadReportFile
                        $auMembers | ForEach-Object {
                            $memberType = $_.AdditionalProperties.'@odata.type'
                            $memberDisplayName = $_.AdditionalProperties.displayName ?? $_.Id
                            Write-Log -Message "    Member: $memberDisplayName (Type: $memberType, ID: $($_.Id))" -SpecificLogFile $AadReportFile
                        }
                    } else { Write-Log -Message "  No members found or error retrieving for AU '$($au.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile}
                } catch { Write-Log -Message "  Error listing members for AU '$($au.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }
               
                try {
                    $scopedRoleAssignments = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $au.Id -All -ErrorAction SilentlyContinue
                    if ($scopedRoleAssignments) {
                        Write-Log -Message "  Scoped Role Assignments in AU '$($au.DisplayName)':" -SpecificLogFile $AadReportFile
                        $scopedRoleAssignments | ForEach-Object {
                            $roleDefInfo = $null
                            try { $roleDefInfo = Get-MgDirectoryRoleDefinition -DirectoryRoleDefinitionId $_.RoleDefinitionId -ErrorAction SilentlyContinue } catch {}
                            $roleName = $roleDefInfo.DisplayName ?? $_.RoleDefinitionId
                           
                            # Attempt to get member display name if not directly available
                            $memberDisplayName = $_.AdditionalProperties.displayName 
                            if (-not $memberDisplayName) {
                                try {
                                    $memberObject = Get-MgDirectoryObject -DirectoryObjectId $_.Id -ErrorAction SilentlyContinue # $_.Id here is the member's ID
                                    $memberDisplayName = $memberObject.DisplayName ?? $_.Id
                                } catch { $memberDisplayName = $_.Id } # Fallback to ID
                            }
                            Write-Log -Message "    Role: '$roleName' assigned to Member: '$($memberDisplayName)' (Member ID: $($_.Id))" -SpecificLogFile $AadReportFile
                            if ($script:privilegedRoles -contains $roleName) { # Using $privilegedRoles from Check #13
                                Write-Log -Message "    ALERT: Privileged role '$roleName' is scoped to AU '$($au.DisplayName)' for member '$($memberDisplayName)'. Review." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                            }
                        }
                    } else { Write-Log -Message "  No scoped role assignments found or error retrieving for AU '$($au.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile}
                } catch { Write-Log -Message "  Error listing scoped role assignments for AU '$($au.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }
            }
        } else {
            Write-Log -Message "No Administrative Units found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
        }
    } catch { Write-Log -Message "Error checking Administrative Units: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 17. Domain Federation Settings & Authentication ---
    Write-Log -Message "Checking Domain Federation Settings & Authentication..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $domains = Get-MgDomain -All -ErrorAction SilentlyContinue
        if ($domains) {
            foreach ($domain in $domains) {
                Write-Log -Message "Domain: $($domain.Id), AuthenticationType: $($domain.AuthenticationType), IsDefault: $($domain.IsDefault), IsInitial: $($domain.IsInitial)" -SpecificLogFile $AadReportFile
                if ($domain.AuthenticationType -eq "Federated") {
                    Write-Log -Message "  ALERT: Domain '$($domain.Id)' is Federated. Review federation settings." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    try {
                        $fedSettingsList = Get-MgDomainFederationConfiguration -DomainId $domain.Id -ErrorAction SilentlyContinue -All 
                        if ($fedSettingsList) {
                             $fedSettingsList | ForEach-Object {
                                Write-Log -Message "    Federation Settings for '$($domain.Id)' (Config ID: $($_.Id)):" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      IssuerUri: $($_.IssuerUri)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      PassiveSignInUri: $($_.PassiveSignInUri)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      ActiveLogOnUri: $($_.ActiveLogOnUri)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      SignOutUri: $($_.SignOutUri)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      MetadataExchangeUri: $($_.MetadataExchangeUri)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      PreferredAuthenticationProtocol: $($_.PreferredAuthenticationProtocol)" -SpecificLogFile $AadReportFile
                                Write-Log -Message "      INFO: Review federation certificates manually for domain '$($domain.Id)' via IdP or audit logs." -Type "INFO" -SpecificLogFile $AadReportFile
                            }
                        } else {
                             Write-Log -Message "    INFO: No specific Get-MgDomainFederationConfiguration found for '$($domain.Id)'. Review domain properties and IdP." -Type "INFO" -SpecificLogFile $AadReportFile
                        }
                    } catch { Write-Log -Message "    Error retrieving federation configuration for '$($domain.Id)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }
                }
            }
        } else { Write-Log -Message "No domains found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile }

        # Check Certificate-Based Authentication (CBA) at organization level
        $orgSettings = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($orgSettings.Count -gt 0) { # Get-MgOrganization returns an array
            $currentOrg = $orgSettings[0]
            if ($currentOrg.CertificateBasedAuthConfiguration) {
                Write-Log -Message "Certificate-Based Authentication (CBA) Configuration found:" -SpecificLogFile $AadReportFile
                foreach ($authConfig in $currentOrg.CertificateBasedAuthConfiguration) { # This is an array of configurations
                    Write-Log -Message "  CBA Authorities:" -SpecificLogFile $AadReportFile
                    if ($authConfig.CertificateAuthorities.Count -eq 0) {
                        Write-Log -Message "  WARN: Certificate-Based Authentication is configured but no Certificate Authorities are defined in this configuration object." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                    foreach($authority in $authConfig.CertificateAuthorities) {
                        Write-Log -Message "    IsRootAuthority: $($authority.IsRootAuthority), Issuer: $($authority.Issuer), IssuerSki: $($authority.IssuerSki)" -SpecificLogFile $AadReportFile
                        if ($authority.IsRootAuthority -eq $false) {
                            Write-Log -Message "    ALERT: Non-root CA '$($authority.Issuer)' configured for CBA. Verify legitimacy." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                }
            } else {
                Write-Log -Message "No organization-wide Certificate-Based Authentication (CBA) configuration found." -Type "INFO" -SpecificLogFile $AadReportFile
            }
        } else { Write-Log -Message "Could not retrieve organization settings for CBA check." -Type "WARN" -SpecificLogFile $AadReportFile}


    } catch { Write-Log -Message "Error checking Domain Federation or CBA Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 18. Conditional Access Policies (CAPs) ---
    Write-Log -Message "Checking Conditional Access Policies..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
        if ($policies) {
            Write-Log -Message "Found $($policies.Count) Conditional Access Policies." -SpecificLogFile $AadReportFile
            foreach ($policy in $policies) {
                Write-Log -Message "Policy: '$($policy.DisplayName)' (ID: $($policy.Id)), State: $($policy.State), Created: $($policy.CreatedDateTime), Modified: $($policy.ModifiedDateTime)" -SpecificLogFile $AadReportFile
                if ($policy.State -eq "disabled") {
                    Write-Log -Message "  ALERT: Conditional Access Policy '$($policy.DisplayName)' is DISABLED." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                } elseif ($policy.State -eq "enabledForReportingButNotEnforced") {
                    Write-Log -Message "  WARN: Conditional Access Policy '$($policy.DisplayName)' is in REPORT-ONLY mode." -Type "WARN" -SpecificLogFile $AadReportFile
                }

                # Log Users
                if ($policy.Conditions.Users) {
                    Write-Log -Message "    Users: IncludeAll: $($policy.Conditions.Users.IncludeAllUsers), ExcludeAll: $($policy.Conditions.Users.ExcludeAllUsers)" -SpecificLogFile $AadReportFile
                    if ($policy.Conditions.Users.IncludeUsers) { Write-Log -Message "      IncludeUsers: $($policy.Conditions.Users.IncludeUsers -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Users.ExcludeUsers) { Write-Log -Message "      ExcludeUsers: $($policy.Conditions.Users.ExcludeUsers -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Users.IncludeGroups) { Write-Log -Message "      IncludeGroups: $($policy.Conditions.Users.IncludeGroups -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Users.ExcludeGroups) { Write-Log -Message "      ExcludeGroups: $($policy.Conditions.Users.ExcludeGroups -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Users.IncludeRoles) { Write-Log -Message "      IncludeRoles: $($policy.Conditions.Users.IncludeRoles -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Users.ExcludeRoles) { Write-Log -Message "      ExcludeRoles: $($policy.Conditions.Users.ExcludeRoles -join '; ')" -SpecificLogFile $AadReportFile }
                } else { Write-Log -Message "    Users: Not Configured" -SpecificLogFile $AadReportFile}
               
                # Log Applications
                if ($policy.Conditions.Applications) {
                    Write-Log -Message "    Applications: IncludeAll: $($policy.Conditions.Applications.IncludeAllApplications), ExcludeAll: $($policy.Conditions.Applications.ExcludeAllApplications)" -SpecificLogFile $AadReportFile
                    if ($policy.Conditions.Applications.IncludeApplications) { Write-Log -Message "      IncludeApplications: $($policy.Conditions.Applications.IncludeApplications -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Applications.ExcludeApplications) { Write-Log -Message "      ExcludeApplications: $($policy.Conditions.Applications.ExcludeApplications -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Applications.IncludeUserActions) { Write-Log -Message "      IncludeUserActions: $($policy.Conditions.Applications.IncludeUserActions -join '; ')" -SpecificLogFile $AadReportFile }
                } else { Write-Log -Message "    Applications: Not Configured" -SpecificLogFile $AadReportFile}


                # Log Locations
                if ($policy.Conditions.Locations) {
                    Write-Log -Message "    Locations: IncludeAll: $($policy.Conditions.Locations.IncludeAllLocations), ExcludeAll: $($policy.Conditions.Locations.ExcludeAllLocations)" -SpecificLogFile $AadReportFile
                    if ($policy.Conditions.Locations.IncludeLocations) { Write-Log -Message "      IncludeLocations: $($policy.Conditions.Locations.IncludeLocations -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Locations.ExcludeLocations) { Write-Log -Message "      ExcludeLocations: $($policy.Conditions.Locations.ExcludeLocations -join '; ')" -SpecificLogFile $AadReportFile }
                    if ($policy.Conditions.Locations.ExcludeLocations -contains "AllTrusted") {
                         Write-Log -Message "      ALERT: Conditional Access Policy '$($policy.DisplayName)' excludes 'AllTrusted' locations. This could be a bypass." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                } else { Write-Log -Message "    Locations: Not Configured" -SpecificLogFile $AadReportFile}
               
                # Log Grant Controls
                if ($policy.GrantControls) {
                    Write-Log -Message "    GrantControls: Operator: $($policy.GrantControls.Operator), BuiltInControls: $($policy.GrantControls.BuiltInControls -join '; '), CustomAuthenticationFactors: $($policy.GrantControls.CustomAuthenticationFactors -join '; '), TermsOfUse: $($policy.GrantControls.TermsOfUse -join '; ')" -SpecificLogFile $AadReportFile
                    if (($policy.GrantControls.BuiltInControls -notcontains "mfa") -and `
                        ($policy.GrantControls.BuiltInControls -notcontains "compliantDevice") -and `
                        ($policy.GrantControls.BuiltInControls -notcontains "domainJoinedDevice") -and ` # Corrected from "hybridAzureADJoinedDevice" to "domainJoinedDevice" as per Graph types
                        ($policy.GrantControls.BuiltInControls -notcontains "approvedApplication") -and `
                        ($policy.GrantControls.BuiltInControls -notcontains "compliantApplication")) {
                        Write-Log -Message "    WARN: Conditional Access Policy '$($policy.DisplayName)' does not appear to require strong authentication (MFA) or device/app compliance for grant. Review controls." -Type "WARN" -IsAlert -SpecificLogFile $AadReportFile
                    }
                } else { Write-Log -Message "    GrantControls: Not Configured (Block access likely)" -SpecificLogFile $AadReportFile}

                # Log Session Controls
                if ($policy.SessionControls) {
                    Write-Log -Message "    SessionControls: SignInFrequency: Interval: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type), PersistentBrowser: $($policy.SessionControls.PersistentBrowser.Mode), AppEnforcedRestrictions: $($policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled), CloudAppSecurity: $($policy.SessionControls.CloudAppSecurity.CloudAppSecurityType) / IsEnabled: $($policy.SessionControls.CloudAppSecurity.IsEnabled)" -SpecificLogFile $AadReportFile
                    if ($policy.SessionControls.SignInFrequency.Value -gt 24 -and $policy.SessionControls.SignInFrequency.Type -eq "hours") { 
                        Write-Log -Message "    WARN: Conditional Access Policy '$($policy.DisplayName)' has a SignInFrequency greater than 24 hours ($($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                     if ($policy.SessionControls.PersistentBrowser.Mode -ne "never" -and $policy.SessionControls.PersistentBrowser.IsEnabled -eq $true) {
                        Write-Log -Message "    WARN: Conditional Access Policy '$($policy.DisplayName)' allows persistent browser sessions (Mode: $($policy.SessionControls.PersistentBrowser.Mode))." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                } else { Write-Log -Message "    SessionControls: Not Configured" -SpecificLogFile $AadReportFile}
                Write-Log -Message "    (E3/P1 Limitation: Risk-based conditions like UserRiskLevels or SignInRiskLevels require Azure AD Premium P2 and are not checked here.)" -Type "INFO" -SpecificLogFile $AadReportFile
            }
        } else {
            Write-Log -Message "No Conditional Access Policies found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
        }
    } catch { Write-Log -Message "Error checking Conditional Access Policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 19. Partner Relationships & Delegated Admin Privileges (DAP/GDAP) ---
    Write-Log -Message "Checking Partner Relationships (DAP/GDAP)..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    # DAP Check (Legacy - MSOnline Module)
    if (Get-Module -Name MSOnline -ListAvailable) {
        Connect-ToMSOnline # Ensure connection
        if ($script:MSOnlineConnected) {
            Write-Log -Message "  Checking for DAP relationships (using MSOnline - legacy)..." -SpecificLogFile $AadReportFile
            try {
                $dapPartners = Get-MsolPartnerContract -All -ErrorAction SilentlyContinue
                if ($dapPartners) {
                    foreach ($partner in $dapPartners) {
                        Write-Log -Message "    DAP Partner: $($partner.TenantId) ($($partner.PartnerType))" -SpecificLogFile $AadReportFile
                        Write-Log -Message "    ALERT: Active DAP relationship found with Partner Tenant ID: $($partner.TenantId). Review and transition to GDAP if possible." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                } else {
                    Write-Log -Message "    No DAP relationships found." -Type "INFO" -SpecificLogFile $AadReportFile
                }
            } catch {
                Write-Log -Message "    Error checking DAP relationships: $($_.Exception.Message). This may be due to MSOnline module deprecation or permissions." -Type "ERROR" -SpecificLogFile $AadReportFile
            }
        } else {
             Write-Log -Message "  Skipping DAP checks as MSOnline connection failed or module not fully functional." -Type "WARN" -SpecificLogFile $AadReportFile
        }
    } else {
        Write-Log -Message "  MSOnline module not found. Skipping legacy DAP checks." -Type "WARN" -SpecificLogFile $AadReportFile
    }

    # GDAP Check (Graph API)
    Write-Log -Message "  Checking for GDAP relationships (using Graph API)..." -SpecificLogFile $AadReportFile
    try {
        $gdapRelationships = Get-MgTenantRelationshipDelegatedAdminRelationship -All -ErrorAction SilentlyContinue
        if ($gdapRelationships) {
            Write-Log -Message "  Found $($gdapRelationships.Count) GDAP relationships." -SpecificLogFile $AadReportFile
            foreach ($gdap in $gdapRelationships) {
                Write-Log -Message "    GDAP Relationship: '$($gdap.DisplayName)' (ID: $($gdap.Id))" -SpecificLogFile $AadReportFile
                Write-Log -Message "      Partner Tenant ID: $($gdap.TenantId)" -SpecificLogFile $AadReportFile
                Write-Log -Message "      Customer Tenant ID: $($gdap.Customer.TenantId)" -SpecificLogFile $AadReportFile
                Write-Log -Message "      Duration: $($gdap.Duration), Status: $($gdap.Status)" -SpecificLogFile $AadReportFile
                Write-Log -Message "      Created: $($gdap.CreatedDateTime), Last Modified: $($gdap.LastModifiedDateTime)" -SpecificLogFile $AadReportFile
               
                if ($gdap.Status -eq "active") {
                    Write-Log -Message "      ALERT: Active GDAP relationship '$($gdap.DisplayName)' with Partner Tenant ID '$($gdap.TenantId)'. Review assigned roles." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    if ($gdap.AccessDetails.UnifiedRoles.Count -gt 0) {
                        Write-Log -Message "      Assigned Roles:" -SpecificLogFile $AadReportFile
                        $gdap.AccessDetails.UnifiedRoles | ForEach-Object {
                            # Attempt to resolve role name from definition
                            $roleDef = Get-MgDirectoryRoleDefinition -Filter "Id eq '$($_.RoleDefinitionId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                            $roleName = $roleDef.DisplayName ?? $_.RoleDefinitionId
                            Write-Log -Message "        Role: $roleName (ID: $($_.RoleDefinitionId))" -SpecificLogFile $AadReportFile
                        }
                    } else {
                        Write-Log -Message "      No specific roles found in this GDAP access detail." -SpecificLogFile $AadReportFile
                    }
                }
            }
        } else {
            Write-Log -Message "  No GDAP relationships found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
        }
    } catch { Write-Log -Message "  Error checking GDAP relationships: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 20. Device Registrations & Compliance ---
    Write-Log -Message "Checking Device Registrations & Compliance (Informational for Intune)..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    try {
        $devices = Get-MgDevice -All -Property "Id,DisplayName,TrustType,OperatingSystem,ApproximateLastSignInDateTime,RegistrationDateTime,DeviceId,IsCompliant,IsManaged" -ErrorAction SilentlyContinue
        if ($devices) {
            Write-Log -Message "  Found $($devices.Count) registered devices." -SpecificLogFile $AadReportFile
            foreach ($device in $devices) {
                Write-Log -Message "    Device: '$($device.DisplayName)' (ID: $($device.DeviceId)), OS: $($device.OperatingSystem), TrustType: $($device.TrustType), Registered: $($device.RegistrationDateTime), LastSignIn: $($device.ApproximateLastSignInDateTime), Compliant: $($device.IsCompliant), Managed: $($device.IsManaged)" -SpecificLogFile $AadReportFile
                if ($device.RegistrationDateTime -and (New-TimeSpan -Start $device.RegistrationDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                    Write-Log -Message "    ALERT: Device '$($device.DisplayName)' (ID: $($device.DeviceId)) was registered recently ($($device.RegistrationDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                }
            }
        } else {
            Write-Log -Message "  No devices found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
        }
        Write-Log -Message "  INFO: Intune compliance and configuration policy checks require Intune-specific Graph API calls or modules and are not covered in this script." -Type "INFO" -SpecificLogFile $AadReportFile
    } catch { Write-Log -Message "  Error checking Device Registrations: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }


    # --- 21. Sign-in Analysis (Leveraging Audit Logs) ---
    Write-Log -Message "Checking Sign-in Logs (requires AuditLog.Read.All scope)..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    if (-not $GraphConnected) {
        Write-Log -Message "Skipping Sign-in Log analysis (Graph API not connected)." -Type "WARN" -SpecificLogFile $AadReportFile
    } else {
        try {
            $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
            # Filter for sign-ins that are either failed OR have some risk indicator.
            # riskEventTypes_v2 is an array; check if it has any non-empty elements.
            # Other risk fields are checked against 'none' and null.
            $signInFilter = "createdDateTime ge $startTime and (" +
                            "status/errorCode ne 0 or " + # Failed sign-ins
                            "riskEventTypes_v2/any(c:c ne '') or " + 
                            "(riskLevelAggregated ne 'none' and riskLevelAggregated ne null) or " +
                            "(riskLevelDuringSignIn ne 'none' and riskLevelDuringSignIn ne null) or " +
                            "(riskState ne 'none' and riskState ne null)" + 
                            ")"

            Write-Log -Message "Querying sign-in logs with filter: $signInFilter (This may take some time for active tenants for the last $($script:LookbackDays) days)" -SpecificLogFile $AadReportFile
           
            $selectProperties = @(
                "Id", "CreatedDateTime", "UserPrincipalName", "UserId", "AppDisplayName", "IpAddress",
                "ClientAppUsed", "DeviceDetail", "Location", "RiskDetail", "RiskLevelAggregated",
                "RiskLevelDuringSignIn", "RiskState", "RiskEventTypes_v2", "Status", 
                "TokenIssuerType", "ConditionalAccessStatus", "MfaDetail" # Added MfaDetail
            )
            $signIns = Get-MgAuditLogSignIn -Filter $signInFilter -All -Property $selectProperties -ErrorAction SilentlyContinue

            if ($null -ne $signIns -and $signIns.Count -gt 0) {
                Write-Log -Message "Found $($signIns.Count) potentially suspicious or failed sign-in events in the last $($script:LookbackDays) days." -SpecificLogFile $AadReportFile
                foreach ($signIn in $signIns) {
                    $isAlertEvent = $false
                    $alertReason = New-Object System.Collections.Generic.List[string]
                   
                    $failureReasonText = if ($signIn.Status.AdditionalDetails) { "$($signIn.Status.FailureReason) ($($signIn.Status.AdditionalDetails))" } else { "$($signIn.Status.FailureReason)" }

                    # Base details for logging
                    $detailedLogEntry = "User: '$($signIn.UserPrincipalName)', App: '$($signIn.AppDisplayName)', IP: $($signIn.IpAddress), Time: $($signIn.CreatedDateTime), ClientApp: '$($signIn.ClientAppUsed)', CA Status: $($signIn.ConditionalAccessStatus), TokenIssuer: $($signIn.TokenIssuerType)"
                    if ($signIn.MfaDetail) {
                        $detailedLogEntry += ", MFA: $($signIn.MfaDetail.AuthMethod) (Detail: $($signIn.MfaDetail.AuthDetail))"
                    }

                    if ($signIn.Status.ErrorCode -ne 0) {
                        $isAlertEvent = $true
                        $alertReason.Add("Failed login (Code: $($signIn.Status.ErrorCode) - $($failureReasonText))")
                        $detailedLogEntry += ", Status: Failed (Code: $($signIn.Status.ErrorCode) - $($failureReasonText))"
                    } else {
                        $detailedLogEntry += ", Status: Success"
                    }

                    $riskInfoParts = New-Object System.Collections.Generic.List[string]
                    if ($signIn.RiskDetail -ne $null -and $signIn.RiskDetail -ne "none" -and $signIn.RiskDetail -ne "hidden" ) { $riskInfoParts.Add("Detail: $($signIn.RiskDetail)") }
                    if ($signIn.RiskLevelAggregated -ne $null -and $signIn.RiskLevelAggregated -ne "none") { $riskInfoParts.Add("AggregatedLvl: $($signIn.RiskLevelAggregated)") }
                    if ($signIn.RiskLevelDuringSignIn -ne $null -and $signIn.RiskLevelDuringSignIn -ne "none") { $riskInfoParts.Add("SignInLvl: $($signIn.RiskLevelDuringSignIn)") }
                    if ($signIn.RiskState -ne $null -and $signIn.RiskState -ne "none") { $riskInfoParts.Add("State: $($signIn.RiskState)") }
                    if ($signIn.RiskEventTypes_v2 -ne $null -and $signIn.RiskEventTypes_v2.Count -gt 0) {
                        $riskInfoParts.Add("Events: $($signIn.RiskEventTypes_v2 -join ', ')")
                    }

                    if ($riskInfoParts.Count -gt 0) {
                        $isAlertEvent = $true # Any risk info makes it an alert
                        $riskSummary = $riskInfoParts -join '; '
                        $alertReason.Add("Risk Detected ($riskSummary)")
                        $detailedLogEntry += ", Risk: ($riskSummary)"
                    }
                   
                    $locationText = "N/A"
                    if ($signIn.Location) {
                        $locationText = "$($signIn.Location.City), $($signIn.Location.State), $($signIn.Location.CountryOrRegion)"
                        $detailedLogEntry += ", Location: $locationText"
                    }

                    if ($isAlertEvent) {
                        $alertSummary = "ALERT: Suspicious/Failed Sign-in for '$($signIn.UserPrincipalName)' at $($signIn.CreatedDateTime) from IP '$($signIn.IpAddress)'. Reasons: $($alertReason -join ' | '). App: '$($signIn.AppDisplayName)'. Location: $locationText."
                        Write-Log -Message $alertSummary -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        Write-Log -Message "  Details: $detailedLogEntry" -Type "INFO" -SpecificLogFile $AadReportFile
                    } else {
                        # This case should ideally not be hit if the filter is effective,
                        # but log as INFO if a non-alerting event slips through.
                        Write-Log -Message "INFO Sign-in (passed filter but not flagged as alert): $detailedLogEntry" -SpecificLogFile $AadReportFile
                    }
                }
                Write-Log -Message "INFO: For 'dormant accounts with activity', correlate these findings with users who had very old LastSignInDateTime values from user object properties (Check #12). Azure AD Audit Logs are the definitive source for activity." -Type "INFO" -SpecificLogFile $AadReportFile
            } elseif ($null -eq $signIns) {
                Write-Log -Message "Sign-in log query returned null. This could be due to an issue with the Graph API call (e.g. permissions, service outage) or no data matched." -Type "WARN" -SpecificLogFile $AadReportFile
            }
            else { # $signIns is an empty collection
                Write-Log -Message "No sign-in events matching the suspicious/failed criteria found in the last $($script:LookbackDays) days." -Type "INFO" -SpecificLogFile $AadReportFile
            }
        } catch {
            Write-Log -Message "Error during Sign-in Log analysis: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile
            if ($signInFilter) { Write-Log -Message "  Filter used: $signInFilter" -Type "ERROR" -SpecificLogFile $AadReportFile }
            Write-Log -Message "  This may be due to insufficient permissions (AuditLog.Read.All required), complex filter issues, or Graph API throttling." -Type "ERROR" -SpecificLogFile $AadReportFile
        }
    }
    Write-Log -Message "INFO: Full Azure AD Identity Protection features (automated risk detection, investigation, and remediation) require Azure AD Premium P2." -Type "INFO" -SpecificLogFile $AadReportFile


    # --- 22. B2B Guest Access & Collaboration Settings ---
    Write-Log -Message "Checking B2B Guest Access & Collaboration Settings..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    if (-not $GraphConnected) {
        Write-Log -Message "Skipping B2B Guest Access checks (Graph API not connected)." -Type "WARN" -SpecificLogFile $AadReportFile
    } else {
        try {
            Write-Log -Message "  Enumerating Guest Users..." -SpecificLogFile $AadReportFile
            $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property "Id,DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity" -ErrorAction SilentlyContinue
            if ($guestUsers) {
                Write-Log -Message "  Found $($guestUsers.Count) guest users." -SpecificLogFile $AadReportFile
                foreach ($guest in $guestUsers) {
                    Write-Log -Message "  Guest: '$($guest.DisplayName)' (UPN: $($guest.UserPrincipalName)), Created: $($guest.CreatedDateTime), LastSignIn: $($guest.SignInActivity.LastSignInDateTime)" -SpecificLogFile $AadReportFile
                    if ((New-TimeSpan -Start $guest.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                        Write-Log -Message "  ALERT: Guest user '$($guest.UserPrincipalName)' created recently ($($guest.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                    if ($null -eq $guest.SignInActivity.LastSignInDateTime -or $guest.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)) {
                        Write-Log -Message "  INFO: Guest user '$($guest.UserPrincipalName)' has no recent sign-in activity (Last sign-in: $($guest.SignInActivity.LastSignInDateTime ?? 'Never')). Consider for review/cleanup." -Type "INFO" -SpecificLogFile $AadReportFile
                    }
                }
            } else {
                Write-Log -Message "  No guest users found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
            }

            Write-Log -Message "  Checking Tenant B2B Collaboration (Authorization) Policy..." -SpecificLogFile $AadReportFile
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
            if ($authPolicy) {
                # The main authorization policy is usually a single object, but Get-MgPolicyAuthorizationPolicy returns an array
                $policy = $authPolicy | Select-Object -First 1 
                if ($policy) {
                    Write-Log -Message "  Authorization Policy ID: $($policy.Id), DisplayName: $($policy.DisplayName), Description: $($policy.Description)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    AllowEmailVerifiedUsersToJoinOrganization: $($policy.AllowEmailVerifiedUsersToJoinOrganization)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    AllowInvitesFrom: $($policy.AllowInvitesFrom)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    AllowedToInviteUsers: $($policy.DefaultUserRolePermissions.AllowedToInviteUsers)" -SpecificLogFile $AadReportFile # Corrected property path
                    Write-Log -Message "    AllowedToUseSspr: $($policy.AllowedToUseSspr)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    BlockMsolPowerShell: $($policy.BlockMsolPowerShell)" -SpecificLogFile $AadReportFile
                   
                    # Guest User Access Restrictions (if available - can be part of defaultUserRolePermissions or separate settings)
                    # Note: Guest user settings are more complex and spread out. This covers some basic ones.
                    # More specific guest settings might be under /policies/externalIdentitiesPolicy or crossTenantAccessPolicy
                    Write-Log -Message "    Guest User Role Permissions:" -SpecificLogFile $AadReportFile
                    Write-Log -Message "      AllowedToCreateApps: $($policy.DefaultUserRolePermissions.AllowedToCreateApps)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "      AllowedToCreateSecurityGroups: $($policy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "      AllowedToReadOtherUsers: $($policy.DefaultUserRolePermissions.AllowedToReadOtherUsers)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "      AllowedToReadDirectory: $($policy.DefaultUserRolePermissions.AllowedToReadDirectory)" -SpecificLogFile $AadReportFile # New property in some versions

                    if ($policy.AllowInvitesFrom -eq "everyone") {
                        Write-Log -Message "  ALERT: B2B policy allows invites from 'everyone'. This is a very permissive setting." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    } elseif ($policy.AllowInvitesFrom -eq "adminsAndGuestInviters") {
                        Write-Log -Message "  INFO: B2B policy allows invites from 'adminsAndGuestInviters'." -Type "INFO" -SpecificLogFile $AadReportFile
                    } elseif ($policy.AllowInvitesFrom -eq "specificAdmins") {
                         Write-Log -Message "  INFO: B2B policy allows invites from 'specificAdmins' (most restrictive for who can invite)." -Type "INFO" -SpecificLogFile $AadReportFile
                    }

                    if ($policy.DefaultUserRolePermissions.AllowedToInviteUsers -eq $true) { # If non-admins/non-guest-inviters can invite
                        Write-Log -Message "  ALERT: B2B policy 'AllowedToInviteUsers' for default user role is TRUE. Members and non-admin users can invite guests." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }

                    # Check Guest self-service sign up via user flows (different endpoint)
                    # This is a more advanced check, for now, we focus on direct invitation settings.
                    # Get-MgIdentityUserFlow might be relevant but is for specific user flows.

                    # Check if guests can invite other guests (This setting is part of the "External collaboration settings" in Azure Portal)
                    # This is often configured under /beta/policies/externalIdentitiesPolicy or reflected in cross-tenant access policy.
                    # For a simpler check, we'll look at a common indicator if available directly on authorization policy or related settings.
                    # The most direct setting for "Guests can invite other guests" is typically managed in the Azure Portal's "External collaboration settings".
                    # Graph API for this specific toggle "Guest users can invite other guests (preview)" is less direct.
                    # We will infer based on common configurations or note it as a manual check.
                    Write-Log -Message "  INFO: Review 'External collaboration settings' in Azure Portal for 'Guest invite settings' (e.g., if guests can invite other guests) and 'Collaboration restrictions'." -Type "INFO" -SpecificLogFile $AadReportFile
                } else {
                     Write-Log -Message "  Could not retrieve the primary authorization policy object." -Type "WARN" -SpecificLogFile $AadReportFile
                }
            } else {
                Write-Log -Message "  No tenant-wide Authorization Policy found or error retrieving it. This is unusual and should be investigated." -Type "ERROR" -SpecificLogFile $AadReportFile
            }
        } catch {
            Write-Log -Message "Error checking B2B Guest Access & Collaboration Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile
        }
    }


    # --- 23. Privileged Access Group Assignments ---
    Write-Log -Message "Checking Privileged Access Group Assignments (Role-assignable groups)..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    if (-not $GraphConnected) {
        Write-Log -Message "Skipping Privileged Access Group checks (Graph API not connected)." -Type "WARN" -SpecificLogFile $AadReportFile
    } else {
        try {
            Write-Log -Message "  Searching for role-assignable groups (isAssignableToRole eq true)..." -SpecificLogFile $AadReportFile
            $roleAssignableGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -All -ErrorAction SilentlyContinue `
                -Property "Id,DisplayName,Description,CreatedDateTime,SecurityEnabled,MailEnabled,GroupTypes"

            if ($null -ne $roleAssignableGroups -and $roleAssignableGroups.Count -gt 0) {
                Write-Log -Message "  Found $($roleAssignableGroups.Count) role-assignable groups." -SpecificLogFile $AadReportFile
                foreach ($group in $roleAssignableGroups) {
                    Write-Log -Message "  Role-Assignable Group: '$($group.DisplayName)' (ID: $($group.Id)), Created: $($group.CreatedDateTime)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    Description: $($group.Description)" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    ALERT: Group '$($group.DisplayName)' (ID: $($group.Id)) is role-assignable. Review its members and assigned roles carefully." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile

                    # Get members of the role-assignable group
                    try {
                        $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                        if ($members) {
                            Write-Log -Message "    Members of '$($group.DisplayName)':" -SpecificLogFile $AadReportFile
                            foreach ($member in $members) {
                                $memberType = $member.AdditionalProperties.'@odata.type'
                                $memberDisplayName = $member.AdditionalProperties.displayName
                                $memberUpnOrAppId = $member.AdditionalProperties.userPrincipalName ?? $member.AdditionalProperties.appId ?? "N/A"
                                Write-Log -Message "      Member: '$memberDisplayName' (Type: $memberType, UPN/AppId: $memberUpnOrAppId, ID: $($member.Id))" -SpecificLogFile $AadReportFile
                                if ($memberType -eq "#microsoft.graph.servicePrincipal") {
                                    Write-Log -Message "      ALERT: Service Principal '$memberDisplayName' (AppId: $memberUpnOrAppId) is a member of role-assignable group '$($group.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                                }
                                if ($memberUpnOrAppId -match "#EXT#") {
                                    Write-Log -Message "      ALERT: Guest User '$memberUpnOrAppId' is a member of role-assignable group '$($group.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                                }
                            }
                            if ($members.Count -eq 0) {
                                Write-Log -Message "      No members found in group '$($group.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile
                            }
                        } else { Write-Log -Message "    No members found or unable to retrieve for group '$($group.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile}
                    } catch { Write-Log -Message "    Error retrieving members for group '$($group.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }

                    # Get directory roles assigned TO this group
                    try {
                        # A group is a directoryObject, so we get its memberOf which are directoryRoles
                        $assignedRoles = Get-MgGroupMemberOfAsDirectoryRole -GroupId $group.Id -All -ErrorAction SilentlyContinue
                        if ($assignedRoles) {
                            Write-Log -Message "    Directory Roles directly assigned to group '$($group.DisplayName)':" -SpecificLogFile $AadReportFile
                            foreach ($role in $assignedRoles) {
                                Write-Log -Message "      Role Name: '$($role.DisplayName)' (Role ID: $($role.RoleTemplateId ?? $role.Id))" -SpecificLogFile $AadReportFile
                                # Using privilegedRoles array from check #13
                                if ($script:privilegedRoles -contains $role.DisplayName) {
                                    Write-Log -Message "      ALERT: Privileged role '$($role.DisplayName)' is assigned to role-assignable group '$($group.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                                } elseif ($role.DisplayName -match "Admin" -or $role.IsBuiltIn -eq $false) {
                                    Write-Log -Message "      INFO: Role '$($role.DisplayName)' (potentially custom or administrative) is assigned to role-assignable group '$($group.DisplayName)'. Review." -Type "INFO" -SpecificLogFile $AadReportFile
                                }
                            }
                            if ($assignedRoles.Count -eq 0) {
                                Write-Log -Message "      No directory roles found directly assigned to group '$($group.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile
                            }
                        } else { Write-Log -Message "    No directory roles found as directly assigned or unable to retrieve for group '$($group.DisplayName)'." -Type "INFO" -SpecificLogFile $AadReportFile}
                    } catch { Write-Log -Message "    Error retrieving roles assigned to group '$($group.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile }
                }
            } else {
                Write-Log -Message "  No role-assignable groups found in the tenant or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
            }
        } catch {
            Write-Log -Message "Error checking Privileged Access Groups: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile
            Write-Log -Message "  This may be due to permissions or Graph API issues." -Type "ERROR" -SpecificLogFile $AadReportFile
        }
    }
    # --- 24. Cross-Tenant Synchronization (CTS) / Multi-Tenant Organization (MTO) Settings ---
    Write-Log -Message "Checking Cross-Tenant Synchronization (CTS) / Multi-Tenant Organization (MTO) Settings..." -Type "SUBSECTION" -SpecificLogFile $AadReportFile
    if (-not $GraphConnected) {
        Write-Log -Message "Skipping Cross-Tenant Synchronization/MTO checks (Graph API not connected)." -Type "WARN" -SpecificLogFile $AadReportFile
    } else {
        try {
            # Check Multi-Tenant Organization (MTO) Status
            Write-Log -Message "  Checking Multi-Tenant Organization (MTO) configuration..." -SpecificLogFile $AadReportFile
            $mto = Get-MgTenantRelationshipMultiTenantOrganization -ErrorAction SilentlyContinue
            if ($mto) {
                Write-Log -Message "  INFO: This tenant is part of a Multi-Tenant Organization: '$($mto.DisplayName)' (ID: $($mto.Id)). Created: $($mto.CreatedDateTime), Last Modified: $($mto.LastModifiedDateTime)" -Type "INFO" -SpecificLogFile $AadReportFile
                Write-Log -Message "  ALERT: Tenant is part of an MTO. Verify all member tenants and configurations are expected." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile

                $mtoMembers = Get-MgTenantRelationshipMultiTenantOrganizationMember -MultiTenantOrganizationId $mto.Id -All -ErrorAction SilentlyContinue
                if ($mtoMembers) {
                    Write-Log -Message "  MTO Member Tenants ($($mtoMembers.Count)):" -SpecificLogFile $AadReportFile
                    foreach ($member in $mtoMembers) {
                        Write-Log -Message "    Tenant ID: $($member.TenantId), DisplayName: $($member.DisplayName), Role: $($member.Role), Joined: $($member.JoinedDateTime)" -SpecificLogFile $AadReportFile
                    }
                } else {
                    Write-Log -Message "    No member tenants listed for this MTO or unable to retrieve." -Type "INFO" -SpecificLogFile $AadReportFile
                }
            } else {
                Write-Log -Message "  This tenant is not configured as part of a Multi-Tenant Organization (MTO)." -Type "INFO" -SpecificLogFile $AadReportFile
            }

            # Check Default Cross-Tenant Access Policy
            Write-Log -Message "  Checking Default Cross-Tenant Access Policy..." -SpecificLogFile $AadReportFile
            $defaultPolicy = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction SilentlyContinue
            if ($defaultPolicy) {
                Write-Log -Message "  Default Policy ID: $($defaultPolicy.Id)" -SpecificLogFile $AadReportFile
                # B2B Collaboration Inbound
                if ($defaultPolicy.B2bCollaborationInbound) {
                    Write-Log -Message "    Default B2B Collaboration Inbound: Users: $($defaultPolicy.B2bCollaborationInbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bCollaborationInbound.Applications.AccessType), TargetTenant: $($defaultPolicy.B2bCollaborationInbound.TargetTenantAccessType)" -SpecificLogFile $AadReportFile
                    if ($defaultPolicy.B2bCollaborationInbound.UsersAndGroups.AccessType -eq "allUsers" -and $defaultPolicy.B2bCollaborationInbound.Applications.AccessType -eq "allApplications") {
                        Write-Log -Message "    ALERT: Default B2B Collaboration Inbound is configured to allow all users and all applications. This is highly permissive." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                }
                # B2B Collaboration Outbound
                if ($defaultPolicy.B2bCollaborationOutbound) {
                    Write-Log -Message "    Default B2B Collaboration Outbound: Users: $($defaultPolicy.B2bCollaborationOutbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bCollaborationOutbound.ExternalApplications.AccessType), TargetTenant: $($defaultPolicy.B2bCollaborationOutbound.TargetTenantAccessType)" -SpecificLogFile $AadReportFile
                    if ($defaultPolicy.B2bCollaborationOutbound.UsersAndGroups.AccessType -eq "allUsers" -and $defaultPolicy.B2bCollaborationOutbound.ExternalApplications.AccessType -eq "allApplications") {
                        Write-Log -Message "    WARN: Default B2B Collaboration Outbound is configured to allow all users and all applications. Review if this is intended." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                }
                # B2B Direct Connect Inbound
                if ($defaultPolicy.B2bDirectConnectInbound) {
                    Write-Log -Message "    Default B2B Direct Connect Inbound: Users: $($defaultPolicy.B2bDirectConnectInbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bDirectConnectInbound.Applications.AccessType), TargetTenant: $($defaultPolicy.B2bDirectConnectInbound.TargetTenantAccessType)" -SpecificLogFile $AadReportFile
                    if ($defaultPolicy.B2bDirectConnectInbound.UsersAndGroups.AccessType -ne "blocked" -or $defaultPolicy.B2bDirectConnectInbound.Applications.AccessType -ne "blocked") {
                        Write-Log -Message "    ALERT: Default B2B Direct Connect Inbound is not fully blocked (Users: $($defaultPolicy.B2bDirectConnectInbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bDirectConnectInbound.Applications.AccessType)). B2B Direct Connect has significant trust implications." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                }
                # B2B Direct Connect Outbound
                if ($defaultPolicy.B2bDirectConnectOutbound) {
                    Write-Log -Message "    Default B2B Direct Connect Outbound: Users: $($defaultPolicy.B2bDirectConnectOutbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bDirectConnectOutbound.Applications.AccessType), TargetTenant: $($defaultPolicy.B2bDirectConnectOutbound.TargetTenantAccessType)" -SpecificLogFile $AadReportFile
                    if ($defaultPolicy.B2bDirectConnectOutbound.UsersAndGroups.AccessType -ne "blocked" -or $defaultPolicy.B2bDirectConnectOutbound.Applications.AccessType -ne "blocked") {
                        Write-Log -Message "    WARN: Default B2B Direct Connect Outbound is not fully blocked (Users: $($defaultPolicy.B2bDirectConnectOutbound.UsersAndGroups.AccessType), Apps: $($defaultPolicy.B2bDirectConnectOutbound.Applications.AccessType)). Review if intended." -Type "WARN" -SpecificLogFile $AadReportFile
                    }
                }
                # Inbound Trust Settings
                if ($defaultPolicy.InboundTrust) {
                    Write-Log -Message "    Default Inbound Trust Settings: IsMfaAccepted: $($defaultPolicy.InboundTrust.IsMfaAccepted), IsCompliantDeviceAccepted: $($defaultPolicy.InboundTrust.IsCompliantDeviceAccepted), IsHybridAzureADJoinedDeviceAccepted: $($defaultPolicy.InboundTrust.IsHybridAzureADJoinedDeviceAccepted)" -SpecificLogFile $AadReportFile
                    if ($defaultPolicy.InboundTrust.IsMfaAccepted -eq $false) {
                        Write-Log -Message "    ALERT: Default Inbound Trust does not accept MFA from other tenants. This weakens security for guest access." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                    }
                }
                Write-Log -Message "    INFO: Default IsInboundAllowed: $($defaultPolicy.IsInboundAllowed), IsOutboundAllowed: $($defaultPolicy.IsOutboundAllowed)" -Type "INFO" -SpecificLogFile $AadReportFile

            } else {
                Write-Log -Message "  Could not retrieve Default Cross-Tenant Access Policy. This is unusual." -Type "ERROR" -SpecificLogFile $AadReportFile
            }

            # Check Partner-Specific Cross-Tenant Access Policies
            Write-Log -Message "  Checking Partner-Specific Cross-Tenant Access Policies..." -SpecificLogFile $AadReportFile
            $partnerPolicies = Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction SilentlyContinue
            if ($partnerPolicies) {
                Write-Log -Message "  Found $($partnerPolicies.Count) partner-specific policies." -SpecificLogFile $AadReportFile
                foreach ($partnerPolicy in $partnerPolicies) {
                    Write-Log -Message "  Partner Policy for Tenant ID: $($partnerPolicy.TenantId) (Policy ID: $($partnerPolicy.Id))" -SpecificLogFile $AadReportFile
                    Write-Log -Message "    IsInboundAllowed: $($partnerPolicy.IsInboundAllowed), IsOutboundAllowed: $($partnerPolicy.IsOutboundAllowed)" -SpecificLogFile $AadReportFile

                    if ($partnerPolicy.B2bCollaborationInbound) {
                        Write-Log -Message "    Partner B2B Collaboration Inbound: Users: $($partnerPolicy.B2bCollaborationInbound.UsersAndGroups.AccessType), Apps: $($partnerPolicy.B2bCollaborationInbound.Applications.AccessType)" -SpecificLogFile $AadReportFile
                        if ($partnerPolicy.B2bCollaborationInbound.UsersAndGroups.AccessType -eq "allUsers" -and $partnerPolicy.B2bCollaborationInbound.Applications.AccessType -eq "allApplications") {
                            Write-Log -Message "    ALERT: Partner policy for $($partnerPolicy.TenantId) allows all inbound B2B users and applications." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                    if ($partnerPolicy.B2bCollaborationOutbound) {
                        Write-Log -Message "    Partner B2B Collaboration Outbound: Users: $($partnerPolicy.B2bCollaborationOutbound.UsersAndGroups.AccessType), Apps: $($partnerPolicy.B2bCollaborationOutbound.ExternalApplications.AccessType)" -SpecificLogFile $AadReportFile
                    }
                    if ($partnerPolicy.B2bDirectConnectInbound) {
                        Write-Log -Message "    Partner B2B Direct Connect Inbound: Users: $($partnerPolicy.B2bDirectConnectInbound.UsersAndGroups.AccessType), Apps: $($partnerPolicy.B2bDirectConnectInbound.Applications.AccessType)" -SpecificLogFile $AadReportFile
                        if ($partnerPolicy.B2bDirectConnectInbound.UsersAndGroups.AccessType -ne "blocked" -or $partnerPolicy.B2bDirectConnectInbound.Applications.AccessType -ne "blocked"){
                            Write-Log -Message "    ALERT: Partner B2B Direct Connect Inbound for $($partnerPolicy.TenantId) is not fully blocked. Review this trusted relationship." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                    if ($partnerPolicy.B2bDirectConnectOutbound) {
                        Write-Log -Message "    Partner B2B Direct Connect Outbound: Users: $($partnerPolicy.B2bDirectConnectOutbound.UsersAndGroups.AccessType), Apps: $($partnerPolicy.B2bDirectConnectOutbound.Applications.AccessType)" -SpecificLogFile $AadReportFile
                    }
                    if ($partnerPolicy.InboundTrust) {
                        Write-Log -Message "    Partner Inbound Trust: IsMfaAccepted: $($partnerPolicy.InboundTrust.IsMfaAccepted), IsCompliantDeviceAccepted: $($partnerPolicy.InboundTrust.IsCompliantDeviceAccepted), IsHybridAzureADJoinedDeviceAccepted: $($partnerPolicy.InboundTrust.IsHybridAzureADJoinedDeviceAccepted)" -SpecificLogFile $AadReportFile
                        if ($partnerPolicy.InboundTrust.IsMfaAccepted -eq $false) {
                            Write-Log -Message "    ALERT: Partner Inbound Trust for $($partnerPolicy.TenantId) does not accept MFA from their tenant." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                    if ($partnerPolicy.AutomaticUserConsentSettings) {
                        Write-Log -Message "    Partner Automatic User Consent Settings: InboundAllowed: $($partnerPolicy.AutomaticUserConsentSettings.InboundAllowed), OutboundAllowed: $($partnerPolicy.AutomaticUserConsentSettings.OutboundAllowed)" -SpecificLogFile $AadReportFile
                        if ($partnerPolicy.AutomaticUserConsentSettings.InboundAllowed -eq $true -or $partnerPolicy.AutomaticUserConsentSettings.OutboundAllowed -eq $true) {
                            Write-Log -Message "    ALERT: Partner policy for $($partnerPolicy.TenantId) has Automatic User Consent enabled (Inbound: $($partnerPolicy.AutomaticUserConsentSettings.InboundAllowed), Outbound: $($partnerPolicy.AutomaticUserConsentSettings.OutboundAllowed)). This can allow users to grant permissions to applications from this partner tenant without admin pre-consent." -Type "ALERT" -IsAlert -SpecificLogFile $AadReportFile
                        }
                    }
                }
            } else {
                Write-Log -Message "  No partner-specific cross-tenant access policies found or error retrieving them." -Type "INFO" -SpecificLogFile $AadReportFile
            }

        } catch {
            Write-Log -Message "Error checking Cross-Tenant Synchronization/MTO Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $AadReportFile
            Write-Log -Message "  This may be due to permissions (Policy.Read.All and related Graph scopes) or API issues." -Type "ERROR" -SpecificLogFile $AadReportFile
        }
    }
    Write-Log -Message "Finished Azure AD / Entra ID Checks." -Type "SECTION"
}


# ==================================================
# SECTION III: SharePoint Online and OneDrive for Business Checks
# ==================================================
function Invoke-SharePointOnlineChecks {
    Write-Log -Message "Starting SharePoint Online and OneDrive for Business Checks" -Type "SECTION"
    if (-not $GraphConnected) {
        Write-Log -Message "Cannot perform SharePoint checks. Not connected to Graph API." -Type "ERROR"
        return
    }
    $SpoReportFile = "SharePointOnline_Report.txt"

    # Helper function to check if a UPN is external
    function Is-SpoUserExternal {
        param (
            [string]$UserPrincipalName
        )
        if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            return $false # Cannot determine
        }
        if ($UserPrincipalName -match "#EXT#") {
            return $true
        }
        if ($UserPrincipalName -match "@") {
            $domainPart = ($UserPrincipalName -split "@")[1]
            if ($script:AcceptedDomains -notcontains $domainPart) {
                return $true
            }
        } else {
            # UPN without domain, likely a synchronized on-prem account before UPN update or special account.
            # For safety, flag for review if it's an SCA.
            Write-Log -Message "  User '$UserPrincipalName' has an unusual UPN format; unable to definitively determine if external by domain. Review manually if granted sensitive permissions." -Type "WARN" -SpecificLogFile $SpoReportFile
        }
        return $false
    }

    # --- 25. SharePoint Site Collection Administrator Privileges ---
    Write-Log -Message "Checking SharePoint Site Collection Administrator Privileges..." -Type "SUBSECTION" -SpecificLogFile $SpoReportFile
    try {
        Write-Log -Message "  Fetching all site collections (this may take a while for large tenants)..." -SpecificLogFile $SpoReportFile
        $sites = Get-MgSite -All -Property "Id,DisplayName,WebUrl,CreatedDateTime" -ErrorAction SilentlyContinue
        if ($null -eq $sites) {
            Write-Log -Message "  Could not retrieve site collections or no sites found. Graph API call might have failed or tenant has no sites." -Type "ERROR" -SpecificLogFile $SpoReportFile
            return
        }

        Write-Log -Message "  Found $($sites.Count) sites to check for Site Collection Administrators." -SpecificLogFile $SpoReportFile
        $sitesCheckedCount = 0
        $totalSites = $sites.Count
        $ProgressUpdateInterval = [math]::Ceiling($totalSites / 20) # Update progress roughly every 5%
        if ($ProgressUpdateInterval -eq 0) { $ProgressUpdateInterval = 1 }


        foreach ($site in $sites) {
            $sitesCheckedCount++
            if (($sitesCheckedCount % $ProgressUpdateInterval -eq 0) -or $sitesCheckedCount -eq $totalSites) {
                 Write-Log -Message "  Processing site $sitesCheckedCount of $totalSites: '$($site.DisplayName)'" -Type "INFO" # Log to main console for progress
            }
            Write-Log -Message "  Checking site: '$($site.DisplayName)' (URL: $($site.WebUrl), ID: $($site.Id))" -SpecificLogFile $SpoReportFile
            try {
                $permissions = Get-MgSitePermission -SiteId $site.Id -All -ErrorAction SilentlyContinue
                if ($null -eq $permissions) {
                    Write-Log -Message "    No permissions retrieved or error for site '$($site.DisplayName)'. Skipping SCA check for this site." -Type "WARN" -SpecificLogFile $SpoReportFile
                    continue
                }

                foreach ($perm in $permissions) {
                    if ($perm.Roles -contains "siteCollectionAdmin") {
                        Write-Log -Message "    Site Collection Admin role found with Permission ID: $($perm.Id) on site '$($site.DisplayName)'" -SpecificLogFile $SpoReportFile

                        $grantedToIdentities = $perm.GrantedToIdentitiesV2
                        # Fallback if GrantedToIdentitiesV2 is empty but GrantedTo (single IdentitySet) might exist
                        if (($grantedToIdentities | Measure-Object).Count -eq 0 -and $perm.GrantedTo) {
                            $grantedToIdentities = @($perm.GrantedTo) # Treat as an array with one item
                            Write-Log -Message "    Using GrantedTo (single identity) for SCA check for Permission ID: $($perm.Id) on site '$($site.DisplayName)'" -SpecificLogFile $SpoReportFile
                        }


                        if (($grantedToIdentities | Measure-Object).Count -eq 0) {
                             Write-Log -Message "    WARN: Site Collection Admin role found (Permission ID: $($perm.Id)) but no GrantedToIdentitiesV2 or GrantedTo information available for site '$($site.DisplayName)'. Investigate permission manually." -Type "WARN" -IsAlert -SpecificLogFile $SpoReportFile
                             continue
                        }
                        
                        foreach ($identitySet in $grantedToIdentities) {
                            if ($identitySet.User) {
                                $userId = $identitySet.User.Id
                                $userDisplayName = $identitySet.User.DisplayName
                                $userPrincipalName = $identitySet.User.AdditionalProperties.userPrincipalName ?? $identitySet.User.Email
                                
                                if ([string]::IsNullOrWhiteSpace($userPrincipalName) -and -not [string]::IsNullOrWhiteSpace($userDisplayName)) {
                                     # Try to resolve UPN if missing, common for some system/synced accounts in SPO permissions
                                     try {
                                        $graphUser = Get-MgUser -UserId $userId -Property UserPrincipalName,DisplayName -ErrorAction SilentlyContinue
                                        if ($graphUser) {
                                            $userPrincipalName = $graphUser.UserPrincipalName
                                            $userDisplayName = $graphUser.DisplayName # Update display name too
                                        }
                                     } catch { Write-Log -Message "    Could not fully resolve user details for ID $userId on site '$($site.DisplayName)'" -Type "WARN" -SpecificLogFile $SpoReportFile }
                                }
                                
                                Write-Log -Message "    SCA User: '$($userDisplayName)' (UPN: $($userPrincipalName ?? 'N/A'), ID: $userId) on site '$($site.DisplayName)'" -SpecificLogFile $SpoReportFile
                                if (Is-SpoUserExternal -UserPrincipalName ($userPrincipalName ?? "")) {
                                    Write-Log -Message "    ALERT: External User '$($userDisplayName)' (UPN: $($userPrincipalName ?? 'N/A')) is a Site Collection Administrator on '$($site.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                                } elseif (($userPrincipalName ?? "") -notmatch "@" -and ($userPrincipalName ?? "") -ne "") { # UPN without @, or other unusual formats
                                     Write-Log -Message "    ALERT: User '$($userDisplayName)' (UPN: $($userPrincipalName ?? 'N/A')) with an unusual UPN format is a Site Collection Administrator on '$($site.DisplayName)'. Review this account." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                                }
                            } elseif ($identitySet.Group) {
                                $groupId = $identitySet.Group.Id
                                $groupDisplayName = $identitySet.Group.DisplayName
                                Write-Log -Message "    ALERT: Group '$($groupDisplayName)' (ID: $groupId) is a Site Collection Administrator on site '$($site.DisplayName)'. Review group membership and purpose." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                            } elseif ($identitySet.Application) {
                                $appId = $identitySet.Application.Id
                                $appDisplayName = $identitySet.Application.DisplayName
                                Write-Log -Message "    ALERT: Application '$($appDisplayName)' (ID: $appId) is a Site Collection Administrator on site '$($site.DisplayName)'. Review application permissions and necessity." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                            } else {
                                Write-Log -Message "    WARN: Site Collection Admin role found for an unknown identity type on site '$($site.DisplayName)'. Details: $($identitySet | ConvertTo-Json -Depth 2 -Compress)" -Type "WARN" -SpecificLogFile $SpoReportFile
                            }
                        }
                    }
                }
            } catch {
                Write-Log -Message "    Error processing permissions for site '$($site.DisplayName)' (ID: $($site.Id)): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
            }
        }
        Write-Log -Message "  Finished checking Site Collection Administrators for all $totalSites sites." -SpecificLogFile $SpoReportFile
    } catch {
        Write-Log -Message "Error checking SharePoint Site Collection Administrator Privileges: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
    }

    # --- 26. SharePoint External Sharing Settings (Tenant & Site Level) ---
    Write-Log -Message "Checking SharePoint External Sharing Settings..." -Type "SUBSECTION" -SpecificLogFile $SpoReportFile
    try {
        Write-Log -Message "  Fetching Tenant-Level SharePoint and OneDrive External Sharing Settings..." -SpecificLogFile $SpoReportFile
        $tenantSettings = Get-MgAdminSharepointSetting -ErrorAction SilentlyContinue
        if ($tenantSettings) {
            Write-Log -Message "  Tenant SharePoint Sharing Capability: $($tenantSettings.SharingCapability)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Tenant OneDrive Sharing Capability: $($tenantSettings.OneDriveSharingCapability)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Default Sharing Link Type: $($tenantSettings.DefaultSharingLinkType)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Default Link Permission: $($tenantSettings.DefaultLinkPermission)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  File Anonymous Link Type: $($tenantSettings.FileAnonymousLinkType)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Folder Anonymous Link Type: $($tenantSettings.FolderAnonymousLinkType)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Prevent External Users From Resharing: $($tenantSettings.PreventExternalUsersFromResharing)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Show People Picker Suggestions For Guest Users: $($tenantSettings.ShowPeoplePickerSuggestionsForGuestUsers)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Sharing Domain Restriction Mode: $($tenantSettings.SharingDomainRestrictionMode)" -SpecificLogFile $SpoReportFile
            Write-Log -Message "  Allowed Domain List: $($tenantSettings.AllowedDomainList -join ', ')" -SpecificLogFile $SpoReportFile #This property seems to be deprecated or incorrect for Get-MgAdminSharepointSetting; usually it's SharingAllowedDomainList
            Write-Log -Message "  Blocked Domain List: $($tenantSettings.BlockedDomainList -join ', ')" -SpecificLogFile $SpoReportFile #Same as above, usually SharingBlockedDomainList

            if ($tenantSettings.SharingAllowedDomainList) { Write-Log -Message "  Sharing Allowed Domain List (SPO): $($tenantSettings.SharingAllowedDomainList -join ', ')" -SpecificLogFile $SpoReportFile}
            if ($tenantSettings.SharingBlockedDomainList) { Write-Log -Message "  Sharing Blocked Domain List (SPO): $($tenantSettings.SharingBlockedDomainList -join ', ')" -SpecificLogFile $SpoReportFile}


            if ($tenantSettings.SharingCapability -in @("ExternalUserAndGuestSharing", "Anyone")) { # "Anyone" is common UI term
                Write-Log -Message "  ALERT: Tenant SharePoint Sharing Capability is '$($tenantSettings.SharingCapability)', which allows 'Anyone' links (anonymous access if link types are also anonymous). This is the most permissive setting." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
            }
            if ($tenantSettings.OneDriveSharingCapability -in @("ExternalUserAndGuestSharing", "Anyone")) {
                Write-Log -Message "  ALERT: Tenant OneDrive Sharing Capability is '$($tenantSettings.OneDriveSharingCapability)', allowing 'Anyone' links for OneDrive. Highly permissive." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
            }
            if ($tenantSettings.DefaultSharingLinkType -eq "Anonymous") {
                Write-Log -Message "  ALERT: Default Sharing Link Type is 'Anonymous'. This may lead to widespread anonymous sharing." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
            }
            if ($tenantSettings.FileAnonymousLinkType -ne "None" -or $tenantSettings.FolderAnonymousLinkType -ne "None") {
                 Write-Log -Message "  WARN: Anonymous link types for Files ('$($tenantSettings.FileAnonymousLinkType)') or Folders ('$($tenantSettings.FolderAnonymousLinkType)') are enabled. Review if this is intended." -Type "WARN" -SpecificLogFile $SpoReportFile
            }
             if ($tenantSettings.PreventExternalUsersFromResharing -eq $false) {
                Write-Log -Message "  WARN: External users ARE allowed to re-share items. This can lead to loss of control over shared content." -Type "WARN" -IsAlert -SpecificLogFile $SpoReportFile
            }

        } else {
            Write-Log -Message "  Could not retrieve Tenant-Level SharePoint Sharing Settings. This may indicate a permissions issue or that settings are not configured (unlikely)." -Type "ERROR" -SpecificLogFile $SpoReportFile
        }

        Write-Log -Message "  Checking Site-Level External Sharing (by inferring from anonymous links and external user permissions)..." -SpecificLogFile $SpoReportFile
        Write-Log -Message "  INFO: This check looks for active anonymous links or external users on sites. For explicit 'SharingCapability' property per site (e.g. 'Anyone', 'New and existing guests'), use SharePoint Online PowerShell: Get-SPOSite -Identity <SiteURL> | Select SharingCapability." -Type "INFO" -SpecificLogFile $SpoReportFile

        if ($null -ne $allSites) {
            $sitesCheckedCountSharing = 0
            $totalSitesSharing = $allSites.Count
            $ProgressUpdateIntervalSharing = [math]::Ceiling($totalSitesSharing / 20)
            if ($ProgressUpdateIntervalSharing -eq 0) { $ProgressUpdateIntervalSharing = 1 }

            foreach ($site in $allSites) {
                $sitesCheckedCountSharing++
                if (($sitesCheckedCountSharing % $ProgressUpdateIntervalSharing -eq 0) -or $sitesCheckedCountSharing -eq $totalSitesSharing) {
                    Write-Log -Message "  Processing site (Sharing Check) $sitesCheckedCountSharing of $totalSitesSharing: '$($site.DisplayName)'" -Type "INFO"
                }
                 Write-Log -Message "  Checking inferred sharing for site: '$($site.DisplayName)' (URL: $($site.WebUrl))" -SpecificLogFile $SpoReportFile
                try {
                    $sitePermissions = Get-MgSitePermission -SiteId $site.Id -All -ErrorAction SilentlyContinue
                    if ($null -eq $sitePermissions) {
                        Write-Log -Message "    No permissions retrieved or error for site '$($site.DisplayName)'. Skipping sharing inference for this site." -Type "WARN" -SpecificLogFile $SpoReportFile
                        continue
                    }
                    $foundAnonLink = $false
                    $foundExternalUser = $false

                    foreach ($perm in $sitePermissions) {
                        if ($perm.Link.Scope -eq 'anonymous') {
                            $foundAnonLink = $true
                            Write-Log -Message "    ALERT: Site '$($site.DisplayName)' has an anonymous link permission (Type: $($perm.Link.Type), ID: $($perm.Id)). WebURL: $($perm.Link.WebUrl)" -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                        }

                        $grantedToIdentities = $perm.GrantedToIdentitiesV2
                        if (($grantedToIdentities | Measure-Object).Count -eq 0 -and $perm.GrantedTo) {
                            $grantedToIdentities = @($perm.GrantedTo)
                        }
                        
                        foreach ($identitySet in $grantedToIdentities) {
                            if ($identitySet.User) {
                                $userPrincipalName = $identitySet.User.AdditionalProperties.userPrincipalName ?? $identitySet.User.Email
                                if (Is-SpoUserExternal -UserPrincipalName ($userPrincipalName ?? "") ) {
                                    # Avoid re-alerting for SCAs if they were already alerted in check 25, but log general external users with other perms.
                                    if (-not ($perm.Roles -contains "siteCollectionAdmin")) {
                                         Write-Log -Message "    INFO: Site '$($site.DisplayName)' has permission (Roles: $($perm.Roles -join ', ')) for external user '$($userPrincipalName)' (ID: $($perm.Id)). Review if access is appropriate." -Type "INFO" -SpecificLogFile $SpoReportFile
                                         $foundExternalUser = $true # Flag that an external user (non-SCA) has some permission.
                                    }
                                }
                            }
                        }
                    }
                    if ($foundAnonLink) {
                         Write-Log -Message "    SUMMARY: Site '$($site.DisplayName)' allows anonymous access via one or more links." -Type "INFO" -SpecificLogFile $SpoReportFile
                    }
                    if ($foundExternalUser) {
                         Write-Log -Message "    SUMMARY: Site '$($site.DisplayName)' has direct permissions granted to one or more external users (excluding SCAs noted previously)." -Type "INFO" -SpecificLogFile $SpoReportFile
                    }

                } catch {
                     Write-Log -Message "    Error processing permissions for sharing inference on site '$($site.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
                }
            }
            Write-Log -Message "  Finished inferring site-level sharing for all $($allSites.Count) sites." -SpecificLogFile $SpoReportFile
        } else {
            Write-Log -Message "  Site list not available, skipping site-level sharing checks." -Type "WARN" -SpecificLogFile $SpoReportFile
        }

    } catch {
        Write-Log -Message "Error checking SharePoint External Sharing Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
    }

    # --- 27. SharePoint Add-ins & SPFx Solutions ---
    Write-Log -Message "Checking SharePoint Add-ins & SPFx Solutions..." -Type "SUBSECTION" -SpecificLogFile $SpoReportFile
    try {
        Write-Log -Message "  Checking API permissions granted to 'SharePoint Online Client Extensibility Web Application Principal' (used by SPFx solutions)..." -SpecificLogFile $SpoReportFile
        
        # High-risk permissions to look for (example list, can be expanded)
        $spfxHighRiskPermissions = @(
            "Sites.FullControl.All", "Sites.Manage.All", "Sites.ReadWrite.All", # SharePoint specific
            "Group.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All", # General Graph
            "Mail.ReadWrite", "Mail.Send", "Contacts.ReadWrite", "Calendars.ReadWrite",
            "Tasks.ReadWrite", "Files.ReadWrite.All", "Presence.ReadWrite.All"
        )

        $spfxExtensibilitySp = $null
        try {
             # Attempt to find by a common AppId first, then by DisplayName
             # Note: The AppId '9777f5c2-0a6a-416f-a866-0253280907de' is for the Enterprise App, not necessarily the SP's AppId property.
             # The DisplayName is generally more reliable for filtering the Service Principal directly.
            $spfxExtensibilitySp = Get-MgServicePrincipal -Filter "displayName eq 'SharePoint Online Client Extensibility Web Application Principal'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $spfxExtensibilitySp) {
                 # Fallback to a well-known AppId if display name search fails (less common for this specific principal to vary by AppId)
                 # This AppId is for the SharePoint Online service principal itself, which isn't what we want.
                 # The one for SPFx is usually identified by DisplayName.
                 # We will stick to DisplayName for now.
            }
        } catch {
            Write-Log -Message "    Error trying to find 'SharePoint Online Client Extensibility Web Application Principal': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
        }

        if ($spfxExtensibilitySp) {
            Write-Log -Message "  Found 'SharePoint Online Client Extensibility Web Application Principal' (ID: $($spfxExtensibilitySp.Id), AppId: $($spfxExtensibilitySp.AppId)). Checking its OAuth2 permission grants..." -SpecificLogFile $SpoReportFile
            
            $delegatedGrants = Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $spfxExtensibilitySp.Id -All -ErrorAction SilentlyContinue
            if ($delegatedGrants) {
                Write-Log -Message "  Found $($delegatedGrants.Count) delegated OAuth2 permission grants for SPFx Extensibility Principal:" -SpecificLogFile $SpoReportFile
                foreach ($grant in $delegatedGrants) {
                    $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue
                    $resourceName = $resourceSp.DisplayName ?? $grant.ResourceId
                    Write-Log -Message "    Scope: '$($grant.Scope)' | Resource: '$resourceName' (ID: $($grant.ResourceId)) | ConsentType: $($grant.ConsentType) | Grant ID: $($grant.Id)" -SpecificLogFile $SpoReportFile
                    
                    $grantedScopes = $grant.Scope -split " "
                    foreach ($scope in $grantedScopes) {
                        if ($spfxHighRiskPermissions -contains $scope) {
                            Write-Log -Message "    ALERT: High-risk delegated permission '$scope' granted to SPFx solutions via Extensibility Principal for resource '$resourceName'." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                        }
                    }
                }
            } else {
                Write-Log -Message "  No delegated OAuth2 permission grants found for 'SharePoint Online Client Extensibility Web Application Principal' or error retrieving them." -Type "INFO" -SpecificLogFile $SpoReportFile
            }
            # App Role Assignments (Application Permissions) - Less common for SPFx client-side code but check anyway
            # Note: SPFx solutions calling backend APIs secured with AAD might use their own AAD App Registration with App Permissions.
            # This check is for App Permissions granted *directly* to the SPFx Extensibility Principal.
            $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spfxExtensibilitySp.Id -All -ErrorAction SilentlyContinue
             if ($appRoleAssignments) {
                Write-Log -Message "  Found $($appRoleAssignments.Count) application permission assignments (App Roles) for SPFx Extensibility Principal:" -SpecificLogFile $SpoReportFile
                foreach($assignment in $appRoleAssignments) {
                    $resourceSpDetails = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -Property DisplayName, AppId -ErrorAction SilentlyContinue
                    $appRoleDetails = $resourceSpDetails.AppRoles | Where-Object {$_.Id -eq $assignment.AppRoleId} | Select-Object -First 1
                    $permissionName = $appRoleDetails.Value ?? $assignment.AppRoleId
                    $resourceDisplayName = $resourceSpDetails.DisplayName ?? $assignment.ResourceId
                    
                    Write-Log -Message "    App Permission: '$permissionName' | Resource: '$resourceDisplayName' (ID: $($assignment.ResourceId)) | Assignment ID: $($assignment.Id)" -SpecificLogFile $SpoReportFile
                     if ($spfxHighRiskPermissions -contains $permissionName) {
                        Write-Log -Message "    ALERT: High-risk application permission '$permissionName' granted to SPFx solutions via Extensibility Principal for resource '$resourceDisplayName'." -Type "ALERT" -IsAlert -SpecificLogFile $SpoReportFile
                    }
                }
            } else {
                 Write-Log -Message "  No application permission assignments found for 'SharePoint Online Client Extensibility Web Application Principal' or error retrieving them." -Type "INFO" -SpecificLogFile $SpoReportFile
            }


        } else {
            Write-Log -Message "  'SharePoint Online Client Extensibility Web Application Principal' not found. SPFx solutions might not be using tenant-wide API permissions, or there was an issue querying." -Type "WARN" -SpecificLogFile $SpoReportFile
        }

        Write-Log -Message "  INFO: For a full inventory of deployed SPFx solutions, use SharePoint PnP PowerShell (e.g., Get-PnPApp -Scope Tenant and Get-PnPApp -Scope Site) or check Tenant/Site Collection App Catalogs via UI." -Type "INFO" -SpecificLogFile $SpoReportFile
        Write-Log -Message "  INFO: Classic SharePoint Add-ins (especially with app-only permissions granted directly within SharePoint, not Azure AD) require discovery via PnP PowerShell (e.g., Get-PnPAddInInstance -List 'Tenant') or manual checks of 'Site Contents' on each site. Graph API has limited visibility into these legacy components." -Type "INFO" -SpecificLogFile $SpoReportFile
   
    } catch {
        Write-Log -Message "Error checking SharePoint Add-ins & SPFx Solutions related permissions: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $SpoReportFile
    }

    Write-Log -Message "Finished SharePoint Online Checks." -Type "SECTION"
}
 
# ==================================================
# SECTION IV: Microsoft Teams Checks
# ==================================================
function Invoke-MicrosoftTeamsChecks {
    Write-Log -Message "Starting Microsoft Teams Checks" -Type "SECTION"
    if (-not $GraphConnected) {
        Write-Log -Message "Cannot perform Teams checks. Not connected to Graph API." -Type "ERROR"
        return
    }
    $TeamsReportFile = "MicrosoftTeams_Report.txt"

    # Helper function (similar to Is-SpoUserExternal, might be good to globalize or pass $script:AcceptedDomains)
    function Is-TeamsUserExternal {
        param (
            [string]$UserPrincipalName
        )
        if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
            return $false 
        }
        if ($UserPrincipalName -match "#EXT#") {
            return $true
        }
        if ($UserPrincipalName -match "@") {
            $domainPart = ($UserPrincipalName -split "@")[1]
            if ($script:AcceptedDomains -notcontains $domainPart) {
                return $true
            }
        } else {
             Write-Log -Message "  User '$UserPrincipalName' in Teams has an unusual UPN format; unable to definitively determine if external by domain. Review manually." -Type "WARN" -SpecificLogFile $TeamsReportFile
        }
        return $false
    }

    # --- 28. Teams External Access & Federation ---
    Write-Log -Message "Checking Teams External Access & Federation Settings..." -Type "SUBSECTION" -SpecificLogFile $TeamsReportFile
    try {
        Write-Log -Message "  Fetching tenant-wide online meeting external access settings..." -SpecificLogFile $TeamsReportFile
        $meetingAccess = Get-MgCommunicationOnlineMeetingExternalAccess -ErrorAction SilentlyContinue
        if ($meetingAccess) {
            Write-Log -Message "  Online Meeting External Access Enabled: $($meetingAccess.IsEnabled)" -SpecificLogFile $TeamsReportFile
            Write-Log -Message "  Allowed Domains: $(if ($meetingAccess.AllowedDomains) {$meetingAccess.AllowedDomains -join ', '} else {'Not Configured (Implies All if Enabled and no Block List)'})" -SpecificLogFile $TeamsReportFile
            Write-Log -Message "  Blocked Domains: $(if ($meetingAccess.BlockedDomains) {$meetingAccess.BlockedDomains -join ', '} else {'Not Configured'})" -SpecificLogFile $TeamsReportFile

            if ($meetingAccess.IsEnabled) {
                if (($null -eq $meetingAccess.AllowedDomains -or $meetingAccess.AllowedDomains.Count -eq 0) -and ($null -eq $meetingAccess.BlockedDomains -or $meetingAccess.BlockedDomains.Count -eq 0)) {
                    Write-Log -Message "  ALERT: Teams online meeting external access is ENABLED with no domain restrictions (neither allow nor block list defined). This allows federation with all external M365 domains for meetings." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                } elseif ($meetingAccess.AllowedDomains.Count -gt 0) {
                     Write-Log -Message "  INFO: Teams online meeting external access is ENABLED and restricted to allowed domains. Review list: $($meetingAccess.AllowedDomains -join ', ')" -Type "INFO" -SpecificLogFile $TeamsReportFile
                }
            } else {
                 Write-Log -Message "  INFO: Teams online meeting external access is DISABLED." -Type "INFO" -SpecificLogFile $TeamsReportFile
            }
        } else {
            Write-Log -Message "  Could not retrieve online meeting external access settings." -Type "WARN" -SpecificLogFile $TeamsReportFile
        }

        Write-Log -Message "  Fetching Teams client configuration (for Guest Access setting)..." -SpecificLogFile $TeamsReportFile
        $teamsConfig = Get-MgTeamworkTeamworkConfiguration -ErrorAction SilentlyContinue
        if ($teamsConfig -and $teamsConfig.TeamsClientConfiguration) {
            Write-Log -Message "  Teams Guest Access Enabled in Teams Configuration: $($teamsConfig.TeamsClientConfiguration.AllowGuestUser)" -SpecificLogFile $TeamsReportFile
            if ($teamsConfig.TeamsClientConfiguration.AllowGuestUser -eq $true) {
                Write-Log -Message "  INFO: Guest access is enabled at the Microsoft Teams service level. Overall guest access also depends on Azure AD B2B settings." -Type "INFO" -SpecificLogFile $TeamsReportFile
                 Write-Log -Message "  ALERT: Guest access is enabled in Teams. Ensure Azure AD B2B policies (see Azure AD Check #22 & #24) are appropriately configured and guest lifecycle is managed." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
            } else {
                Write-Log -Message "  INFO: Guest access is disabled at the Microsoft Teams service level." -Type "INFO" -SpecificLogFile $TeamsReportFile
            }
        } else {
            Write-Log -Message "  Could not retrieve Teams client configuration or guest access setting." -Type "WARN" -SpecificLogFile $TeamsReportFile
        }
        Write-Log -Message "  INFO: For detailed chat/federation settings (e.g., 'Allow all external domains', 'Block specific domains'), review the Microsoft Teams Admin Center, as direct Graph API queries for these specific UI settings can be complex or limited." -Type "INFO" -SpecificLogFile $TeamsReportFile

    } catch {
        Write-Log -Message "Error checking Teams External Access & Federation settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile
    }

    # --- 29. Team Ownership & Membership ---
    Write-Log -Message "Checking Team Ownership & Membership..." -Type "SUBSECTION" -SpecificLogFile $TeamsReportFile
    try {
        $criticalTeamKeywords = @("Admin", "Security", "Finance", "HR", "Legal", "Executive", "Confidential", "Compliance", "C-level", "Management") # User can customize
        Write-Log -Message "  Identifying critical teams based on keywords: $($criticalTeamKeywords -join ', ')" -SpecificLogFile $TeamsReportFile
        Write-Log -Message "  Fetching all Teams (this may take a while for large tenants)..." -SpecificLogFile $TeamsReportFile
        
        $allTeams = Get-MgTeam -All -Property "Id,DisplayName,Description,CreatedDateTime,IsArchived" -ErrorAction SilentlyContinue
        if ($null -eq $allTeams) {
            Write-Log -Message "  Could not retrieve Teams list or no Teams found." -Type "ERROR" -SpecificLogFile $TeamsReportFile
            return # Exit this specific check if no teams can be processed
        }

        Write-Log -Message "  Found $($allTeams.Count) Teams to process." -SpecificLogFile $TeamsReportFile
        $teamsCheckedCount = 0
        $totalTeamsToProcess = $allTeams.Count
        $ProgressInterval = [math]::Ceiling($totalTeamsToProcess / 20) # Update progress roughly every 5%
        if ($ProgressInterval -eq 0) { $ProgressInterval = 1 }

        foreach ($team in $allTeams) {
            $teamsCheckedCount++
            if (($teamsCheckedCount % $ProgressInterval -eq 0) -or $teamsCheckedCount -eq $totalTeamsToProcess) {
                Write-Log -Message "  Processing Team $teamsCheckedCount of $totalTeamsToProcess: '$($team.DisplayName)'" -Type "INFO"
            }

            $isCriticalTeam = $false
            foreach ($keyword in $criticalTeamKeywords) {
                if (($team.DisplayName -match $keyword) -or ($team.Description -match $keyword)) {
                    $isCriticalTeam = $true
                    break
                }
            }
            $teamLogPrefix = if ($isCriticalTeam) { "CRITICAL TEAM" } else { "Team" }

            Write-Log -Message "  Checking $teamLogPrefix: '$($team.DisplayName)' (ID: $($team.Id)), Archived: $($team.IsArchived)" -SpecificLogFile $TeamsReportFile
            if ($isCriticalTeam) {
                Write-Log -Message "  ALERT: Team '$($team.DisplayName)' identified as potentially critical. Pay close attention to its ownership and membership." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
            }

            # Check Owners
            try {
                $owners = Get-MgTeamOwner -TeamId $team.Id -All -ErrorAction SilentlyContinue
                if ($owners) {
                    Write-Log -Message "    Owners ($($owners.Count)) for '$($team.DisplayName)':" -SpecificLogFile $TeamsReportFile
                    if ($owners.Count -eq 0) {
                         Write-Log -Message "    ALERT: $teamLogPrefix '$($team.DisplayName)' has NO owners." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                    } elseif ($owners.Count -eq 1) {
                         Write-Log -Message "    ALERT: $teamLogPrefix '$($team.DisplayName)' has only ONE owner. This is a risk for manageability and if the owner account is compromised/lost." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                    }

                    foreach ($owner in $owners) {
                        $ownerUpn = $owner.AdditionalProperties.userPrincipalName ?? $owner.Mail ?? $owner.DisplayName
                        Write-Log -Message "      Owner: '$($owner.DisplayName)' (UPN: $ownerUpn, ID: $($owner.Id))" -SpecificLogFile $TeamsReportFile
                        if (Is-TeamsUserExternal -UserPrincipalName $ownerUpn) {
                            Write-Log -Message "      ALERT: External User '$($owner.DisplayName)' (UPN: $ownerUpn) is an OWNER of $teamLogPrefix '$($team.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                        }
                    }
                } else { Write-Log -Message "    No owners found or unable to retrieve for '$($team.DisplayName)'." -Type "WARN" -SpecificLogFile $TeamsReportFile }
            } catch { Write-Log -Message "    Error retrieving owners for '$($team.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile }

            # Check Members
            try {
                $members = Get-MgTeamMember -TeamId $team.Id -All -ErrorAction SilentlyContinue
                if ($members) {
                    $guestMemberCount = 0
                    $memberDetailsToLog = New-Object System.Collections.Generic.List[string]

                    foreach ($member in $members) {
                        $memberUpn = $member.AdditionalProperties.userPrincipalName ?? $member.Mail ?? $member.DisplayName
                        $memberDisplayName = $member.DisplayName ?? "Unknown Member"
                        $memberId = $member.Id ?? "Unknown ID"
                        $roles = ($member.Roles -join ', ') # Should be 'member' or 'guest' effectively from this cmdlet
                        $isExternal = Is-TeamsUserExternal -UserPrincipalName $memberUpn
                        
                        $logEntry = "Member: '$memberDisplayName' (UPN: $memberUpn, Roles: $roles, ID: $memberId)"
                        if($isExternal){ $logEntry += " - EXTERNAL" }
                        $memberDetailsToLog.Add($logEntry)

                        if ($isExternal) {
                            $guestMemberCount++
                            if ($isCriticalTeam) {
                                Write-Log -Message "      ALERT: External User '$memberDisplayName' (UPN: $memberUpn) is a MEMBER of CRITICAL TEAM '$($team.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                            }
                        }
                    }
                    Write-Log -Message "    Members ($($members.Count)) for '$($team.DisplayName)' (Guests: $guestMemberCount):" -SpecificLogFile $TeamsReportFile
                    $memberDetailsToLog | ForEach-Object { Write-Log -Message "      $_" -SpecificLogFile $TeamsReportFile }
                    
                    if ($guestMemberCount -gt 0 -and -not $isCriticalTeam) { # Log non-critical teams with guests too
                         Write-Log -Message "    INFO: Team '$($team.DisplayName)' has $guestMemberCount guest member(s)." -Type "INFO" -SpecificLogFile $TeamsReportFile
                    }
                    if ($members.Count -gt 500 -and $isCriticalTeam){ # Arbitrary large number for a critical team
                        Write-Log -Message "    WARN: Critical team '$($team.DisplayName)' has a very large number of members ($($members.Count)). Review if appropriate." -Type "WARN" -SpecificLogFile $TeamsReportFile
                    }

                } else { Write-Log -Message "    No members found or unable to retrieve for '$($team.DisplayName)'." -Type "WARN" -SpecificLogFile $TeamsReportFile }
            } catch { Write-Log -Message "    Error retrieving members for '$($team.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile }
        }
        Write-Log -Message "  Finished checking Team Ownership & Membership for all $totalTeamsToProcess Teams." -SpecificLogFile $TeamsReportFile
    } catch {
        Write-Log -Message "Error during Team Ownership & Membership check: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile
    }


    # --- 30. Teams App Permissions & Policies ---
    Write-Log -Message "Checking Teams App Permissions & Policies..." -Type "SUBSECTION" -SpecificLogFile $TeamsReportFile
    try {
        # 1. Check Teams App Permission Policies
        Write-Log -Message "  Fetching Teams App Permission Policies..." -SpecificLogFile $TeamsReportFile
        $appPermissionPolicies = Get-MgTeamworkTeamsAppPermissionPolicy -All -ErrorAction SilentlyContinue
        if ($appPermissionPolicies) {
            Write-Log -Message "  Found $($appPermissionPolicies.Count) Teams App Permission Policies." -SpecificLogFile $TeamsReportFile
            foreach ($policy in $appPermissionPolicies) {
                Write-Log -Message "  Policy: '$($policy.DisplayName)' (ID: $($policy.Id)), Description: $($policy.Description)" -SpecificLogFile $TeamsReportFile
                
                # Microsoft Apps
                $msAppsSet = $policy.MicrosoftAppsPermissionSet
                Write-Log -Message "    Microsoft Apps: Mode: $($msAppsSet.PermissionMode), Allowed: $(($msAppsSet.AllowedApps | Join-String -Separator ', ') ?? 'N/A'), Blocked: $(($msAppsSet.BlockedApps | Join-String -Separator ', ') ?? 'N/A')" -SpecificLogFile $TeamsReportFile
                if ($msAppsSet.PermissionMode -eq "allowAll") {
                    Write-Log -Message "    INFO: Policy '$($policy.DisplayName)' allows ALL Microsoft apps." -Type "INFO" -SpecificLogFile $TeamsReportFile
                }

                # Third-Party Apps
                $thirdPartyAppsSet = $policy.ThirdPartyAppsPermissionSet
                Write-Log -Message "    Third-Party Apps: Mode: $($thirdPartyAppsSet.PermissionMode), Allowed: $(($thirdPartyAppsSet.AllowedApps | Join-String -Separator ', ') ?? 'N/A'), Blocked: $(($thirdPartyAppsSet.BlockedApps | Join-String -Separator ', ') ?? 'N/A')" -SpecificLogFile $TeamsReportFile
                if ($thirdPartyAppsSet.PermissionMode -eq "allowAll") {
                    Write-Log -Message "    ALERT: Policy '$($policy.DisplayName)' allows ALL Third-Party apps. This is highly permissive and should be reviewed." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                } elseif ($thirdPartyAppsSet.PermissionMode -ne "blockAll" -and $thirdPartyAppsSet.PermissionMode -ne "blockSpecificApps") { # allowSpecificApps
                    Write-Log -Message "    WARN: Policy '$($policy.DisplayName)' allows some Third-Party apps. Review allowed list: $(($thirdPartyAppsSet.AllowedApps | Join-String -Separator ', ') ?? 'N/A')" -Type "WARN" -SpecificLogFile $TeamsReportFile
                }


                # Custom Apps
                $customAppsSet = $policy.CustomAppsPermissionSet
                Write-Log -Message "    Custom Apps: Mode: $($customAppsSet.PermissionMode), Allowed: $(($customAppsSet.AllowedApps | Join-String -Separator ', ') ?? 'N/A'), Blocked: $(($customAppsSet.BlockedApps | Join-String -Separator ', ') ?? 'N/A')" -SpecificLogFile $TeamsReportFile
                if ($customAppsSet.PermissionMode -eq "allowAll") {
                    Write-Log -Message "    ALERT: Policy '$($policy.DisplayName)' allows ALL Custom apps. Review security implications and governance for custom apps." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                } elseif ($customAppsSet.PermissionMode -ne "blockAll" -and $customAppsSet.PermissionMode -ne "blockSpecificApps") {
                     Write-Log -Message "    WARN: Policy '$($policy.DisplayName)' allows some Custom apps. Review allowed list and vetting process: $(($customAppsSet.AllowedApps | Join-String -Separator ', ') ?? 'N/A')" -Type "WARN" -SpecificLogFile $TeamsReportFile
                }
            }
        } else {
            Write-Log -Message "  No Teams App Permission Policies found or error retrieving them." -Type "INFO" -SpecificLogFile $TeamsReportFile
        }

        # 2. Check Teams App Setup Policies
        Write-Log -Message "  Fetching Teams App Setup Policies..." -SpecificLogFile $TeamsReportFile
        $appSetupPolicies = Get-MgTeamworkTeamsAppSetupPolicy -All -ErrorAction SilentlyContinue
        if ($appSetupPolicies) {
            Write-Log -Message "  Found $($appSetupPolicies.Count) Teams App Setup Policies." -SpecificLogFile $TeamsReportFile
            foreach ($policy in $appSetupPolicies) {
                Write-Log -Message "  Policy: '$($policy.DisplayName)' (ID: $($policy.Id)), Description: $($policy.Description)" -SpecificLogFile $TeamsReportFile
                Write-Log -Message "    Allow Create Custom Apps: $($policy.AllowCreateCustomApps)" -SpecificLogFile $TeamsReportFile
                Write-Log -Message "    Allow User Pinning: $($policy.AllowUserPinning)" -SpecificLogFile $TeamsReportFile
                Write-Log -Message "    Allow SideLoading: $($policy.AllowSideLoading) (Note: Sideloading is often controlled globally or via custom app policies too)" -SpecificLogFile $TeamsReportFile
                
                if ($policy.AllowCreateCustomApps -eq $true) {
                    Write-Log -Message "    ALERT: App Setup Policy '$($policy.DisplayName)' allows users to create/upload custom apps. This could be a security risk if not governed." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                }
                if ($policy.AllowSideLoading -eq $true) { # Though often a global setting, if per-policy it's relevant
                    Write-Log -Message "    WARN: App Setup Policy '$($policy.DisplayName)' explicitly allows sideloading. Review global custom app policy." -Type "WARN" -SpecificLogFile $TeamsReportFile
                }

                if ($policy.InstalledApps) {
                    Write-Log -Message "    Pinned Apps by default in policy '$($policy.DisplayName)':" -SpecificLogFile $TeamsReportFile
                    foreach ($app in $policy.InstalledApps) {
                        $teamsApp = Get-MgAppCatalogTeamApp -TeamsAppId $app.TeamsApp.Id -ErrorAction SilentlyContinue
                        Write-Log -Message "      App: $($teamsApp.DisplayName ?? $app.TeamsApp.Id) (DistributionMethod: $($teamsApp.DistributionMethod ?? 'N/A'))" -SpecificLogFile $TeamsReportFile
                    }
                }
            }
        } else {
            Write-Log -Message "  No Teams App Setup Policies found or error retrieving them." -Type "INFO" -SpecificLogFile $TeamsReportFile
        }

        # 3. Check Resource-Specific Consent (RSC) for apps within Teams
        Write-Log -Message "  Checking Resource-Specific Consent (RSC) grants for apps in Teams..." -SpecificLogFile $TeamsReportFile
        if ($null -ne $allTeams) { # $allTeams fetched in check #29
            Write-Log -Message "  Iterating through $($allTeams.Count) teams for RSC grants..." -SpecificLogFile $TeamsReportFile
            $rscTeamsCheckedCount = 0
            $rscTotalTeams = $allTeams.Count
            $rscProgressInterval = [math]::Ceiling($rscTotalTeams / 10) # Update more frequently if many teams
            if ($rscProgressInterval -eq 0) { $rscProgressInterval = 1 }

            foreach ($team in $allTeams) {
                $rscTeamsCheckedCount++
                 if (($rscTeamsCheckedCount % $rscProgressInterval -eq 0) -or $rscTeamsCheckedCount -eq $rscTotalTeams) {
                    Write-Log -Message "  Processing Team (RSC Check) $rscTeamsCheckedCount of $rscTotalTeams: '$($team.DisplayName)'" -Type "INFO"
                }

                try {
                    $rscGrants = Get-MgTeamPermissionGrant -TeamId $team.Id -All -ErrorAction SilentlyContinue
                    if ($rscGrants) {
                        Write-Log -Message "  Found $($rscGrants.Count) RSC grant(s) for Team: '$($team.DisplayName)' (ID: $($team.Id))" -SpecificLogFile $TeamsReportFile
                        foreach ($grant in $rscGrants) {
                            $clientAppSp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue # ClientId is ServicePrincipal ObjectId
                            $clientAppName = $clientAppSp.DisplayName ?? $grant.ClientAppId ?? "Unknown App"
                            Write-Log -Message "    ALERT: RSC Grant found in Team '$($team.DisplayName)'!" -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                            Write-Log -Message "      Grant ID: $($grant.Id)" -SpecificLogFile $TeamsReportFile
                            Write-Log -Message "      App Name: '$clientAppName' (Client SP ID: $($grant.ClientId), Client App ID: $($grant.ClientAppId))" -SpecificLogFile $TeamsReportFile
                            Write-Log -Message "      Granted Permission: '$($grant.Permission)' (Type: $($grant.PermissionType))" -SpecificLogFile $TeamsReportFile
                            Write-Log -Message "      Resource App ID (Target API): $($grant.ResourceAppId)" -SpecificLogFile $TeamsReportFile
                            
                            # Define high-risk RSC permissions (can be expanded)
                            $highRiskRscPermissions = @(
                                "Group.ReadWrite.All", # Full control over the group/team this is granted to
                                "ChannelMessage.ReadWrite.Group", "ChatMessage.ReadWrite.Group", "ChatMessage.Send.Group",
                                "Files.ReadWrite.Group", "Sites.ReadWrite.Group", "Sites.FullControl.Group",
                                "TeamSettings.ReadWrite.Group", "ChannelSettings.ReadWrite.Group",
                                "Members.ReadWrite.Group", "Owners.ReadWrite.Group",
                                "Tab.ReadWrite.Group", "AppCatalog.ReadWrite.Group",
                                "OnlineMeeting.ReadWrite.Group" # If meetings are tied to the Team context
                            )
                            if ($highRiskRscPermissions -contains $grant.Permission) {
                                Write-Log -Message "      RISK: High-privilege RSC permission '$($grant.Permission)' granted to '$clientAppName' in Team '$($team.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $TeamsReportFile
                            }
                        }
                    }
                } catch {
                    Write-Log -Message "    Error retrieving RSC grants for Team '$($team.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile
                }
            }
             Write-Log -Message "  Finished checking RSC grants for all available teams." -SpecificLogFile $TeamsReportFile
        } else {
            Write-Log -Message "  Teams list not available (from check #29), skipping RSC grants check." -Type "WARN" -SpecificLogFile $TeamsReportFile
        }
        Write-Log -Message "  INFO: Review Azure AD App Registrations (Check #14 & #15) for broader API consents that Teams apps might leverage if they use their own AAD App Registration." -Type "INFO" -SpecificLogFile $TeamsReportFile

    } catch {
        Write-Log -Message "Error checking Teams App Permissions & Policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $TeamsReportFile
    }

    Write-Log -Message "Finished Microsoft Teams Checks." -Type "SECTION"
}

# ==================================================
# SECTION V: Power Platform (Power Automate, Power Apps, Dataverse) Checks
# ==================================================
function Invoke-PowerPlatformChecks {
    Write-Log -Message "Starting Power Platform Checks" -Type "SECTION"
    $PpReportFile = "PowerPlatform_Report.txt"
    
    # Attempt to connect to Power Platform Admin
    # The Install-Or-Import-Module function should have already tried to install Microsoft.PowerApps.Administration.PowerShell
    # if it was marked as non-optional or if we decide to make it so.
    # For now, Connect-ToPowerPlatformAdmin includes its own check for module availability.
    Connect-ToPowerPlatformAdmin

    if (-not $PpAdminConnected) {
        Write-Log -Message "Skipping Power Platform checks as connection was not successful or module is unavailable." -Type "WARN" -SpecificLogFile $PpReportFile
        return
    }
    
    Write-Log -Message "INFO: Power Platform checks are dependent on the 'Microsoft.PowerApps.Administration.PowerShell' module and successful authentication via Add-PowerAppsAccount." -Type "INFO" -SpecificLogFile $PpReportFile
    Write-Log -Message "INFO: The following checks iterate through environments. This can be time-consuming in tenants with many environments." -Type "INFO" -SpecificLogFile $PpReportFile

    # --- 31. Power Automate Flows ---
    Write-Log -Message "Checking Power Automate Flows..." -Type "SUBSECTION" -SpecificLogFile $PpReportFile
    try {
        $environments = Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue
        if (-not $environments) {
            Write-Log -Message "  Could not retrieve Power Platform environments." -Type "ERROR" -SpecificLogFile $PpReportFile
        } else {
            Write-Log -Message "  Found $($environments.Count) environments. Checking flows in each..." -SpecificLogFile $PpReportFile
            foreach ($env in $environments) {
                Write-Log -Message "  Environment: '$($env.DisplayName)' (ID: $($env.EnvironmentName))" -SpecificLogFile $PpReportFile
                $flows = Get-AdminFlow -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
                if ($flows) {
                    Write-Log -Message "    Found $($flows.Count) flows in '$($env.DisplayName)'." -SpecificLogFile $PpReportFile
                    foreach ($flow in $flows) {
                        Write-Log -Message "    Flow: '$($flow.DisplayName)' (ID: $($flow.FlowName)), State: $($flow.Internal.properties.state), Created: $($flow.Internal.properties.createdTime)" -SpecificLogFile $PpReportFile
                        
                        # Check for HTTP Triggers/Actions (potential for misuse)
                        if ($flow.Internal.properties.definitionSummary.triggers | Where-Object Type -EQ "Request") {
                            Write-Log -Message "    ALERT: Flow '$($flow.DisplayName)' in env '$($env.DisplayName)' has an HTTP Request trigger. Review its security and purpose (URL might be exposed)." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                        }
                        if ($flow.Internal.properties.definitionSummary.actions | Where-Object Type -Match "Http") { # Matches Http, HttpWebhook etc.
                            Write-Log -Message "    WARN: Flow '$($flow.DisplayName)' in env '$($env.DisplayName)' uses HTTP actions. Review configured URLs and authentication." -Type "WARN" -SpecificLogFile $PpReportFile
                        }

                        # Check Connectors for known sensitive ones or custom connectors
                        $connectors = $flow.Internal.properties.definitionSummary.referencedConnections.apiReferences
                        if ($connectors) {
                            Write-Log -Message "      Connectors used by '$($flow.DisplayName)':" -SpecificLogFile $PpReportFile
                            foreach($connectorRef in $connectors){
                                Write-Log -Message "        - $($connectorRef.DisplayName) (Name: $($connectorRef.Name), Type: $($connectorRef.Type))" -SpecificLogFile $PpReportFile
                                if ($connectorRef.Type -match "CustomConnector" -or $connectorRef.Name -match "shared_logicflows") { # shared_logicflows for calling other flows
                                     Write-Log -Message "        ALERT: Flow '$($flow.DisplayName)' uses a Custom Connector ('$($connectorRef.DisplayName)') or calls another Logic Flow. Investigate for complex or hidden logic/permissions." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                                }
                            }
                        }
                        
                        # Check Sharing
                        try {
                            $flowPermissions = Get-AdminFlowPermission -EnvironmentName $env.EnvironmentName -FlowName $flow.FlowName -ErrorAction SilentlyContinue
                            if ($flowPermissions) {
                                foreach ($permission in $flowPermissions) {
                                    if ($permission.Principal.type -eq "Tenant" -and ($permission.RoleName -eq "CanEdit" -or $permission.RoleName -eq "Owner")) {
                                         Write-Log -Message "      ALERT: Flow '$($flow.DisplayName)' in env '$($env.DisplayName)' is shared with the entire Tenant (Everyone) with '$($permission.RoleName)' permissions." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                                    } elseif ($permission.Principal.type -eq "Group") {
                                         Write-Log -Message "      INFO: Flow '$($flow.DisplayName)' in env '$($env.DisplayName)' is shared with Group '$($permission.Principal.DisplayName)' (ID: $($permission.Principal.id)) with role '$($permission.RoleName)'." -Type "INFO" -SpecificLogFile $PpReportFile
                                    }
                                }
                            }
                        } catch { Write-Log -Message "      Error checking permissions for flow '$($flow.DisplayName)': $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $PpReportFile}
                        
                        # Recently created flows
                        if ($flow.Internal.properties.createdTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                             Write-Log -Message "    INFO: Flow '$($flow.DisplayName)' in env '$($env.DisplayName)' was created recently ($($flow.Internal.properties.createdTime))." -Type "INFO" -SpecificLogFile $PpReportFile
                        }
                    }
                } else { Write-Log -Message "    No flows found or error retrieving flows in '$($env.DisplayName)'." -Type "INFO" -SpecificLogFile $PpReportFile}
            }
        }
    } catch {
        Write-Log -Message "Error checking Power Automate Flows: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $PpReportFile
    }

    # --- 32. Power Apps Applications ---
    Write-Log -Message "Checking Power Apps Applications..." -Type "SUBSECTION" -SpecificLogFile $PpReportFile
    try {
        $environments = Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue # Re-fetch or use $environments from above if scope allows
        if (-not $environments) {
            Write-Log -Message "  Could not retrieve Power Platform environments for Power Apps check." -Type "ERROR" -SpecificLogFile $PpReportFile
        } else {
            Write-Log -Message "  Checking Power Apps in $($environments.Count) environments..." -SpecificLogFile $PpReportFile
            foreach ($env in $environments) {
                Write-Log -Message "  Environment: '$($env.DisplayName)' (ID: $($env.EnvironmentName))" -SpecificLogFile $PpReportFile
                $apps = Get-AdminPowerApp -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
                if ($apps) {
                    Write-Log -Message "    Found $($apps.Count) Power Apps in '$($env.DisplayName)'." -SpecificLogFile $PpReportFile
                    foreach ($app in $apps) {
                        Write-Log -Message "    App: '$($app.DisplayName)' (ID: $($app.AppName)), Type: $($app.Internal.properties.appType), Created: $($app.Internal.properties.createdTime)" -SpecificLogFile $PpReportFile
                        
                        # Check Sharing
                        try {
                            $appPermissions = Get-AdminPowerAppPermission -EnvironmentName $env.EnvironmentName -AppName $app.AppName -ErrorAction SilentlyContinue
                            if ($appPermissions) {
                                foreach ($permission in $appPermissions) {
                                    if ($permission.Principal.type -eq "Tenant") { # Shared with Everyone
                                        Write-Log -Message "      ALERT: Power App '$($app.DisplayName)' in env '$($env.DisplayName)' is shared with the entire Tenant (Everyone) with role '$($permission.RoleName)'." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                                    } elseif ($permission.Principal.type -eq "Group") {
                                        Write-Log -Message "      INFO: Power App '$($app.DisplayName)' in env '$($env.DisplayName)' is shared with Group '$($permission.Principal.DisplayName)' (ID: $($permission.Principal.id)) with role '$($permission.RoleName)'." -Type "INFO" -SpecificLogFile $PpReportFile
                                    }
                                }
                            }
                        } catch {Write-Log -Message "      Error checking permissions for app '$($app.DisplayName)': $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $PpReportFile}

                        # Check Connectors (basic listing)
                        if ($app.Internal.properties.connectionReferences) {
                            Write-Log -Message "      Connectors used by '$($app.DisplayName)':" -SpecificLogFile $PpReportFile
                            foreach($connRef in $app.Internal.properties.connectionReferences.PSObject.Properties){
                                Write-Log -Message "        - $($connRef.Name) (API ID: $($connRef.Value.apiId), Connection Name: $($connRef.Value.connectionName))" -SpecificLogFile $PpReportFile
                                if ($connRef.Value.apiId -match "/customconnectors/") {
                                    Write-Log -Message "        ALERT: Power App '$($app.DisplayName)' uses a Custom Connector ('$($connRef.Name)'). Investigate its functionality and permissions." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                                }
                            }
                        }
                         # Recently created apps
                        if ($app.Internal.properties.createdTime -gt (Get-Date).AddDays(-$script:LookbackDays)) {
                             Write-Log -Message "    INFO: App '$($app.DisplayName)' in env '$($env.DisplayName)' was created recently ($($app.Internal.properties.createdTime))." -Type "INFO" -SpecificLogFile $PpReportFile
                        }
                    }
                } else { Write-Log -Message "    No Power Apps found or error retrieving apps in '$($env.DisplayName)'." -Type "INFO" -SpecificLogFile $PpReportFile}
            }
        }
    } catch {
        Write-Log -Message "Error checking Power Apps Applications: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $PpReportFile
    }

    # --- 33. Power Platform DLP Policies ---
    Write-Log -Message "Checking Power Platform DLP Policies..." -Type "SUBSECTION" -SpecificLogFile $PpReportFile
    try {
        $dlpPolicies = Get-AdminDlpPolicy -ErrorAction SilentlyContinue
        if ($dlpPolicies) {
            Write-Log -Message "  Found $($dlpPolicies.Count) DLP Policies." -SpecificLogFile $PpReportFile
            foreach ($policy in $dlpPolicies) {
                Write-Log -Message "  DLP Policy: '$($policy.DisplayName)' (ID: $($policy.PolicyName)), Created: $($policy.createdTimestamp), Scope: $(if($policy.EnvironmentName){'Environment: ' + $policy.EnvironmentName}else{'Tenant-wide'})" -SpecificLogFile $PpReportFile

                $businessConnectors = $policy.ConnectorGroups | Where-Object {$_.groupType -eq "Business"} | Select-Object -ExpandProperty connectors
                $nonBusinessConnectors = $policy.ConnectorGroups | Where-Object {$_.groupType -eq "NonBusiness"} | Select-Object -ExpandProperty connectors
                $blockedConnectors = $policy.ConnectorGroups | Where-Object {$_.groupType -eq "Blocked"} | Select-Object -ExpandProperty connectors

                Write-Log -Message "    Business Connectors ($($businessConnectors.Count)): $(($businessConnectors.connectorName | Sort-Object | Join-String -Separator ', ') ?? 'None')" -SpecificLogFile $PpReportFile
                Write-Log -Message "    Non-Business Connectors ($($nonBusinessConnectors.Count)): $(($nonBusinessConnectors.connectorName | Sort-Object | Join-String -Separator ', ') ?? 'None')" -SpecificLogFile $PpReportFile
                Write-Log -Message "    Blocked Connectors ($($blockedConnectors.Count)): $(($blockedConnectors.connectorName | Sort-Object | Join-String -Separator ', ') ?? 'None')" -SpecificLogFile $PpReportFile
                Write-Log -Message "    Default Group For New Connectors: $($policy.DefaultConnectorGroup)" -SpecificLogFile $PpReportFile

                # Basic check for sensitive connectors co-mingling
                $sensitiveBusinessConnectors = @("shared_sharepointonline", "shared_sql", "shared_commondataservice", "shared_office365users", "shared_office365outlook") # Example list
                $potentialExfiltrationConnectors = @("shared_twitter", "shared_rss", "shared_dropbox", "shared_googledrive", "shared_box", "shared_http") # Example list

                $riskyBusiness = $businessConnectors.connectorName | Where-Object {$sensitiveBusinessConnectors -contains $_}
                $riskyNonBusinessForExfil = $nonBusinessConnectors.connectorName | Where-Object {$potentialExfiltrationConnectors -contains $_}
                
                if ($riskyBusiness.Count -gt 0 -and $riskyNonBusinessForExfil.Count -gt 0) {
                     Write-Log -Message "    ALERT: DLP Policy '$($policy.DisplayName)' allows sensitive business connectors ($( $riskyBusiness -join ', ')) to potentially co-mingle data with non-business/exfiltration-capable connectors ($( $riskyNonBusinessForExfil -join ', ')) as they are not in the same blocked/business group. Review policy design." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                }
                if ($policy.DefaultConnectorGroup -eq "NonBusiness" -or $policy.DefaultConnectorGroup -eq "Business") { # NonBusiness is more risky for new connectors
                     Write-Log -Message "    WARN: DLP Policy '$($policy.DisplayName)' has Default Connector Group as '$($policy.DefaultConnectorGroup)'. New connectors will default here, review implications." -Type "WARN" -SpecificLogFile $PpReportFile
                }
                 if (($businessConnectors.connectorName -contains "shared_http") -or ($nonBusinessConnectors.connectorName -contains "shared_http" -and $policy.DefaultConnectorGroup -ne "Blocked")) {
                    Write-Log -Message "    ALERT: DLP Policy '$($policy.DisplayName)' allows the HTTP connector in a non-blocked group. This connector is very powerful and should be restricted or heavily governed (e.g. with URL filtering if available/configured)." -Type "ALERT" -IsAlert -SpecificLogFile $PpReportFile
                }
                 # Check for custom connector handling
                $customConnectorSettings = $policy.ConnectorGroups | Where-Object {$_.isCustomConnectorGroup -eq $true}
                if ($customConnectorSettings) {
                    Write-Log -Message "    Custom Connector Group Policy: $($customConnectorSettings.groupType)" -SpecificLogFile $PpReportFile
                    if ($customConnectorSettings.groupType -ne "Blocked") {
                         Write-Log -Message "    WARN: DLP Policy '$($policy.DisplayName)' does not block custom connectors by default. Custom connectors should be individually assessed and assigned to appropriate groups." -Type "WARN" -SpecificLogFile $PpReportFile
                    }
                } else {
                     Write-Log -Message "    INFO: DLP Policy '$($policy.DisplayName)' does not have explicit custom connector group settings; they may fall into the default group: $($policy.DefaultConnectorGroup)." -Type "INFO" -SpecificLogFile $PpReportFile
                }


            }
        } else {
            Write-Log -Message "  No Power Platform DLP Policies found or error retrieving them. This is a significant gap if policies are expected." -Type "WARN" -IsAlert -SpecificLogFile $PpReportFile
        }
    } catch {
        Write-Log -Message "Error checking Power Platform DLP Policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $PpReportFile
    }

    Write-Log -Message "Finished Power Platform Checks." -Type "SECTION"
}

# ==================================================
# SECTION VI: General Azure & Cross-Service Checks
# ==================================================
function Invoke-GeneralAzureChecks {
    Write-Log -Message "Starting General Azure & Cross-Service Checks" -Type "SECTION"
    if (-not $GraphConnected) {
        Write-Log -Message "Some general checks rely on Graph API. Not connected." -Type "WARN"
    }
    $GeneralReportFile = "GeneralAzure_CrossService_Report.txt"

    # --- 34. Azure Automation Accounts and Runbooks ---
    Write-Log -Message "Checking Azure Automation Accounts and Runbooks (Requires Az module & context)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Azure Automation checks. Requires Az PowerShell module." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 35. Microsoft Graph API Subscriptions (Webhooks) ---
    Write-Log -Message "Checking Microsoft Graph API Subscriptions (Webhooks)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Microsoft Graph API Subscription checks." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 36. Application Proxy Configurations ---
    Write-Log -Message "Checking Application Proxy Configurations..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Application Proxy Configuration checks." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 37. Secure Score Settings and History ---
    Write-Log -Message "Checking Secure Score (Informational)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Secure Score checks." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 38. API Permissions Changes (Auditing) ---
    Write-Log -Message "Checking API Permissions Changes (via Audit Logs - requires AuditLog.Read.All)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement API Permissions Changes audit." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 39. Custom Integration Endpoints ---
    Write-Log -Message "Checking Custom Integration Endpoints (e.g., SharePoint List Webhooks - Manual/Service Specific)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "INFO: Checking custom integration endpoints is service-specific and may require different tools/APIs per service." -Type "INFO" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement checks for known custom integration points if applicable." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 40. Data Loss Prevention Policy Changes (Tenant-wide) ---
    Write-Log -Message "Checking Data Loss Prevention Policy Changes (M365 services DLP)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement M365 Data Loss Prevention Policy checks (Requires Security & Compliance PowerShell)." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 41. Audit Log Settings & Export ---
    Write-Log -Message "Checking Audit Log Settings & Export..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Audit Log Settings & Export checks." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 42. Microsoft Sentinel/SIEM Integration Status ---
    Write-Log -Message "Checking Microsoft Sentinel/SIEM Integration Status (Requires Az module & context)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Microsoft Sentinel/SIEM Integration checks. Requires Az PowerShell module." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 43. Azure Key Vault Access Policies & Secrets ---
    Write-Log -Message "Checking Azure Key Vault Access Policies (If used by M365 apps - Requires Az module)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Azure Key Vault checks. Requires Az PowerShell module." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 44. Managed Tenant Delegations (Lighthouse) ---
    Write-Log -Message "Checking Managed Tenant Delegations (Lighthouse - Informational for MSPs)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Managed Tenant Delegation (Lighthouse) checks. Requires Az PowerShell module." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 45. Exchange Online PowerShell Module Connections (Session Logging) ---
    Write-Log -Message "Checking Exchange Online PowerShell Module Connections (via Audit Logs)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Exchange Online PowerShell Connection audit." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 46. Dynamic Groups with Malicious Membership Rules ---
    Write-Log -Message "Checking Dynamic Groups with Malicious Membership Rules..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Dynamic Group membership rule checks." -Type "WARN" -SpecificLogFile $GeneralReportFile

    # --- 47. Azure Policy Assignments for M365 services ---
    Write-Log -Message "Checking Azure Policy Assignments for M365 services (Requires Az module)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    Write-Log -Message "TODO: Implement Azure Policy Assignment checks. Requires Az PowerShell module." -Type "WARN" -SpecificLogFile $GeneralReportFile

    Write-Log -Message "Finished General Azure & Cross-Service Checks." -Type "SECTION"
}

#endregion Check Implementations

#region Main Script Execution
Write-Log -Message "==================================================" -Type "INFO"
Write-Log -Message "Initiating M365 Persistence Checks..." -Type "INFO"
Write-Log -Message "==================================================" -Type "INFO"

# Execute checks by section
Invoke-ExchangeOnlineChecks
Invoke-AzureADChecks
Invoke-SharePointOnlineChecks
Invoke-MicrosoftTeamsChecks
Invoke-PowerPlatformChecks
Invoke-GeneralAzureChecks


#endregion Main Script Execution

#region Script Cleanup
Write-Log -Message "==================================================" -Type "INFO"
Write-Log -Message "M365 Persistence Check Script Finished." -Type "INFO"

if ($ExoConnected) {
    Write-Log -Message "Disconnecting from Exchange Online..." -Type "INFO"
    Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' } | Remove-PSSession -Confirm:$false
}
if ($GraphConnected) {
    Write-Log -Message "Disconnecting from Microsoft Graph..." -Type "INFO"
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
if ($MSOnlineConnected) {
    Write-Log -Message "Disconnecting from MSOnline..." -Type "INFO"
    # MSOnline doesn't have a specific Disconnect-MsolService, session is usually process-bound
    # No explicit disconnect needed, but good to note.
}

Write-Log -Message "Reports are available in: $ReportDir" -Type "INFO"
Write-Log -Message "Alerts summary is in: $AlertLogFile (if any alerts were generated)" -Type "INFO"
Write-Log -Message "Please review all generated reports and alerts carefully." -Type "WARN"
Write-Log -Message "==================================================" -Type "INFO"

#endregion Script Cleanup

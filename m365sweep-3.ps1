<#
.SYNOPSIS
    Scans a Microsoft 365 E3 tenant for common attacker persistence techniques.
.DESCRIPTION
    This script checks various configurations across Exchange Online, Azure AD (Entra ID),
    SharePoint Online, Teams, Power Platform, and other services based on a predefined
    list of potential persistence points relevant for M365 E3 subscriptions.
    It outputs findings to the console and to text files in a timestamped report directory.
.NOTES
    Version: 3.56
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
    Write-Log -Message "Checking Azure Automation Accounts and Runbooks..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Check if Az module is available
        if (-not (Get-Module -ListAvailable -Name Az.Automation)) {
            Write-Log -Message "Az.Automation module not found. Install using: Install-Module -Name Az.Automation -Repository PSGallery -Force" -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Automation checks due to missing Az.Automation module." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Check if already connected to Azure
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Log -Message "Not connected to Azure. Please use Connect-AzAccount before running this script for Azure-specific checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Automation checks due to missing Azure connection." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Connected to Azure subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -SpecificLogFile $GeneralReportFile
        
        # Get all automation accounts
        $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        
        if (-not $automationAccounts) {
            Write-Log -Message "No Azure Automation accounts found in the current subscription." -Type "INFO" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Found $($automationAccounts.Count) Automation accounts. Analyzing each..." -SpecificLogFile $GeneralReportFile
        
        # Suspicious patterns in runbooks to look for
        $suspiciousPatterns = @(
            "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "DownloadFile", 
            "DownloadString", "Start-Process", "Start-Job", "Invoke-Expression", "IEX", 
            "ExecutionPolicy", "Bypass", "-EncodedCommand", "FromBase64", "System.Convert",
            "Get-Credential", "New-Object", "DirectoryServices.DirectoryEntry", "ADSI",
            "RunAs", "psexec", "ConvertTo-SecureString", "Add-MsolRoleMember", "New-AzADServicePrincipal",
            "Add-AzRoleAssignment", "Get-RunAsAccount", "Invoke-Command", "PSSession", "PSRemoting",
            "scriptblock", "password", "secret", "token", "key", "certificate"
        )
        
        foreach ($aa in $automationAccounts) {
            Write-Log -Message "Automation Account: $($aa.AutomationAccountName) (Resource Group: $($aa.ResourceGroupName), Location: $($aa.Location))" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Created on: $($aa.CreationTime), Last Modified: $($aa.LastModifiedTime)" -SpecificLogFile $GeneralReportFile
            
            # Check recent creation
            if ((New-TimeSpan -Start $aa.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                Write-Log -Message "ALERT: Automation Account '$($aa.AutomationAccountName)' was created recently ($($aa.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Check runbooks in this account
            $runbooks = Get-AzAutomationRunbook -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -ErrorAction SilentlyContinue
            
            if ($runbooks) {
                Write-Log -Message "Found $($runbooks.Count) runbooks in account '$($aa.AutomationAccountName)':" -SpecificLogFile $GeneralReportFile
                
                foreach ($rb in $runbooks) {
                    Write-Log -Message "  Runbook: $($rb.Name) (Type: $($rb.RunbookType), State: $($rb.State), Created: $($rb.CreationTime), Last Modified: $($rb.LastModifiedTime))" -SpecificLogFile $GeneralReportFile
                    
                    # Check recent creation/modification
                    if ((New-TimeSpan -Start $rb.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                        Write-Log -Message "  ALERT: Runbook '$($rb.Name)' in account '$($aa.AutomationAccountName)' was created recently ($($rb.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    if ((New-TimeSpan -Start $rb.LastModifiedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                        Write-Log -Message "  ALERT: Runbook '$($rb.Name)' in account '$($aa.AutomationAccountName)' was modified recently ($($rb.LastModifiedTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Get runbook content for PowerShell-based runbooks
                    if ($rb.RunbookType -like "*PowerShell*" -or $rb.RunbookType -eq "Script") {
                        try {
                            $rbContent = Export-AzAutomationRunbook -Name $rb.Name -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -Slot "Published" -ErrorAction SilentlyContinue
                            
                            if ($rbContent) {
                                # Save runbook content to file
                                $rbContentFile = Join-Path -Path $ReportDir -ChildPath "Runbook_$($aa.AutomationAccountName)_$($rb.Name).ps1"
                                $rbContent | Out-File -FilePath $rbContentFile -Encoding UTF8 -Force
                                Write-Log -Message "  Runbook content saved to: $rbContentFile" -SpecificLogFile $GeneralReportFile
                                
                                # Check for suspicious patterns
                                $foundPatterns = @()
                                foreach ($pattern in $suspiciousPatterns) {
                                    if ($rbContent -match $pattern) {
                                        $foundPatterns += $pattern
                                    }
                                }
                                
                                if ($foundPatterns.Count -gt 0) {
                                    Write-Log -Message "  ALERT: Runbook '$($rb.Name)' contains potentially suspicious patterns: $($foundPatterns -join ', '). Review content manually." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            } else {
                                Write-Log -Message "  WARN: Could not export content for runbook '$($rb.Name)'." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                        } catch {
                            Write-Log -Message "  ERROR: Failed to analyze runbook '$($rb.Name)' content: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    # Check runbook schedules
                    try {
                        $schedules = Get-AzAutomationScheduledRunbook -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -RunbookName $rb.Name -ErrorAction SilentlyContinue
                        if ($schedules) {
                            Write-Log -Message "  Runbook '$($rb.Name)' has $($schedules.Count) schedules:" -SpecificLogFile $GeneralReportFile
                            foreach ($schedule in $schedules) {
                                Write-Log -Message "    Schedule: $($schedule.ScheduleName), Frequency: $($schedule.Frequency), Created: $($schedule.CreationTime)" -SpecificLogFile $GeneralReportFile
                                if ((New-TimeSpan -Start $schedule.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    Write-Log -Message "    ALERT: Schedule '$($schedule.ScheduleName)' for runbook '$($rb.Name)' was created recently ($($schedule.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "  WARN: Could not retrieve schedules for runbook '$($rb.Name)': $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Check runbook webhooks (if supported by the runbook type)
                    try {
                        $webhooks = Get-AzAutomationWebhook -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -RunbookName $rb.Name -ErrorAction SilentlyContinue
                        if ($webhooks) {
                            Write-Log -Message "  ALERT: Runbook '$($rb.Name)' has $($webhooks.Count) webhooks defined. Webhooks allow external triggering of runbooks." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($webhook in $webhooks) {
                                Write-Log -Message "    Webhook: $($webhook.Name), Created: $($webhook.CreationTime), Expires: $($webhook.ExpiryTime)" -SpecificLogFile $GeneralReportFile
                                if ((New-TimeSpan -Start $webhook.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    Write-Log -Message "    ALERT: Webhook '$($webhook.Name)' for runbook '$($rb.Name)' was created recently ($($webhook.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "  WARN: Could not retrieve webhooks for runbook '$($rb.Name)': $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "No runbooks found in account '$($aa.AutomationAccountName)' or error retrieving them." -Type "INFO" -SpecificLogFile $GeneralReportFile
            }
            
            # Check for credentials, certificates, and connections in the automation account
            try {
                $credentials = Get-AzAutomationCredential -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -ErrorAction SilentlyContinue
                if ($credentials) {
                    Write-Log -Message "Found $($credentials.Count) credential assets in automation account '$($aa.AutomationAccountName)':" -SpecificLogFile $GeneralReportFile
                    foreach ($cred in $credentials) {
                        Write-Log -Message "  Credential: $($cred.Name), Created: $($cred.CreationTime), Last Modified: $($cred.LastModifiedTime), Username: $($cred.UserName)" -SpecificLogFile $GeneralReportFile
                        if ((New-TimeSpan -Start $cred.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                            Write-Log -Message "  ALERT: Credential '$($cred.Name)' in account '$($aa.AutomationAccountName)' was created recently ($($cred.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        if ((New-TimeSpan -Start $cred.LastModifiedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                            Write-Log -Message "  ALERT: Credential '$($cred.Name)' in account '$($aa.AutomationAccountName)' was modified recently ($($cred.LastModifiedTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
                
                $certificates = Get-AzAutomationCertificate -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -ErrorAction SilentlyContinue
                if ($certificates) {
                    Write-Log -Message "Found $($certificates.Count) certificate assets in automation account '$($aa.AutomationAccountName)':" -SpecificLogFile $GeneralReportFile
                    foreach ($cert in $certificates) {
                        Write-Log -Message "  Certificate: $($cert.Name), Created: $($cert.CreationTime), Last Modified: $($cert.LastModifiedTime), Expires: $($cert.ExpiryTime)" -SpecificLogFile $GeneralReportFile
                        if ((New-TimeSpan -Start $cert.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                            Write-Log -Message "  ALERT: Certificate '$($cert.Name)' in account '$($aa.AutomationAccountName)' was created recently ($($cert.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
                
                $connections = Get-AzAutomationConnection -AutomationAccountName $aa.AutomationAccountName -ResourceGroupName $aa.ResourceGroupName -ErrorAction SilentlyContinue
                if ($connections) {
                    Write-Log -Message "Found $($connections.Count) connection assets in automation account '$($aa.AutomationAccountName)':" -SpecificLogFile $GeneralReportFile
                    foreach ($conn in $connections) {
                        Write-Log -Message "  Connection: $($conn.Name), Type: $($conn.ConnectionTypeName), Created: $($conn.CreationTime), Last Modified: $($conn.LastModifiedTime)" -SpecificLogFile $GeneralReportFile
                        if ((New-TimeSpan -Start $conn.CreationTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                            Write-Log -Message "  ALERT: Connection '$($conn.Name)' in account '$($aa.AutomationAccountName)' was created recently ($($conn.CreationTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
            } catch {
                Write-Log -Message "  WARN: Could not retrieve credential, certificate, or connection assets for automation account '$($aa.AutomationAccountName)': $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
            }
        }
        
        Write-Log -Message "Completed Azure Automation account and runbook checks." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Azure Automation Accounts and Runbooks: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 35. Microsoft Graph API Subscriptions (Webhooks) ---
    Write-Log -Message "Checking Microsoft Graph API Subscriptions (Webhooks)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check Graph Subscriptions." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "Subscription.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All" -or 
                $context.Scopes -contains "Directory.ReadWrite.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (Subscription.Read.All, Directory.Read.All, or Directory.ReadWrite.All). Some subscription details may not be available." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }

        # Define potentially suspicious notification URLs
        $suspiciousUrlPatterns = @(
            "ngrok.io", "tunnel.me", "serveo.net", "webhookrelay", "hookbin", "requestcatcher",
            "requestbin", "pipedream.net", "cloudflare.workers", "glitch.me", "free.beeceptor.com",
            ".000webhostapp.com", "herokuapp.com", ".repl.co", ".deta.dev", "pastebin", ".workers.dev",
            "example.com", "test.com", "onion."
        )

        # Get Graph subscriptions
        $subscriptions = Get-MgSubscription -All -ErrorAction SilentlyContinue
        
        if (-not $subscriptions) {
            Write-Log -Message "No Microsoft Graph subscriptions found or unable to retrieve them." -Type "INFO" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Found $($subscriptions.Count) Microsoft Graph API subscriptions. Analyzing each..." -SpecificLogFile $GeneralReportFile
        
        # Check subscriptions
        foreach ($sub in $subscriptions) {
            $createdDateTime = $sub.CreatedDateTime ?? "Unknown"
            $expirationDateTime = $sub.ExpirationDateTime ?? "Unknown"
            
            Write-Log -Message "Subscription: ID: $($sub.Id)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Created: $createdDateTime, Expires: $expirationDateTime" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Resource: $($sub.Resource)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Change Type: $($sub.ChangeType)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Notification URL: $($sub.NotificationUrl)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Application ID: $($sub.ApplicationId)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Client State: $($sub.ClientState)" -SpecificLogFile $GeneralReportFile
            
            # Check if recently created
            if ($createdDateTime -ne "Unknown") {
                try {
                    if ((New-TimeSpan -Start $createdDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                        Write-Log -Message "  ALERT: Subscription was created recently ($createdDateTime)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  WARN: Unable to parse creation date to check recency." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
            }
            
            # Check for suspicious notification URLs
            if ($sub.NotificationUrl) {
                $isSuspiciousUrl = $false
                $suspiciousPatternMatched = ""
                
                foreach ($pattern in $suspiciousUrlPatterns) {
                    if ($sub.NotificationUrl -like "*$pattern*") {
                        $isSuspiciousUrl = $true
                        $suspiciousPatternMatched = $pattern
                        break
                    }
                }
                
                if ($isSuspiciousUrl) {
                    Write-Log -Message "  ALERT: Subscription has potentially suspicious notification URL matching pattern '$suspiciousPatternMatched': $($sub.NotificationUrl)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                # Check for non-HTTPS URLs (security issue)
                if ($sub.NotificationUrl -notlike "https://*") {
                    Write-Log -Message "  ALERT: Subscription using non-HTTPS notification URL: $($sub.NotificationUrl)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
            }
            
            # Check the resources being monitored
            $sensitiveResources = @(
                "users", "groups", "directoryObjects", "servicePrincipals", "applications", 
                "auditLogs", "signIns", "identityRiskEvents", "deviceManagement", 
                "roleManagement", "identityGovernance", "security"
            )
            
            $isMonitoringSensitiveResource = $false
            $sensitiveResourceMatched = ""
            
            foreach ($resource in $sensitiveResources) {
                if ($sub.Resource -like "*$resource*") {
                    $isMonitoringSensitiveResource = $true
                    $sensitiveResourceMatched = $resource
                    break
                }
            }
            
            if ($isMonitoringSensitiveResource) {
                Write-Log -Message "  ALERT: Subscription is monitoring sensitive resource type '$sensitiveResourceMatched': $($sub.Resource)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Try to get app info if Application ID is present
            if ($sub.ApplicationId) {
                try {
                    $appInfo = Get-MgServicePrincipal -Filter "appId eq '$($sub.ApplicationId)'" -ErrorAction SilentlyContinue
                    if ($appInfo) {
                        Write-Log -Message "  Application Name: $($appInfo.DisplayName)" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  Application Owner: $($appInfo.AppOwnerOrganizationId)" -SpecificLogFile $GeneralReportFile
                        
                        # Check if app is from this tenant
                        if ($appInfo.AppOwnerOrganizationId -ne $script:TenantId) {
                            Write-Log -Message "  ALERT: Subscription is for an application from another tenant (Owner: $($appInfo.AppOwnerOrganizationId), Current Tenant: $($script:TenantId))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "  ALERT: Could not retrieve information about the application ID: $($sub.ApplicationId). The application might have been deleted or is inaccessible." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  WARN: Error retrieving application information: $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
            }
            
            # Check for specifically concerning combinations (e.g., monitoring admin activity with external callback)
            $adminResources = @("roleManagement", "auditLogs", "security/alerts")
            $isMonitoringAdminResource = $false
            
            foreach ($resource in $adminResources) {
                if ($sub.Resource -like "*$resource*") {
                    $isMonitoringAdminResource = $true
                    break
                }
            }
            
            if ($isMonitoringAdminResource -and $isSuspiciousUrl) {
                Write-Log -Message "  CRITICAL ALERT: Subscription is monitoring admin activity ($($sub.Resource)) and sending notifications to a suspicious URL: $($sub.NotificationUrl). This could indicate an attacker monitoring admin actions!" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
        }
        
        Write-Log -Message "Completed Microsoft Graph API Subscriptions check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Microsoft Graph API Subscriptions: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 36. Application Proxy Configurations ---
    Write-Log -Message "Checking Application Proxy Configurations..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check Application Proxy configurations." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "Application.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All" -or 
                $context.Scopes -contains "Directory.ReadWrite.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (Application.Read.All, Directory.Read.All, or Directory.ReadWrite.All). Some application proxy details may not be available." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }

        # Get all applications with onPremisesPublishing configuration
        $filter = "onPremisesPublishing/enabled eq true"
        $select = "id,appId,displayName,createdDateTime,onPremisesPublishing,web,verifiedPublisher,publisherName,signInAudience,requiredResourceAccess"
        
        $appProxyApps = Get-MgApplication -Filter $filter -Property $select -All -ErrorAction SilentlyContinue
        
        if (-not $appProxyApps -or $appProxyApps.Count -eq 0) {
            Write-Log -Message "No Application Proxy applications found." -Type "INFO" -SpecificLogFile $GeneralReportFile
            
            # Check if there are any on-premises application proxy connectors
            Write-Log -Message "Checking for Application Proxy connectors..." -SpecificLogFile $GeneralReportFile
            
            try {
                $connectors = Get-MgOnPremisesPublishingProfile -ErrorAction SilentlyContinue
                if ($connectors -and $connectors.ConnectorGroups) {
                    Write-Log -Message "Found Application Proxy connector groups with no published applications:" -Type "WARN" -SpecificLogFile $GeneralReportFile
                    
                    foreach ($connectorGroup in $connectors.ConnectorGroups) {
                        Write-Log -Message "  Connector Group: $($connectorGroup.Name) (ID: $($connectorGroup.Id))" -SpecificLogFile $GeneralReportFile
                        
                        if ($connectorGroup.Connectors -and $connectorGroup.Connectors.Count -gt 0) {
                            foreach ($connector in $connectorGroup.Connectors) {
                                Write-Log -Message "    Connector: $($connector.Name) (ID: $($connector.Id), Status: $($connector.Status))" -SpecificLogFile $GeneralReportFile
                                if ($connector.MachineName) {
                                    Write-Log -Message "      Machine: $($connector.MachineName), Connector Version: $($connector.ConnectorVersion)" -SpecificLogFile $GeneralReportFile
                                }
                            }
                        } else {
                            Write-Log -Message "    No connectors in this group." -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    Write-Log -Message "WARN: Application Proxy connectors exist but no applications are published. This could be normal in a staging environment or could indicate incomplete attack setup." -Type "WARN" -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "No Application Proxy connectors found." -Type "INFO" -SpecificLogFile $GeneralReportFile
                }
            } catch {
                Write-Log -Message "Error checking Application Proxy connectors: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
            
            return
        }

        Write-Log -Message "Found $($appProxyApps.Count) Application Proxy applications. Analyzing each..." -SpecificLogFile $GeneralReportFile
        
        # Define potentially suspicious URL patterns
        $suspiciousUrlPatterns = @(
            "ngrok.io", "tunnel.me", "serveo.net", "webhookrelay", "hookbin", "requestcatcher",
            "requestbin", "pipedream.net", "cloudflare.workers", "glitch.me", "free.beeceptor.com",
            ".000webhostapp.com", "herokuapp.com", ".repl.co", ".deta.dev", "pastebin", ".workers.dev"
        )
        
        # Check each application proxy application
        foreach ($app in $appProxyApps) {
            Write-Log -Message "Application: $($app.DisplayName) (ID: $($app.Id), AppId: $($app.AppId))" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Created: $($app.CreatedDateTime), Publisher: $($app.PublisherName)" -SpecificLogFile $GeneralReportFile
            
            # Check if app was created recently
            if ((New-TimeSpan -Start $app.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                Write-Log -Message "  ALERT: Application Proxy app '$($app.DisplayName)' was created recently ($($app.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Check on-premises publishing configuration
            if ($app.OnPremisesPublishing) {
                Write-Log -Message "  On-Premises Publishing Configuration:" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    External URL: $($app.OnPremisesPublishing.ExternalUrl)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Internal URL: $($app.OnPremisesPublishing.InternalUrl)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Pre-Authentication Method: $($app.OnPremisesPublishing.ExternalAuthenticationType)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Connector Group ID: $($app.OnPremisesPublishing.ConnectorGroupId)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Allows Persistent Access: $($app.OnPremisesPublishing.IsTranslateLinksInBodyEnabled)" -SpecificLogFile $GeneralReportFile
                
                # Check for pass-through authentication (no pre-auth)
                if ($app.OnPremisesPublishing.ExternalAuthenticationType -eq "passthru") {
                    Write-Log -Message "  ALERT: Application Proxy app '$($app.DisplayName)' uses pass-through authentication (no pre-authentication). This bypasses Azure AD authentication and relies solely on backend authentication." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                # Check for suspicious external URL
                $suspiciousExternal = $false
                foreach ($pattern in $suspiciousUrlPatterns) {
                    if ($app.OnPremisesPublishing.ExternalUrl -like "*$pattern*") {
                        $suspiciousExternal = $true
                        Write-Log -Message "  ALERT: Application Proxy app '$($app.DisplayName)' has a suspicious external URL: $($app.OnPremisesPublishing.ExternalUrl) (matches pattern: $pattern)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        break
                    }
                }
                
                # Check if internal URL is accessible from Internet (should be internal-only)
                $internalUrl = $app.OnPremisesPublishing.InternalUrl
                if ($internalUrl -like "https://*.com*" -or 
                    $internalUrl -like "https://*.net*" -or 
                    $internalUrl -like "https://*.org*" -or 
                    $internalUrl -like "https://*.io*" -or 
                    $internalUrl -like "http://*.com*" -or 
                    $internalUrl -like "http://*.net*" -or 
                    $internalUrl -like "http://*.org*" -or 
                    $internalUrl -like "http://*.io*") {
                    
                    # Check if it's not an obvious internal address like intranet.company.com
                    if ($internalUrl -notlike "*intranet*" -and 
                        $internalUrl -notlike "*internal*" -and 
                        $internalUrl -notlike "*corp*" -and 
                        $internalUrl -notlike "*local*") {
                        Write-Log -Message "  WARN: Application Proxy app '$($app.DisplayName)' has an internal URL that appears to be a public domain: $internalUrl. Verify this is an internal application." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                # Check for non-HTTPS internal URL
                if ($internalUrl -like "http://*" -and $internalUrl -notlike "https://*") {
                    Write-Log -Message "  WARN: Application Proxy app '$($app.DisplayName)' uses non-HTTPS internal URL: $internalUrl. This may expose credentials." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
                
                # Check if link translation is enabled (can modify content)
                if ($app.OnPremisesPublishing.IsTranslateLinksInBodyEnabled -eq $true) {
                    Write-Log -Message "  INFO: Application Proxy app '$($app.DisplayName)' has link translation enabled. This modifies content but is often needed for applications with hardcoded internal URLs." -Type "INFO" -SpecificLogFile $GeneralReportFile
                }
                
                # Check for custom domains
                if ($app.OnPremisesPublishing.VerifiedCustomDomainName) {
                    Write-Log -Message "    Custom Domain: $($app.OnPremisesPublishing.VerifiedCustomDomainName)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    WARN: Application uses a custom domain. Ensure this domain is properly secured and verified." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
                
                # Check if SSL certificate validation is disabled
                if ($app.OnPremisesPublishing.IsBackendSSLCertificateValidationEnabled -eq $false) {
                    Write-Log -Message "  ALERT: Application Proxy app '$($app.DisplayName)' has SSL certificate validation disabled. This could allow MITM attacks." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
            }
            
            # Check redirect URIs for suspicious patterns
            if ($app.Web -and $app.Web.RedirectUris) {
                Write-Log -Message "  Redirect URIs:" -SpecificLogFile $GeneralReportFile
                foreach ($uri in $app.Web.RedirectUris) {
                    Write-Log -Message "    $uri" -SpecificLogFile $GeneralReportFile
                    
                    # Check for suspicious redirect URIs
                    $suspiciousRedirect = $false
                    foreach ($pattern in $suspiciousUrlPatterns) {
                        if ($uri -like "*$pattern*") {
                            $suspiciousRedirect = $true
                            Write-Log -Message "    ALERT: Application Proxy app '$($app.DisplayName)' has a suspicious redirect URI: $uri (matches pattern: $pattern)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            break
                        }
                    }
                    
                    # Check for localhost redirects (not always bad but worth noting)
                    if ($uri -like "*localhost*" -or $uri -like "*127.0.0.1*") {
                        Write-Log -Message "    WARN: Application Proxy app '$($app.DisplayName)' has a localhost redirect URI: $uri. This is suspicious for production apps but may be normal for development." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
            }
            
            # Check sign-in audience
            if ($app.SignInAudience -eq "AzureADMultipleOrgs" -or $app.SignInAudience -eq "AzureADandPersonalMicrosoftAccount") {
                Write-Log -Message "  ALERT: Application Proxy app '$($app.DisplayName)' is configured for multi-tenant access ($($app.SignInAudience)). Application Proxy apps should typically be single-tenant." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Check if app is verified
            if ($app.VerifiedPublisher -and $app.VerifiedPublisher.IsVerified -eq $true) {
                Write-Log -Message "  Verified Publisher: Yes (Publisher: $($app.VerifiedPublisher.DisplayName))" -SpecificLogFile $GeneralReportFile
            } else {
                Write-Log -Message "  Verified Publisher: No" -SpecificLogFile $GeneralReportFile
            }
            
            # Check for required resource access
            if ($app.RequiredResourceAccess -and $app.RequiredResourceAccess.Count -gt 0) {
                Write-Log -Message "  Required Resource Access:" -SpecificLogFile $GeneralReportFile
                foreach ($resource in $app.RequiredResourceAccess) {
                    $resourceAppInfo = Get-MgServicePrincipal -Filter "appId eq '$($resource.ResourceAppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    $resourceAppName = $resourceAppInfo.DisplayName ?? $resource.ResourceAppId
                    Write-Log -Message "    Resource: $resourceAppName (AppId: $($resource.ResourceAppId))" -SpecificLogFile $GeneralReportFile
                    
                    # Check if the app has permissions to sensitive resources
                    $sensitiveApps = @(
                        "00000003-0000-0000-c000-000000000000", # Microsoft Graph
                        "00000002-0000-0ff1-ce00-000000000000", # Exchange Online
                        "00000003-0000-0ff1-ce00-000000000000"  # SharePoint Online
                    )
                    
                    if ($sensitiveApps -contains $resource.ResourceAppId) {
                        foreach ($permission in $resource.ResourceAccess) {
                            $permObject = $null
                            $permName = $permission.Id # Default to ID if name not found
                            
                            if ($permission.Type -eq "Role") { # Application Permission
                                $permObject = $resourceAppInfo.AppRoles | Where-Object {$_.Id -eq $permission.Id} | Select-Object -First 1
                                if ($permObject) { $permName = $permObject.Value }
                                
                                # High-risk application permissions
                                $highRiskPerms = @(
                                    "Directory.ReadWrite.All", "Directory.Read.All", "User.ReadWrite.All", "Mail.ReadWrite", 
                                    "Mail.Read", "Files.ReadWrite.All", "Sites.ReadWrite.All"
                                )
                                
                                if ($permObject -and $highRiskPerms -contains $permObject.Value) {
                                    Write-Log -Message "    ALERT: Application Proxy app '$($app.DisplayName)' has high-risk application permission: $($permObject.Value) for $resourceAppName" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                                
                                Write-Log -Message "      App Permission (Role): $permName (ID: $($permission.Id))" -SpecificLogFile $GeneralReportFile
                            } 
                            elseif ($permission.Type -eq "Scope") { # Delegated Permission
                                $permObject = $resourceAppInfo.Oauth2PermissionScopes | Where-Object {$_.Id -eq $permission.Id} | Select-Object -First 1
                                if ($permObject) { $permName = $permObject.Value }
                                Write-Log -Message "      Delegated Permission (Scope): $permName (ID: $($permission.Id))" -SpecificLogFile $GeneralReportFile
                            }
                        }
                    }
                }
            }
        }
        
        # Check the connector groups and connectors
        Write-Log -Message "Checking Application Proxy connectors and connector groups..." -SpecificLogFile $GeneralReportFile
        
        try {
            $onPremProfile = Get-MgOnPremisesPublishingProfile -ErrorAction SilentlyContinue
            
            if ($onPremProfile -and $onPremProfile.ConnectorGroups) {
                Write-Log -Message "Found $($onPremProfile.ConnectorGroups.Count) connector groups." -SpecificLogFile $GeneralReportFile
                
                foreach ($connectorGroup in $onPremProfile.ConnectorGroups) {
                    Write-Log -Message "Connector Group: $($connectorGroup.Name) (ID: $($connectorGroup.Id))" -SpecificLogFile $GeneralReportFile
                    
                    # Get applications using this connector group
                    $appsUsingGroup = $appProxyApps | Where-Object { $_.OnPremisesPublishing.ConnectorGroupId -eq $connectorGroup.Id }
                    Write-Log -Message "  Applications using this connector group: $($appsUsingGroup.Count)" -SpecificLogFile $GeneralReportFile
                    
                    if ($appsUsingGroup.Count -eq 0) {
                        Write-Log -Message "  WARN: Connector group '$($connectorGroup.Name)' is not used by any application. Consider removing if not needed." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($connectorGroup.Connectors -and $connectorGroup.Connectors.Count -gt 0) {
                        Write-Log -Message "  Connectors in this group: $($connectorGroup.Connectors.Count)" -SpecificLogFile $GeneralReportFile
                        
                        foreach ($connector in $connectorGroup.Connectors) {
                            Write-Log -Message "    Connector: $($connector.Name) (ID: $($connector.Id))" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Status: $($connector.Status), Machine Name: $($connector.MachineName)" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Connector Version: $($connector.ConnectorVersion), Externalip: $($connector.ExternalIp)" -SpecificLogFile $GeneralReportFile
                            
                            if ($connector.Status -ne "active") {
                                Write-Log -Message "      WARN: Connector '$($connector.Name)' is not active (Status: $($connector.Status)). Applications using this connector group may not be accessible." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                            
                            # Check if connector was recently created
                            if ($connector.CreatedDateTime -and (New-TimeSpan -Start $connector.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "      ALERT: Connector '$($connector.Name)' was created recently ($($connector.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  ALERT: Connector group '$($connectorGroup.Name)' has no connectors. Applications using this group will not function." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "No connector groups found or error retrieving them." -Type "INFO" -SpecificLogFile $GeneralReportFile
            }
        } catch {
            Write-Log -Message "Error checking connector groups: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Application Proxy configurations check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Application Proxy configurations: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 37. Secure Score Settings and History ---
    Write-Log -Message "Checking Secure Score (Informational)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check Secure Score." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "SecurityEvents.Read.All" -or 
                $context.Scopes -contains "Security.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (SecurityEvents.Read.All, Security.Read.All, or Directory.Read.All). Some Secure Score details may not be available." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }

        # Get current secure scores
        $secureScores = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=5" -ErrorAction SilentlyContinue
        
        if (-not $secureScores -or -not $secureScores.value -or $secureScores.value.Count -eq 0) {
            Write-Log -Message "Could not retrieve Secure Score information or no scores available." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Get the most recent score
        $currentScore = $secureScores.value | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1
        
        Write-Log -Message "Current Secure Score: $($currentScore.currentScore) out of $($currentScore.maxScore) ($(($currentScore.currentScore / $currentScore.maxScore).ToString("P2")))" -SpecificLogFile $GeneralReportFile
        Write-Log -Message "Score recorded on: $($currentScore.createdDateTime)" -SpecificLogFile $GeneralReportFile
        
        # Get previous scores for comparison if available
        if ($secureScores.value.Count -gt 1) {
            $previousScore = $secureScores.value | Sort-Object -Property createdDateTime -Descending | Select-Object -Skip 1 -First 1
            $scoreDifference = $currentScore.currentScore - $previousScore.currentScore
            
            if ($scoreDifference -gt 0) {
                Write-Log -Message "Score increased by $scoreDifference points since previous reading on $($previousScore.createdDateTime)." -SpecificLogFile $GeneralReportFile
            } 
            elseif ($scoreDifference -lt 0) {
                $absDifference = [Math]::Abs($scoreDifference)
                Write-Log -Message "ALERT: Score decreased by $absDifference points since previous reading on $($previousScore.createdDateTime). Review recent security changes." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            else {
                Write-Log -Message "Score unchanged since previous reading on $($previousScore.createdDateTime)." -SpecificLogFile $GeneralReportFile
            }
        }
        
        # Get secure score control profiles
        $secureScoreControls = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles" -ErrorAction SilentlyContinue
        
        if ($secureScoreControls -and $secureScoreControls.value) {
            Write-Log -Message "Found $($secureScoreControls.value.Count) secure score controls. Analyzing status..." -SpecificLogFile $GeneralReportFile
            
            # Get secure score control profiles with their current states
            $currentControlStates = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores/$($currentScore.id)/controlScores" -ErrorAction SilentlyContinue
            
            if ($currentControlStates -and $currentControlStates.value) {
                $controlStatesById = @{}
                foreach ($controlState in $currentControlStates.value) {
                    $controlStatesById[$controlState.controlName] = $controlState
                }
                
                # Define critical security controls that should be implemented
                $criticalControls = @(
                    "AdminMFAV2", "MFARegistrationV2", "PWAgePolicyNew", "OneAdmin", 
                    "SelfServicePasswordReset", "ModernAuthentication",
                    "PrivilegedIdentity", "DLPEnabled", "LegacyAuthDisabled", 
                    "RoleGroupMFA", "Malware"
                )
                
                # Define mapping for control display names
                $controlDisplayNames = @{
                    "AdminMFAV2" = "MFA for Administrators"
                    "MFARegistrationV2" = "MFA Registration"
                    "PWAgePolicyNew" = "Password Expiration Policy"
                    "OneAdmin" = "More Than One Global Admin"
                    "SelfServicePasswordReset" = "Self-Service Password Reset"
                    "ModernAuthentication" = "Modern Authentication"
                    "PrivilegedIdentity" = "Privileged Identity Management"
                    "DLPEnabled" = "DLP Policies"
                    "LegacyAuthDisabled" = "Legacy Authentication Disabled"
                    "RoleGroupMFA" = "MFA for Role Groups"
                    "Malware" = "Malware Protection"
                    # Add more mappings as needed
                }
                
                # Lists for tracking control status
                $implementedControls = New-Object System.Collections.Generic.List[string]
                $partialControls = New-Object System.Collections.Generic.List[string]
                $notImplementedControls = New-Object System.Collections.Generic.List[string]
                $criticalNotImplemented = New-Object System.Collections.Generic.List[string]
                
                # Process each control
                foreach ($control in $secureScoreControls.value) {
                    $controlState = $controlStatesById[$control.id]
                    $displayName = $control.title
                    $maxScore = $control.maxScore
                    
                    if ($controlState) {
                        $currentScore = $controlState.score
                        $implementationStatus = "Unknown"
                        
                        if ($currentScore -eq $maxScore) {
                            $implementationStatus = "Fully Implemented"
                            $implementedControls.Add($displayName)
                        } 
                        elseif ($currentScore -gt 0) {
                            $implementationStatus = "Partially Implemented"
                            $partialControls.Add($displayName)
                        }
                        else {
                            $implementationStatus = "Not Implemented"
                            $notImplementedControls.Add($displayName)
                            
                            # Check if this is a critical control
                            if ($criticalControls -contains $control.id) {
                                $criticalControlName = if ($controlDisplayNames.ContainsKey($control.id)) { $controlDisplayNames[$control.id] } else { $displayName }
                                $criticalNotImplemented.Add($criticalControlName)
                            }
                        }
                        
                        Write-Log -Message "  Control: $displayName (ID: $($control.id))" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "    Status: $implementationStatus - Score $currentScore/$maxScore" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "    Description: $($control.description)" -SpecificLogFile $GeneralReportFile
                        
                        # Add more specific alerts for certain critical controls
                        if ($control.id -eq "AdminMFAV2" -and $implementationStatus -ne "Fully Implemented") {
                            Write-Log -Message "    ALERT: MFA for administrators is not fully implemented. This is a critical security control." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        if ($control.id -eq "OneAdmin" -and $implementationStatus -ne "Fully Implemented") {
                            Write-Log -Message "    ALERT: Only one Global Administrator detected. This creates a single point of failure." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        if ($control.id -eq "LegacyAuthDisabled" -and $implementationStatus -ne "Fully Implemented") {
                            Write-Log -Message "    ALERT: Legacy authentication is not fully disabled. This poses a significant security risk for credential attacks." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                    else {
                        Write-Log -Message "  Control: $displayName (ID: $($control.id))" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "    Status: Not Found in Current Scores" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "    Description: $($control.description)" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                # Summarize control implementation status
                Write-Log -Message "Summary of Secure Score Controls:" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Fully Implemented: $($implementedControls.Count)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Partially Implemented: $($partialControls.Count)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Not Implemented: $($notImplementedControls.Count)" -SpecificLogFile $GeneralReportFile
                
                if ($criticalNotImplemented.Count -gt 0) {
                    Write-Log -Message "ALERT: The following critical security controls are not implemented:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    foreach ($control in $criticalNotImplemented) {
                        Write-Log -Message "  - $control" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                }
                
                # Get score history for trend analysis
                try {
                    $scoreHistory = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=90" -ErrorAction SilentlyContinue
                    
                    if ($scoreHistory -and $scoreHistory.value -and $scoreHistory.value.Count -gt 0) {
                        $historicalScores = $scoreHistory.value | Sort-Object -Property createdDateTime
                        $oldestScore = $historicalScores[0]
                        $newestScore = $historicalScores[-1]
                        
                        $longTermChange = $newestScore.currentScore - $oldestScore.currentScore
                        $percentChange = if ($oldestScore.currentScore -gt 0) { ($longTermChange / $oldestScore.currentScore).ToString("P2") } else { "N/A" }
                        
                        Write-Log -Message "Secure Score Trend Analysis:" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  Period: $($oldestScore.createdDateTime) to $($newestScore.createdDateTime)" -SpecificLogFile $GeneralReportFile
                        
                        if ($longTermChange -gt 0) {
                            Write-Log -Message "  Positive trend: Score increased by $longTermChange points ($percentChange) over this period." -SpecificLogFile $GeneralReportFile
                        } 
                        elseif ($longTermChange -lt 0) {
                            $absChange = [Math]::Abs($longTermChange)
                            Write-Log -Message "  ALERT: Negative trend: Score decreased by $absChange points ($percentChange) over this period." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        else {
                            Write-Log -Message "  Neutral trend: Score unchanged over this period." -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check for significant drops in score (potential security regression)
                        $significantDrops = New-Object System.Collections.Generic.List[PSObject]
                        
                        for ($i = 1; $i -lt $historicalScores.Count; $i++) {
                            $currentEntry = $historicalScores[$i]
                            $previousEntry = $historicalScores[$i-1]
                            $scoreDrop = $previousEntry.currentScore - $currentEntry.currentScore
                            
                            if ($scoreDrop -gt 5) { # Threshold for significant drop
                                $dropInfo = [PSCustomObject]@{
                                    Date = $currentEntry.createdDateTime
                                    Drop = $scoreDrop
                                    PreviousScore = $previousEntry.currentScore
                                    NewScore = $currentEntry.currentScore
                                }
                                $significantDrops.Add($dropInfo)
                            }
                        }
                        
                        if ($significantDrops.Count -gt 0) {
                            Write-Log -Message "  ALERT: Detected $($significantDrops.Count) significant score drops in the historical data:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            
                            foreach ($drop in $significantDrops) {
                                Write-Log -Message "    - On $($drop.Date): Score dropped by $($drop.Drop) points (from $($drop.PreviousScore) to $($drop.NewScore))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                            
                            Write-Log -Message "    These drops may indicate security controls being disabled or security policy changes." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error retrieving score history: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # Provide recommendations for improvement
                Write-Log -Message "Top 5 Recommended Actions for Improving Secure Score:" -SpecificLogFile $GeneralReportFile
                
                # Combine unimplemented critical controls with highest impact controls
                $recommendationControls = New-Object System.Collections.Generic.List[PSObject]
                
                foreach ($control in $secureScoreControls.value) {
                    $controlState = $controlStatesById[$control.id]
                    if ($controlState -and $controlState.score -lt $control.maxScore) {
                        $implementationPercentage = if ($control.maxScore -gt 0) { ($controlState.score / $control.maxScore) } else { 0 }
                        $isImplemented = $implementationPercentage -ge 0.9 # Consider 90%+ as effectively implemented
                        
                        if (-not $isImplemented) {
                            $isCritical = $criticalControls -contains $control.id
                            $displayName = $control.title
                            $impact = $control.maxScore
                            
                            $recommendationControls.Add([PSCustomObject]@{
                                Name = $displayName
                                Description = $control.description
                                Impact = $impact
                                IsCritical = $isCritical
                                Implementation = $implementationPercentage
                                RecommendationLink = $control.implementationPath
                            })
                        }
                    }
                }
                
                # Sort by critical first, then by impact
                $topRecommendations = $recommendationControls | Sort-Object -Property @{Expression="IsCritical"; Descending=$true}, @{Expression="Impact"; Descending=$true} | Select-Object -First 5
                
                foreach ($recommendation in $topRecommendations) {
                    $criticalTag = if ($recommendation.IsCritical) { " [CRITICAL]" } else { "" }
                    Write-Log -Message "  - $($recommendation.Name)$criticalTag - Impact: $($recommendation.Impact) points" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    $($recommendation.Description)" -SpecificLogFile $GeneralReportFile
                    if ($recommendation.RecommendationLink) {
                        Write-Log -Message "    Implementation Guidance: $($recommendation.RecommendationLink)" -SpecificLogFile $GeneralReportFile
                    }
                }
            }
            else {
                Write-Log -Message "Could not retrieve control scores for the current Secure Score." -Type "WARN" -SpecificLogFile $GeneralReportFile
            }
        }
        else {
            Write-Log -Message "Could not retrieve Secure Score control profiles." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Secure Score check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Secure Score: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 38. API Permissions Changes (Auditing) ---
    Write-Log -Message "Checking API Permissions Changes (via Audit Logs)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check API Permissions Changes." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "AuditLog.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (AuditLog.Read.All or Directory.Read.All). Cannot check API permission changes." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Define the time period to look back (using script's global LookbackDays)
        $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        Write-Log -Message "Searching for API permission changes from $startTime to $endTime..." -SpecificLogFile $GeneralReportFile
        
        # Define operations related to API permissions that we want to audit
        $permissionOperations = @(
            "Consent to application", 
            "Add app role assignment", 
            "Add delegated permission grant", 
            "Add OAuth2PermissionGrant", 
            "Add service principal", 
            "Add application",
            "Update application"
        )
        
        # Create filter for the specific operations we're interested in
        $operationFilter = $permissionOperations | ForEach-Object { "activityDisplayName eq '$_'" }
        $filter = "activityDateTime ge $startTime and ($($operationFilter -join ' or '))"
        
        # Query audit logs with the filter
        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
        
        if (-not $auditLogs -or $auditLogs.Count -eq 0) {
            Write-Log -Message "No API permission changes found in the audit logs for the specified period." -Type "INFO" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Found $($auditLogs.Count) API permission change events. Analyzing each..." -SpecificLogFile $GeneralReportFile
        
        # Define high-risk permissions to specifically flag
        $highRiskPermissions = @(
            "Directory.ReadWrite.All", "Directory.Read.All", "RoleManagement.ReadWrite.Directory",
            "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All", "Group.ReadWrite.All",
            "User.ReadWrite.All", "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
            "Sites.ReadWrite.All", "Sites.FullControl.All", "MailboxSettings.ReadWrite",
            "Policy.ReadWrite.ApplicationConfiguration", "DeviceManagementApps.ReadWrite.All"
        )
        
        # Create a summary for each affected application
        $appPermissionChanges = @{}
        
        foreach ($log in $auditLogs) {
            $timestamp = $log.ActivityDateTime
            $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.User.DisplayName ?? $log.InitiatedBy.App.DisplayName ?? "Unknown"
            $activity = $log.ActivityDisplayName
            $result = $log.Result
            $resourceId = $log.TargetResources[0].Id
            $resourceDisplayName = $log.TargetResources[0].DisplayName
            $resourceType = $log.TargetResources[0].Type
            
            # Log the basic event details
            Write-Log -Message "Permission Change Event:" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Time: $timestamp" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Actor: $actor" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Activity: $activity" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Result: $result" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Resource: $resourceDisplayName (ID: $resourceId, Type: $resourceType)" -SpecificLogFile $GeneralReportFile
            
            # Extract modified properties to get permission details
            $modifiedProps = $log.TargetResources[0].ModifiedProperties
            $permissionDetails = ""
            $permissionName = ""
            $permissionValue = ""
            $resourceAppId = ""
            $isHighRisk = $false
            
            foreach ($prop in $modifiedProps) {
                $propName = $prop.DisplayName
                $newValue = $prop.NewValue
                $oldValue = $prop.OldValue
                
                Write-Log -Message "    Modified Property: $propName" -SpecificLogFile $GeneralReportFile
                
                if ($newValue -and $newValue -ne "[]" -and $newValue -ne "null") {
                    Write-Log -Message "      New Value: $newValue" -SpecificLogFile $GeneralReportFile
                }
                
                if ($oldValue -and $oldValue -ne "[]" -and $oldValue -ne "null") {
                    Write-Log -Message "      Old Value: $oldValue" -SpecificLogFile $GeneralReportFile
                }
                
                # Try to extract specific permission information based on property name
                if ($propName -eq "AppRole.Value" -or $propName -eq "OAuth2Permission.Value") {
                    $permissionName = $propName
                    $permissionValue = $newValue
                    
                    # Check if this is a high-risk permission
                    foreach ($highRiskPerm in $highRiskPermissions) {
                        if ($newValue -like "*$highRiskPerm*") {
                            $isHighRisk = $true
                            break
                        }
                    }
                }
                elseif ($propName -eq "ResourceApplication") {
                    $resourceAppId = $newValue
                }
                elseif ($propName -like "*Permission*" -or $propName -like "*AppRole*" -or $propName -like "*Scope*") {
                    $permissionDetails += "[$propName: $newValue] "
                }
            }
            
            # Store this change in our application summary dictionary
            if (-not [string]::IsNullOrEmpty($resourceDisplayName)) {
                if (-not $appPermissionChanges.ContainsKey($resourceDisplayName)) {
                    $appPermissionChanges[$resourceDisplayName] = @{
                        ResourceId = $resourceId
                        ResourceType = $resourceType
                        Changes = New-Object System.Collections.Generic.List[PSObject]
                        HighRiskPermissions = $false
                    }
                }
                
                $appPermissionChanges[$resourceDisplayName].Changes.Add([PSCustomObject]@{
                    Timestamp = $timestamp
                    Actor = $actor
                    Activity = $activity
                    Result = $result
                    PermissionName = $permissionName
                    PermissionValue = $permissionValue
                    ResourceAppId = $resourceAppId
                    PermissionDetails = $permissionDetails
                    IsHighRisk = $isHighRisk
                })
                
                if ($isHighRisk) {
                    $appPermissionChanges[$resourceDisplayName].HighRiskPermissions = $true
                }
            }
            
            # Generate alerts for high-risk or suspicious permission changes
            if ($isHighRisk) {
                Write-Log -Message "  ALERT: High-risk permission $permissionValue granted to $resourceDisplayName by $actor on $timestamp." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Alert on admin consent grants specifically
            if ($activity -eq "Consent to application") {
                Write-Log -Message "  ALERT: Admin consent granted to $resourceDisplayName by $actor on $timestamp. Review permission scope carefully." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
            # Alert on non-admin actors granting permissions (if they're not Global Admins or App Admins)
            if ($actor -ne "Unknown" -and $actor -ne "Microsoft Azure AD Cloud Sync" -and $actor -ne "MS-PIM" -and $actor -notlike "*admin*") {
                Write-Log -Message "  ALERT: Permission change for $resourceDisplayName made by $actor who may not be an administrator. Verify this account has permission to make these changes." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
        }
        
        # Generate a summary by application
        Write-Log -Message "Summary of API Permission Changes by Application:" -SpecificLogFile $GeneralReportFile
        foreach ($appName in $appPermissionChanges.Keys) {
            $appInfo = $appPermissionChanges[$appName]
            $changeCount = $appInfo.Changes.Count
            $highRiskTag = if ($appInfo.HighRiskPermissions) { " [HIGH RISK PERMISSIONS]" } else { "" }
            
            Write-Log -Message "Application: $appName$highRiskTag" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Resource ID: $($appInfo.ResourceId)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Resource Type: $($appInfo.ResourceType)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Total Changes: $changeCount" -SpecificLogFile $GeneralReportFile
            
            if ($appInfo.HighRiskPermissions) {
                $highRiskChanges = $appInfo.Changes | Where-Object { $_.IsHighRisk }
                
                foreach ($change in $highRiskChanges) {
                    Write-Log -Message "  High-Risk Change on $($change.Timestamp) by $($change.Actor):" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    Action: $($change.Activity)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    Permission: $($change.PermissionValue)" -SpecificLogFile $GeneralReportFile
                    
                    # Try to resolve resource app name from ID if available
                    if (-not [string]::IsNullOrEmpty($change.ResourceAppId)) {
                        try {
                            $resourceApp = Get-MgServicePrincipal -Filter "appId eq '$($change.ResourceAppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($resourceApp) {
                                Write-Log -Message "    Resource App: $($resourceApp.DisplayName) (AppId: $($change.ResourceAppId))" -SpecificLogFile $GeneralReportFile
                            } else {
                                Write-Log -Message "    Resource App ID: $($change.ResourceAppId)" -SpecificLogFile $GeneralReportFile
                            }
                        } catch {
                            Write-Log -Message "    Resource App ID: $($change.ResourceAppId)" -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
            }
        }
        
        # Identify any potential pattern of privilege escalation
        $potentialEscalationApps = New-Object System.Collections.Generic.List[string]
        
        foreach ($appName in $appPermissionChanges.Keys) {
            $appInfo = $appPermissionChanges[$appName]
            $appChanges = $appInfo.Changes
            
            # Sort changes by timestamp
            $sortedChanges = $appChanges | Sort-Object -Property Timestamp
            
            # Check for progression from low to high privileges
            $hadLowPrivileges = $false
            $laterGainedHighPrivileges = $false
            
            for ($i = 0; $i -lt $sortedChanges.Count; $i++) {
                $change = $sortedChanges[$i]
                
                if (-not $change.IsHighRisk -and -not $hadLowPrivileges) {
                    $hadLowPrivileges = $true
                }
                
                if ($change.IsHighRisk -and $hadLowPrivileges) {
                    $laterGainedHighPrivileges = $true
                    break
                }
            }
            
            if ($hadLowPrivileges -and $laterGainedHighPrivileges) {
                $potentialEscalationApps.Add($appName)
            }
        }
        
        if ($potentialEscalationApps.Count -gt 0) {
            Write-Log -Message "ALERT: Detected potential privilege escalation pattern for the following applications:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            foreach ($appName in $potentialEscalationApps) {
                Write-Log -Message "  - $appName" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            Write-Log -Message "  These applications initially received low-privilege permissions and later obtained high-privilege permissions." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed API Permission Changes audit." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking API Permission Changes: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 39. Custom Integration Endpoints ---
    Write-Log -Message "Checking Custom Integration Endpoints (e.g., SharePoint List Webhooks, Teams Webhooks)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Many custom integration endpoint checks require Graph API." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Checking for custom integration endpoints across multiple services..." -SpecificLogFile $GeneralReportFile
        
        # Define potentially suspicious URL patterns (reusing from earlier checks)
        $suspiciousUrlPatterns = @(
            "ngrok.io", "tunnel.me", "serveo.net", "webhookrelay", "hookbin", "requestcatcher",
            "requestbin", "pipedream.net", "cloudflare.workers", "glitch.me", "free.beeceptor.com",
            ".000webhostapp.com", "herokuapp.com", ".repl.co", ".deta.dev", "pastebin", ".workers.dev",
            "example.com", "test.com", "onion.", "webhook.site"
        )
        
        # --- 1. SharePoint List Webhooks ---
        Write-Log -Message "Checking SharePoint List Webhooks..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Get all sites
            $sites = Get-MgSite -All -Property "Id,DisplayName,WebUrl" -ErrorAction SilentlyContinue
            
            if (-not $sites) {
                Write-Log -Message "  Could not retrieve SharePoint sites or no sites found." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                Write-Log -Message "  Found $($sites.Count) SharePoint sites. Checking for list webhooks..." -SpecificLogFile $GeneralReportFile
                
                $siteProcessed = 0
                $totalWebhooksFound = 0
                $suspiciousWebhooks = New-Object System.Collections.Generic.List[PSObject]
                
                # Progress tracking for many sites
                $ProgressInterval = [math]::Max(1, [math]::Floor($sites.Count / 10))
                
                foreach ($site in $sites) {
                    $siteProcessed++
                    
                    # Show progress periodically
                    if ($siteProcessed % $ProgressInterval -eq 0 -or $siteProcessed -eq $sites.Count) {
                        Write-Log -Message "  Processing site $siteProcessed of $($sites.Count): $($site.DisplayName)" -Type "INFO"
                    }
                    
                    try {
                        # Get all lists in the site
                        $lists = Get-MgSiteList -SiteId $site.Id -All -ErrorAction SilentlyContinue
                        
                        if ($lists) {
                            foreach ($list in $lists) {
                                # Check for webhooks on this list
                                $webhooksUri = "https://graph.microsoft.com/v1.0/sites/$($site.Id)/lists/$($list.Id)/subscriptions"
                                $webhooks = Invoke-MgGraphRequest -Method Get -Uri $webhooksUri -ErrorAction SilentlyContinue
                                
                                if ($webhooks -and $webhooks.value) {
                                    $listWebhooks = $webhooks.value
                                    $totalWebhooksFound += $listWebhooks.Count
                                    
                                    if ($listWebhooks.Count -gt 0) {
                                        Write-Log -Message "    Found $($listWebhooks.Count) webhooks on list '$($list.DisplayName)' in site '$($site.DisplayName)':" -SpecificLogFile $GeneralReportFile
                                        
                                        foreach ($webhook in $listWebhooks) {
                                            Write-Log -Message "      Webhook ID: $($webhook.id)" -SpecificLogFile $GeneralReportFile
                                            Write-Log -Message "        NotificationUrl: $($webhook.notificationUrl)" -SpecificLogFile $GeneralReportFile
                                            Write-Log -Message "        Expires: $($webhook.expirationDateTime)" -SpecificLogFile $GeneralReportFile
                                            Write-Log -Message "        Created: $($webhook.createdDateTime)" -SpecificLogFile $GeneralReportFile
                                            
                                            # Check for recently created webhooks
                                            $isRecent = $false
                                            if ($webhook.createdDateTime) {
                                                try {
                                                    $createdDate = [DateTime]$webhook.createdDateTime
                                                    if ((New-TimeSpan -Start $createdDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                                        $isRecent = $true
                                                    }
                                                } catch {}
                                            }
                                            
                                            # Check for suspicious notification URLs
                                            $isSuspicious = $false
                                            $matchedPattern = ""
                                            foreach ($pattern in $suspiciousUrlPatterns) {
                                                if ($webhook.notificationUrl -like "*$pattern*") {
                                                    $isSuspicious = $true
                                                    $matchedPattern = $pattern
                                                    break
                                                }
                                            }
                                            
                                            # Alert for suspicious or recent webhooks
                                            if ($isSuspicious) {
                                                $suspiciousWebhooks.Add([PSCustomObject]@{
                                                    SiteUrl = $site.WebUrl
                                                    SiteName = $site.DisplayName
                                                    ListName = $list.DisplayName
                                                    WebhookId = $webhook.id
                                                    NotificationUrl = $webhook.notificationUrl
                                                    Pattern = $matchedPattern
                                                    IsRecent = $isRecent
                                                })
                                                
                                                Write-Log -Message "        ALERT: Webhook uses suspicious notification URL matching pattern '$matchedPattern'." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                            
                                            if ($isRecent) {
                                                Write-Log -Message "        ALERT: Webhook was created recently ($($webhook.createdDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "    Error checking lists or webhooks in site '$($site.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                Write-Log -Message "  Completed SharePoint List Webhooks check. Found $totalWebhooksFound webhooks across all sites." -SpecificLogFile $GeneralReportFile
                
                if ($suspiciousWebhooks.Count -gt 0) {
                    Write-Log -Message "  ALERT: Found $($suspiciousWebhooks.Count) suspicious SharePoint list webhooks:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    foreach ($webhook in $suspiciousWebhooks) {
                        $recentTag = if ($webhook.IsRecent) { " [RECENT]" } else { "" }
                        Write-Log -Message "    - Site: $($webhook.SiteName), List: $($webhook.ListName), URL: $($webhook.NotificationUrl), Pattern: $($webhook.Pattern)$recentTag" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                }
            }
        } catch {
            Write-Log -Message "  Error checking SharePoint List Webhooks: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 2. Teams Incoming Webhooks ---
        Write-Log -Message "Checking Teams Incoming Webhooks..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Get all teams
            $teams = Get-MgTeam -All -ErrorAction SilentlyContinue
            
            if (-not $teams) {
                Write-Log -Message "  Could not retrieve Teams or no teams found." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                Write-Log -Message "  Found $($teams.Count) Teams. Checking for incoming webhooks..." -SpecificLogFile $GeneralReportFile
                
                $teamsProcessed = 0
                $totalConnectorsFound = 0
                $suspiciousConnectors = New-Object System.Collections.Generic.List[PSObject]
                
                # Progress tracking for many teams
                $ProgressInterval = [math]::Max(1, [math]::Floor($teams.Count / 10))
                
                foreach ($team in $teams) {
                    $teamsProcessed++
                    
                    # Show progress periodically
                    if ($teamsProcessed % $ProgressInterval -eq 0 -or $teamsProcessed -eq $teams.Count) {
                        Write-Log -Message "  Processing team $teamsProcessed of $($teams.Count): $($team.DisplayName)" -Type "INFO"
                    }
                    
                    try {
                        # Get all channels in the team
                        $channels = Get-MgTeamChannel -TeamId $team.Id -All -ErrorAction SilentlyContinue
                        
                        if ($channels) {
                            foreach ($channel in $channels) {
                                # Check for webhooks (connectors) on this channel
                                $connectorsUri = "https://graph.microsoft.com/v1.0/teams/$($team.Id)/channels/$($channel.Id)/tabs"
                                $tabs = Invoke-MgGraphRequest -Method Get -Uri $connectorsUri -ErrorAction SilentlyContinue
                                
                                if ($tabs -and $tabs.value) {
                                    # Look for connector tabs
                                    $connectorTabs = $tabs.value | Where-Object { 
                                        $_.teamsApp.id -eq "405a659c-238a-450d-aaff-gho7c00e0cdc" -or  # Exact ID may vary, but we'll cast a wide net
                                        $_.displayName -like "*Connector*" -or 
                                        $_.displayName -like "*Webhook*" 
                                    }
                                    
                                    if ($connectorTabs) {
                                        $totalConnectorsFound += $connectorTabs.Count
                                        
                                        Write-Log -Message "    Found $($connectorTabs.Count) potential webhook connector tabs in channel '$($channel.DisplayName)' in team '$($team.DisplayName)':" -SpecificLogFile $GeneralReportFile
                                        
                                        foreach ($tab in $connectorTabs) {
                                            Write-Log -Message "      Tab: $($tab.displayName) (ID: $($tab.id))" -SpecificLogFile $GeneralReportFile
                                            
                                            if ($tab.configuration.entityId -or $tab.configuration.contentUrl) {
                                                Write-Log -Message "        Configuration: $($tab.configuration.entityId ?? $tab.configuration.contentUrl)" -SpecificLogFile $GeneralReportFile
                                            }
                                            
                                            # Check for suspicious configuration
                                            $isSuspicious = $false
                                            $matchedPattern = ""
                                            $configString = $tab.configuration.entityId ?? $tab.configuration.contentUrl ?? ""
                                            
                                            foreach ($pattern in $suspiciousUrlPatterns) {
                                                if ($configString -like "*$pattern*") {
                                                    $isSuspicious = $true
                                                    $matchedPattern = $pattern
                                                    break
                                                }
                                            }
                                            
                                            # Alert for suspicious webhooks
                                            if ($isSuspicious) {
                                                $suspiciousConnectors.Add([PSCustomObject]@{
                                                    TeamName = $team.DisplayName
                                                    ChannelName = $channel.DisplayName
                                                    TabName = $tab.displayName
                                                    TabId = $tab.id
                                                    Configuration = $configString
                                                    Pattern = $matchedPattern
                                                })
                                                
                                                Write-Log -Message "        ALERT: Tab potentially contains suspicious webhook configuration matching pattern '$matchedPattern'." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "    Error checking channels or connectors in team '$($team.DisplayName)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                Write-Log -Message "  Completed Teams Incoming Webhooks check. Found $totalConnectorsFound potential webhook connectors across all teams." -SpecificLogFile $GeneralReportFile
                
                if ($suspiciousConnectors.Count -gt 0) {
                    Write-Log -Message "  ALERT: Found $($suspiciousConnectors.Count) suspicious Teams webhook connectors:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    foreach ($connector in $suspiciousConnectors) {
                        Write-Log -Message "    - Team: $($connector.TeamName), Channel: $($connector.ChannelName), Tab: $($connector.TabName), Configuration: $($connector.Configuration), Pattern: $($connector.Pattern)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                }
            }
        } catch {
            Write-Log -Message "  Error checking Teams Incoming Webhooks: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 3. Check Power Automate HTTP Webhook Triggers (supplement to earlier Power Platform checks) ---
        Write-Log -Message "Checking for additional Power Automate HTTP Webhook Triggers..." -SpecificLogFile $GeneralReportFile
        
        if (-not $PpAdminConnected) {
            Write-Log -Message "  Power Platform Admin not connected. Cannot check Power Automate HTTP Triggers." -Type "WARN" -SpecificLogFile $GeneralReportFile
        } else {
            try {
                # This is supplemental to the Power Platform checks (section 31)
                # It specifically focuses on HTTP triggers that could be used for persistence
                
                $environments = Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue
                
                if (-not $environments) {
                    Write-Log -Message "  Could not retrieve Power Platform environments." -Type "WARN" -SpecificLogFile $GeneralReportFile
                } else {
                    $httpTriggerFlows = New-Object System.Collections.Generic.List[PSObject]
                    
                    foreach ($env in $environments) {
                        Write-Log -Message "  Checking for HTTP triggered flows in environment: $($env.DisplayName)..." -SpecificLogFile $GeneralReportFile
                        
                        $flows = Get-AdminFlow -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
                        
                        if ($flows) {
                            $envHttpFlows = $flows | Where-Object { 
                                $_.Internal.properties.definitionSummary.triggers | Where-Object { 
                                    $_.Type -eq "Request" -or 
                                    $_.Kind -like "*HttpWebhook*" -or 
                                    $_.Kind -like "*Webhook*" 
                                } 
                            }
                            
                            if ($envHttpFlows) {
                                Write-Log -Message "    Found $($envHttpFlows.Count) HTTP triggered flows in environment $($env.DisplayName):" -SpecificLogFile $GeneralReportFile
                                
                                foreach ($flow in $envHttpFlows) {
                                    Write-Log -Message "      Flow: $($flow.DisplayName) (ID: $($flow.FlowName))" -SpecificLogFile $GeneralReportFile
                                    
                                    # Get trigger details
                                    $trigger = $flow.Internal.properties.definitionSummary.triggers | Where-Object { 
                                        $_.Type -eq "Request" -or 
                                        $_.Kind -like "*HttpWebhook*" -or 
                                        $_.Kind -like "*Webhook*" 
                                    } | Select-Object -First 1
                                    
                                    Write-Log -Message "        Trigger Type: $($trigger.Type), Kind: $($trigger.Kind)" -SpecificLogFile $GeneralReportFile
                                    
                                    # Check creation and modification dates
                                    $isRecent = $false
                                    if ($flow.Internal.properties.createdTime) {
                                        try {
                                            $createdDate = [DateTime]$flow.Internal.properties.createdTime
                                            if ((New-TimeSpan -Start $createdDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                                $isRecent = $true
                                                Write-Log -Message "        ALERT: Flow was created recently ($($flow.Internal.properties.createdTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                        } catch {}
                                    }
                                    
                                    # Store for summary
                                    $httpTriggerFlows.Add([PSCustomObject]@{
                                        EnvironmentName = $env.DisplayName
                                        FlowName = $flow.DisplayName
                                        FlowId = $flow.FlowName
                                        TriggerType = $trigger.Type
                                        TriggerKind = $trigger.Kind
                                        IsRecent = $isRecent
                                    })
                                }
                            } else {
                                Write-Log -Message "    No HTTP triggered flows found in environment $($env.DisplayName)." -SpecificLogFile $GeneralReportFile
                            }
                        }
                    }
                    
                    if ($httpTriggerFlows.Count -gt 0) {
                        $recentFlows = $httpTriggerFlows | Where-Object { $_.IsRecent }
                        
                        if ($recentFlows.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($recentFlows.Count) recently created HTTP triggered flows:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($flow in $recentFlows) {
                                Write-Log -Message "    - Environment: $($flow.EnvironmentName), Flow: $($flow.FlowName), Trigger: $($flow.TriggerType)/$($flow.TriggerKind)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Special note about webhook triggers
                        Write-Log -Message "  NOTE: HTTP triggered flows can be used legitimately for integration scenarios. Review all flows carefully to determine if they are legitimate." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    }
                }
            } catch {
                Write-Log -Message "  Error checking Power Automate HTTP Triggers: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        # --- 4. Azure Logic Apps with HTTP Triggers (if applicable) ---
        Write-Log -Message "Checking Azure Logic Apps with HTTP Triggers (if Az module available)..." -SpecificLogFile $GeneralReportFile
        
        # Check if Az module is available
        if (-not (Get-Module -ListAvailable -Name Az.LogicApp)) {
            Write-Log -Message "  Az.LogicApp module not available. Skipping Azure Logic Apps check." -Type "INFO" -SpecificLogFile $GeneralReportFile
        } else {
            try {
                # Check if connected to Azure
                $azContext = Get-AzContext -ErrorAction SilentlyContinue
                
                if (-not $azContext) {
                    Write-Log -Message "  Not connected to Azure. Please use Connect-AzAccount before running this script to check Logic Apps." -Type "WARN" -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "  Connected to Azure subscription: $($azContext.Subscription.Name). Checking Logic Apps..." -SpecificLogFile $GeneralReportFile
                    
                    # Get all Logic Apps
                    $logicApps = Get-AzLogicApp -ErrorAction SilentlyContinue
                    
                    if (-not $logicApps) {
                        Write-Log -Message "  No Logic Apps found in the current subscription." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    } else {
                        Write-Log -Message "  Found $($logicApps.Count) Logic Apps. Checking for HTTP triggers..." -SpecificLogFile $GeneralReportFile
                        
                        $httpTriggerApps = New-Object System.Collections.Generic.List[PSObject]
                        
                        foreach ($app in $logicApps) {
                            try {
                                # Get workflow definition
                                $definition = Get-AzLogicAppWorkflowDefinition -ResourceGroupName $app.ResourceGroupName -Name $app.Name -ErrorAction SilentlyContinue
                                
                                if ($definition -and $definition.Triggers) {
                                    # Check for HTTP triggers
                                    $httpTriggers = $definition.Triggers.PSObject.Properties | Where-Object { 
                                        $_.Value.Type -eq "Request" -or 
                                        $_.Value.Type -like "*Http*" -or 
                                        $_.Value.Type -like "*Webhook*" 
                                    }
                                    
                                    if ($httpTriggers) {
                                        Write-Log -Message "    Logic App with HTTP trigger: $($app.Name) (Resource Group: $($app.ResourceGroupName))" -SpecificLogFile $GeneralReportFile
                                        
                                        foreach ($trigger in $httpTriggers) {
                                            Write-Log -Message "      Trigger: $($trigger.Name), Type: $($trigger.Value.Type)" -SpecificLogFile $GeneralReportFile
                                            
                                            if ($trigger.Value.Inputs -and $trigger.Value.Inputs.Schema) {
                                                Write-Log -Message "        Has defined schema for incoming requests" -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                        
                                        # Check if recently created or modified
                                        if ((New-TimeSpan -Start $app.CreatedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                            Write-Log -Message "      ALERT: Logic App was created recently ($($app.CreatedTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                        if ((New-TimeSpan -Start $app.ChangedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                            Write-Log -Message "      ALERT: Logic App was modified recently ($($app.ChangedTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                        
                                        # Store for summary
                                        $httpTriggerApps.Add([PSCustomObject]@{
                                            Name = $app.Name
                                            ResourceGroup = $app.ResourceGroupName
                                            CreatedTime = $app.CreatedTime
                                            ChangedTime = $app.ChangedTime
                                            IsRecentlyCreated = (New-TimeSpan -Start $app.CreatedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays
                                            IsRecentlyModified = (New-TimeSpan -Start $app.ChangedTime -End (Get-Date)).TotalDays -lt $script:LookbackDays
                                        })
                                    }
                                }
                            } catch {
                                Write-Log -Message "    Error checking Logic App $($app.Name): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        if ($httpTriggerApps.Count -gt 0) {
                            $recentApps = $httpTriggerApps | Where-Object { $_.IsRecentlyCreated -or $_.IsRecentlyModified }
                            
                            if ($recentApps.Count -gt 0) {
                                Write-Log -Message "  ALERT: Found $($recentApps.Count) recently created or modified Logic Apps with HTTP triggers:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                foreach ($app in $recentApps) {
                                    $createdTag = if ($app.IsRecentlyCreated) { " [RECENTLY CREATED]" } else { "" }
                                    $modifiedTag = if ($app.IsRecentlyModified) { " [RECENTLY MODIFIED]" } else { "" }
                                    Write-Log -Message "    - Logic App: $($app.Name), Resource Group: $($app.ResourceGroup)$createdTag$modifiedTag" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Log -Message "  Error checking Azure Logic Apps: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        # --- 5. Custom SharePoint Framework (SPFx) Extensions with Server-Side Components ---
        Write-Log -Message "Checking for Custom SharePoint Framework Extensions (SPFx) with potential back doors..." -SpecificLogFile $GeneralReportFile
        
        try {
            if (-not $GraphConnected) {
                Write-Log -Message "  Graph API not connected. Cannot check SPFx Extensions." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                # Get tenant app catalog
                $tenantApps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites?filter=siteCollection/root ne null and site/template eq 'APPCATALOG#0'" -ErrorAction SilentlyContinue
                
                if (-not $tenantApps -or -not $tenantApps.value -or $tenantApps.value.Count -eq 0) {
                    Write-Log -Message "  Could not retrieve tenant app catalog or no app catalog found." -Type "WARN" -SpecificLogFile $GeneralReportFile
                } else {
                    # There should typically be only one tenant app catalog
                    $appCatalog = $tenantApps.value[0]
                    Write-Log -Message "  Found tenant app catalog: $($appCatalog.displayName) ($($appCatalog.webUrl))" -SpecificLogFile $GeneralReportFile
                    
                    # Get apps in the app catalog
                    $appCatalogId = $appCatalog.id
                    $apps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$appCatalogId/lists" -ErrorAction SilentlyContinue
                    
                    if (-not $apps -or -not $apps.value) {
                        Write-Log -Message "  Could not retrieve apps from tenant app catalog." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    } else {
                        # Find the Apps list (contains SPFx solutions)
                        $appsList = $apps.value | Where-Object { $_.displayName -eq "Apps" -or $_.displayName -eq "TenantAppCatalog" }
                        
                        if (-not $appsList) {
                            Write-Log -Message "  Could not find Apps list in tenant app catalog." -Type "WARN" -SpecificLogFile $GeneralReportFile
                        } else {
                            # Get apps from the Apps list
                            $appsListId = $appsList.id
                            $spfxApps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$appCatalogId/lists/$appsListId/items?expand=fields" -ErrorAction SilentlyContinue
                            
                            if (-not $spfxApps -or -not $spfxApps.value) {
                                Write-Log -Message "  Could not retrieve apps from Apps list or no apps found." -Type "INFO" -SpecificLogFile $GeneralReportFile
                            } else {
                                Write-Log -Message "  Found $($spfxApps.value.Count) apps in tenant app catalog. Checking for suspicious SPFx solutions..." -SpecificLogFile $GeneralReportFile
                                
                                $recentSpfxApps = New-Object System.Collections.Generic.List[PSObject]
                                
                                foreach ($app in $spfxApps.value) {
                                    $appFields = $app.fields
                                    $appTitle = $appFields.Title
                                    $appModified = $appFields.Modified
                                    $appCreated = $appFields.Created
                                    
                                    # Some basic app metadata
                                    Write-Log -Message "    App: $appTitle" -SpecificLogFile $GeneralReportFile
                                    Write-Log -Message "      Created: $appCreated, Modified: $appModified" -SpecificLogFile $GeneralReportFile
                                    
                                    # Check for recent creation or modification
                                    $isRecentlyCreated = $false
                                    $isRecentlyModified = $false
                                    
                                    if ($appCreated) {
                                        try {
                                            $createdDate = [DateTime]$appCreated
                                            if ((New-TimeSpan -Start $createdDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                                $isRecentlyCreated = $true
                                            }
                                        } catch {}
                                    }
                                    
                                    if ($appModified) {
                                        try {
                                            $modifiedDate = [DateTime]$appModified
                                            if ((New-TimeSpan -Start $modifiedDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                                $isRecentlyModified = $true
                                            }
                                        } catch {}
                                    }
                                    
                                    if ($isRecentlyCreated) {
                                        Write-Log -Message "      ALERT: App was created recently ($appCreated)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                    
                                    if ($isRecentlyModified) {
                                        Write-Log -Message "      ALERT: App was modified recently ($appModified)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                    
                                    if ($isRecentlyCreated -or $isRecentlyModified) {
                                        $recentSpfxApps.Add([PSCustomObject]@{
                                            Title = $appTitle
                                            Created = $appCreated
                                            Modified = $appModified
                                            IsRecentlyCreated = $isRecentlyCreated
                                            IsRecentlyModified = $isRecentlyModified
                                        })
                                    }
                                }
                                
                                if ($recentSpfxApps.Count -gt 0) {
                                    Write-Log -Message "  ALERT: Found $($recentSpfxApps.Count) recently created or modified SPFx apps:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    foreach ($app in $recentSpfxApps) {
                                        $createdTag = if ($app.IsRecentlyCreated) { " [RECENTLY CREATED]" } else { "" }
                                        $modifiedTag = if ($app.IsRecentlyModified) { " [RECENTLY MODIFIED]" } else { "" }
                                        Write-Log -Message "    - App: $($app.Title)$createdTag$modifiedTag" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                    Write-Log -Message "  NOTE: These SPFx solutions should be reviewed for potential security risks. Download and examine the .sppkg files for suspicious code or remote endpoints." -Type "WARN" -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log -Message "  Error checking SharePoint Framework Extensions: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Custom Integration Endpoints check." -SpecificLogFile $GeneralReportFile
        Write-Log -Message "NOTE: This check identified visible integration endpoints. Additional endpoints may exist that are not directly visible in the admin interfaces. For a complete analysis, review each service's specific administration tools and audit logs." -Type "INFO" -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Custom Integration Endpoints: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 40. Data Loss Prevention Policy Changes (Tenant-wide) ---
    Write-Log -Message "Checking Data Loss Prevention Policy Changes..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Flag for whether we have any DLP info to analyze
        $dlpInfoFound = $false
        
        # --- 1. Check Security & Compliance PowerShell module availability
        Write-Log -Message "Checking DLP policies from Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
        
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Log -Message "ExchangeOnlineManagement module not found. This is required for DLP policy checks from Security & Compliance Center." -Type "WARN" -SpecificLogFile $GeneralReportFile
        } else {
            try {
                # Check if connected to Security & Compliance Center
                $sccConnected = $false
                $sccSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*.compliance.protection.outlook.com'}
                
                if ($sccSession -and $sccSession.State -eq 'Opened') {
                    $sccConnected = $true
                    Write-Log -Message "Already connected to Security & Compliance Center." -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "Connecting to Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
                    try {
                        Connect-IPPSSession -ErrorAction Stop
                        $sccConnected = $true
                        Write-Log -Message "Successfully connected to Security & Compliance Center." -SpecificLogFile $GeneralReportFile
                    } catch {
                        Write-Log -Message "Could not connect to Security & Compliance Center: $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                if ($sccConnected) {
                    # Get DLP policies
                    try {
                        $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
                        
                        if ($dlpPolicies -and $dlpPolicies.Count -gt 0) {
                            $dlpInfoFound = $true
                            Write-Log -Message "Found $($dlpPolicies.Count) DLP policies in Security & Compliance Center." -SpecificLogFile $GeneralReportFile
                            
                            # Check each policy
                            foreach ($policy in $dlpPolicies) {
                                Write-Log -Message "DLP Policy: $($policy.Name)" -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "  Mode: $($policy.Mode)" -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "  Created: $($policy.WhenCreated), Last Modified: $($policy.WhenChanged)" -SpecificLogFile $GeneralReportFile
                                
                                # Check for recently created or modified policies
                                $isRecentlyCreated = $false
                                $isRecentlyModified = $false
                                
                                if ((New-TimeSpan -Start $policy.WhenCreated -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    $isRecentlyCreated = $true
                                    Write-Log -Message "  ALERT: Policy was created recently ($($policy.WhenCreated))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                                
                                if ((New-TimeSpan -Start $policy.WhenChanged -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    $isRecentlyModified = $true
                                    Write-Log -Message "  ALERT: Policy was modified recently ($($policy.WhenChanged))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                                
                                # Check if policy is disabled or in TestMode
                                if ($policy.Mode -eq "Disable") {
                                    Write-Log -Message "  ALERT: Policy is currently DISABLED." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                } elseif ($policy.Mode -eq "TestWithoutNotifications" -or $policy.Mode -eq "TestWithNotifications") {
                                    Write-Log -Message "  WARN: Policy is in test mode ($($policy.Mode)). Not enforcing any actions." -Type "WARN" -SpecificLogFile $GeneralReportFile
                                }
                                
                                # Check location status
                                if ($policy.ExchangeLocation -eq "All") {
                                    Write-Log -Message "  Exchange: All mailboxes" -SpecificLogFile $GeneralReportFile
                                } else {
                                    Write-Log -Message "  Exchange: Limited locations or disabled" -SpecificLogFile $GeneralReportFile
                                }
                                
                                if ($policy.SharePointLocation -eq "All") {
                                    Write-Log -Message "  SharePoint: All sites" -SpecificLogFile $GeneralReportFile
                                } else {
                                    Write-Log -Message "  SharePoint: Limited locations or disabled" -SpecificLogFile $GeneralReportFile
                                }
                                
                                if ($policy.OneDriveLocation -eq "All") {
                                    Write-Log -Message "  OneDrive: All locations" -SpecificLogFile $GeneralReportFile
                                } else {
                                    Write-Log -Message "  OneDrive: Limited locations or disabled" -SpecificLogFile $GeneralReportFile
                                }
                                
                                if ($policy.TeamsLocation -eq "All") {
                                    Write-Log -Message "  Teams: All teams" -SpecificLogFile $GeneralReportFile
                                } else {
                                    Write-Log -Message "  Teams: Limited locations or disabled" -SpecificLogFile $GeneralReportFile
                                }
                                
                                # Get rules for this policy to see actions
                                try {
                                    $rules = Get-DlpComplianceRule -Policy $policy.Name -ErrorAction Stop
                                    
                                    if ($rules -and $rules.Count -gt 0) {
                                        Write-Log -Message "  Policy has $($rules.Count) rule(s):" -SpecificLogFile $GeneralReportFile
                                        
                                        foreach ($rule in $rules) {
                                            Write-Log -Message "    Rule: $($rule.Name)" -SpecificLogFile $GeneralReportFile
                                            
                                            # Check if rule was modified recently
                                            if ((New-TimeSpan -Start $rule.WhenChanged -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                                Write-Log -Message "    ALERT: Rule was modified recently ($($rule.WhenChanged))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                            
                                            # Check blocked actions
                                            if ($rule.BlockAccess -eq $true) {
                                                Write-Log -Message "    Actions: Blocks access" -SpecificLogFile $GeneralReportFile
                                            } else {
                                                Write-Log -Message "    Actions: Does not block access (notification or audit only)" -SpecificLogFile $GeneralReportFile
                                            }
                                            
                                            # Check sensitive info types
                                            if ($rule.ContentContainsSensitiveInformation) {
                                                $sensitiveTypes = $rule.ContentContainsSensitiveInformation | Select-Object -ExpandProperty Name | Sort-Object -Unique
                                                Write-Log -Message "    Sensitive Info Types: $($sensitiveTypes -join ', ')" -SpecificLogFile $GeneralReportFile
                                            } else {
                                                Write-Log -Message "    No specific sensitive info types defined." -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    } else {
                                        Write-Log -Message "  WARN: Policy has no associated rules. It will not have any effect." -Type "WARN" -SpecificLogFile $GeneralReportFile
                                    }
                                } catch {
                                    Write-Log -Message "  Error getting rules for policy '$($policy.Name)': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                                }
                            }
                        } else {
                            Write-Log -Message "No DLP policies found in Security & Compliance Center." -Type "WARN" -SpecificLogFile $GeneralReportFile
                        }
                    } catch {
                        Write-Log -Message "Error retrieving DLP policies from Security & Compliance Center: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Disconnect from Security & Compliance Center if we connected in this function
                    if (-not $sccSession) {
                        Write-Log -Message "Disconnecting from Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
                        Get-PSSession | Where-Object {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*.compliance.protection.outlook.com'} | Remove-PSSession -Confirm:$false
                    }
                }
            } catch {
                Write-Log -Message "Error in Security & Compliance DLP check: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        # --- 2. Check Graph API for DLP policy changes in audit logs
        if ($GraphConnected) {
            Write-Log -Message "Checking audit logs for DLP policy changes..." -SpecificLogFile $GeneralReportFile
            
            # Ensure we have the required permission
            $context = Get-MgContext
            $hasRequiredPermission = $false
            if ($context.Scopes) {
                if ($context.Scopes -contains "AuditLog.Read.All" -or 
                    $context.Scopes -contains "SecurityEvents.Read.All") {
                    $hasRequiredPermission = $true
                }
            }
            
            if (-not $hasRequiredPermission) {
                Write-Log -Message "Connected to Graph API but missing required permissions (AuditLog.Read.All or SecurityEvents.Read.All). Cannot check audit logs for DLP changes." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                try {
                    # Define the time period to look back
                    $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    
                    # Define operations related to DLP that we want to audit
                    $dlpOperations = @(
                        "DlpRuleMatch",
                        "Create DLP policy",
                        "Update DLP policy",
                        "Remove DLP policy",
                        "Create DLP rule",
                        "Update DLP rule",
                        "Remove DLP rule",
                        "DLP status changed" 
                    )
                    
                    # Create filter for the specific operations we're interested in
                    $operationFilter = $dlpOperations | ForEach-Object { "activityDisplayName eq '$_'" }
                    $filter = "activityDateTime ge $startTime and ($($operationFilter -join ' or '))"
                    
                    # Query audit logs with the filter
                    Write-Log -Message "Querying audit logs for DLP policy changes since $startTime..." -SpecificLogFile $GeneralReportFile
                    $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
                    
                    if ($auditLogs -and $auditLogs.Count -gt 0) {
                        $dlpInfoFound = $true
                        Write-Log -Message "Found $($auditLogs.Count) DLP-related events in the audit logs. Analyzing..." -SpecificLogFile $GeneralReportFile
                        
                        # Group audit events by policy for clarity
                        $policyEvents = @{}
                        
                        foreach ($log in $auditLogs) {
                            $timestamp = $log.ActivityDateTime
                            $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.User.DisplayName ?? $log.InitiatedBy.App.DisplayName ?? "Unknown"
                            $activity = $log.ActivityDisplayName
                            $result = $log.Result
                            
                            # Extract target name (policy or rule name)
                            $targetName = $null
                            if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                                $targetName = $log.TargetResources[0].DisplayName
                            }
                            
                            if (-not $targetName -and $activity -eq "DlpRuleMatch") {
                                # For DlpRuleMatch, the name might be in properties
                                $modifiedProps = $log.TargetResources[0].ModifiedProperties
                                foreach ($prop in $modifiedProps) {
                                    if ($prop.DisplayName -eq "PolicyName" -or $prop.DisplayName -eq "PolicyDetails") {
                                        $targetName = $prop.NewValue -replace '"', ''
                                        break
                                    }
                                }
                            }
                            
                            if (-not $targetName) {
                                $targetName = "Unknown Policy/Rule"
                            }
                            
                            # Add to policy events dictionary
                            if (-not $policyEvents.ContainsKey($targetName)) {
                                $policyEvents[$targetName] = New-Object System.Collections.Generic.List[PSObject]
                            }
                            
                            $policyEvents[$targetName].Add([PSCustomObject]@{
                                Timestamp = $timestamp
                                Actor = $actor
                                Activity = $activity
                                Result = $result
                                Details = $log
                            })
                        }
                        
                        # List events by policy
                        foreach ($policyName in $policyEvents.Keys) {
                            $events = $policyEvents[$policyName]
                            Write-Log -Message "Policy/Rule: $policyName" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "  Found $($events.Count) events:" -SpecificLogFile $GeneralReportFile
                            
                            # Sort events by timestamp
                            $sortedEvents = $events | Sort-Object -Property Timestamp
                            
                            foreach ($event in $sortedEvents) {
                                Write-Log -Message "  - $($event.Timestamp): $($event.Activity) by $($event.Actor) - Result: $($event.Result)" -SpecificLogFile $GeneralReportFile
                                
                                # Alert on policy creation, deletion, and changes
                                if ($event.Activity -eq "Create DLP policy" -or $event.Activity -eq "Create DLP rule") {
                                    Write-Log -Message "    ALERT: New DLP policy/rule created." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                } elseif ($event.Activity -eq "Remove DLP policy" -or $event.Activity -eq "Remove DLP rule") {
                                    Write-Log -Message "    ALERT: DLP policy/rule was deleted." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                } elseif ($event.Activity -eq "DLP status changed" -or $event.Activity -eq "Update DLP policy" -or $event.Activity -eq "Update DLP rule") {
                                    # Check for specific changes in the modified properties
                                    $modifiedProps = $event.Details.TargetResources[0].ModifiedProperties
                                    $dlpDisabled = $false
                                    $policyMode = $null
                                    
                                    foreach ($prop in $modifiedProps) {
                                        $propName = $prop.DisplayName
                                        $oldValue = $prop.OldValue
                                        $newValue = $prop.NewValue
                                        
                                        if ($propName -eq "Enabled" -and $oldValue -eq "True" -and $newValue -eq "False") {
                                            $dlpDisabled = $true
                                        } elseif ($propName -eq "Mode" -or $propName -eq "PolicyMode") {
                                            $policyMode = $newValue
                                        }
                                    }
                                    
                                    if ($dlpDisabled) {
                                        Write-Log -Message "    CRITICAL ALERT: DLP policy/rule was DISABLED." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    } elseif ($policyMode -and $policyMode -match "Test|Disable") {
                                        Write-Log -Message "    ALERT: DLP policy mode changed to '$policyMode'. Policy may not be fully enforcing actions." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    } else {
                                        Write-Log -Message "    ALERT: DLP policy/rule was updated. Review changes." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                }
                            }
                        }
                        
                        # Look for potential tampering patterns
                        Write-Log -Message "Analyzing for potential DLP tampering patterns..." -SpecificLogFile $GeneralReportFile
                        
                        # Group by actor to see if specific users are making many DLP changes
                        $actorCounts = @{}
                        foreach ($log in $auditLogs) {
                            $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.User.DisplayName ?? $log.InitiatedBy.App.DisplayName ?? "Unknown"
                            if (-not $actorCounts.ContainsKey($actor)) {
                                $actorCounts[$actor] = 0
                            }
                            $actorCounts[$actor]++
                        }
                        
                        # Flag actors with many changes
                        $suspiciousActors = $actorCounts.GetEnumerator() | Where-Object { $_.Value -gt 3 } | Sort-Object -Property Value -Descending
                        if ($suspiciousActors.Count -gt 0) {
                            Write-Log -Message "  ALERT: The following users/apps have made multiple DLP policy changes:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($actor in $suspiciousActors) {
                                Write-Log -Message "    - $($actor.Key): $($actor.Value) changes" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Look for disabling then re-enabling (tampering pattern)
                        $disableThenEnablePattern = $false
                        foreach ($policyName in $policyEvents.Keys) {
                            $events = $policyEvents[$policyName] | Sort-Object -Property Timestamp
                            
                            # Detect disable followed by enable within short time
                            for ($i = 0; $i -lt $events.Count - 1; $i++) {
                                $currentEvent = $events[$i]
                                $nextEvent = $events[$i + 1]
                                
                                # Check if current event disables and next event enables
                                $currentDisables = $false
                                $nextEnables = $false
                                
                                if ($currentEvent.Activity -match "Update" -or $currentEvent.Activity -match "status changed") {
                                    $modifiedProps = $currentEvent.Details.TargetResources[0].ModifiedProperties
                                    foreach ($prop in $modifiedProps) {
                                        if (($prop.DisplayName -eq "Enabled" -and $prop.OldValue -eq "True" -and $prop.NewValue -eq "False") -or
                                            ($prop.DisplayName -eq "Mode" -and $prop.NewValue -match "Disable")) {
                                            $currentDisables = $true
                                            break
                                        }
                                    }
                                }
                                
                                if ($nextEvent.Activity -match "Update" -or $nextEvent.Activity -match "status changed") {
                                    $modifiedProps = $nextEvent.Details.TargetResources[0].ModifiedProperties
                                    foreach ($prop in $modifiedProps) {
                                        if (($prop.DisplayName -eq "Enabled" -and $prop.OldValue -eq "False" -and $prop.NewValue -eq "True") -or
                                            ($prop.DisplayName -eq "Mode" -and $prop.OldValue -match "Disable" -and $prop.NewValue -match "Enable")) {
                                            $nextEnables = $true
                                            break
                                        }
                                    }
                                }
                                
                                # If pattern detected, flag it
                                if ($currentDisables -and $nextEnables) {
                                    $timeBetween = New-TimeSpan -Start $currentEvent.Timestamp -End $nextEvent.Timestamp
                                    
                                    if ($timeBetween.TotalHours -lt 24) {
                                        $disableThenEnablePattern = $true
                                        Write-Log -Message "  CRITICAL ALERT: Detected potential tampering pattern for policy '$policyName': Disabled at $($currentEvent.Timestamp) by $($currentEvent.Actor) and then re-enabled at $($nextEvent.Timestamp) by $($nextEvent.Actor). Time between: $($timeBetween.TotalMinutes) minutes." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                }
                            }
                        }
                        
                        if ($disableThenEnablePattern) {
                            Write-Log -Message "  This pattern of temporarily disabling DLP policies could indicate an attacker trying to exfiltrate data while evading DLP controls." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "No DLP policy change events found in the audit logs for the specified period." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking audit logs for DLP changes: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
        } else {
            Write-Log -Message "Graph API not connected. Cannot check audit logs for DLP changes." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 3. Check Power Platform DLP policies (if connected to Power Platform)
        if ($PpAdminConnected) {
            Write-Log -Message "Checking Power Platform DLP policies (supplement to earlier Power Platform checks)..." -SpecificLogFile $GeneralReportFile
            
            try {
                $ppDlpPolicies = Get-AdminDlpPolicy -ErrorAction SilentlyContinue
                
                if ($ppDlpPolicies -and $ppDlpPolicies.Count -gt 0) {
                    $dlpInfoFound = $true
                    Write-Log -Message "Found $($ppDlpPolicies.Count) Power Platform DLP policies." -SpecificLogFile $GeneralReportFile
                    
                    # We already did a detailed analysis in section 33, so we'll focus on recent changes here
                    foreach ($policy in $ppDlpPolicies) {
                        Write-Log -Message "Power Platform DLP Policy: $($policy.DisplayName) (ID: $($policy.PolicyName))" -SpecificLogFile $GeneralReportFile
                        
                        # Check for recent creation or modification
                        if ($policy.createdTimestamp) {
                            $createdDate = $policy.createdTimestamp
                            Write-Log -Message "  Created: $createdDate" -SpecificLogFile $GeneralReportFile
                            
                            if ((New-TimeSpan -Start $createdDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "  ALERT: Policy was created recently ($createdDate)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        if ($policy.lastModifiedTimestamp) {
                            $modifiedDate = $policy.lastModifiedTimestamp
                            Write-Log -Message "  Last Modified: $modifiedDate" -SpecificLogFile $GeneralReportFile
                            
                            if ((New-TimeSpan -Start $modifiedDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "  ALERT: Policy was modified recently ($modifiedDate)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    }
                } else {
                    Write-Log -Message "No Power Platform DLP policies found." -Type "INFO" -SpecificLogFile $GeneralReportFile
                }
            } catch {
                Write-Log -Message "Error checking Power Platform DLP policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        # Check if we found any DLP info
        if (-not $dlpInfoFound) {
            Write-Log -Message "No DLP policy information found from any source. This could indicate a lack of DLP policies or limitations in access to DLP information." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "RECOMMENDATION: Deploy appropriate DLP policies to protect sensitive data." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Data Loss Prevention Policy Changes check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Data Loss Prevention Policy Changes: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 41. Audit Log Settings & Export ---
    Write-Log -Message "Checking Audit Log Settings & Export..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Track if we were able to get any audit settings
        $auditSettingsFound = $false
        
        # --- 1. Check Exchange Online Management module for unified audit log settings
        Write-Log -Message "Checking Unified Audit Log settings..." -SpecificLogFile $GeneralReportFile
        
        if ($ExoConnected) {
            try {
                # Check if unified audit logging is enabled
                $adminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
                
                if ($adminAuditLogConfig) {
                    $auditSettingsFound = $true
                    Write-Log -Message "Admin Audit Log Configuration:" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  UnifiedAuditLogIngestionEnabled: $($adminAuditLogConfig.UnifiedAuditLogIngestionEnabled)" -SpecificLogFile $GeneralReportFile
                    
                    if ($adminAuditLogConfig.UnifiedAuditLogIngestionEnabled -ne $true) {
                        Write-Log -Message "  CRITICAL ALERT: Unified Audit Log ingestion is DISABLED. This prevents the recording of most audit events." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } else {
                    Write-Log -Message "Could not retrieve Admin Audit Log Configuration." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
                
                # Check audit log search settings
                try {
                    $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
                    
                    if ($orgConfig) {
                        $auditSettingsFound = $true
                        Write-Log -Message "Organization Audit Settings:" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  AuditDisabled: $($orgConfig.AuditDisabled)" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  DefaultAuditSet: $($orgConfig.DefaultAuditSet -join ', ')" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  AuditLogAgeLimit: $($orgConfig.AuditLogAgeLimit)" -SpecificLogFile $GeneralReportFile
                        
                        if ($orgConfig.AuditDisabled -eq $true) {
                            Write-Log -Message "  CRITICAL ALERT: Organization-wide auditing is DISABLED." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        if ($orgConfig.AuditLogAgeLimit -lt 90) {
                            Write-Log -Message "  ALERT: Audit log retention period is less than 90 days ($($orgConfig.AuditLogAgeLimit)). This may be insufficient for security investigations." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "Could not retrieve Organization Configuration." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking Organization Audit Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # Check mailbox audit configuration 
                try {
                    $mailboxAuditConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue | Select-Object -Property AuditDisabled, *Audit*
                    
                    if ($mailboxAuditConfig) {
                        Write-Log -Message "Mailbox Audit Configuration:" -SpecificLogFile $GeneralReportFile
                        
                        # Check if mailbox auditing is enabled by default
                        if ($mailboxAuditConfig.AuditDisabled -eq $true) {
                            Write-Log -Message "  ALERT: Default mailbox auditing is DISABLED." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        } else {
                            Write-Log -Message "  Default mailbox auditing is enabled." -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Get default mailbox audit flags
                        $adminActions = $mailboxAuditConfig.DefaultAuditAdminActions -join ', '
                        $delegateActions = $mailboxAuditConfig.DefaultAuditDelegateActions -join ', '
                        $ownerActions = $mailboxAuditConfig.DefaultAuditOwnerActions -join ', '
                        
                        Write-Log -Message "  Default Admin Actions: $adminActions" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  Default Delegate Actions: $delegateActions" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  Default Owner Actions: $ownerActions" -SpecificLogFile $GeneralReportFile
                        
                        # Check for missing critical audit actions
                        $criticalAdminActions = @("Copy", "Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")
                        $criticalDelegateActions = @("Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update")
                        $criticalOwnerActions = @("HardDelete", "MailboxLogin", "MoveToDeletedItems", "SoftDelete", "Update")
                        
                        $missingAdminActions = $criticalAdminActions | Where-Object { $mailboxAuditConfig.DefaultAuditAdminActions -notcontains $_ }
                        $missingDelegateActions = $criticalDelegateActions | Where-Object { $mailboxAuditConfig.DefaultAuditDelegateActions -notcontains $_ }
                        $missingOwnerActions = $criticalOwnerActions | Where-Object { $mailboxAuditConfig.DefaultAuditOwnerActions -notcontains $_ }
                        
                        if ($missingAdminActions.Count -gt 0) {
                            Write-Log -Message "  ALERT: Missing critical Admin audit actions: $($missingAdminActions -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        if ($missingDelegateActions.Count -gt 0) {
                            Write-Log -Message "  ALERT: Missing critical Delegate audit actions: $($missingDelegateActions -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        if ($missingOwnerActions.Count -gt 0) {
                            Write-Log -Message "  ALERT: Missing critical Owner audit actions: $($missingOwnerActions -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check individual mailboxes with auditing disabled
                        Write-Log -Message "Checking individual mailboxes with audit logging disabled..." -SpecificLogFile $GeneralReportFile
                        $mailboxes = Get-Mailbox -ResultSize 1000 -Filter { AuditEnabled -eq $false } -ErrorAction SilentlyContinue
                        
                        if ($mailboxes -and $mailboxes.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($mailboxes.Count) mailboxes with auditing explicitly disabled:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            
                            foreach ($mailbox in $mailboxes) {
                                Write-Log -Message "    - $($mailbox.UserPrincipalName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        } else {
                            Write-Log -Message "  No individual mailboxes found with auditing explicitly disabled." -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "Could not retrieve Mailbox Audit Configuration." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking Mailbox Audit Configuration: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            } catch {
                Write-Log -Message "Error checking Exchange Online Audit Settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        } else {
            Write-Log -Message "Not connected to Exchange Online. Cannot check unified audit log settings." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 2. Check Security & Compliance PowerShell for audit retention policies
        Write-Log -Message "Checking audit retention policies in Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
        
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Log -Message "ExchangeOnlineManagement module not found. This is required for audit retention policy checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
        } else {
            try {
                # Check if connected to Security & Compliance Center
                $sccConnected = $false
                $sccSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*.compliance.protection.outlook.com'}
                
                if ($sccSession -and $sccSession.State -eq 'Opened') {
                    $sccConnected = $true
                    Write-Log -Message "Already connected to Security & Compliance Center." -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "Connecting to Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
                    try {
                        Connect-IPPSSession -ErrorAction Stop
                        $sccConnected = $true
                        Write-Log -Message "Successfully connected to Security & Compliance Center." -SpecificLogFile $GeneralReportFile
                    } catch {
                        Write-Log -Message "Could not connect to Security & Compliance Center: $($_.Exception.Message)" -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                if ($sccConnected) {
                    # Check retention policies for audit logs
                    try {
                        # Get audit configuration settings
                        $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
                        
                        if ($auditConfig) {
                            $auditSettingsFound = $true
                            Write-Log -Message "Audit Configuration:" -SpecificLogFile $GeneralReportFile
                            
                            # Check if Advanced Audit is enabled (E5 feature)
                            if (Get-Command Get-AdvancedAuditPolicy -ErrorAction SilentlyContinue) {
                                try {
                                    $advAuditPolicy = Get-AdvancedAuditPolicy -ErrorAction SilentlyContinue
                                    if ($advAuditPolicy) {
                                        Write-Log -Message "  Advanced Audit Policy:" -SpecificLogFile $GeneralReportFile
                                        Write-Log -Message "    Enabled: $($advAuditPolicy.Enabled)" -SpecificLogFile $GeneralReportFile
                                        Write-Log -Message "    Retention Period: $($advAuditPolicy.GeneralRetention)" -SpecificLogFile $GeneralReportFile
                                        Write-Log -Message "    HighValueTenantRetention: $($advAuditPolicy.HighValueTenantRetention)" -SpecificLogFile $GeneralReportFile
                                        
                                        if ($advAuditPolicy.Enabled -ne $true) {
                                            Write-Log -Message "    ALERT: Advanced Audit is not enabled." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                        
                                        if ($advAuditPolicy.GeneralRetention -lt 90) {
                                            Write-Log -Message "    ALERT: Advanced Audit general retention is less than 90 days ($($advAuditPolicy.GeneralRetention))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "    Error retrieving Advanced Audit Policy: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                                }
                            } else {
                                Write-Log -Message "  Advanced Audit not available (requires E5 license or add-on)." -SpecificLogFile $GeneralReportFile
                            }
                            
                            # Check retention policies that might include audit data
                            try {
                                $retentionPolicies = Get-RetentionPolicy -ErrorAction SilentlyContinue
                                
                                if ($retentionPolicies) {
                                    $auditRelatedPolicies = $retentionPolicies | Where-Object { 
                                        $_.Name -like "*Audit*" -or 
                                        $_.Name -like "*Log*" -or 
                                        $_.Name -like "*Compliance*" 
                                    }
                                    
                                    if ($auditRelatedPolicies) {
                                        Write-Log -Message "  Found $($auditRelatedPolicies.Count) retention policies that may affect audit data:" -SpecificLogFile $GeneralReportFile
                                        
                                        foreach ($policy in $auditRelatedPolicies) {
                                            Write-Log -Message "    Policy: $($policy.Name)" -SpecificLogFile $GeneralReportFile
                                            Write-Log -Message "      Enabled: $($policy.Enabled)" -SpecificLogFile $GeneralReportFile
                                            
                                            # Get retention policy tags associated with this policy
                                            $tags = @($policy.RetentionPolicyTagLinks)
                                            Write-Log -Message "      Associated Tags: $($tags -join ', ')" -SpecificLogFile $GeneralReportFile
                                            
                                            if (-not $policy.Enabled) {
                                                Write-Log -Message "      ALERT: Retention policy '$($policy.Name)' is disabled." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    } else {
                                        Write-Log -Message "  No audit-related retention policies found." -SpecificLogFile $GeneralReportFile
                                    }
                                } else {
                                    Write-Log -Message "  Could not retrieve retention policies." -Type "WARN" -SpecificLogFile $GeneralReportFile
                                }
                            } catch {
                                Write-Log -Message "  Error checking retention policies: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                        } else {
                            Write-Log -Message "Could not retrieve Admin Audit Log Configuration from Security & Compliance Center." -Type "WARN" -SpecificLogFile $GeneralReportFile
                        }
                    } catch {
                        Write-Log -Message "Error checking audit configuration in Security & Compliance Center: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Disconnect from Security & Compliance Center if we connected in this function
                    if (-not $sccSession) {
                        Write-Log -Message "Disconnecting from Security & Compliance Center..." -SpecificLogFile $GeneralReportFile
                        Get-PSSession | Where-Object {$_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*.compliance.protection.outlook.com'} | Remove-PSSession -Confirm:$false
                    }
                }
            } catch {
                Write-Log -Message "Error in Security & Compliance audit settings check: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        # --- 3. Check for audit log exports using Graph API
        if ($GraphConnected) {
            Write-Log -Message "Checking for configured audit log exports using Graph API..." -SpecificLogFile $GeneralReportFile
            
            # Ensure we have the required permission
            $context = Get-MgContext
            $hasRequiredPermission = $false
            if ($context.Scopes) {
                if ($context.Scopes -contains "AuditLog.Read.All" -or 
                    $context.Scopes -contains "ThreatHunting.Read.All" -or
                    $context.Scopes -contains "SecurityEvents.Read.All") {
                    $hasRequiredPermission = $true
                }
            }
            
            if (-not $hasRequiredPermission) {
                Write-Log -Message "Connected to Graph API but missing required permissions (AuditLog.Read.All, ThreatHunting.Read.All, or SecurityEvents.Read.All). Cannot check audit log exports." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                try {
                    # Check for Log Analytics workspace connections
                    Write-Log -Message "Checking for Sentinel/Log Analytics workspace connections..." -SpecificLogFile $GeneralReportFile
                    
                    # API path for data connectors depends on whether Sentinel is licensed/configured
                    $dataConnectorsUri = "https://graph.microsoft.com/v1.0/security/dataConnectors"
                    try {
                        $dataConnectors = Invoke-MgGraphRequest -Method GET -Uri $dataConnectorsUri -ErrorAction SilentlyContinue
                        
                        if ($dataConnectors -and $dataConnectors.value) {
                            $auditSettingsFound = $true
                            $auditConnectors = $dataConnectors.value | Where-Object { $_.dataTypes.logTypes -contains "AuditLogs" -or $_.dataTypes.alertTypes -contains "Audit" }
                            
                            if ($auditConnectors) {
                                Write-Log -Message "  Found $($auditConnectors.Count) data connectors for audit logs:" -SpecificLogFile $GeneralReportFile
                                
                                foreach ($connector in $auditConnectors) {
                                    Write-Log -Message "    Connector: $($connector.displayName) (ID: $($connector.id))" -SpecificLogFile $GeneralReportFile
                                    Write-Log -Message "      Connector Type: $($connector.connectorType)" -SpecificLogFile $GeneralReportFile
                                    Write-Log -Message "      Status: $($connector.state.connectionStatus)" -SpecificLogFile $GeneralReportFile
                                    Write-Log -Message "      Last Connected: $($connector.state.lastConnectionStatusUpdatedDateTime)" -SpecificLogFile $GeneralReportFile
                                    
                                    # Check for connection issues
                                    if ($connector.state.connectionStatus -ne "Connected") {
                                        Write-Log -Message "      ALERT: Audit log connector is not connected. Status: $($connector.state.connectionStatus)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                    
                                    # Check if recently modified
                                    if ($connector.lastModifiedDateTime) {
                                        $lastModifiedDate = [DateTime]$connector.lastModifiedDateTime
                                        if ((New-TimeSpan -Start $lastModifiedDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                            Write-Log -Message "      ALERT: Connector was modified recently ($($connector.lastModifiedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                    }
                                }
                            } else {
                                Write-Log -Message "  No audit log data connectors found." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                        } else {
                            Write-Log -Message "  No data connectors found or unable to access data connectors API." -Type "WARN" -SpecificLogFile $GeneralReportFile
                        }
                    } catch {
                        Write-Log -Message "  Error checking data connectors: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Check for audit log changes in Graph audit logs
                    Write-Log -Message "Checking for changes to audit settings in audit logs..." -SpecificLogFile $GeneralReportFile
                    try {
                        # Define the time period to look back
                        $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                        
                        # Define operations related to audit settings
                        $auditOperations = @(
                            "Update organization",
                            "Update policy",
                            "Set administration audit log configuration",
                            "Create connector",
                            "Update connector",
                            "Remove connector",
                            "Set audit configuration",
                            "Set mailbox audit configuration"
                        )
                        
                        # Create filter for the specific operations we're interested in
                        $operationFilter = $auditOperations | ForEach-Object { "activityDisplayName eq '$_'" }
                        $filter = "activityDateTime ge $startTime and ($($operationFilter -join ' or '))"
                        
                        # Query audit logs with the filter
                        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
                        
                        if ($auditLogs -and $auditLogs.Count -gt 0) {
                            $auditSettingsFound = $true
                            Write-Log -Message "  Found $($auditLogs.Count) events related to audit configuration changes:" -SpecificLogFile $GeneralReportFile
                            
                            foreach ($log in $auditLogs) {
                                $timestamp = $log.ActivityDateTime
                                $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.User.DisplayName ?? $log.InitiatedBy.App.DisplayName ?? "Unknown"
                                $activity = $log.ActivityDisplayName
                                $result = $log.Result
                                
                                Write-Log -Message "    $timestamp: $activity by $actor - Result: $result" -SpecificLogFile $GeneralReportFile
                                
                                # Check for audit disabling activities
                                $auditDisabled = $false
                                if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                                    $modifiedProps = $log.TargetResources[0].ModifiedProperties
                                    foreach ($prop in $modifiedProps) {
                                        $propName = $prop.DisplayName
                                        $oldValue = $prop.OldValue
                                        $newValue = $prop.NewValue
                                        
                                        if (($propName -eq "AuditEnabled" -or $propName -eq "AuditDisabled" -or $propName -eq "UnifiedAuditLogIngestionEnabled") -and
                                            (($oldValue -eq "True" -and $newValue -eq "False") -or ($oldValue -eq "False" -and $newValue -eq "True"))) {
                                            $auditDisabled = ($propName -eq "AuditDisabled" -and $newValue -eq "True") -or ($propName -eq "AuditEnabled" -and $newValue -eq "False") -or ($propName -eq "UnifiedAuditLogIngestionEnabled" -and $newValue -eq "False")
                                            
                                            Write-Log -Message "      Modified Property: $propName, Old Value: $oldValue, New Value: $newValue" -SpecificLogFile $GeneralReportFile
                                        }
                                    }
                                }
                                
                                if ($auditDisabled) {
                                    Write-Log -Message "      CRITICAL ALERT: Audit logging was DISABLED by $actor on $timestamp." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                } else {
                                    Write-Log -Message "      ALERT: Audit configuration was changed by $actor on $timestamp." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        } else {
                            Write-Log -Message "  No audit configuration changes found in audit logs for the specified period." -Type "INFO" -SpecificLogFile $GeneralReportFile
                        }
                    } catch {
                        Write-Log -Message "  Error checking audit logs for audit configuration changes: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking audit log exports: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
        } else {
            Write-Log -Message "Graph API not connected. Cannot check audit log exports or recent changes to audit settings." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        # Check if any audit settings were found
        if (-not $auditSettingsFound) {
            Write-Log -Message "No audit settings found from any source. This could indicate a lack of proper audit configuration or limitations in access to audit information." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "RECOMMENDATION: Enable unified audit logging and configure appropriate retention and export settings." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Audit Log Settings & Export check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Audit Log Settings & Export: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 42. Microsoft Sentinel/SIEM Integration Status ---
    Write-Log -Message "Checking Microsoft Sentinel/SIEM Integration Status..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Check if Az module is available
        if (-not (Get-Module -ListAvailable -Name Az.SecurityInsights)) {
            Write-Log -Message "Az.SecurityInsights module not found. Install using: Install-Module -Name Az.SecurityInsights -Repository PSGallery -Force" -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Additionally, Az.OperationalInsights and Az.ResourceGraph may be needed for complete SIEM checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Microsoft Sentinel/SIEM Integration checks due to missing Az.SecurityInsights module." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Check if already connected to Azure
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Log -Message "Not connected to Azure. Please use Connect-AzAccount before running this script for Sentinel-specific checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Microsoft Sentinel/SIEM Integration checks due to missing Azure connection." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Connected to Azure subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -SpecificLogFile $GeneralReportFile
        
        # --- 1. Check for Log Analytics workspaces with Sentinel enabled
        Write-Log -Message "Checking for Log Analytics workspaces with Microsoft Sentinel enabled..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Get all Log Analytics workspaces in the subscription
            $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
            
            if (-not $workspaces -or $workspaces.Count -eq 0) {
                Write-Log -Message "No Log Analytics workspaces found in subscription $($azContext.Subscription.Name)." -Type "WARN" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "Microsoft Sentinel requires a Log Analytics workspace to operate." -Type "WARN" -SpecificLogFile $GeneralReportFile
                return
            }
            
            Write-Log -Message "Found $($workspaces.Count) Log Analytics workspaces in subscription $($azContext.Subscription.Name)." -SpecificLogFile $GeneralReportFile
            
            $sentinelWorkspaces = @()
            
            foreach ($workspace in $workspaces) {
                # Check if Microsoft Sentinel solution is installed on this workspace
                $isSentinelEnabled = $false
                try {
                    # Use Get-AzMonitorLogAnalyticsSolution to check for Sentinel solution
                    $sentinelSolution = Get-AzMonitorLogAnalyticsSolution -ResourceGroupName $workspace.ResourceGroupName -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Name -eq "SecurityInsights($($workspace.Name))" }
                    
                    if ($sentinelSolution) {
                        $isSentinelEnabled = $true
                        $sentinelWorkspaces += $workspace
                        Write-Log -Message "Microsoft Sentinel is enabled on workspace: $($workspace.Name) (Resource Group: $($workspace.ResourceGroupName))" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking if Sentinel is enabled on workspace $($workspace.Name): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                if (-not $isSentinelEnabled) {
                    Write-Log -Message "Workspace $($workspace.Name) (Resource Group: $($workspace.ResourceGroupName)) does not have Microsoft Sentinel enabled." -SpecificLogFile $GeneralReportFile
                }
            }
            
            if ($sentinelWorkspaces.Count -eq 0) {
                Write-Log -Message "ALERT: Microsoft Sentinel is not enabled on any workspace in subscription $($azContext.Subscription.Name)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                Write-Log -Message "Without Microsoft Sentinel, advanced security monitoring and threat detection capabilities are limited." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                return
            }
            
            # --- 2. For each Sentinel-enabled workspace, check data connectors
            foreach ($workspace in $sentinelWorkspaces) {
                Write-Log -Message "Analyzing Microsoft Sentinel workspace: $($workspace.Name)" -SpecificLogFile $GeneralReportFile
                $workspaceRG = $workspace.ResourceGroupName
                $workspaceName = $workspace.Name
                
                # Check data connectors
                Write-Log -Message "Checking data connectors for workspace $workspaceName..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $dataConnectors = Get-AzSentinelDataConnector -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -ErrorAction SilentlyContinue
                    
                    if ($dataConnectors -and $dataConnectors.Count -gt 0) {
                        Write-Log -Message "Found $($dataConnectors.Count) data connectors in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                        
                        # Group connectors by type for better reporting
                        $connectorsByType = @{}
                        foreach ($connector in $dataConnectors) {
                            $connectorType = if ($connector.Kind) { $connector.Kind } else { "Unknown" }
                            if (-not $connectorsByType.ContainsKey($connectorType)) {
                                $connectorsByType[$connectorType] = New-Object System.Collections.Generic.List[PSObject]
                            }
                            $connectorsByType[$connectorType].Add($connector)
                        }
                        
                        # Report on each connector type
                        foreach ($type in $connectorsByType.Keys) {
                            $typeConnectors = $connectorsByType[$type]
                            Write-Log -Message "  Connector Type: $type (Count: $($typeConnectors.Count))" -SpecificLogFile $GeneralReportFile
                            
                            foreach ($connector in $typeConnectors) {
                                $connectorName = $connector.Name
                                
                                # Get status based on connector type
                                $status = "Unknown"
                                $lastData = "Unknown"
                                
                                # Different connector types have different properties
                                if ($connector.Kind -eq "AzureActiveDirectory") {
                                    $status = $connector.DataTypes.Alerts.State
                                    $lastData = $connector.DataTypes.Alerts.LastDataReceivedQuery
                                } elseif ($connector.Kind -eq "Office365") {
                                    $status = $connector.DataTypes.Exchange.State
                                    $lastData = $connector.DataTypes.Exchange.LastDataReceivedQuery
                                } elseif ($connector.Kind -eq "MicrosoftThreatProtection") {
                                    $status = $connector.DataTypes.Incidents.State
                                    $lastData = $connector.DataTypes.Incidents.LastDataReceivedQuery
                                } elseif ($connector.Kind -eq "AzureAdvancedThreatProtection") {
                                    $status = $connector.DataTypes.Alerts.State
                                    $lastData = $connector.DataTypes.Alerts.LastDataReceivedQuery
                                } elseif ($connector.Kind -eq "MicrosoftDefenderAdvancedThreatProtection") {
                                    $status = $connector.DataTypes.Alerts.State
                                    $lastData = $connector.DataTypes.Alerts.LastDataReceivedQuery
                                }
                                # Add more connector types as needed
                                
                                Write-Log -Message "    Connector: $connectorName, Status: $status" -SpecificLogFile $GeneralReportFile
                                if ($status -ne "Enabled" -and $status -ne "Connected") {
                                    Write-Log -Message "    ALERT: Connector $connectorName is not enabled/connected. Status: $status" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                                
                                # Check for recent data ingestion if we can get that info
                                if ($lastData -and $lastData -ne "Unknown") {
                                    # This would be a KQL query string, typically complex to execute here
                                    Write-Log -Message "    Last Data Received Query available but execution requires direct LA access." -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                        
                        # Check for critical missing connectors
                        $criticalConnectors = @("AzureActiveDirectory", "Office365", "AzureAdvancedThreatProtection", "MicrosoftDefenderAdvancedThreatProtection", "MicrosoftCloudAppSecurity")
                        $missingCritical = $criticalConnectors | Where-Object { -not $connectorsByType.ContainsKey($_) }
                        
                        if ($missingCritical.Count -gt 0) {
                            Write-Log -Message "  ALERT: Missing critical data connectors: $($missingCritical -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "  These connectors are important for comprehensive security monitoring in Microsoft 365." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check for any recently modified connectors
                        $recentlyModifiedConnectors = $dataConnectors | Where-Object { 
                            if ($_.TimeGenerated) {
                                (New-TimeSpan -Start $_.TimeGenerated -End (Get-Date)).TotalDays -lt $script:LookbackDays
                            } elseif ($_.LastModifiedOn) {
                                (New-TimeSpan -Start $_.LastModifiedOn -End (Get-Date)).TotalDays -lt $script:LookbackDays
                            } else {
                                $false
                            }
                        }
                        
                        if ($recentlyModifiedConnectors -and $recentlyModifiedConnectors.Count -gt 0) {
                            Write-Log -Message "  ALERT: $($recentlyModifiedConnectors.Count) connectors were recently modified:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($connector in $recentlyModifiedConnectors) {
                                $modifiedDate = $connector.TimeGenerated ?? $connector.LastModifiedOn
                                Write-Log -Message "    - $($connector.Name) (Kind: $($connector.Kind)) on $modifiedDate" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  ALERT: No data connectors found in workspace $workspaceName. Microsoft Sentinel will not receive security data." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking data connectors for workspace $workspaceName: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 3. Check analytics rules
                Write-Log -Message "Checking analytics rules for workspace $workspaceName..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $analyticsRules = Get-AzSentinelAlertRule -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -ErrorAction SilentlyContinue
                    
                    if ($analyticsRules -and $analyticsRules.Count -gt 0) {
                        Write-Log -Message "Found $($analyticsRules.Count) analytics rules in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                        
                        # Group rules by status for better reporting
                        $enabledRules = $analyticsRules | Where-Object { $_.Enabled -eq $true }
                        $disabledRules = $analyticsRules | Where-Object { $_.Enabled -ne $true }
                        
                        Write-Log -Message "  Enabled Rules: $($enabledRules.Count)" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "  Disabled Rules: $($disabledRules.Count)" -SpecificLogFile $GeneralReportFile
                        
                        if ($disabledRules.Count -gt 0) {
                            # Calculate percentage of disabled rules
                            $disabledPercentage = [math]::Round(($disabledRules.Count / $analyticsRules.Count) * 100, 2)
                            
                            if ($disabledPercentage -gt 50) {
                                Write-Log -Message "  CRITICAL ALERT: $disabledPercentage% of analytics rules are disabled. This severely impacts threat detection capabilities." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            } elseif ($disabledPercentage -gt 20) {
                                Write-Log -Message "  ALERT: $disabledPercentage% of analytics rules are disabled. Review these rules to ensure proper threat detection." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                            
                            # Look for recently disabled rules
                            $recentlyDisabledRules = $disabledRules | Where-Object { 
                                if ($_.LastModifiedDateTime) {
                                    (New-TimeSpan -Start $_.LastModifiedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays
                                } elseif ($_.LastModifiedOn) {
                                    (New-TimeSpan -Start $_.LastModifiedOn -End (Get-Date)).TotalDays -lt $script:LookbackDays
                                } else {
                                    $false
                                }
                            }
                            
                            if ($recentlyDisabledRules -and $recentlyDisabledRules.Count -gt 0) {
                                Write-Log -Message "  ALERT: $($recentlyDisabledRules.Count) rules were recently disabled:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                foreach ($rule in $recentlyDisabledRules) {
                                    $modifiedDate = $rule.LastModifiedDateTime ?? $rule.LastModifiedOn
                                    Write-Log -Message "    - $($rule.DisplayName) (Type: $($rule.Kind)) on $modifiedDate" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                        
                        # Look for critical rule types to ensure coverage
                        $criticalTactics = @("PrivilegeEscalation", "DefenseEvasion", "Persistence", "InitialAccess", "Exfiltration", "CommandAndControl")
                        
                        # If rules have MITRE tactics, check coverage
                        $tacticCoverage = @{}
                        foreach ($tactic in $criticalTactics) {
                            $tacticCoverage[$tactic] = @{
                                TotalRules = 0
                                EnabledRules = 0
                            }
                        }
                        
                        foreach ($rule in $analyticsRules) {
                            if ($rule.Tactics) {
                                foreach ($tactic in $rule.Tactics) {
                                    if ($criticalTactics -contains $tactic) {
                                        $tacticCoverage[$tactic].TotalRules++
                                        if ($rule.Enabled -eq $true) {
                                            $tacticCoverage[$tactic].EnabledRules++
                                        }
                                    }
                                }
                            }
                        }
                        
                        Write-Log -Message "  Critical MITRE Tactics Coverage:" -SpecificLogFile $GeneralReportFile
                        foreach ($tactic in $criticalTactics) {
                            $coverage = $tacticCoverage[$tactic]
                            Write-Log -Message "    $tactic: $($coverage.EnabledRules) enabled out of $($coverage.TotalRules) total rules" -SpecificLogFile $GeneralReportFile
                            
                            if ($coverage.TotalRules -eq 0) {
                                Write-Log -Message "    ALERT: No rules found for critical tactic: $tactic" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            } elseif ($coverage.EnabledRules -eq 0) {
                                Write-Log -Message "    ALERT: All rules for critical tactic '$tactic' are disabled" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  CRITICAL ALERT: No analytics rules found in workspace $workspaceName. Microsoft Sentinel will not detect any threats." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking analytics rules for workspace $workspaceName: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 4. Check incident settings
                Write-Log -Message "Checking incident settings for workspace $workspaceName..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $automationRules = Get-AzSentinelAutomationRule -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -ErrorAction SilentlyContinue
                    
                    if ($automationRules -and $automationRules.Count -gt 0) {
                        Write-Log -Message "Found $($automationRules.Count) automation rules in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                        
                        # Check for suspicious automation rules that might suppress/close incidents
                        $suspiciousRules = $automationRules | Where-Object { 
                            ($_.Actions.IncidentStatus -eq "Closed") -or 
                            ($_.Actions.AlertStatus -eq "Closed")
                        }
                        
                        if ($suspiciousRules -and $suspiciousRules.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($suspiciousRules.Count) automation rules that automatically close incidents or alerts:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($rule in $suspiciousRules) {
                                Write-Log -Message "    - $($rule.DisplayName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "      Incident Status: $($rule.Actions.IncidentStatus)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "      Alert Status: $($rule.Actions.AlertStatus)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                
                                # If recently created, that's extra suspicious
                                if ($rule.CreatedDateTime -and (New-TimeSpan -Start $rule.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    Write-Log -Message "      CRITICAL ALERT: This rule was created recently ($($rule.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    } else {
                        Write-Log -Message "  No automation rules found in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking automation rules for workspace $workspaceName: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 5. Check watchlists
                Write-Log -Message "Checking watchlists for workspace $workspaceName..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $watchlists = Get-AzSentinelWatchlist -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -ErrorAction SilentlyContinue
                    
                    if ($watchlists -and $watchlists.Count -gt 0) {
                        Write-Log -Message "Found $($watchlists.Count) watchlists in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                        
                        foreach ($watchlist in $watchlists) {
                            Write-Log -Message "  Watchlist: $($watchlist.DisplayName) (Alias: $($watchlist.Alias))" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "    Items Count: $($watchlist.ItemsCount)" -SpecificLogFile $GeneralReportFile
                            
                            # Check for recently modified watchlists
                            if ($watchlist.Updated -and (New-TimeSpan -Start $watchlist.Updated -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "    ALERT: Watchlist was updated recently ($($watchlist.Updated))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  No watchlists found in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking watchlists for workspace $workspaceName: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 6. Check scheduled queries (saved searches) in Log Analytics
                Write-Log -Message "Checking scheduled queries in workspace $workspaceName..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $workspaceRG -WorkspaceName $workspaceName -ErrorAction SilentlyContinue
                    
                    if ($savedSearches -and $savedSearches.Count -gt 0) {
                        Write-Log -Message "Found $($savedSearches.Count) saved searches/scheduled queries in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                        
                        # Look for potentially suspicious queries
                        $suspiciousQueries = $savedSearches | Where-Object { 
                            $_.Query -match "delete|remove|drop|truncate|update" -or
                            $_.Query -match "disable|stop|turn off"
                        }
                        
                        if ($suspiciousQueries -and $suspiciousQueries.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($suspiciousQueries.Count) potentially suspicious saved queries:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($query in $suspiciousQueries) {
                                Write-Log -Message "    - $($query.Name)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "      Query: $($query.Query)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  No saved searches/scheduled queries found in workspace $workspaceName." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking saved searches for workspace $workspaceName: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
            
            # --- 7. Check for external SIEM integration (if not using Sentinel)
            if ($sentinelWorkspaces.Count -eq 0) {
                Write-Log -Message "Checking for external SIEM integration since Microsoft Sentinel is not enabled..." -SpecificLogFile $GeneralReportFile
                
                # This is difficult to check without knowing the specific external SIEM
                # We can check for common integration mechanisms
                
                # Check for Event Hub namespaces (common integration point for external SIEMs)
                try {
                    $eventHubNamespaces = Get-AzEventHubNamespace -ErrorAction SilentlyContinue
                    
                    if ($eventHubNamespaces -and $eventHubNamespaces.Count -gt 0) {
                        Write-Log -Message "Found $($eventHubNamespaces.Count) Event Hub namespaces that could be used for SIEM integration." -SpecificLogFile $GeneralReportFile
                        
                        foreach ($namespace in $eventHubNamespaces) {
                            Write-Log -Message "  Event Hub Namespace: $($namespace.Name) (Resource Group: $($namespace.ResourceGroupName))" -SpecificLogFile $GeneralReportFile
                            
                            # Check for Event Hubs in the namespace
                            try {
                                $eventHubs = Get-AzEventHub -ResourceGroupName $namespace.ResourceGroupName -Namespace $namespace.Name -ErrorAction SilentlyContinue
                                
                                if ($eventHubs -and $eventHubs.Count -gt 0) {
                                    Write-Log -Message "    Found $($eventHubs.Count) Event Hubs in namespace $($namespace.Name)." -SpecificLogFile $GeneralReportFile
                                    
                                    # Look for Event Hubs with names suggesting security data
                                    $securityEventHubs = $eventHubs | Where-Object { 
                                        $_.Name -match "security|audit|log|siem|sentinel|defender|azure|activity" 
                                    }
                                    
                                    if ($securityEventHubs -and $securityEventHubs.Count -gt 0) {
                                        Write-Log -Message "    Potential security-related Event Hubs: $($securityEventHubs.Count)" -SpecificLogFile $GeneralReportFile
                                        foreach ($hub in $securityEventHubs) {
                                            Write-Log -Message "      - $($hub.Name)" -SpecificLogFile $GeneralReportFile
                                        }
                                    }
                                } else {
                                    Write-Log -Message "    No Event Hubs found in namespace $($namespace.Name)." -SpecificLogFile $GeneralReportFile
                                }
                            } catch {
                                Write-Log -Message "    Error checking Event Hubs in namespace $($namespace.Name): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "No Event Hub namespaces found for potential SIEM integration." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking Event Hub namespaces: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # Check for storage accounts with diagnostic settings (another common integration mechanism)
                try {
                    $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
                    
                    if ($storageAccounts -and $storageAccounts.Count -gt 0) {
                        $securityStorageAccounts = $storageAccounts | Where-Object { 
                            $_.StorageAccountName -match "security|audit|log|siem" 
                        }
                        
                        if ($securityStorageAccounts -and $securityStorageAccounts.Count -gt 0) {
                            Write-Log -Message "Found $($securityStorageAccounts.Count) storage accounts with names suggesting security/audit use." -SpecificLogFile $GeneralReportFile
                            foreach ($storage in $securityStorageAccounts) {
                                Write-Log -Message "  Storage Account: $($storage.StorageAccountName) (Resource Group: $($storage.ResourceGroupName))" -SpecificLogFile $GeneralReportFile
                            }
                        } else {
                            Write-Log -Message "No storage accounts with security/audit-related names found." -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "No storage accounts found." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking storage accounts: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # Check for Azure Monitor diagnostic settings
                try {
                    # This is difficult to check globally - we'd need to check each resource
                    Write-Log -Message "NOTE: Comprehensive checking of diagnostic settings requires examining each resource individually." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "RECOMMENDATION: If Microsoft Sentinel is not in use, verify that a proper SIEM integration exists via Event Hubs, Storage Accounts, or API connections." -Type "WARN" -SpecificLogFile $GeneralReportFile
                } catch {
                    Write-Log -Message "Error checking diagnostic settings: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
        } catch {
            Write-Log -Message "Error checking for Log Analytics workspaces: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Microsoft Sentinel/SIEM Integration Status check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Microsoft Sentinel/SIEM Integration Status: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 43. Azure Key Vault Access Policies & Secrets ---
    Write-Log -Message "Checking Azure Key Vault Access Policies & Secrets..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Check if Az.KeyVault module is available
        if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
            Write-Log -Message "Az.KeyVault module not found. Install using: Install-Module -Name Az.KeyVault -Repository PSGallery -Force" -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Key Vault checks due to missing Az.KeyVault module." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Check if already connected to Azure
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Log -Message "Not connected to Azure. Please use Connect-AzAccount before running this script for Key Vault-specific checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Key Vault checks due to missing Azure connection." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Connected to Azure subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -SpecificLogFile $GeneralReportFile
        
        # --- 1. Get all Key Vaults in the subscription
        Write-Log -Message "Checking for Azure Key Vaults in subscription..." -SpecificLogFile $GeneralReportFile
        
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        
        if (-not $keyVaults -or $keyVaults.Count -eq 0) {
            Write-Log -Message "No Key Vaults found in subscription $($azContext.Subscription.Name)." -Type "INFO" -SpecificLogFile $GeneralReportFile
            return
        }
        
        Write-Log -Message "Found $($keyVaults.Count) Key Vaults in subscription $($azContext.Subscription.Name)." -SpecificLogFile $GeneralReportFile
        
        # --- 2. Define M365-related service principal patterns to look for
        $m365RelatedAppIds = @(
            # Microsoft Graph
            "00000003-0000-0000-c000-000000000000",
            # Office 365 Exchange Online 
            "00000002-0000-0ff1-ce00-000000000000",
            # Office 365 SharePoint Online
            "00000003-0000-0ff1-ce00-000000000000",
            # Office 365 Management API
            "c5393580-f805-4401-95e8-94b7a6ef2fc2",
            # Power BI Service
            "00000009-0000-0000-c000-000000000000",
            # Azure AD
            "00000002-0000-0000-c000-000000000000",
            # Dynamics CRM
            "00000007-0000-0000-c000-000000000000",
            # PowerApps
            "86c22ba4-1113-47d4-b5fc-4efbfaf4db47",
            # Intune
            "a3b7ee43-a32a-4593-a9b7-a84077d0539e"
        )
        
        $m365RelatedAppNamePatterns = @(
            "Microsoft 365", 
            "Office 365", 
            "Exchange Online", 
            "SharePoint Online", 
            "Teams", 
            "Power Apps", 
            "Power Automate", 
            "Power BI", 
            "Dynamics 365", 
            "Intune", 
            "Azure AD", 
            "Microsoft Entra"
        )
        
        # --- 3. Check each Key Vault
        foreach ($vault in $keyVaults) {
            $vaultName = $vault.VaultName
            $resourceGroupName = $vault.ResourceGroupName
            
            Write-Log -Message "Analyzing Key Vault: $vaultName (Resource Group: $resourceGroupName)" -SpecificLogFile $GeneralReportFile
            
            # Get detailed vault info
            $vaultInfo = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
            
            if ($vaultInfo) {
                # Check Key Vault protection settings
                Write-Log -Message "  Key Vault Protection Settings:" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Soft Delete Enabled: $($vaultInfo.EnableSoftDelete)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "    Purge Protection Enabled: $($vaultInfo.EnablePurgeProtection)" -SpecificLogFile $GeneralReportFile
                
                if (-not $vaultInfo.EnableSoftDelete) {
                    Write-Log -Message "    ALERT: Soft Delete is not enabled for Key Vault '$vaultName'. This means deleted secrets cannot be recovered." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                if (-not $vaultInfo.EnablePurgeProtection) {
                    Write-Log -Message "    WARN: Purge Protection is not enabled for Key Vault '$vaultName'. This means soft-deleted secrets can be permanently deleted within the retention period." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
                
                # Check if vault is network restricted or public
                if ($vaultInfo.NetworkAcls -and $vaultInfo.NetworkAcls.DefaultAction -eq "Deny") {
                    Write-Log -Message "    Network Access: Restricted (Default Action: Deny)" -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "    ALERT: Network Access: Public (Default Action: Allow) - Key Vault is accessible from the internet" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                # --- 4. Check Access Policies
                Write-Log -Message "  Checking Access Policies..." -SpecificLogFile $GeneralReportFile
                
                $accessPolicies = $vaultInfo.AccessPolicies
                
                if ($accessPolicies -and $accessPolicies.Count -gt 0) {
                    Write-Log -Message "  Found $($accessPolicies.Count) access policies in Key Vault '$vaultName'." -SpecificLogFile $GeneralReportFile
                    
                    foreach ($policy in $accessPolicies) {
                        $objectId = $policy.ObjectId
                        $tenantId = $policy.TenantId
                        $applicationId = $policy.ApplicationId
                        
                        # Try to get identity information
                        $identityInfo = $null
                        $identityType = "Unknown"
                        $displayName = "Unknown"
                        $appId = $null
                        
                        # Try to resolve the identity (user, service principal, or app)
                        try {
                            # First try as service principal
                            $spInfo = Get-AzADServicePrincipal -ObjectId $objectId -ErrorAction SilentlyContinue
                            if ($spInfo) {
                                $identityInfo = $spInfo
                                $identityType = "Service Principal"
                                $displayName = $spInfo.DisplayName
                                $appId = $spInfo.ApplicationId
                            } else {
                                # Try as user
                                $userInfo = Get-AzADUser -ObjectId $objectId -ErrorAction SilentlyContinue
                                if ($userInfo) {
                                    $identityInfo = $userInfo
                                    $identityType = "User"
                                    $displayName = $userInfo.DisplayName
                                } else {
                                    # Try as AD group
                                    $groupInfo = Get-AzADGroup -ObjectId $objectId -ErrorAction SilentlyContinue
                                    if ($groupInfo) {
                                        $identityInfo = $groupInfo
                                        $identityType = "Group"
                                        $displayName = $groupInfo.DisplayName
                                    }
                                }
                            }
                        } catch {
                            Write-Log -Message "    Error resolving identity for ObjectId $objectId: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Log policy information
                        Write-Log -Message "    Policy for $identityType '$displayName' (ObjectId: $objectId):" -SpecificLogFile $GeneralReportFile
                        
                        # Check permissions in the policy
                        $secretPerms = $policy.PermissionsToSecrets -join ', '
                        $keyPerms = $policy.PermissionsToKeys -join ', '
                        $certPerms = $policy.PermissionsToCertificates -join ', '
                        $storagePerms = $policy.PermissionsToStorage -join ', '
                        
                        Write-Log -Message "      Secret Permissions: $secretPerms" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "      Key Permissions: $keyPerms" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "      Certificate Permissions: $certPerms" -SpecificLogFile $GeneralReportFile
                        Write-Log -Message "      Storage Permissions: $storagePerms" -SpecificLogFile $GeneralReportFile
                        
                        # Check for high-risk permissions
                        $highRiskPermissions = @("All", "Purge", "Delete", "Backup", "Restore")
                        $hasHighRiskPerms = $false
                        $highRiskPermsFound = @()
                        
                        $allPermissions = @($policy.PermissionsToSecrets) + @($policy.PermissionsToKeys) + @($policy.PermissionsToCertificates) + @($policy.PermissionsToStorage)
                        foreach ($perm in $allPermissions) {
                            if ($highRiskPermissions -contains $perm) {
                                $hasHighRiskPerms = $true
                                $highRiskPermsFound += $perm
                            }
                        }
                        
                        if ($hasHighRiskPerms) {
                            Write-Log -Message "      ALERT: Identity has high-risk permissions: $($highRiskPermsFound -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check if this is an M365-related service principal
                        $isM365Related = $false
                        if ($identityType -eq "Service Principal" -and $appId) {
                            if ($m365RelatedAppIds -contains $appId) {
                                $isM365Related = $true
                                Write-Log -Message "      INFO: This is a known Microsoft 365 service principal." -Type "INFO" -SpecificLogFile $GeneralReportFile
                            } else {
                                foreach ($pattern in $m365RelatedAppNamePatterns) {
                                    if ($displayName -like "*$pattern*") {
                                        $isM365Related = $true
                                        Write-Log -Message "      INFO: This appears to be a Microsoft 365 related service principal based on name pattern." -Type "INFO" -SpecificLogFile $GeneralReportFile
                                        break
                                    }
                                }
                            }
                        }
                        
                        # Check for external tenant IDs (potential cross-tenant access)
                        if ($tenantId -ne $azContext.Tenant.Id) {
                            Write-Log -Message "      CRITICAL ALERT: Policy is for an external tenant ID: $tenantId (current tenant: $($azContext.Tenant.Id))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    # Check for potential excessive access
                    $adminCount = $accessPolicies.Count
                    $allAccessCount = ($accessPolicies | Where-Object { $_.PermissionsToSecrets -contains "All" }).Count
                    
                    if ($adminCount -gt 5) {
                        Write-Log -Message "  ALERT: Key Vault '$vaultName' has $adminCount access policies. Review if all are necessary." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($allAccessCount -gt 2) {
                        Write-Log -Message "  ALERT: Key Vault '$vaultName' has $allAccessCount policies with 'All' permission to secrets. This is excessive." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } else {
                    Write-Log -Message "  No access policies found in Key Vault '$vaultName' or error retrieving them." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 5. Check Secrets
                Write-Log -Message "  Checking Secrets..." -SpecificLogFile $GeneralReportFile
                
                try {
                    # Attempt to get secrets (will only succeed if caller has permissions)
                    $secrets = Get-AzKeyVaultSecret -VaultName $vaultName -ErrorAction SilentlyContinue
                    
                    if ($secrets -and $secrets.Count -gt 0) {
                        Write-Log -Message "  Found $($secrets.Count) secrets in Key Vault '$vaultName'." -SpecificLogFile $GeneralReportFile
                        
                        # Look for secrets with no expiration
                        $noExpirySecrets = $secrets | Where-Object { $null -eq $_.Expires }
                        if ($noExpirySecrets -and $noExpirySecrets.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($noExpirySecrets.Count) secrets with no expiration date:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($secret in $noExpirySecrets) {
                                Write-Log -Message "    - $($secret.Name)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Look for expired secrets still enabled
                        $expiredSecrets = $secrets | Where-Object { $null -ne $_.Expires -and $_.Expires -lt (Get-Date) -and $_.Enabled -eq $true }
                        if ($expiredSecrets -and $expiredSecrets.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($expiredSecrets.Count) expired secrets that are still enabled:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($secret in $expiredSecrets) {
                                Write-Log -Message "    - $($secret.Name) (Expired: $($secret.Expires))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Look for recently modified secrets
                        $recentSecrets = $secrets | Where-Object { $null -ne $_.Updated -and (New-TimeSpan -Start $_.Updated -End (Get-Date)).TotalDays -lt $script:LookbackDays }
                        if ($recentSecrets -and $recentSecrets.Count -gt 0) {
                            Write-Log -Message "  ALERT: Found $($recentSecrets.Count) recently modified secrets:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($secret in $recentSecrets) {
                                Write-Log -Message "    - $($secret.Name) (Last Updated: $($secret.Updated))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Look for M365-related secrets
                        $m365Secrets = $secrets | Where-Object { 
                            $secretName = $_.Name.ToLower()
                            $secretName -like "*client*secret*" -or 
                            $secretName -like "*app*secret*" -or 
                            $secretName -like "*tenant*" -or 
                            $secretName -like "*office*" -or 
                            $secretName -like "*m365*" -or 
                            $secretName -like "*microsoft365*" -or 
                            $secretName -like "*sharepoint*" -or 
                            $secretName -like "*exchange*" -or 
                            $secretName -like "*graph*" -or 
                            $secretName -like "*teams*" -or 
                            $secretName -like "*power*" -or 
                            $secretName -like "*dynamics*" -or 
                            $secretName -like "*intune*" -or 
                            $secretName -like "*azure*ad*" -or 
                            $secretName -like "*entra*" 
                        }
                        
                        if ($m365Secrets -and $m365Secrets.Count -gt 0) {
                            Write-Log -Message "  Found $($m365Secrets.Count) secrets that appear to be related to Microsoft 365 services:" -SpecificLogFile $GeneralReportFile
                            foreach ($secret in $m365Secrets) {
                                Write-Log -Message "    - $($secret.Name) (Enabled: $($secret.Enabled), Expires: $($secret.Expires))" -SpecificLogFile $GeneralReportFile
                                
                                # Additional alert for recently changed M365 secrets
                                if ($null -ne $secret.Updated -and (New-TimeSpan -Start $secret.Updated -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    Write-Log -Message "    ALERT: Microsoft 365 related secret '$($secret.Name)' was recently modified ($($secret.Updated))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                    } else {
                        Write-Log -Message "  No secrets found in Key Vault '$vaultName' or insufficient permissions to view them." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking secrets in Key Vault '$vaultName': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  This may be due to insufficient permissions to list secrets." -Type "INFO" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 6. Check Key Vault Diagnostic Settings
                Write-Log -Message "  Checking Diagnostic Settings..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId $vaultInfo.ResourceId -ErrorAction SilentlyContinue
                    
                    if ($diagnosticSettings -and $diagnosticSettings.Count -gt 0) {
                        Write-Log -Message "  Found $($diagnosticSettings.Count) diagnostic settings for Key Vault '$vaultName'." -SpecificLogFile $GeneralReportFile
                        
                        $auditLogsEnabled = $false
                        
                        foreach ($setting in $diagnosticSettings) {
                            Write-Log -Message "    Diagnostic Setting: $($setting.Name)" -SpecificLogFile $GeneralReportFile
                            
                            # Check if audit logs are being collected
                            $auditLogSetting = $setting.Logs | Where-Object { $_.Category -eq "AuditEvent" }
                            if ($auditLogSetting -and $auditLogSetting.Enabled) {
                                $auditLogsEnabled = $true
                                
                                # Check where logs are being sent
                                if ($setting.WorkspaceId) {
                                    $workspace = Get-AzOperationalInsightsWorkspace -ResourceId $setting.WorkspaceId -ErrorAction SilentlyContinue
                                    Write-Log -Message "      Audit logs are sent to Log Analytics workspace: $($workspace.Name)" -SpecificLogFile $GeneralReportFile
                                }
                                if ($setting.StorageAccountId) {
                                    $storageAccount = Get-AzStorageAccount -ResourceId $setting.StorageAccountId -ErrorAction SilentlyContinue
                                    Write-Log -Message "      Audit logs are sent to Storage Account: $($storageAccount.StorageAccountName)" -SpecificLogFile $GeneralReportFile
                                }
                                if ($setting.EventHubAuthorizationRuleId) {
                                    Write-Log -Message "      Audit logs are sent to Event Hub: $($setting.EventHubName)" -SpecificLogFile $GeneralReportFile
                                }
                            } else {
                                Write-Log -Message "      Audit logs are NOT enabled in this diagnostic setting." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        if (-not $auditLogsEnabled) {
                            Write-Log -Message "  ALERT: Audit logging is not enabled for Key Vault '$vaultName'. This prevents tracking of access to secrets." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "  ALERT: No diagnostic settings found for Key Vault '$vaultName'. Audit logging is not configured." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "  Error checking diagnostic settings for Key Vault '$vaultName': $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
                
                # --- 7. Check Key Vault Firewall Rules
                Write-Log -Message "  Checking Firewall Rules..." -SpecificLogFile $GeneralReportFile
                
                if ($vaultInfo.NetworkAcls -and $vaultInfo.NetworkAcls.DefaultAction -eq "Deny") {
                    $allowedIps = $vaultInfo.NetworkAcls.IpAddressRanges
                    $allowedVnets = $vaultInfo.NetworkAcls.VirtualNetworkResourceIds
                    
                    Write-Log -Message "    Key Vault has network restrictions:" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "      Default Action: $($vaultInfo.NetworkAcls.DefaultAction)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "      Bypass: $($vaultInfo.NetworkAcls.Bypass)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "      Allowed IP Ranges: $($allowedIps -join ', ')" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "      Allowed VNets: $($allowedVnets.Count)" -SpecificLogFile $GeneralReportFile
                    
                    # Check for overly permissive IP ranges
                    $wideRanges = $allowedIps | Where-Object { $_ -like "0.0.0.0*" -or $_ -like "0.0.*" -or $_ -like "10.*" }
                    if ($wideRanges -and $wideRanges.Count -gt 0) {
                        Write-Log -Message "      ALERT: Key Vault has overly permissive IP ranges: $($wideRanges -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($vaultInfo.NetworkAcls.Bypass -eq "AzureServices" -or $vaultInfo.NetworkAcls.Bypass -like "*AzureServices*") {
                        Write-Log -Message "      WARN: Key Vault allows bypass for all Azure Services. Consider restricting to specific services." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "  Error retrieving detailed information for Key Vault '$vaultName'." -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        }
        
        Write-Log -Message "Completed Azure Key Vault Access Policies & Secrets check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Azure Key Vault Access Policies & Secrets: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 44. Managed Tenant Delegations (Lighthouse) ---
    Write-Log -Message "Checking Managed Tenant Delegations (Lighthouse)..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Check if Az.ManagedServices module is available
        if (-not (Get-Module -ListAvailable -Name Az.ManagedServices)) {
            Write-Log -Message "Az.ManagedServices module not found. Install using: Install-Module -Name Az.ManagedServices -Repository PSGallery -Force" -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Managed Tenant Delegations (Lighthouse) checks due to missing Az.ManagedServices module." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Check if already connected to Azure
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Log -Message "Not connected to Azure. Please use Connect-AzAccount before running this script for Lighthouse-specific checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Managed Tenant Delegations (Lighthouse) checks due to missing Azure connection." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Connected to Azure subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -SpecificLogFile $GeneralReportFile
        
        # --- 1. Check for delegations TO other tenants (you as customer, MSP as provider)
        Write-Log -Message "Checking for delegations of your tenant TO external managing tenants (Lighthouse projections)..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Get all delegations where this tenant is the customer
            $delegations = Get-AzManagedServicesAssignment -ErrorAction SilentlyContinue
            
            if (-not $delegations -or $delegations.Count -eq 0) {
                Write-Log -Message "No Lighthouse delegations found where this tenant is being managed by external tenants." -SpecificLogFile $GeneralReportFile
            } else {
                Write-Log -Message "ALERT: Found $($delegations.Count) Lighthouse delegations where your tenant is being managed by external tenants:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                
                foreach ($delegation in $delegations) {
                    $managingTenantId = $delegation.ManagedByTenantId
                    
                    Write-Log -Message "  Delegation Name: $($delegation.Name)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Managing Tenant ID: $managingTenantId" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Delegation Scope: $($delegation.Id)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Created: $($delegation.ProvisioningState)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    
                    # Get the delegated authorizations (what permissions the managing tenant has)
                    $authorizations = Get-AzManagedServicesDefinition -Name $delegation.DefinitionId -ErrorAction SilentlyContinue
                    
                    if ($authorizations) {
                        Write-Log -Message "  Delegated Permissions:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($authorization in $authorizations.Authorization) {
                            $roleDefinition = Get-AzRoleDefinition -Id $authorization.RoleDefinitionId -ErrorAction SilentlyContinue
                            $roleName = $roleDefinition.Name ?? $authorization.RoleDefinitionId
                            
                            Write-Log -Message "    - Role: $roleName" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Principal ID: $($authorization.PrincipalId)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Principal ID Type: $($authorization.PrincipalIdDisplayName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            
                            # Check for highly privileged roles
                            $criticalRoles = @(
                                "Owner", "Contributor", "User Access Administrator", "Azure Kubernetes Service Contributor Role", 
                                "Virtual Machine Contributor", "Storage Account Contributor", "Key Vault Administrator", 
                                "Network Contributor", "SQL Server Contributor", "SQL Security Manager"
                            )
                            
                            if ($criticalRoles -contains $roleName) {
                                Write-Log -Message "      CRITICAL ALERT: Delegation grants highly privileged role '$roleName' to the managing tenant!" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        # Check if the delegation was created recently
                        if ($delegation.ProvisioningState -match "Accepted" -and $delegation.ProvisioningState -match "\d{1,2}/\d{1,2}/\d{4}") {
                            try {
                                $creationDateString = $delegation.ProvisioningState -replace "^.*?(\d{1,2}/\d{1,2}/\d{4}).*$", '$1'
                                $creationDate = [DateTime]::Parse($creationDateString)
                                
                                if ((New-TimeSpan -Start $creationDate -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                    Write-Log -Message "  ALERT: This delegation was created recently ($creationDateString). Verify if this is expected." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                }
                            } catch {
                                Write-Log -Message "  Could not parse creation date from ProvisioningState." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                        }
                    } else {
                        Write-Log -Message "  Could not retrieve authorization details for this delegation." -Type "WARN" -SpecificLogFile $GeneralReportFile
                    }
                    
                    Write-Log -Message "  RECOMMENDATION: Verify this delegation is expected and the managing tenant is trusted." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
            }
        } catch {
            Write-Log -Message "Error checking for Lighthouse delegations TO other tenants: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 2. Check for delegations FROM other tenants (you as MSP, customer has delegated to you)
        # This is less security critical but still informative
        Write-Log -Message "Checking for delegations FROM other tenants (where you are the managing tenant)..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Get all delegations where this tenant is the managing tenant
            $managedTenants = Get-AzManagedServicesRegistration -ErrorAction SilentlyContinue
            
            if (-not $managedTenants -or $managedTenants.Count -eq 0) {
                Write-Log -Message "No tenants found that have delegated resources to your tenant." -SpecificLogFile $GeneralReportFile
            } else {
                Write-Log -Message "Found $($managedTenants.Count) tenant registrations where other tenants have delegated resources to your tenant." -SpecificLogFile $GeneralReportFile
                
                foreach ($registration in $managedTenants) {
                    $customerTenantId = $registration.TenantId
                    
                    Write-Log -Message "  Customer Tenant ID: $customerTenantId" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Registration Name: $($registration.Name)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Registration State: $($registration.ProvisioningState)" -SpecificLogFile $GeneralReportFile
                    
                    # Get the delegated resources
                    $managedResources = Get-AzManagedServicesAssignment -TargetRegistrationId $registration.RegistrationId -ErrorAction SilentlyContinue
                    
                    if ($managedResources -and $managedResources.Count -gt 0) {
                        Write-Log -Message "  Managed Resources from this tenant: $($managedResources.Count)" -SpecificLogFile $GeneralReportFile
                        
                        foreach ($resource in $managedResources) {
                            Write-Log -Message "    - Resource: $($resource.Id)" -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check if any registrations were created recently
                        $recentRegistrations = $managedResources | Where-Object {
                            if ($_.ProvisioningState -match "\d{1,2}/\d{1,2}/\d{4}") {
                                try {
                                    $creationDateString = $_.ProvisioningState -replace "^.*?(\d{1,2}/\d{1,2}/\d{4}).*$", '$1'
                                    $creationDate = [DateTime]::Parse($creationDateString)
                                    return (New-TimeSpan -Start $creationDate -End (Get-Date)).TotalDays -lt $script:LookbackDays
                                } catch {
                                    return $false
                                }
                            } else {
                                return $false
                            }
                        }
                        
                        if ($recentRegistrations -and $recentRegistrations.Count -gt 0) {
                            Write-Log -Message "  INFO: $($recentRegistrations.Count) delegations from this customer were created recently. Verify these are expected." -Type "INFO" -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "  No specific resource delegations found from this tenant." -SpecificLogFile $GeneralReportFile
                    }
                }
            }
        } catch {
            Write-Log -Message "Error checking for Lighthouse delegations FROM other tenants: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 3. Check for GDAP Delegations (Graph API)
        if ($GraphConnected) {
            Write-Log -Message "Checking for GDAP (Granular Delegated Admin Privileges) relationships..." -SpecificLogFile $GeneralReportFile
            
            # This is a supplemental check to the earlier Azure AD section (check #19)
            # Here we're focusing on it from the Managed Services perspective
            
            try {
                $gdapRelationships = Get-MgTenantRelationshipDelegatedAdminRelationship -All -ErrorAction SilentlyContinue
                
                if ($gdapRelationships -and $gdapRelationships.Count -gt 0) {
                    Write-Log -Message "Found $($gdapRelationships.Count) GDAP relationships. This supplements the earlier detailed GDAP check." -SpecificLogFile $GeneralReportFile
                    
                    # Count active vs. inactive relationships
                    $activeRelationships = $gdapRelationships | Where-Object { $_.Status -eq "active" }
                    $inactiveRelationships = $gdapRelationships | Where-Object { $_.Status -ne "active" }
                    
                    Write-Log -Message "  Active GDAP Relationships: $($activeRelationships.Count)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Inactive GDAP Relationships: $($inactiveRelationships.Count)" -SpecificLogFile $GeneralReportFile
                    
                    # Check for recently created relationships
                    $recentRelationships = $gdapRelationships | Where-Object {
                        (New-TimeSpan -Start $_.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays
                    }
                    
                    if ($recentRelationships -and $recentRelationships.Count -gt 0) {
                        Write-Log -Message "  ALERT: $($recentRelationships.Count) GDAP relationships were created recently:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($relationship in $recentRelationships) {
                            Write-Log -Message "    - Relationship: $($relationship.DisplayName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Partner Tenant ID: $($relationship.TenantId)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Created: $($relationship.CreatedDateTime)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Status: $($relationship.Status)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    # Check for high-privilege GDAP delegations
                    $highPrivilegeRoles = @(
                        "Global Administrator", "Privileged Role Administrator", "Exchange Administrator", 
                        "SharePoint Administrator", "User Administrator", "Authentication Administrator",
                        "Conditional Access Administrator", "Security Administrator", "Application Administrator",
                        "Cloud Application Administrator", "Compliance Administrator", "Device Administrator"
                    )
                    
                    $highPrivilegeRelationships = New-Object System.Collections.Generic.List[PSObject]
                    
                    foreach ($relationship in $gdapRelationships) {
                        if ($relationship.Status -eq "active" -and $relationship.AccessDetails -and $relationship.AccessDetails.UnifiedRoles) {
                            foreach ($role in $relationship.AccessDetails.UnifiedRoles) {
                                # Try to resolve role name
                                $roleDef = Get-MgDirectoryRoleDefinition -DirectoryRoleDefinitionId $role.RoleDefinitionId -ErrorAction SilentlyContinue
                                $roleName = $roleDef.DisplayName ?? $role.RoleDefinitionId
                                
                                if ($highPrivilegeRoles -contains $roleName) {
                                    $highPrivilegeRelationships.Add([PSCustomObject]@{
                                        RelationshipName = $relationship.DisplayName
                                        PartnerTenantId = $relationship.TenantId
                                        RoleName = $roleName
                                        Status = $relationship.Status
                                        Created = $relationship.CreatedDateTime
                                    })
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($highPrivilegeRelationships.Count -gt 0) {
                        Write-Log -Message "  ALERT: Found $($highPrivilegeRelationships.Count) GDAP relationships with high-privilege roles:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($relation in $highPrivilegeRelationships) {
                            Write-Log -Message "    - Relationship: $($relation.RelationshipName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Partner Tenant ID: $($relation.PartnerTenantId)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      High-Privilege Role: $($relation.RoleName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "      Created: $($relation.Created)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                } else {
                    Write-Log -Message "No GDAP relationships found or error retrieving them." -SpecificLogFile $GeneralReportFile
                }
            } catch {
                Write-Log -Message "Error checking GDAP relationships: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        } else {
            Write-Log -Message "Graph API not connected. Skipping GDAP relationship check." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 4. Check for partner delegations in audit logs (if available)
        if ($GraphConnected) {
            Write-Log -Message "Checking audit logs for recent partner delegation activities..." -SpecificLogFile $GeneralReportFile
            
            # Ensure we have the required permission
            $context = Get-MgContext
            $hasRequiredPermission = $false
            if ($context.Scopes) {
                if ($context.Scopes -contains "AuditLog.Read.All" -or 
                    $context.Scopes -contains "Directory.Read.All") {
                    $hasRequiredPermission = $true
                }
            }
            
            if (-not $hasRequiredPermission) {
                Write-Log -Message "Connected to Graph API but missing required permissions (AuditLog.Read.All or Directory.Read.All). Cannot check audit logs for partner delegations." -Type "WARN" -SpecificLogFile $GeneralReportFile
            } else {
                try {
                    # Define the time period to look back
                    $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                    
                    # Define operations related to partner delegations
                    $delegationOperations = @(
                        "Create delegated admin relationship",
                        "Update delegated admin relationship",
                        "Delete delegated admin relationship",
                        "Add service to delegated admin relationship",
                        "Remove service from delegated admin relationship",
                        "Add role to delegated admin relationship",
                        "Remove role from delegated admin relationship",
                        "Create delegated admin customer addition",
                        "Accept delegated admin customer addition"
                    )
                    
                    # Create filter for the specific operations we're interested in
                    $operationFilter = $delegationOperations | ForEach-Object { "activityDisplayName eq '$_'" }
                    $filter = "activityDateTime ge $startTime and ($($operationFilter -join ' or '))"
                    
                    # Query audit logs with the filter
                    $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
                    
                    if ($auditLogs -and $auditLogs.Count -gt 0) {
                        Write-Log -Message "ALERT: Found $($auditLogs.Count) partner delegation events in the audit logs:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($log in $auditLogs) {
                            $timestamp = $log.ActivityDateTime
                            $actor = $log.InitiatedBy.User.UserPrincipalName ?? $log.InitiatedBy.User.DisplayName ?? $log.InitiatedBy.App.DisplayName ?? "Unknown"
                            $activity = $log.ActivityDisplayName
                            $result = $log.Result
                            
                            Write-Log -Message "  $timestamp: $activity by $actor - Result: $result" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            
                            # Extract details about the delegated relationship if available
                            if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                                foreach ($resource in $log.TargetResources) {
                                    Write-Log -Message "    Target: $($resource.DisplayName) (Type: $($resource.Type))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    
                                    # Extract modified properties for more details
                                    if ($resource.ModifiedProperties) {
                                        foreach ($prop in $resource.ModifiedProperties) {
                                            $propName = $prop.DisplayName
                                            $oldValue = $prop.OldValue
                                            $newValue = $prop.NewValue
                                            
                                            if ($newValue -and $newValue -ne "[]") {
                                                Write-Log -Message "      $propName: $newValue" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        Write-Log -Message "No partner delegation events found in audit logs for the specified period." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking audit logs for partner delegations: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
        } else {
            Write-Log -Message "Graph API not connected. Skipping audit log check for partner delegation activities." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Managed Tenant Delegations (Lighthouse) check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Managed Tenant Delegations (Lighthouse): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 45. Exchange Online PowerShell Module Connections (Session Logging) ---
    Write-Log -Message "Checking Exchange Online PowerShell Module Connections..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check Exchange Online PowerShell connections." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "AuditLog.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (AuditLog.Read.All or Directory.Read.All). Cannot check Exchange Online PowerShell connections." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }
        
        # --- 1. Check audit logs for Exchange PowerShell connections
        Write-Log -Message "Searching audit logs for Exchange Online PowerShell connections..." -SpecificLogFile $GeneralReportFile
        
        # Define the time period to look back
        $startTime = (Get-Date).AddDays(-$script:LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Define operations related to Exchange PowerShell
        $exchangePSOperations = @(
            "WindowsAzure-ActiveDirectoryActivity-Run-Shell-Command", # Most PowerShell activity in the tenant
            "ExchangePowerShell-CmdletAccess", # Exchange Online PowerShell cmdlet access
            "Connect-ExchangeOnline", # EXO V2 module specific
            "New-PSSession", # Older Exchange Online PowerShell sessions
            "User signed in to Exchange Online PowerShell" # Another name for the activity
        )
        
        # Create filter for the specific operations we're interested in
        $operationFilter = $exchangePSOperations | ForEach-Object { "activityDisplayName eq '$_' or operations/any(o: o eq '$_')" }
        $filter = "activityDateTime ge $startTime and ($($operationFilter -join ' or '))"
        
        # First try checking Azure AD signin logs for PowerShell activity
        try {
            # Query for PowerShell sign-ins
            $filter = "createdDateTime ge $startTime and (appDisplayName eq 'Azure Active Directory PowerShell' or appDisplayName eq 'Exchange Online PowerShell' or clientAppUsed eq 'PowerShell' or appDisplayName eq 'Powershell MSOnline' or appDisplayName eq 'Microsoft Exchange REST API Based PowerShell')"
            $signInLogs = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction SilentlyContinue
            
            if ($signInLogs -and $signInLogs.Count -gt 0) {
                Write-Log -Message "Found $($signInLogs.Count) PowerShell sign-ins to Exchange Online or related services." -SpecificLogFile $GeneralReportFile
                
                # Organize sign-ins by user for better analysis
                $signInsByUser = @{}
                foreach ($signIn in $signInLogs) {
                    $user = $signIn.UserPrincipalName
                    if (-not $signInsByUser.ContainsKey($user)) {
                        $signInsByUser[$user] = New-Object System.Collections.Generic.List[PSObject]
                    }
                    $signInsByUser[$user].Add($signIn)
                }
                
                # Process each user's sign-ins
                foreach ($user in $signInsByUser.Keys) {
                    $userSignIns = $signInsByUser[$user]
                    $signInCount = $userSignIns.Count
                    
                    Write-Log -Message "User: $user - $signInCount PowerShell sign-ins" -SpecificLogFile $GeneralReportFile
                    
                    # Get distinct client apps and IP addresses
                    $distinctApps = $userSignIns | Select-Object -ExpandProperty AppDisplayName -Unique
                    $distinctIPs = $userSignIns | Select-Object -ExpandProperty IpAddress -Unique
                    
                    Write-Log -Message "  Applications: $($distinctApps -join ', ')" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  IP Addresses: $($distinctIPs -join ', ')" -SpecificLogFile $GeneralReportFile
                    
                    # Check for excessive usage
                    if ($signInCount -gt 10) {
                        Write-Log -Message "  ALERT: User $user has excessive PowerShell sign-ins ($signInCount) in the past $script:LookbackDays days." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Check for off-hours activity
                    $offHoursSignIns = $userSignIns | Where-Object {
                        $hour = [DateTime]::Parse($_.CreatedDateTime).Hour
                        $hour -lt 6 -or $hour -gt 18
                    }
                    
                    if ($offHoursSignIns -and $offHoursSignIns.Count -gt 0) {
                        Write-Log -Message "  ALERT: User $user has $($offHoursSignIns.Count) PowerShell sign-ins during off-hours (before 6 AM or after 6 PM)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($offHoursSignIn in $offHoursSignIns) {
                            Write-Log -Message "    Time: $($offHoursSignIn.CreatedDateTime), IP: $($offHoursSignIn.IpAddress), App: $($offHoursSignIn.AppDisplayName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    # Check for unusual locations
                    $distinctLocations = $userSignIns | ForEach-Object {
                        if ($_.Location) {
                            "$($_.Location.City), $($_.Location.State), $($_.Location.CountryOrRegion)"
                        } else {
                            "Unknown Location"
                        }
                    } | Select-Object -Unique
                    
                    if ($distinctLocations.Count -gt 1) {
                        Write-Log -Message "  ALERT: User $user has PowerShell sign-ins from multiple locations: $($distinctLocations -join '; ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    # Check for failed sign-ins
                    $failedSignIns = $userSignIns | Where-Object { $_.Status.ErrorCode -ne 0 }
                    if ($failedSignIns -and $failedSignIns.Count -gt 0) {
                        Write-Log -Message "  ALERT: User $user has $($failedSignIns.Count) failed PowerShell sign-in attempts." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        
                        foreach ($failedSignIn in $failedSignIns) {
                            $failureReason = $failedSignIn.Status.FailureReason ?? "Unknown reason"
                            Write-Log -Message "    Time: $($failedSignIn.CreatedDateTime), IP: $($failedSignIn.IpAddress), Failure: $failureReason" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                    
                    # Sample of recent sessions
                    $recentSessions = $userSignIns | Sort-Object -Property CreatedDateTime -Descending | Select-Object -First 5
                    Write-Log -Message "  Recent PowerShell Sessions:" -SpecificLogFile $GeneralReportFile
                    foreach ($session in $recentSessions) {
                        $location = if ($session.Location) { "$($session.Location.City), $($session.Location.State), $($session.Location.CountryOrRegion)" } else { "Unknown Location" }
                        $status = if ($session.Status.ErrorCode -eq 0) { "Success" } else { "Failed: $($session.Status.FailureReason)" }
                        
                        Write-Log -Message "    $($session.CreatedDateTime): $($session.AppDisplayName) from $($session.IpAddress) ($location) - $status" -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "No PowerShell sign-ins found in the specified period." -SpecificLogFile $GeneralReportFile
            }
        } catch {
            Write-Log -Message "Error querying sign-in logs for PowerShell activity: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 2. Check audit logs for specific Exchange Online PowerShell cmdlet execution
        Write-Log -Message "Checking audit logs for specific Exchange Online PowerShell cmdlet execution..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Try to get Exchange admin audit logs via directory audit logs
            $filter = "activityDateTime ge $startTime and (loggedByService eq 'Exchange' or category eq 'ExchangeAdmin' or category eq 'ExchangeItemGroup')"
            $exchangeAdminLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
            
            if ($exchangeAdminLogs -and $exchangeAdminLogs.Count -gt 0) {
                Write-Log -Message "Found $($exchangeAdminLogs.Count) Exchange admin audit events." -SpecificLogFile $GeneralReportFile
                
                # Identify PowerShell related events
                $powershellEvents = $exchangeAdminLogs | Where-Object {
                    ($_.ActivityDisplayName -like "*PowerShell*") -or
                    ($_.AdditionalDetails | Where-Object { $_.Key -eq "Client" -and $_.Value -like "*PowerShell*" }) -or
                    ($_.AdditionalDetails | Where-Object { $_.Key -eq "CommandName" -and $_.Value -ne $null })
                }
                
                if ($powershellEvents -and $powershellEvents.Count -gt 0) {
                    Write-Log -Message "Found $($powershellEvents.Count) Exchange PowerShell command executions." -SpecificLogFile $GeneralReportFile
                    
                    # Group by user for better analysis
                    $eventsByUser = @{}
                    foreach ($event in $powershellEvents) {
                        $user = $event.InitiatedBy.User.UserPrincipalName ?? $event.InitiatedBy.User.DisplayName ?? "Unknown"
                        if (-not $eventsByUser.ContainsKey($user)) {
                            $eventsByUser[$user] = New-Object System.Collections.Generic.List[PSObject]
                        }
                        $eventsByUser[$user].Add($event)
                    }
                    
                    # Process events for each user
                    foreach ($user in $eventsByUser.Keys) {
                        $userEvents = $eventsByUser[$user]
                        $eventCount = $userEvents.Count
                        
                        Write-Log -Message "User: $user - $eventCount Exchange PowerShell commands" -SpecificLogFile $GeneralReportFile
                        
                        # Extract and count distinct commands
                        $commandCounts = @{}
                        foreach ($event in $userEvents) {
                            $command = $null
                            
                            # Try to get command details
                            $commandDetail = $event.AdditionalDetails | Where-Object { $_.Key -eq "CommandName" }
                            if ($commandDetail) {
                                $command = $commandDetail.Value
                            } else {
                                # Try parsing from ActivityDisplayName as fallback
                                if ($event.ActivityDisplayName -match "Cmdlet: (.+)") {
                                    $command = $matches[1]
                                } else {
                                    $command = "Unknown Command"
                                }
                            }
                            
                            if (-not $commandCounts.ContainsKey($command)) {
                                $commandCounts[$command] = 0
                            }
                            $commandCounts[$command]++
                        }
                        
                        # List top commands
                        $topCommands = $commandCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10
                        Write-Log -Message "  Top Commands:" -SpecificLogFile $GeneralReportFile
                        foreach ($cmd in $topCommands) {
                            Write-Log -Message "    $($cmd.Key): $($cmd.Value) times" -SpecificLogFile $GeneralReportFile
                        }
                        
                        # Check for potentially suspicious commands
                        $suspiciousCommands = @(
                            "Set-Mailbox", "New-TransportRule", "Set-TransportRule", "New-InboxRule", "Set-InboxRule",
                            "Add-MailboxPermission", "Add-RecipientPermission", "New-ManagementRoleAssignment",
                            "Set-AdminAuditLogConfig", "Set-AuthenticationPolicy", "Set-ActiveSyncOrganizationSettings",
                            "Export-Mailbox", "Search-Mailbox", "New-MailboxExportRequest", "Set-CASMailbox",
                            "New-ApplicationAccessPolicy", "Set-ApplicationAccessPolicy", "New-TestCmdletPreprocessor", 
                            "Set-ConnectionFilterPolicy", "New-TransportRuleAction", "Set-RemoteDomain"
                        )
                        
                        $detectedSuspiciousCommands = $commandCounts.Keys | Where-Object { $suspiciousCommands -contains $_ }
                        
                        if ($detectedSuspiciousCommands -and $detectedSuspiciousCommands.Count -gt 0) {
                            Write-Log -Message "  ALERT: User $user executed potentially suspicious commands:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            foreach ($cmd in $detectedSuspiciousCommands) {
                                Write-Log -Message "    - $cmd ($($commandCounts[$cmd]) times)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                
                                # For highly suspicious commands, show the individual executions
                                if ($cmd -in @("Set-TransportRule", "New-TransportRule", "Add-MailboxPermission", "Set-AdminAuditLogConfig", "Set-AuthenticationPolicy")) {
                                    $cmdEvents = $userEvents | Where-Object {
                                        ($_.AdditionalDetails | Where-Object { $_.Key -eq "CommandName" -and $_.Value -eq $cmd }) -or
                                        ($_.ActivityDisplayName -match "Cmdlet: $cmd")
                                    }
                                    
                                    foreach ($cmdEvent in $cmdEvents) {
                                        $timestamp = $cmdEvent.ActivityDateTime
                                        $parameters = ""
                                        
                                        # Try to extract command parameters
                                        $paramDetail = $cmdEvent.AdditionalDetails | Where-Object { $_.Key -eq "Parameters" }
                                        if ($paramDetail) {
                                            $parameters = $paramDetail.Value
                                        }
                                        
                                        Write-Log -Message "      $timestamp: $cmd $parameters" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                }
                            }
                        }
                        
                        # Check for off-hours activity
                        $offHoursEvents = $userEvents | Where-Object {
                            $hour = [DateTime]::Parse($_.ActivityDateTime).Hour
                            $hour -lt 6 -or $hour -gt 18
                        }
                        
                        if ($offHoursEvents -and $offHoursEvents.Count -gt 0) {
                            Write-Log -Message "  ALERT: User $user executed $($offHoursEvents.Count) Exchange PowerShell commands during off-hours." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                        }
                    }
                } else {
                    Write-Log -Message "No Exchange PowerShell command executions found in audit logs." -SpecificLogFile $GeneralReportFile
                }
            } else {
                Write-Log -Message "No Exchange admin audit events found in the specified period or insufficient permissions." -SpecificLogFile $GeneralReportFile
            }
        } catch {
            Write-Log -Message "Error querying audit logs for Exchange PowerShell commands: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 3. Check for PowerShell Module installation via audit logs
        Write-Log -Message "Checking for PowerShell module installations..." -SpecificLogFile $GeneralReportFile
        
        try {
            $filter = "activityDateTime ge $startTime and (activityDisplayName eq 'Install-Module' or activityDisplayName eq 'Update-Module')"
            $moduleInstallLogs = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction SilentlyContinue
            
            if ($moduleInstallLogs -and $moduleInstallLogs.Count -gt 0) {
                Write-Log -Message "Found $($moduleInstallLogs.Count) PowerShell module installation/update events." -SpecificLogFile $GeneralReportFile
                
                foreach ($event in $moduleInstallLogs) {
                    $timestamp = $event.ActivityDateTime
                    $actor = $event.InitiatedBy.User.UserPrincipalName ?? $event.InitiatedBy.User.DisplayName ?? "Unknown"
                    $activity = $event.ActivityDisplayName
                    
                    # Try to extract module name
                    $moduleName = "Unknown Module"
                    if ($event.TargetResources -and $event.TargetResources.Count -gt 0) {
                        $moduleName = $event.TargetResources[0].DisplayName ?? "Unknown Module"
                    }
                    
                    # Check for Exchange or Azure modules
                    if ($moduleName -like "*Exchange*" -or $moduleName -like "*MSOnline*" -or $moduleName -like "*Azure*" -or $moduleName -like "*Graph*") {
                        Write-Log -Message "  ALERT: $timestamp - $actor performed $activity for module: $moduleName" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    } else {
                        Write-Log -Message "  $timestamp - $actor performed $activity for module: $moduleName" -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "No PowerShell module installation/update events found in audit logs." -SpecificLogFile $GeneralReportFile
            }
        } catch {
            Write-Log -Message "Error checking for PowerShell module installations: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        # --- 4. Check Exchange Online cmdlet audit settings
        if ($ExoConnected) {
            Write-Log -Message "Checking Exchange Online PowerShell auditing configuration..." -SpecificLogFile $GeneralReportFile
            
            try {
                $adminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
                
                if ($adminAuditLogConfig) {
                    Write-Log -Message "Exchange Admin Audit Log Configuration:" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Admin Audit Log Enabled: $($adminAuditLogConfig.AdminAuditLogEnabled)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Admin Audit Log Age Limit: $($adminAuditLogConfig.AdminAuditLogAgeLimit)" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Admin Audit Log Cmdlets: $($adminAuditLogConfig.AdminAuditLogCmdlets -join ', ')" -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "  Admin Audit Log Parameters: $($adminAuditLogConfig.AdminAuditLogParameters -join ', ')" -SpecificLogFile $GeneralReportFile
                    
                    if (-not $adminAuditLogConfig.AdminAuditLogEnabled) {
                        Write-Log -Message "  CRITICAL ALERT: Exchange Admin Audit Logging is DISABLED. No PowerShell command execution will be logged." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($adminAuditLogConfig.AdminAuditLogCmdlets -and $adminAuditLogConfig.AdminAuditLogCmdlets.Count -gt 0 -and $adminAuditLogConfig.AdminAuditLogCmdlets[0] -ne "*") {
                        Write-Log -Message "  ALERT: Exchange Admin Audit Logging is not configured to log all cmdlets. Only specific cmdlets are being logged." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($adminAuditLogConfig.AdminAuditLogParameters -and $adminAuditLogConfig.AdminAuditLogParameters.Count -gt 0 -and $adminAuditLogConfig.AdminAuditLogParameters[0] -ne "*") {
                        Write-Log -Message "  ALERT: Exchange Admin Audit Logging is not configured to log all parameters. Only specific parameters are being logged." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    
                    if ($adminAuditLogConfig.AdminAuditLogAgeLimit -lt 90) {
                        Write-Log -Message "  ALERT: Exchange Admin Audit Log age limit is set to $($adminAuditLogConfig.AdminAuditLogAgeLimit) days, which is less than the recommended 90 days." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                } else {
                    Write-Log -Message "Could not retrieve Exchange Admin Audit Log configuration." -Type "WARN" -SpecificLogFile $GeneralReportFile
                }
            } catch {
                Write-Log -Message "Error checking Exchange Admin Audit Log configuration: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
            }
        } else {
            Write-Log -Message "Not connected to Exchange Online. Cannot check Exchange PowerShell auditing configuration." -Type "WARN" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Exchange Online PowerShell Module Connections check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Exchange Online PowerShell Module Connections: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 46. Dynamic Groups with Malicious Membership Rules ---
    Write-Log -Message "Checking Dynamic Groups with Malicious Membership Rules..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        if (-not $GraphConnected) {
            Write-Log -Message "Graph API not connected. Cannot check Dynamic Groups." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Ensure we have the required permission
        $context = Get-MgContext
        $hasRequiredPermission = $false
        if ($context.Scopes) {
            if ($context.Scopes -contains "Group.Read.All" -or 
                $context.Scopes -contains "Directory.Read.All") {
                $hasRequiredPermission = $true
            }
        }

        if (-not $hasRequiredPermission) {
            Write-Log -Message "Connected to Graph API but missing required permissions (Group.Read.All or Directory.Read.All). Cannot check Dynamic Groups." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }
        
        # --- 1. Get all dynamic groups
        Write-Log -Message "Retrieving dynamic groups from Azure AD / Microsoft Entra ID..." -SpecificLogFile $GeneralReportFile
        
        try {
            # Use membershipRule to filter for dynamic groups
            $dynamicGroups = Get-MgGroup -Filter "membershipRule ne null and groupTypes/any(c:c eq 'DynamicMembership')" -All -Property "id,displayName,description,membershipRule,createdDateTime,renewedDateTime,securityEnabled,isAssignableToRole,mail,assignedLicenses" -ErrorAction SilentlyContinue
            
            if (-not $dynamicGroups -or $dynamicGroups.Count -eq 0) {
                Write-Log -Message "No dynamic groups found." -SpecificLogFile $GeneralReportFile
                return
            }
            
            Write-Log -Message "Found $($dynamicGroups.Count) dynamic groups. Analyzing membership rules..." -SpecificLogFile $GeneralReportFile
            
            # --- 2. Define suspicious patterns in membership rules
            $suspiciousPatterns = @{
                # Basic elements that could be suspicious in certain contexts
                "AllUsersOrDevices" = @("user.", "device.")
                
                # Suspicious properties to match
                "SuspiciousProperties" = @(
                    "userType", "onPremisesSecurityIdentifier", "onPremisesSyncEnabled", 
                    "accountEnabled", "creationType", "dirSyncEnabled", "mail", "otherMails", 
                    "proxyAddresses", "userPrincipalName", "displayName", "givenName", "surname",
                    "memberOf", "assignedPlans", "assignedLicenses"
                )
                
                # Suspicious operators when combined with certain properties
                "SuspiciousOperators" = @("-eq", "-ne", "-match", "-notmatch", "-contains", "-notcontains")
                
                # Complex patterns that could indicate attempts to hide malicious rules
                "ComplexPatterns" = @(
                    # Negated contains to exclude specific users from a group that would match everyone else
                    @{
                        Pattern = ".*-notcontains.*"
                        Description = "Negated contains operator - could be used to include all users except specific ones"
                    },
                    # Complex boolean logic to target a specific user indirectly
                    @{
                        Pattern = ".*-and.*-and.*-and.*"
                        Description = "Complex chained AND conditions - could be used to target specific users indirectly"
                    },
                    # OR condition with multiple overlapping criteria (shotgun approach to ensure inclusion)
                    @{
                        Pattern = ".*-or.*-or.*-or.*"
                        Description = "Multiple OR conditions - could cast a wide net to ensure target inclusion"
                    },
                    # Matching on security identifiers or GUIDs (very specific targeting)
                    @{
                        Pattern = ".*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}.*"
                        Description = "Contains GUID/UUID - potentially targeting specific objects by ID"
                    },
                    # Matching on email domains that might be suspicious
                    @{
                        Pattern = ".*(gmail|yahoo|hotmail|outlook\.com|protonmail|dea\.gov|fbi\.gov|nsa\.gov|gchq\.gov|intelligence|security).*"
                        Description = "References to external email domains or security agencies"
                    },
                    # Rules that check for domain joined status
                    @{
                        Pattern = ".*onPremises.*"
                        Description = "References to on-premises attributes - could be used to distinguish cloud-only vs on-prem"
                    },
                    # Rules that try to detect specific apps installed
                    @{
                        Pattern = ".*assignedPlans.*"
                        Description = "Checks user's assigned plans or services - could target users with specific capabilities"
                    },
                    # Rules looking for specific roles
                    @{
                        Pattern = ".*memberOf.*"
                        Description = "Checks group membership - could be used to cascade permissions"
                    }
                )
            }
            
            # --- 3. Check each dynamic group
            $suspiciousGroups = New-Object System.Collections.Generic.List[PSObject]
            $recentlyModifiedGroups = New-Object System.Collections.Generic.List[PSObject]
            
            foreach ($group in $dynamicGroups) {
                Write-Log -Message "Group: $($group.DisplayName) (ID: $($group.Id))" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Created: $($group.CreatedDateTime)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Membership Rule: $($group.MembershipRule)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Security Enabled: $($group.SecurityEnabled)" -SpecificLogFile $GeneralReportFile
                Write-Log -Message "  Role Assignable: $($group.IsAssignableToRole)" -SpecificLogFile $GeneralReportFile
                
                # Check if group was created recently
                $isRecentlyCreated = $false
                if ((New-TimeSpan -Start $group.CreatedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                    $isRecentlyCreated = $true
                    Write-Log -Message "  ALERT: Group was created recently ($($group.CreatedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    $recentlyModifiedGroups.Add($group)
                }
                
                # Check if the rule was modified recently (if we can get that information)
                $isRecentlyModified = $false
                if ($group.RenewedDateTime -and (New-TimeSpan -Start $group.RenewedDateTime -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                    $isRecentlyModified = $true
                    Write-Log -Message "  ALERT: Group membership rule was updated recently ($($group.RenewedDateTime))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    if (-not $recentlyModifiedGroups.Contains($group)) {
                        $recentlyModifiedGroups.Add($group)
                    }
                }
                
                # Analyze the membership rule
                $rule = $group.MembershipRule
                $isSuspicious = $false
                $suspiciousReasons = New-Object System.Collections.Generic.List[string]
                
                # Check for overly broad rules with minimal filtering
                if ($rule -match "^\s*user\.") {
                    $simpleUserRules = @(
                        "user.objectId -ne null",
                        "user.userType -eq 'Member'",
                        "user.accountEnabled -eq true"
                    )
                    
                    foreach ($simpleRule in $simpleUserRules) {
                        if ($rule -eq $simpleRule) {
                            $isSuspicious = $true
                            $suspiciousReasons.Add("Extremely broad rule that includes all users: '$rule'")
                        }
                    }
                }
                
                # Check each suspicious property
                foreach ($property in $suspiciousPatterns.SuspiciousProperties) {
                    if ($rule -match $property) {
                        # Further check if it's combined with a suspicious operator
                        foreach ($operator in $suspiciousPatterns.SuspiciousOperators) {
                            if ($rule -match "$property\s*$operator") {
                                $isSuspicious = $true
                                $suspiciousReasons.Add("Uses suspicious property '$property' with operator '$operator'")
                            }
                        }
                    }
                }
                
                # Check for complex patterns
                foreach ($pattern in $suspiciousPatterns.ComplexPatterns) {
                    if ($rule -match $pattern.Pattern) {
                        $isSuspicious = $true
                        $suspiciousReasons.Add("$($pattern.Description): '$rule'")
                    }
                }
                
                # High-risk combinations
                if ($group.SecurityEnabled -eq $true -and $group.IsAssignableToRole -eq $true -and $isSuspicious) {
                    $suspiciousReasons.Add("CRITICAL: This is a security-enabled, role-assignable group with suspicious membership rule")
                    Write-Log -Message "  CRITICAL ALERT: This is a security-enabled, role-assignable group with suspicious membership rule." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                # If any suspicious criteria found, add to the suspicious groups list
                if ($isSuspicious) {
                    $suspiciousGroups.Add([PSCustomObject]@{
                        Group = $group
                        Reasons = $suspiciousReasons
                        IsRecentlyCreated = $isRecentlyCreated
                        IsRecentlyModified = $isRecentlyModified
                    })
                    
                    foreach ($reason in $suspiciousReasons) {
                        Write-Log -Message "  ALERT: $reason" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                }
                
                # --- 4. For security groups, check if the group has any role assignments
                if ($group.SecurityEnabled -eq $true) {
                    try {
                        # Check if the group is assigned to any directory roles
                        if ($group.IsAssignableToRole -eq $true) {
                            # Get role assignments for this group
                            $groupRoles = Get-MgDirectoryRoleMember -All -ErrorAction SilentlyContinue | Where-Object {
                                $_.Id -eq $group.Id
                            }
                            
                            if ($groupRoles -and $groupRoles.Count -gt 0) {
                                $roleNames = New-Object System.Collections.Generic.List[string]
                                
                                foreach ($role in $groupRoles) {
                                    $roleDef = Get-MgDirectoryRole -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                                    if ($roleDef) {
                                        $roleNames.Add($roleDef.DisplayName)
                                    }
                                }
                                
                                if ($roleNames.Count -gt 0) {
                                    Write-Log -Message "  ALERT: Dynamic group is assigned to these directory roles: $($roleNames -join ', ')" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    
                                    # If the group wasn't already marked as suspicious based on rule, add it now
                                    if (-not $isSuspicious) {
                                        $suspiciousGroups.Add([PSCustomObject]@{
                                            Group = $group
                                            Reasons = @("Group has privileged directory role assignments: $($roleNames -join ', ')")
                                            IsRecentlyCreated = $isRecentlyCreated
                                            IsRecentlyModified = $isRecentlyModified
                                        })
                                    }
                                }
                            }
                        }
                        
                        # Check if group has app role assignments
                        $appRoleAssignments = Get-MgGroupAppRoleAssignment -GroupId $group.Id -All -ErrorAction SilentlyContinue
                        
                        if ($appRoleAssignments -and $appRoleAssignments.Count -gt 0) {
                            Write-Log -Message "  Group has $($appRoleAssignments.Count) application role assignments:" -SpecificLogFile $GeneralReportFile
                            
                            foreach ($assignment in $appRoleAssignments) {
                                # Try to get application details
                                try {
                                    $resourceApp = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                                    $appName = $resourceApp.DisplayName ?? "Unknown App"
                                    
                                    # Try to get role details
                                    $roleName = "Unknown Role"
                                    if ($resourceApp -and $resourceApp.AppRoles) {
                                        $role = $resourceApp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId } | Select-Object -First 1
                                        if ($role) {
                                            $roleName = $role.DisplayName ?? $role.Value ?? "Unknown Role"
                                        }
                                    }
                                    
                                    Write-Log -Message "    Application: $appName, Role: $roleName" -SpecificLogFile $GeneralReportFile
                                    
                                    # Check for sensitive applications
                                    $sensitiveApps = @("Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online", "Azure Key Vault", "Azure Storage")
                                    if ($sensitiveApps -contains $appName) {
                                        Write-Log -Message "    ALERT: Dynamic group has role assignment to sensitive application: $appName (Role: $roleName)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        
                                        # If the group wasn't already marked as suspicious based on rule, add it now
                                        if (-not $isSuspicious) {
                                            $suspiciousGroups.Add([PSCustomObject]@{
                                                Group = $group
                                                Reasons = @("Group has role assignment to sensitive application: $appName (Role: $roleName)")
                                                IsRecentlyCreated = $isRecentlyCreated
                                                IsRecentlyModified = $isRecentlyModified
                                            })
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "    Error getting details for app role assignment: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                                }
                            }
                        }
                        
                        # Check if group has any team associated with it (for Teams access)
                        try {
                            $team = Get-MgTeam -Filter "groupId eq '$($group.Id)'" -ErrorAction SilentlyContinue
                            if ($team) {
                                Write-Log -Message "  Group is associated with Microsoft Teams team: $($team.DisplayName)" -SpecificLogFile $GeneralReportFile
                            }
                        } catch {
                            # Ignore errors here, it's just an informational check
                        }
                        
                    } catch {
                        Write-Log -Message "  Error checking role assignments for group $($group.DisplayName): $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                }
                
                # --- 5. For security and mail-enabled groups, check actual membership
                if ($group.SecurityEnabled -eq $true -or $group.Mail) {
                    try {
                        # Get group members count (using transitive members to catch nested groups)
                        $memberCount = 0
                        try {
                            $members = Get-MgGroupTransitiveMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                            $memberCount = ($members | Measure-Object).Count
                        } catch {
                            # If transitive members fails, try direct members
                            try {
                                $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                                $memberCount = ($members | Measure-Object).Count
                            } catch {
                                Write-Log -Message "  Could not retrieve member count for group." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        if ($memberCount -gt 0) {
                            Write-Log -Message "  Group has $memberCount members." -SpecificLogFile $GeneralReportFile
                            
                            # Check for extreme membership counts (too many/few)
                            if ($memberCount > 1000) {
                                Write-Log -Message "  WARN: Dynamic group has a very large number of members ($memberCount). Verify if this is expected." -Type "WARN" -SpecificLogFile $GeneralReportFile
                            } elseif ($memberCount < 3 -and $group.IsAssignableToRole -eq $true) {
                                Write-Log -Message "  ALERT: Role-assignable dynamic group has very few members ($memberCount). This could be a targeted privilege escalation." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                            
                            # If role-assignable, check if any administrative users have been added
                            if ($group.IsAssignableToRole -eq $true) {
                                # Check if we can see the actual members
                                if ($members) {
                                    try {
                                        # Get admin role members for comparison
                                        $adminRoleIds = @(
                                            "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                                            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
                                            "158c047a-c907-4556-b7ef-446551a6b5f7", # Security Administrator
                                            "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e", # Exchange Administrator
                                            "f2ef992c-3afb-46b9-b7cf-a126ee74c451", # Global Reader
                                            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
                                            "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Recipient Administrator
                                            "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # User Administrator
                                            "fdd7a751-b60b-444a-984c-02652fe8fa1c"  # Teams Administrator
                                        )
                                        
                                        $adminMembers = New-Object System.Collections.Generic.List[PSObject]
                                        
                                        foreach ($adminRoleId in $adminRoleIds) {
                                            $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $adminRoleId -All -ErrorAction SilentlyContinue
                                            if ($roleMembers) {
                                                foreach ($roleMember in $roleMembers) {
                                                    if ($members.Id -contains $roleMember.Id) {
                                                        $adminMembers.Add($roleMember)
                                                    }
                                                }
                                            }
                                        }
                                        
                                        if ($adminMembers.Count -gt 0) {
                                            Write-Log -Message "  CRITICAL ALERT: Dynamic group contains $($adminMembers.Count) members with administrative roles." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                            
                                            foreach ($admin in $adminMembers) {
                                                # Try to get user details
                                                try {
                                                    $user = Get-MgUser -UserId $admin.Id -Property "DisplayName,UserPrincipalName" -ErrorAction SilentlyContinue
                                                    if ($user) {
                                                        Write-Log -Message "    - $($user.DisplayName) ($($user.UserPrincipalName))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                                    } else {
                                                        Write-Log -Message "    - Unknown User (ID: $($admin.Id))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                                    }
                                                } catch {
                                                    Write-Log -Message "    - Unknown User (ID: $($admin.Id))" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                                }
                                            }
                                            
                                            if (-not $suspiciousGroups.Group.Id.Contains($group.Id)) {
                                                $suspiciousGroups.Add([PSCustomObject]@{
                                                    Group = $group
                                                    Reasons = @("Group contains $($adminMembers.Count) members with administrative roles")
                                                    IsRecentlyCreated = $isRecentlyCreated
                                                    IsRecentlyModified = $isRecentlyModified
                                                })
                                            }
                                        }
                                    } catch {
                                        Write-Log -Message "  Error checking admin role members: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "  Error checking group membership: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                    }
                }
            }
            
            # --- 6. Summarize findings
            Write-Log -Message "Dynamic Groups Analysis Summary:" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Total Dynamic Groups: $($dynamicGroups.Count)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Recently Created/Modified Groups: $($recentlyModifiedGroups.Count)" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "  Suspicious Groups: $($suspiciousGroups.Count)" -SpecificLogFile $GeneralReportFile
            
            if ($suspiciousGroups.Count -gt 0) {
                Write-Log -Message "Summary of Suspicious Dynamic Groups:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                foreach ($suspiciousGroup in $suspiciousGroups) {
                    $group = $suspiciousGroup.Group
                    $reasons = $suspiciousGroup.Reasons
                    
                    $timeFlags = New-Object System.Collections.Generic.List[string]
                    if ($suspiciousGroup.IsRecentlyCreated) { $timeFlags.Add("Recently Created") }
                    if ($suspiciousGroup.IsRecentlyModified) { $timeFlags.Add("Recently Modified") }
                    $timeInfo = if ($timeFlags.Count -gt 0) { " [" + ($timeFlags -join ", ") + "]" } else { "" }
                    
                    Write-Log -Message "  - '$($group.DisplayName)'$timeInfo" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    Rule: $($group.MembershipRule)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    Write-Log -Message "    Concerns: $($reasons -join "; ")" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                }
                
                Write-Log -Message "RECOMMENDATION: Review all suspicious dynamic groups carefully, especially those that are security-enabled, role-assignable, or include administrative users." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
            }
            
        } catch {
            Write-Log -Message "Error retrieving or analyzing dynamic groups: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Dynamic Groups with Malicious Membership Rules check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Dynamic Groups with Malicious Membership Rules: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

    # --- 47. Azure Policy Assignments for M365 services ---
    Write-Log -Message "Checking Azure Policy Assignments for M365 services..." -Type "SUBSECTION" -SpecificLogFile $GeneralReportFile
    try {
        # Check if Az.PolicyInsights module is available
        if (-not (Get-Module -ListAvailable -Name Az.PolicyInsights)) {
            Write-Log -Message "Az.PolicyInsights module not found. Install using: Install-Module -Name Az.PolicyInsights -Repository PSGallery -Force" -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Additionally, Az.Resources may be needed for complete policy checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Policy Assignments checks due to missing Az.PolicyInsights module." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        # Check if already connected to Azure
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Log -Message "Not connected to Azure. Please use Connect-AzAccount before running this script for Azure Policy checks." -Type "WARN" -SpecificLogFile $GeneralReportFile
            Write-Log -Message "Skipping Azure Policy Assignments checks due to missing Azure connection." -Type "WARN" -SpecificLogFile $GeneralReportFile
            return
        }

        Write-Log -Message "Connected to Azure subscription: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -SpecificLogFile $GeneralReportFile
        
        # --- 1. Identify M365-related policy assignments
        Write-Log -Message "Identifying Microsoft 365-related policy assignments..." -SpecificLogFile $GeneralReportFile
        
        # Define patterns that may indicate M365-related policies
        $m365PolicyPatterns = @(
            "Office 365", "Microsoft 365", "Intune", "Exchange", "SharePoint", "Teams", 
            "OneDrive", "Defender", "Endpoint", "Information Protection", "Compliance",
            "ATP", "Windows Update", "Windows 10", "Windows 11", "App Protection",
            "Conditional Access", "MFA", "Multi-Factor Authentication", "Identity Protection",
            "Password", "Credential", "Data Loss Prevention", "DLP", "Retention", "eDiscovery",
            "Sensitivity", "Classification", "Mobile Device", "MDM", "MAM", "AAD", "Privileged Identity",
            "Azure AD", "Entra", "Authentication", "PIM", "MIP", "BYOD", "Azure Active Directory"
        )
        
        try {
            # Get all policy assignments in the subscription
            $allPolicyAssignments = Get-AzPolicyAssignment -ErrorAction SilentlyContinue
            
            if (-not $allPolicyAssignments -or $allPolicyAssignments.Count -eq 0) {
                Write-Log -Message "No Azure Policy assignments found in the current subscription." -Type "INFO" -SpecificLogFile $GeneralReportFile
                return
            }
            
            # Filter for potentially M365-related policies based on naming patterns
            $m365RelatedAssignments = $allPolicyAssignments | Where-Object {
                $assignment = $_
                $m365PolicyPatterns | Where-Object {
                    $pattern = $_
                    $assignment.Name -like "*$pattern*" -or
                    $assignment.DisplayName -like "*$pattern*" -or
                    $assignment.Description -like "*$pattern*" -or
                    $assignment.Metadata -like "*$pattern*" -or
                    $assignment.PolicyDefinitionId -like "*$pattern*"
                }
            } | Sort-Object -Property DisplayName
            
            if (-not $m365RelatedAssignments -or $m365RelatedAssignments.Count -eq 0) {
                Write-Log -Message "No Microsoft 365-related Azure Policy assignments found in the current subscription based on naming patterns." -Type "INFO" -SpecificLogFile $GeneralReportFile
                
                # Get Microsoft Intune-specific built-in policy assignments as a fallback
                $intunePolicyAssignments = $allPolicyAssignments | Where-Object {
                    $_.PolicyDefinitionId -like "*/providers/Microsoft.Authorization/policyDefinitions/*" -and
                    ($_.PolicyDefinitionId -like "*intune*" -or $_.PolicyDefinitionId -like "*device*" -or $_.PolicyDefinitionId -like "*endpoint*")
                }
                
                if ($intunePolicyAssignments -and $intunePolicyAssignments.Count -gt 0) {
                    Write-Log -Message "Found $($intunePolicyAssignments.Count) Microsoft Intune/Endpoint Manager-related policy assignments." -SpecificLogFile $GeneralReportFile
                    $m365RelatedAssignments = $intunePolicyAssignments
                } else {
                    Write-Log -Message "No Microsoft Intune-related Azure Policy assignments found either." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    
                    # Since we couldn't find any obvious M365 policies, check for custom policies that might be related
                    Write-Log -Message "Checking if any custom policies might be related to Microsoft 365 services..." -SpecificLogFile $GeneralReportFile
                    
                    $customPolicyAssignments = $allPolicyAssignments | Where-Object {
                        # Custom policies typically have subscription or management group paths
                        $_.PolicyDefinitionId -like "*/subscriptions/*" -or
                        $_.PolicyDefinitionId -like "*/managementGroups/*" 
                    }
                    
                    if ($customPolicyAssignments -and $customPolicyAssignments.Count -gt 0) {
                        Write-Log -Message "Found $($customPolicyAssignments.Count) custom policy assignments. Analyzing for potential M365 relevance..." -SpecificLogFile $GeneralReportFile
                        
                        # Get policy definitions for custom policies to analyze content
                        foreach ($assignment in $customPolicyAssignments) {
                            $policyDefinitionId = $assignment.PolicyDefinitionId
                            try {
                                $policyDefinition = Get-AzPolicyDefinition -Id $policyDefinitionId -ErrorAction SilentlyContinue
                                
                                if ($policyDefinition) {
                                    $policyContent = $policyDefinition.Properties.PolicyRule | ConvertTo-Json -Depth 10
                                    
                                    # Check if any M365 patterns in policy content
                                    $isM365Related = $false
                                    foreach ($pattern in $m365PolicyPatterns) {
                                        if ($policyContent -like "*$pattern*") {
                                            $isM365Related = $true
                                            break
                                        }
                                    }
                                    
                                    if ($isM365Related) {
                                        if (-not $m365RelatedAssignments) {
                                            $m365RelatedAssignments = @($assignment)
                                        } else {
                                            $m365RelatedAssignments += $assignment
                                        }
                                        
                                        Write-Log -Message "  Custom policy '$($assignment.DisplayName)' appears to be related to Microsoft 365 services." -SpecificLogFile $GeneralReportFile
                                    }
                                }
                            } catch {
                                Write-Log -Message "  Error analyzing custom policy definition $policyDefinitionId: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                        }
                        
                        if ($m365RelatedAssignments -and $m365RelatedAssignments.Count -gt 0) {
                            Write-Log -Message "Found $($m365RelatedAssignments.Count) custom policies potentially related to Microsoft 365 services after content analysis." -SpecificLogFile $GeneralReportFile
                        } else {
                            Write-Log -Message "No custom policies appear to be related to Microsoft 365 services after content analysis." -Type "INFO" -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "No custom policy assignments found in the current subscription." -Type "INFO" -SpecificLogFile $GeneralReportFile
                    }
                }
            } else {
                Write-Log -Message "Found $($m365RelatedAssignments.Count) Microsoft 365-related Azure Policy assignments." -SpecificLogFile $GeneralReportFile
            }
            
            # --- 2. Analyze M365 policy assignments
            if ($m365RelatedAssignments -and $m365RelatedAssignments.Count -gt 0) {
                # Categorize policies by types/services
                $policyCategories = @{
                    "Security" = New-Object System.Collections.Generic.List[PSObject]
                    "Compliance" = New-Object System.Collections.Generic.List[PSObject]
                    "Device Management" = New-Object System.Collections.Generic.List[PSObject]
                    "Configuration" = New-Object System.Collections.Generic.List[PSObject]
                    "Other" = New-Object System.Collections.Generic.List[PSObject]
                }
                
                foreach ($assignment in $m365RelatedAssignments) {
                    $categorized = $false
                    
                    # Categorize based on name/description patterns
                    if ($assignment.DisplayName -match "(Security|Secure|Threat|Protection|Protect|Attack|Defender|Malware|Firewall|Encryption|Encrypt|Password|Credential)" -or
                        $assignment.Description -match "(Security|Secure|Threat|Protection|Protect|Attack|Defender|Malware|Firewall|Encryption|Encrypt|Password|Credential)") {
                        $policyCategories["Security"].Add($assignment)
                        $categorized = $true
                    }
                    elseif ($assignment.DisplayName -match "(Compliance|Compliant|DLP|Data Loss|Retention|Legal|Privacy|GDPR|eDiscovery|Classification|Audit|Log)" -or
                            $assignment.Description -match "(Compliance|Compliant|DLP|Data Loss|Retention|Legal|Privacy|GDPR|eDiscovery|Classification|Audit|Log)") {
                        $policyCategories["Compliance"].Add($assignment)
                        $categorized = $true
                    }
                    elseif ($assignment.DisplayName -match "(Device|Intune|Endpoint|Mobile|MDM|MAM|Windows|Update|Patch|BYOD|Autopilot)" -or
                            $assignment.Description -match "(Device|Intune|Endpoint|Mobile|MDM|MAM|Windows|Update|Patch|BYOD|Autopilot)") {
                        $policyCategories["Device Management"].Add($assignment)
                        $categorized = $true
                    }
                    elseif ($assignment.DisplayName -match "(Configuration|Setting|Setup|Provision|Standard|Baseline)" -or
                            $assignment.Description -match "(Configuration|Setting|Setup|Provision|Standard|Baseline)") {
                        $policyCategories["Configuration"].Add($assignment)
                        $categorized = $true
                    }
                    
                    if (-not $categorized) {
                        $policyCategories["Other"].Add($assignment)
                    }
                }
                
                # Analyze and report on each category
                foreach ($category in $policyCategories.Keys) {
                    $policies = $policyCategories[$category]
                    if ($policies.Count -gt 0) {
                        Write-Log -Message "$category Policies ($($policies.Count)):" -SpecificLogFile $GeneralReportFile
                        
                        foreach ($policy in $policies) {
                            Write-Log -Message "  Name: $($policy.DisplayName)" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "  Description: $($policy.Description)" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "  Policy Definition ID: $($policy.PolicyDefinitionId)" -SpecificLogFile $GeneralReportFile
                            Write-Log -Message "  Scope: $($policy.Scope)" -SpecificLogFile $GeneralReportFile
                            
                            # Check if recently created/modified
                            if ($policy.Metadata -and $policy.Metadata.createdOn -and 
                                (New-TimeSpan -Start ([DateTime]::Parse($policy.Metadata.createdOn)) -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "  ALERT: Policy was created recently ($($policy.Metadata.createdOn))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                            
                            if ($policy.Metadata -and $policy.Metadata.updatedOn -and 
                                (New-TimeSpan -Start ([DateTime]::Parse($policy.Metadata.updatedOn)) -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                Write-Log -Message "  ALERT: Policy was updated recently ($($policy.Metadata.updatedOn))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                            }
                            
                            # Get policy states and compliance
                            try {
                                $policyStates = Get-AzPolicyState -PolicyAssignmentName $policy.Name -ErrorAction SilentlyContinue
                                
                                if ($policyStates) {
                                    $nonCompliantStates = $policyStates | Where-Object { $_.ComplianceState -eq "NonCompliant" }
                                    $compliantStates = $policyStates | Where-Object { $_.ComplianceState -eq "Compliant" }
                                    $totalStates = $policyStates.Count
                                    
                                    if ($totalStates -gt 0) {
                                        $compliancePercentage = [math]::Round(($compliantStates.Count / $totalStates) * 100, 2)
                                        Write-Log -Message "  Compliance: $compliancePercentage% ($($compliantStates.Count) of $totalStates resources compliant)" -SpecificLogFile $GeneralReportFile
                                        
                                        if ($compliancePercentage -lt 50) {
                                            Write-Log -Message "  ALERT: Low compliance rate ($compliancePercentage%) for policy '$($policy.DisplayName)'." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                        
                                        # If there are non-compliant resources, list a sample
                                        if ($nonCompliantStates.Count -gt 0) {
                                            $sampleSize = [Math]::Min(5, $nonCompliantStates.Count)
                                            $sampleNonCompliant = $nonCompliantStates | Select-Object -First $sampleSize
                                            
                                            Write-Log -Message "  Sample of Non-Compliant Resources:" -SpecificLogFile $GeneralReportFile
                                            foreach ($state in $sampleNonCompliant) {
                                                Write-Log -Message "    - $($state.ResourceId)" -SpecificLogFile $GeneralReportFile
                                            }
                                        }
                                    } else {
                                        Write-Log -Message "  No compliance states found for this policy." -SpecificLogFile $GeneralReportFile
                                    }
                                } else {
                                    Write-Log -Message "  Could not retrieve policy states." -SpecificLogFile $GeneralReportFile
                                }
                            } catch {
                                Write-Log -Message "  Error retrieving policy states: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                            
                            # Check for exemptions on this policy
                            try {
                                $exemptions = Get-AzPolicyExemption -PolicyAssignmentName $policy.Name -ErrorAction SilentlyContinue
                                
                                if ($exemptions -and $exemptions.Count -gt 0) {
                                    Write-Log -Message "  ALERT: Policy has $($exemptions.Count) exemptions:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    
                                    foreach ($exemption in $exemptions) {
                                        Write-Log -Message "    - Exemption: $($exemption.Name), Scope: $($exemption.Scope)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        Write-Log -Message "      Category: $($exemption.ExemptionCategory), Expires: $($exemption.ExpiresOn)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        
                                        # Check if recently created
                                        if ($exemption.CreatedOn -and (New-TimeSpan -Start $exemption.CreatedOn -End (Get-Date)).TotalDays -lt $script:LookbackDays) {
                                            Write-Log -Message "      ALERT: Exemption was created recently ($($exemption.CreatedOn))." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                        
                                        # Warn about permanent exemptions
                                        if (-not $exemption.ExpiresOn) {
                                            Write-Log -Message "      ALERT: Exemption has no expiration date (permanent exemption)." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                        }
                                    }
                                }
                            } catch {
                                Write-Log -Message "  Error retrieving policy exemptions: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                            }
                            
                            Write-Log -Message "" -SpecificLogFile $GeneralReportFile
                        }
                    }
                }
                
                # --- 3. Check for specific M365 security policy gaps
                Write-Log -Message "Checking for critical Microsoft 365 security policy gaps..." -SpecificLogFile $GeneralReportFile
                
                # Define critical security policies that should exist
                $criticalSecurityPolicies = @(
                    @{
                        Name = "MFA Requirement"
                        Patterns = @("MFA", "Multi-Factor Authentication", "Conditional Access", "Two-Factor", "2FA")
                        Found = $false
                    },
                    @{
                        Name = "Device Compliance"
                        Patterns = @("Device Compliance", "Compliant Device", "Intune Compliance", "Endpoint Compliance")
                        Found = $false
                    },
                    @{
                        Name = "Data Protection/DLP"
                        Patterns = @("DLP", "Data Loss Prevention", "Information Protection", "Data Protection", "Sensitivity")
                        Found = $false
                    },
                    @{
                        Name = "Endpoint Protection"
                        Patterns = @("Endpoint Protection", "Defender", "Antivirus", "Anti-malware", "EDR", "Windows Defender")
                        Found = $false
                    },
                    @{
                        Name = "Update Management"
                        Patterns = @("Update Management", "Windows Update", "Security Update", "Patch Management")
                        Found = $false
                    },
                    @{
                        Name = "Identity Protection"
                        Patterns = @("Identity Protection", "Privileged Identity", "PIM", "User Risk", "Sign-in Risk")
                        Found = $false
                    }
                )
                
                # Check each policy against our critical list
                foreach ($assignment in $m365RelatedAssignments) {
                    foreach ($criticalPolicy in $criticalSecurityPolicies) {
                        if (-not $criticalPolicy.Found) {
                            foreach ($pattern in $criticalPolicy.Patterns) {
                                if ($assignment.DisplayName -like "*$pattern*" -or 
                                    $assignment.Description -like "*$pattern*" -or
                                    $assignment.PolicyDefinitionId -like "*$pattern*") {
                                    $criticalPolicy.Found = $true
                                    break
                                }
                            }
                        }
                    }
                }
                
                # Report missing critical policies
                $missingPolicies = $criticalSecurityPolicies | Where-Object { -not $_.Found }
                if ($missingPolicies -and $missingPolicies.Count -gt 0) {
                    Write-Log -Message "ALERT: Missing critical security policies for Microsoft 365:" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    foreach ($missing in $missingPolicies) {
                        Write-Log -Message "  - $($missing.Name)" -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                    }
                    Write-Log -Message "Consider implementing Azure Policies for these security areas to improve Microsoft 365 security posture." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                } else {
                    Write-Log -Message "All critical Microsoft 365 security policy types appear to be covered." -SpecificLogFile $GeneralReportFile
                }
                
                # --- 4. Check for recent policy state changes (compliance changes)
                Write-Log -Message "Checking for recent Azure Policy state changes affecting Microsoft 365..." -SpecificLogFile $GeneralReportFile
                
                try {
                    $startTime = (Get-Date).AddDays(-$script:LookbackDays)
                    $endTime = Get-Date
                    
                    $recentStateChanges = Get-AzPolicyStateSummary -From $startTime -To $endTime -ErrorAction SilentlyContinue
                    
                    if ($recentStateChanges) {
                        # Check if any of our M365 policies have state changes
                        $m365PolicyIds = $m365RelatedAssignments | ForEach-Object { $_.PolicyAssignmentId }
                        
                        $relevantChanges = $recentStateChanges | Where-Object { 
                            $change = $_
                            $m365PolicyIds | Where-Object { $change.PolicyAssignmentId -eq $_ }
                        }
                        
                        if ($relevantChanges -and $relevantChanges.Count -gt 0) {
                            Write-Log -Message "Found $($relevantChanges.Count) recent policy state changes for Microsoft 365 policies:" -SpecificLogFile $GeneralReportFile
                            
                            foreach ($change in $relevantChanges) {
                                $policyAssignment = $m365RelatedAssignments | Where-Object { $_.PolicyAssignmentId -eq $change.PolicyAssignmentId } | Select-Object -First 1
                                $policyName = $policyAssignment.DisplayName ?? $policyAssignment.Name ?? "Unknown Policy"
                                
                                Write-Log -Message "  Policy: $policyName" -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "  Timestamp: $($change.Timestamp)" -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "  Non-Compliant Resources: $($change.NonCompliantResources)" -SpecificLogFile $GeneralReportFile
                                Write-Log -Message "  Compliant Resources: $($change.CompliantResources)" -SpecificLogFile $GeneralReportFile
                                
                                # Check for significant compliance drop
                                if ($change.PreviousNonCompliantResources -ne $null -and $change.NonCompliantResources -ne $null) {
                                    $complianceChange = $change.NonCompliantResources - $change.PreviousNonCompliantResources
                                    
                                    if ($complianceChange -gt 5) {
                                        Write-Log -Message "  ALERT: Significant increase in non-compliant resources ($complianceChange) for policy '$policyName'." -Type "ALERT" -IsAlert -SpecificLogFile $GeneralReportFile
                                    }
                                }
                                
                                Write-Log -Message "" -SpecificLogFile $GeneralReportFile
                            }
                        } else {
                            Write-Log -Message "No recent state changes found for Microsoft 365-related policies." -SpecificLogFile $GeneralReportFile
                        }
                    } else {
                        Write-Log -Message "No policy state changes found in the specified time period." -SpecificLogFile $GeneralReportFile
                    }
                } catch {
                    Write-Log -Message "Error checking recent policy state changes: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
                }
            }
        } catch {
            Write-Log -Message "Error retrieving Azure Policy assignments: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
        }
        
        Write-Log -Message "Completed Azure Policy Assignments for M365 services check." -SpecificLogFile $GeneralReportFile
        
    } catch {
        Write-Log -Message "Error checking Azure Policy Assignments for M365 services: $($_.Exception.Message)" -Type "ERROR" -SpecificLogFile $GeneralReportFile
    }

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

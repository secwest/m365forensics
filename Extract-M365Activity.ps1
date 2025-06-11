# ================================================================================================
# M365 Incident Response Log Extraction Script - Forensic Evidence Collection
# ================================================================================================
# 
# DESCRIPTION:
#   Microsoft 365 log extraction tool for incident response and forensic analysis.
#   Extracts Exchange Online, Azure AD, and security logs with cryptographic verification.
#
# VERSION: 3.0.7 - Forensic Evidence Edition
# CREATED: June 2025
# 
# PURPOSE:
#   - Extract M365 audit logs and configuration data for security incident investigation
#   - Maintain cryptographic integrity of collected evidence
#   - Provide comprehensive logging and error handling
#   - Generate forensically sound evidence documentation
#
# REQUIREMENTS:
#   - PowerShell 5.1 or later
#   - Global Administrator or equivalent M365 roles
#   - ExchangeOnlineManagement module
#   - Microsoft.Graph modules (Authentication, Users, Identity.DirectoryManagement)
#   - AzureAD module (fallback)
#
# USAGE:
#   .\Extract-M365Logs.ps1 [-DaysBack 90] [-OutputPath "C:\Evidence"]
#
# PARAMETERS:
#   -DaysBack    : Number of days to look back for logs (default: 90)
#   -OutputPath  : Directory to save extracted data (default: auto-generated timestamped folder)
#
# EXAMPLE USAGE:
#   .\Extract-M365Logs.ps1                                    # Extract 90 days with default path
#   .\Extract-M365Logs.ps1 -DaysBack 30                      # Extract 30 days with default path
#   .\Extract-M365Logs.ps1 -DaysBack 60 -OutputPath "C:\Case123"  # Custom timeframe and path
#
# OPERATIONS PERFORMED:
#   1. Module verification and installation
#   2. M365 service authentication (Exchange Online, Microsoft Graph, Azure AD)
#   3. Exchange audit log extraction (Send, MailboxLogin, MailItemsAccessed operations)
#   4. Mailbox audit log collection (Admin, Delegate, External, Owner logon types)
#   5. Message trace log extraction (email flow analysis)
#   6. Transport rule configuration export
#   7. Mailbox permission enumeration
#   8. Inbox forwarding rule detection
#   9. Azure AD sign-in log extraction (requires Azure AD Premium)
#   10. Azure AD audit log collection
#   11. User account and role assignment extraction
#   12. OAuth application and service principal enumeration
#   13. Conditional Access policy export
#   14. Cryptographic hash calculation for all evidence files
#   15. Evidence manifest generation with chain of custody information
#
# OUTPUT FILES:
#   - Exchange_Audit_Logs.csv           : Unified audit log for Exchange operations
#   - All_Mailbox_Audit_Logs.csv        : Individual mailbox access logs
#   - Message_Trace.csv                 : Email routing and delivery logs
#   - Transport_Rules.csv               : Mail flow rule configuration
#   - Mailbox_Permissions.csv           : Mailbox access permissions
#   - Forwarding_Rules.csv              : Email forwarding and redirection rules
#   - AzureAD_SignIn_Logs.csv          : User authentication events
#   - AzureAD_Audit_Logs.csv           : Directory modification events
#   - All_Users.csv                     : User account information
#   - All_Role_Members.csv              : Administrative role assignments
#   - OAuth_Applications.csv            : Third-party application permissions
#   - Conditional_Access_Policies.csv   : Access control policies
#   - execution_log.txt                 : Complete execution log
#   - error_log.txt                     : Error-specific log entries
#   - evidence_manifest.csv             : Cryptographic hashes and metadata
#   - chain_of_custody.txt              : Evidence handling documentation
#
# FORENSIC FEATURES:
#   - SHA256, SHA1, and MD5 checksums for all evidence files
#   - Timestamped execution logging
#   - Chain of custody documentation
#   - Evidence manifest with file metadata
#   - Robust error handling to preserve partial evidence
#
# SECURITY CONSIDERATIONS:
#   - Requires high-privilege administrative access
#   - Logs may contain sensitive information - secure storage required
#   - Network traffic contains authentication tokens - use secure connections
#   - Consider running from secure, isolated workstation
#
# TROUBLESHOOTING:
#   - "Access Denied" errors: Verify administrative role assignments
#   - "Module not found" errors: Run as administrator for installation
#   - "Authentication failed" errors: Check MFA settings and conditional access
#   - "Azure AD Premium required" warnings: Some logs require P1/P2 licensing
#
# ================================================================================================

param(
    [int]$DaysBack = 90,
    [string]$OutputPath = "C:\M365_Incident_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmm')"
)

# Initialize logging and evidence tracking
$LogFile = "$OutputPath\execution_log.txt"
$ErrorLogFile = "$OutputPath\error_log.txt"
$EvidenceManifest = "$OutputPath\evidence_manifest.csv"
$ChainOfCustody = "$OutputPath\chain_of_custody.txt"

# Evidence tracking array
$EvidenceFiles = @()

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = "White"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Write to console with color
    Write-Host $LogEntry -ForegroundColor $Color
    
    # Write to log file (create directory if needed)
    if (!(Test-Path -Path (Split-Path $LogFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $LogEntry
    
    # Write errors to separate error log
    if ($Level -eq "ERROR" -or $Level -eq "WARNING") {
        Add-Content -Path $ErrorLogFile -Value $LogEntry
    }
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileHashes {
    param(
        [string]$FilePath
    )
    
    try {
        $FileInfo = Get-Item $FilePath -ErrorAction Stop
        $SHA256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        $SHA1 = (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
        $MD5 = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
        
        return [PSCustomObject]@{
            FileName = $FileInfo.Name
            FullPath = $FileInfo.FullName
            Size = $FileInfo.Length
            Created = $FileInfo.CreationTime
            Modified = $FileInfo.LastWriteTime
            SHA256 = $SHA256
            SHA1 = $SHA1
            MD5 = $MD5
            CollectionTime = Get-Date
            Collector = $env:USERNAME
            Workstation = $env:COMPUTERNAME
        }
    } catch {
        Write-Log "ERROR: Failed to calculate hashes for $FilePath - $($_.Exception.Message)" "ERROR" "Red"
        return $null
    }
}

function Export-DataSafely {
    param(
        [Object[]]$Data,
        [string]$FilePath,
        [string]$Description
    )
    
    try {
        Write-Log "COMMAND: Exporting $Description to $FilePath" "INFO" "Cyan"
        
        if ($Data -and $Data.Count -gt 0) {
            $Data | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-Log "SUCCESS: Exported $($Data.Count) records for $Description" "INFO" "Green"
            
            # Calculate and store evidence hashes
            $HashInfo = Get-FileHashes -FilePath $FilePath
            if ($HashInfo) {
                $HashInfo | Add-Member -NotePropertyName "Description" -NotePropertyValue $Description
                $script:EvidenceFiles += $HashInfo
                Write-Log "EVIDENCE: SHA256: $($HashInfo.SHA256)" "INFO" "Magenta"
            }
            return $true
        } else {
            Write-Log "WARNING: No data found for $Description" "WARNING" "Yellow"
            # Create empty file to indicate we checked
            "No data found for $Description on $(Get-Date)" | Out-File -FilePath $FilePath
            
            # Still hash the empty file for completeness
            $HashInfo = Get-FileHashes -FilePath $FilePath
            if ($HashInfo) {
                $HashInfo | Add-Member -NotePropertyName "Description" -NotePropertyValue "$Description (No Data)"
                $script:EvidenceFiles += $HashInfo
            }
            return $false
        }
    } catch {
        Write-Log "ERROR: Failed to export $Description - $($_.Exception.Message)" "ERROR" "Red"
        return $false
    }
}

function Connect-M365Services {
    $connections = @{
        'ExchangeOnline' = $false
        'MicrosoftGraph' = $false
        'AzureAD' = $false
    }
    
    # Connect to Exchange Online
    try {
        Write-Log "COMMAND: Connect-ExchangeOnline" "INFO" "Cyan"
        Connect-ExchangeOnline -ShowProgress $true -ErrorAction Stop
        $connections.ExchangeOnline = $true
        Write-Log "SUCCESS: Connected to Exchange Online" "INFO" "Green"
    } catch {
        Write-Log "ERROR: Failed to connect to Exchange Online - $($_.Exception.Message)" "ERROR" "Red"
        Write-Log "TROUBLESHOOTING: Ensure you have Exchange Administrator or Global Administrator role" "INFO" "Yellow"
    }
    
    # Connect to Microsoft Graph (replaces MSOnline)
    try {
        Write-Log "COMMAND: Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','AuditLog.Read.All'" "INFO" "Cyan"
        Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All","Organization.Read.All" -ErrorAction Stop
        $connections.MicrosoftGraph = $true
        $context = Get-MgContext
        Write-Log "SUCCESS: Connected to Microsoft Graph (Tenant: $($context.TenantId))" "INFO" "Green"
    } catch {
        Write-Log "ERROR: Failed to connect to Microsoft Graph - $($_.Exception.Message)" "ERROR" "Red"
        Write-Log "TROUBLESHOOTING: Ensure you have Global Administrator or appropriate reader roles" "INFO" "Yellow"
    }
    
    # Connect to Azure AD (fallback for some operations)
    try {
        Write-Log "COMMAND: Connect-AzureAD" "INFO" "Cyan"
        $AzureADConnection = Connect-AzureAD -ErrorAction Stop
        $connections.AzureAD = $true
        Write-Log "SUCCESS: Connected to Azure AD (Tenant: $($AzureADConnection.TenantDomain))" "INFO" "Green"
    } catch {
        Write-Log "ERROR: Failed to connect to Azure AD - $($_.Exception.Message)" "ERROR" "Red"
        Write-Log "TROUBLESHOOTING: Azure AD module may require different authentication. Continuing with Graph API..." "INFO" "Yellow"
    }
    
    return $connections
}

function Initialize-ChainOfCustody {
    $CustodyInfo = @"
========================================================================================
CHAIN OF CUSTODY DOCUMENTATION
========================================================================================

CASE INFORMATION:
Investigation Type: M365 Security Incident Response
Collection Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") UTC
Collection Method: Automated PowerShell Script (Extract-M365Logs.ps1 v3.0)

EVIDENCE COLLECTOR:
Name: $env:USERNAME
Workstation: $env:COMPUTERNAME  
Domain: $env:USERDOMAIN
Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)
PowerShell Version: $($PSVersionTable.PSVersion)

COLLECTION PARAMETERS:
Date Range: $StartDate to $EndDate (UTC)
Days Back: $DaysBack
Output Path: $OutputPath

M365 TENANT INFORMATION:
Tenant ID: [To be populated during connection]
Connected Services: [To be populated during execution]

EVIDENCE INTEGRITY:
All collected files have been cryptographically hashed using SHA256, SHA1, and MD5
algorithms. Verify evidence integrity by recalculating hashes and comparing to the
evidence manifest (evidence_manifest.csv).

COLLECTION NOTES:
- All timestamps in logs are preserved in their original timezone
- Empty data sets are documented but may indicate insufficient permissions
- Partial collection may occur due to licensing or permission limitations
- Network connectivity required for cloud service authentication

WARNING: This evidence contains potentially sensitive organizational data.
Handle according to your organization's data protection and incident response procedures.

========================================================================================
COLLECTION LOG:
========================================================================================

"@
    
    $CustodyInfo | Out-File -FilePath $ChainOfCustody -Encoding UTF8
    Write-Log "EVIDENCE: Chain of custody documentation initialized" "INFO" "Magenta"
}

# Start main execution
Write-Log "========================================" "INFO" "Magenta"
Write-Log "M365 FORENSIC LOG EXTRACTION v3.0" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"
Write-Log "Script started by: $env:USERNAME" "INFO" "White"
Write-Log "Execution time: $(Get-Date)" "INFO" "White"
Write-Log "Output directory: $OutputPath" "INFO" "White"
Write-Log "Days back: $DaysBack" "INFO" "White"
Write-Log "PowerShell version: $($PSVersionTable.PSVersion)" "INFO" "White"

# Check admin rights
if (!(Test-AdminRights)) {
    Write-Log "WARNING: Script not running as administrator. Some operations may fail." "WARNING" "Yellow"
}

# Check and install required modules
Write-Log "========================================" "INFO" "Magenta"
Write-Log "CHECKING AND INSTALLING MODULES" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"

$RequiredModules = @('ExchangeOnlineManagement', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement', 'AzureAD')
$ModuleStatus = @{}

foreach ($Module in $RequiredModules) {
    try {
        Write-Log "COMMAND: Get-Module -ListAvailable -Name $Module" "INFO" "Cyan"
        $InstalledModule = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue
        
        if ($InstalledModule) {
            Write-Log "SUCCESS: Module $Module is already installed (Version: $($InstalledModule[0].Version))" "INFO" "Green"
            $ModuleStatus[$Module] = $true
        } else {
            Write-Log "INFO: Module $Module not found. Installing..." "INFO" "Yellow"
            Write-Log "COMMAND: Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser" "INFO" "Cyan"
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Log "SUCCESS: Module $Module installed successfully" "INFO" "Green"
            $ModuleStatus[$Module] = $true
        }
    } catch {
        Write-Log "ERROR: Failed to install module $Module - $($_.Exception.Message)" "ERROR" "Red"
        $ModuleStatus[$Module] = $false
    }
}

# Create output directory
try {
    Write-Log "COMMAND: New-Item -ItemType Directory -Path $OutputPath -Force" "INFO" "Cyan"
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Log "SUCCESS: Created output directory: $OutputPath" "INFO" "Green"
} catch {
    Write-Log "ERROR: Failed to create output directory - $($_.Exception.Message)" "ERROR" "Red"
    exit 1
}

# Set date range
$StartDate = (Get-Date).AddDays(-$DaysBack).ToString("MM/dd/yyyy")
$EndDate = (Get-Date).ToString("MM/dd/yyyy")
Write-Log "INFO: Date range: $StartDate to $EndDate" "INFO" "White"

# Initialize chain of custody
Initialize-ChainOfCustody

# Connect to M365 services
Write-Log "========================================" "INFO" "Magenta"
Write-Log "CONNECTING TO M365 SERVICES" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"

$ServiceConnections = Connect-M365Services

# Update chain of custody with connection info
$ConnectionInfo = "`nCONNECTED SERVICES:`n"
$ServiceConnections.GetEnumerator() | ForEach-Object {
    $ConnectionInfo += "- $($_.Key): $($_.Value)`n"
}
Add-Content -Path $ChainOfCustody -Value $ConnectionInfo

# Start data extraction
Write-Log "========================================" "INFO" "Magenta"
Write-Log "STARTING EVIDENCE COLLECTION" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"

$ExtractionResults = @{}

# 1. EXCHANGE ONLINE AUDIT LOGS
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 1: Extracting Exchange audit logs..." "INFO" "Yellow"
        Write-Log "COMMAND: Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000" "INFO" "Cyan"
        $ExchangeAuditLogs = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations UserLoggedIn,MailboxLogin,Send,MailItemsAccessed,FileAccessed,FileAccessedExtended -ErrorAction Stop
        $ExtractionResults['ExchangeAudit'] = Export-DataSafely -Data $ExchangeAuditLogs -FilePath "$OutputPath\Exchange_Audit_Logs.csv" -Description "Exchange Audit Logs"
    } catch {
        Write-Log "ERROR: Failed to extract Exchange audit logs - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['ExchangeAudit'] = $false
    }
} else {
    Write-Log "SKIP: Exchange Online not connected, skipping Exchange audit logs" "WARNING" "Yellow"
}

# 2. MAILBOX AUDIT LOGS
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 2: Extracting mailbox audit logs..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-Mailbox -ResultSize Unlimited" "INFO" "Cyan"
        $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        Write-Log "INFO: Found $($Mailboxes.Count) mailboxes to process" "INFO" "White"
        
        $AllMailboxAuditLogs = @()
        foreach ($Mailbox in $Mailboxes) {
            try {
                Write-Log "COMMAND: Search-MailboxAuditLog -Identity $($Mailbox.PrimarySmtpAddress)" "INFO" "Cyan"
                $MailboxAuditLogs = Search-MailboxAuditLog -Identity $Mailbox.PrimarySmtpAddress -StartDate $StartDate -EndDate $EndDate -LogonTypes Admin,Delegate,External,Owner -ShowDetails -ErrorAction SilentlyContinue
                if ($MailboxAuditLogs) {
                    $AllMailboxAuditLogs += $MailboxAuditLogs
                }
                Write-Log "INFO: Processed mailbox: $($Mailbox.PrimarySmtpAddress)" "INFO" "White"
            } catch {
                Write-Log "WARNING: Failed to get audit logs for $($Mailbox.PrimarySmtpAddress) - $($_.Exception.Message)" "WARNING" "Yellow"
            }
        }
        $ExtractionResults['MailboxAudit'] = Export-DataSafely -Data $AllMailboxAuditLogs -FilePath "$OutputPath\All_Mailbox_Audit_Logs.csv" -Description "All Mailbox Audit Logs"
    } catch {
        Write-Log "ERROR: Failed to extract mailbox audit logs - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['MailboxAudit'] = $false
    }
}

# 3. MESSAGE TRACE LOGS
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 3: Extracting message trace logs..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-MessageTrace -StartDate $StartDate -EndDate $EndDate" "INFO" "Cyan"
        $MessageTrace = Get-MessageTrace -StartDate $StartDate -EndDate $EndDate -ErrorAction Stop
        $ExtractionResults['MessageTrace'] = Export-DataSafely -Data $MessageTrace -FilePath "$OutputPath\Message_Trace.csv" -Description "Message Trace Logs"
    } catch {
        Write-Log "ERROR: Failed to extract message trace logs - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['MessageTrace'] = $false
    }
}

# 4. TRANSPORT RULES
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 4: Extracting transport rules..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-TransportRule" "INFO" "Cyan"
        $TransportRules = Get-TransportRule -ErrorAction Stop
        $ExtractionResults['TransportRules'] = Export-DataSafely -Data $TransportRules -FilePath "$OutputPath\Transport_Rules.csv" -Description "Transport Rules"
    } catch {
        Write-Log "ERROR: Failed to extract transport rules - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['TransportRules'] = $false
    }
}

# 5. MAILBOX PERMISSIONS
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 5: Extracting mailbox permissions..." "INFO" "Yellow"
        if ($Mailboxes) {
            $AllMailboxPermissions = @()
            foreach ($Mailbox in $Mailboxes) {
                try {
                    Write-Log "COMMAND: Get-MailboxPermission -Identity $($Mailbox.PrimarySmtpAddress)" "INFO" "Cyan"
                    $Permissions = Get-MailboxPermission -Identity $Mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue | Where-Object {$_.User -ne "NT AUTHORITY\SELF"}
                    if ($Permissions) {
                        $AllMailboxPermissions += $Permissions
                    }
                } catch {
                    Write-Log "WARNING: Failed to get permissions for $($Mailbox.PrimarySmtpAddress)" "WARNING" "Yellow"
                }
            }
            $ExtractionResults['MailboxPermissions'] = Export-DataSafely -Data $AllMailboxPermissions -FilePath "$OutputPath\Mailbox_Permissions.csv" -Description "Mailbox Permissions"
        }
    } catch {
        Write-Log "ERROR: Failed to extract mailbox permissions - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['MailboxPermissions'] = $false
    }
}

# 6. FORWARDING RULES
if ($ServiceConnections.ExchangeOnline) {
    try {
        Write-Log "STEP 6: Extracting forwarding rules..." "INFO" "Yellow"
        if ($Mailboxes) {
            $AllForwardingRules = @()
            foreach ($Mailbox in $Mailboxes) {
                try {
                    Write-Log "COMMAND: Get-InboxRule -Mailbox $($Mailbox.PrimarySmtpAddress)" "INFO" "Cyan"
                    $InboxRules = Get-InboxRule -Mailbox $Mailbox.PrimarySmtpAddress -ErrorAction SilentlyContinue
                    $ForwardingRules = $InboxRules | Where-Object {$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo}
                    if ($ForwardingRules) {
                        $AllForwardingRules += $ForwardingRules
                    }
                } catch {
                    Write-Log "WARNING: Failed to get inbox rules for $($Mailbox.PrimarySmtpAddress)" "WARNING" "Yellow"
                }
            }
            $ExtractionResults['ForwardingRules'] = Export-DataSafely -Data $AllForwardingRules -FilePath "$OutputPath\Forwarding_Rules.csv" -Description "Forwarding Rules"
        }
    } catch {
        Write-Log "ERROR: Failed to extract forwarding rules - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['ForwardingRules'] = $false
    }
}

# 7. AZURE AD SIGN-IN LOGS
if ($ServiceConnections.AzureAD) {
    try {
        Write-Log "STEP 7: Extracting Azure AD sign-in logs..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-AzureADAuditSignInLogs" "INFO" "Cyan"
        $SignInLogs = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $StartDate and createdDateTime le $EndDate" -ErrorAction Stop
        $ExtractionResults['SignInLogs'] = Export-DataSafely -Data $SignInLogs -FilePath "$OutputPath\AzureAD_SignIn_Logs.csv" -Description "Azure AD Sign-in Logs"
    } catch {
        Write-Log "WARNING: Azure AD sign-in logs require Azure AD Premium or may not be available - $($_.Exception.Message)" "WARNING" "Yellow"
        $ExtractionResults['SignInLogs'] = $false
    }
}

# 8. AZURE AD AUDIT LOGS
if ($ServiceConnections.AzureAD) {
    try {
        Write-Log "STEP 8: Extracting Azure AD audit logs..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-AzureADAuditDirectoryLogs" "INFO" "Cyan"
        $AuditLogs = Get-AzureADAuditDirectoryLogs -Filter "activityDateTime ge $StartDate and activityDateTime le $EndDate" -ErrorAction Stop
        $ExtractionResults['AuditLogs'] = Export-DataSafely -Data $AuditLogs -FilePath "$OutputPath\AzureAD_Audit_Logs.csv" -Description "Azure AD Audit Logs"
    } catch {
        Write-Log "WARNING: Error extracting Azure AD audit logs - $($_.Exception.Message)" "WARNING" "Yellow"
        $ExtractionResults['AuditLogs'] = $false
    }
}

# 9. USER AND ADMIN ROLE ASSIGNMENTS
if ($ServiceConnections.MicrosoftGraph) {
    try {
        Write-Log "STEP 9: Extracting user and role information..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-MgUser -All" "INFO" "Cyan"
        $Users = Get-MgUser -All -ErrorAction Stop
        $ExtractionResults['Users'] = Export-DataSafely -Data $Users -FilePath "$OutputPath\All_Users.csv" -Description "All Users"
        
        Write-Log "COMMAND: Get-MgDirectoryRole" "INFO" "Cyan"
        $AdminRoles = Get-MgDirectoryRole -ErrorAction Stop
        $AllRoleMembers = @()
        foreach ($Role in $AdminRoles) {
            try {
                Write-Log "COMMAND: Get-MgDirectoryRoleMember -DirectoryRoleId $($Role.Id)" "INFO" "Cyan"
                $RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -ErrorAction SilentlyContinue
                foreach ($Member in $RoleMembers) {
                    $MemberDetail = [PSCustomObject]@{
                        RoleName = $Role.DisplayName
                        RoleId = $Role.Id
                        MemberId = $Member.Id
                        MemberType = $Member.AdditionalProperties.'@odata.type'
                        ObjectId = $Member.Id
                    }
                    $AllRoleMembers += $MemberDetail
                }
            } catch {
                Write-Log "WARNING: Failed to get members for role $($Role.DisplayName)" "WARNING" "Yellow"
            }
        }
        $ExtractionResults['RoleMembers'] = Export-DataSafely -Data $AllRoleMembers -FilePath "$OutputPath\All_Role_Members.csv" -Description "All Role Members"
    } catch {
        Write-Log "ERROR: Failed to extract user and role information - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['Users'] = $false
        $ExtractionResults['RoleMembers'] = $false
    }
} else {
    Write-Log "SKIP: Microsoft Graph not connected, skipping user and role extraction" "WARNING" "Yellow"
}

# 10. OAUTH APPLICATIONS AND PERMISSIONS
if ($ServiceConnections.AzureAD) {
    try {
        Write-Log "STEP 10: Extracting OAuth applications..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-AzureADServicePrincipal -All" "INFO" "Cyan"
        $ServicePrincipals = Get-AzureADServicePrincipal -All $true -ErrorAction Stop
        $ExtractionResults['ServicePrincipals'] = Export-DataSafely -Data $ServicePrincipals -FilePath "$OutputPath\OAuth_Applications.csv" -Description "OAuth Applications"
    } catch {
        Write-Log "ERROR: Failed to extract OAuth applications - $($_.Exception.Message)" "ERROR" "Red"
        $ExtractionResults['ServicePrincipals'] = $false
    }
}

# 11. CONDITIONAL ACCESS POLICIES
if ($ServiceConnections.AzureAD) {
    try {
        Write-Log "STEP 11: Extracting Conditional Access policies..." "INFO" "Yellow"
        Write-Log "COMMAND: Get-AzureADMSConditionalAccessPolicy" "INFO" "Cyan"
        $CAPolicies = Get-AzureADMSConditionalAccessPolicy -ErrorAction Stop
        $ExtractionResults['CAPolicies'] = Export-DataSafely -Data $CAPolicies -FilePath "$OutputPath\Conditional_Access_Policies.csv" -Description "Conditional Access Policies"
    } catch {
        Write-Log "WARNING: Error extracting Conditional Access policies - $($_.Exception.Message)" "WARNING" "Yellow"
        $ExtractionResults['CAPolicies'] = $false
    }
}

# Generate evidence manifest
Write-Log "========================================" "INFO" "Magenta"
Write-Log "GENERATING EVIDENCE MANIFEST" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"

if ($EvidenceFiles.Count -gt 0) {
    try {
        Write-Log "COMMAND: Exporting evidence manifest with $($EvidenceFiles.Count) files" "INFO" "Cyan"
        $EvidenceFiles | Export-Csv -Path $EvidenceManifest -NoTypeInformation
        Write-Log "SUCCESS: Evidence manifest created with cryptographic hashes" "INFO" "Green"
        
        # Hash the manifest itself
        $ManifestHash = Get-FileHashes -FilePath $EvidenceManifest
        if ($ManifestHash) {
            Write-Log "EVIDENCE: Manifest SHA256: $($ManifestHash.SHA256)" "INFO" "Magenta"
        }
    } catch {
        Write-Log "ERROR: Failed to create evidence manifest - $($_.Exception.Message)" "ERROR" "Red"
    }
} else {
    Write-Log "WARNING: No evidence files collected to manifest" "WARNING" "Yellow"
}

# Hash the log files themselves
$LogHashes = @()
$LogFiles = @($LogFile, $ErrorLogFile, $ChainOfCustody)
foreach ($LogFilePath in $LogFiles) {
    if (Test-Path $LogFilePath) {
        $LogHash = Get-FileHashes -FilePath $LogFilePath
        if ($LogHash) {
            $LogHashes += $LogHash
            Write-Log "EVIDENCE: Log file hash - $($LogHash.FileName): $($LogHash.SHA256)" "INFO" "Magenta"
        }
    }
}

# Append log file hashes to manifest
if ($LogHashes.Count -gt 0) {
    $LogHashes | Export-Csv -Path $EvidenceManifest -NoTypeInformation -Append
}

# Generate summary report
Write-Log "========================================" "INFO" "Magenta"
Write-Log "COLLECTION SUMMARY" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"

$SuccessCount = ($ExtractionResults.Values | Where-Object {$_ -eq $true}).Count
$TotalCount = $ExtractionResults.Count

Write-Log "Evidence collection completed: $SuccessCount/$TotalCount successful" "INFO" "White"
Write-Log "Total evidence files: $($EvidenceFiles.Count)" "INFO" "White"
Write-Log "Results saved to: $OutputPath" "INFO" "Green"
Write-Log "Evidence manifest: $EvidenceManifest" "INFO" "White"
Write-Log "Chain of custody: $ChainOfCustody" "INFO" "White"
Write-Log "Execution log: $LogFile" "INFO" "White"
Write-Log "Error log: $ErrorLogFile" "INFO" "White"

# Update chain of custody with completion info
$CompletionInfo = @"

COLLECTION COMPLETED:
End Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") UTC
Total Files Collected: $($EvidenceFiles.Count)
Successful Operations: $SuccessCount/$TotalCount
Evidence Manifest: evidence_manifest.csv

VERIFICATION INSTRUCTIONS:
1. Verify file integrity by recalculating hashes and comparing to manifest
2. Preserve original timestamps and file permissions
3. Store evidence in secure, tamper-evident storage
4. Document any subsequent access or analysis

Digital signature/hash of this custody document:
$(if (Test-Path $ChainOfCustody) { (Get-FileHash -Path $ChainOfCustody -Algorithm SHA256).Hash } else { "Not available" })

"@

Add-Content -Path $ChainOfCustody -Value $CompletionInfo

# Priority analysis guidance
Write-Log "========================================" "INFO" "Magenta"
Write-Log "ANALYSIS PRIORITY GUIDANCE" "INFO" "Magenta"
Write-Log "========================================" "INFO" "Magenta"
Write-Log "CRITICAL PRIORITY (Immediate Analysis):" "INFO" "Red"
Write-Log "- Message_Trace.csv (email flow, spoofed messages)" "INFO" "White"
Write-Log "- Forwarding_Rules.csv (malicious redirects)" "INFO" "White"
Write-Log "- Exchange_Audit_Logs.csv (Send operations, suspicious access)" "INFO" "White"
Write-Log "HIGH PRIORITY:" "INFO" "Yellow"
Write-Log "- AzureAD_SignIn_Logs.csv (unusual login patterns)" "INFO" "White"
Write-Log "- OAuth_Applications.csv (unauthorized applications)" "INFO" "White"
Write-Log "- All_Role_Members.csv (privilege escalation)" "INFO" "White"
Write-Log "MEDIUM PRIORITY:" "INFO" "Green"
Write-Log "- All_Mailbox_Audit_Logs.csv (detailed mailbox access)" "INFO" "White"
Write-Log "- Mailbox_Permissions.csv (unauthorized access grants)" "INFO" "White"
Write-Log "- Transport_Rules.csv (mail flow manipulation)" "INFO" "White"

Write-Log "========================================" "INFO" "Magenta"
Write-Log "EVIDENCE COLLECTION COMPLETED" "INFO" "Magenta"
Write-Log "Script execution completed at $(Get-Date)" "INFO" "Green"
Write-Log "========================================" "INFO" "Magenta"

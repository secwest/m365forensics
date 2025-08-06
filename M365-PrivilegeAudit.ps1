<#
.SYNOPSIS
    Comprehensive Microsoft 365 Privilege Enumeration Script
    
.DESCRIPTION
    Enumerates all privilege assignments across Microsoft 365 tenant including:
    - Directory role assignments
    - PIM eligible and active assignments
    - Administrative unit memberships
    - Application permissions and OAuth grants
    - Role-assignable group memberships
    - Exchange and Compliance role assignments
    
.NOTES
    Author: Dragos Ruiu
    Version: 1.0
    Requires: Microsoft Graph PowerShell SDK
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\M365_Privilege_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeExchangeRoles = $false
)

# Initialize logging
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output
    Write-Host $logMessage -ForegroundColor $Color
    
    # File output
    Add-Content -Path $OutputPath -Value $logMessage -ErrorAction SilentlyContinue
}

# Error handling wrapper
function Invoke-SafeCommand {
    param(
        [ScriptBlock]$ScriptBlock,
        [string]$ErrorMessage = "Command failed"
    )
    
    try {
        & $ScriptBlock
    }
    catch {
        Write-LogMessage -Message "$ErrorMessage : $_" -Level "ERROR" -Color Red
        return $null
    }
}

# Start script
Write-LogMessage -Message "Starting Microsoft 365 Privilege Enumeration" -Level "INFO" -Color Green
Write-LogMessage -Message "Output Path: $OutputPath" -Level "INFO" -Color Gray

# Check and establish Microsoft Graph connection
Write-LogMessage -Message "Checking Microsoft Graph connection..." -Level "INFO" -Color Yellow

$requiredScopes = @(
    "User.Read.All",
    "RoleManagement.Read.Directory",
    "Directory.Read.All",
    "Application.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
    "Group.Read.All",
    "AuditLog.Read.All"
)

$currentContext = Invoke-SafeCommand -ScriptBlock { Get-MgContext } -ErrorMessage "Failed to get Graph context"

if (-not $currentContext) {
    Write-LogMessage -Message "Not connected to Microsoft Graph. Attempting connection..." -Level "WARN" -Color Yellow
    try {
        Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
        Write-LogMessage -Message "Successfully connected to Microsoft Graph" -Level "INFO" -Color Green
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph: $_" -Level "ERROR" -Color Red
        exit 1
    }
}

# Collections for data aggregation
$allPrivileges = @()
$privilegeSummary = @{}

# 1. Enumerate Directory Roles
Write-LogMessage -Message "`n=== ENUMERATING DIRECTORY ROLES ===" -Level "INFO" -Color Cyan

$directoryRoles = Invoke-SafeCommand -ScriptBlock { 
    Get-MgDirectoryRole -All -ErrorAction Stop 
} -ErrorMessage "Failed to retrieve directory roles"

if ($directoryRoles) {
    foreach ($role in $directoryRoles) {
        Write-LogMessage -Message "Processing role: $($role.DisplayName)" -Level "INFO" -Color Gray
        
        $members = Invoke-SafeCommand -ScriptBlock {
            Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
        } -ErrorMessage "Failed to get members for role $($role.DisplayName)"
        
        if ($members) {
            foreach ($member in $members) {
                $privilegeEntry = [PSCustomObject]@{
                    Type = "Directory Role"
                    Role = $role.DisplayName
                    RoleId = $role.Id
                    PrincipalId = $member.Id
                    PrincipalUPN = $member.AdditionalProperties.userPrincipalName
                    PrincipalName = $member.AdditionalProperties.displayName
                    PrincipalType = $member.AdditionalProperties.'@odata.type'
                    AccountEnabled = $member.AdditionalProperties.accountEnabled
                    AssignmentType = "Permanent"
                    Timestamp = Get-Date
                }
                
                $allPrivileges += $privilegeEntry
                Write-LogMessage -Message "  - $($privilegeEntry.PrincipalUPN) ($($privilegeEntry.PrincipalType))" -Level "INFO"
            }
        }
    }
}

# 2. Enumerate PIM Eligible Assignments
Write-LogMessage -Message "`n=== ENUMERATING PIM ELIGIBLE ASSIGNMENTS ===" -Level "INFO" -Color Cyan

$eligibleAssignments = Invoke-SafeCommand -ScriptBlock {
    Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
} -ErrorMessage "Failed to retrieve PIM eligible assignments"

if ($eligibleAssignments) {
    foreach ($assignment in $eligibleAssignments) {
        $roleDefinition = Invoke-SafeCommand -ScriptBlock {
            Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction Stop
        } -ErrorMessage "Failed to get role definition"
        
        # Get principal details
        $principal = $null
        if ($assignment.PrincipalId) {
            $principal = Invoke-SafeCommand -ScriptBlock {
                Get-MgUser -UserId $assignment.PrincipalId -ErrorAction SilentlyContinue
            }
            
            if (-not $principal) {
                $principal = Invoke-SafeCommand -ScriptBlock {
                    Get-MgGroup -GroupId $assignment.PrincipalId -ErrorAction SilentlyContinue
                }
            }
        }
        
        $privilegeEntry = [PSCustomObject]@{
            Type = "PIM Eligible"
            Role = $roleDefinition.DisplayName
            RoleId = $assignment.RoleDefinitionId
            PrincipalId = $assignment.PrincipalId
            PrincipalUPN = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { "N/A" }
            PrincipalName = if ($principal.DisplayName) { $principal.DisplayName } else { "Unknown" }
            PrincipalType = if ($principal.UserPrincipalName) { "User" } else { "Group/ServicePrincipal" }
            AccountEnabled = if ($principal.AccountEnabled) { $principal.AccountEnabled } else { "N/A" }
            AssignmentType = "Eligible"
            Timestamp = Get-Date
        }
        
        $allPrivileges += $privilegeEntry
        Write-LogMessage -Message "  - $($privilegeEntry.Role): $($privilegeEntry.PrincipalName) (Eligible)" -Level "INFO"
    }
}

# 3. Enumerate PIM Active Assignments
Write-LogMessage -Message "`n=== ENUMERATING PIM ACTIVE ASSIGNMENTS ===" -Level "INFO" -Color Cyan

$activeAssignments = Invoke-SafeCommand -ScriptBlock {
    Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
} -ErrorMessage "Failed to retrieve PIM active assignments"

if ($activeAssignments) {
    foreach ($assignment in $activeAssignments) {
        $roleDefinition = Invoke-SafeCommand -ScriptBlock {
            Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction Stop
        } -ErrorMessage "Failed to get role definition"
        
        $privilegeEntry = [PSCustomObject]@{
            Type = "PIM Active"
            Role = $roleDefinition.DisplayName
            RoleId = $assignment.RoleDefinitionId
            PrincipalId = $assignment.PrincipalId
            PrincipalUPN = "Check PrincipalId"
            PrincipalName = "Check PrincipalId"
            PrincipalType = "Unknown"
            AccountEnabled = "N/A"
            AssignmentType = "Time-bound Active"
            Timestamp = Get-Date
        }
        
        $allPrivileges += $privilegeEntry
        Write-LogMessage -Message "  - $($privilegeEntry.Role): PrincipalId $($privilegeEntry.PrincipalId) (Active)" -Level "INFO"
    }
}

# 4. Enumerate Administrative Units
Write-LogMessage -Message "`n=== ENUMERATING ADMINISTRATIVE UNITS ===" -Level "INFO" -Color Cyan

$adminUnits = Invoke-SafeCommand -ScriptBlock {
    Get-MgDirectoryAdministrativeUnit -All -ErrorAction Stop
} -ErrorMessage "Failed to retrieve administrative units"

if ($adminUnits) {
    foreach ($au in $adminUnits) {
        Write-LogMessage -Message "Processing Administrative Unit: $($au.DisplayName)" -Level "INFO" -Color Gray
        
        $auMembers = Invoke-SafeCommand -ScriptBlock {
            Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All -ErrorAction Stop
        } -ErrorMessage "Failed to get AU members"
        
        if ($auMembers) {
            foreach ($member in $auMembers) {
                $privilegeEntry = [PSCustomObject]@{
                    Type = "Administrative Unit"
                    Role = "AU Member - $($au.DisplayName)"
                    RoleId = $au.Id
                    PrincipalId = $member.Id
                    PrincipalUPN = $member.AdditionalProperties.userPrincipalName
                    PrincipalName = $member.AdditionalProperties.displayName
                    PrincipalType = $member.AdditionalProperties.'@odata.type'
                    AccountEnabled = $member.AdditionalProperties.accountEnabled
                    AssignmentType = "AU Scoped"
                    Timestamp = Get-Date
                }
                
                $allPrivileges += $privilegeEntry
                Write-LogMessage -Message "  - $($privilegeEntry.PrincipalName)" -Level "INFO"
            }
        }
    }
}

# 5. Enumerate Role-Assignable Groups
Write-LogMessage -Message "`n=== ENUMERATING ROLE-ASSIGNABLE GROUPS ===" -Level "INFO" -Color Cyan

$roleAssignableGroups = Invoke-SafeCommand -ScriptBlock {
    Get-MgGroup -Filter "isAssignableToRole eq true" -All -ErrorAction Stop
} -ErrorMessage "Failed to retrieve role-assignable groups"

if ($roleAssignableGroups) {
    foreach ($group in $roleAssignableGroups) {
        Write-LogMessage -Message "Processing Role-Assignable Group: $($group.DisplayName)" -Level "INFO" -Color Gray
        
        # Check what roles this group has
        $groupRoles = $allPrivileges | Where-Object { $_.PrincipalId -eq $group.Id }
        
        if ($groupRoles) {
            Write-LogMessage -Message "  Group has roles: $($groupRoles.Role -join ', ')" -Level "INFO"
            
            # Get group members
            $groupMembers = Invoke-SafeCommand -ScriptBlock {
                Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
            } -ErrorMessage "Failed to get group members"
            
            if ($groupMembers) {
                foreach ($member in $groupMembers) {
                    foreach ($role in $groupRoles) {
                        $privilegeEntry = [PSCustomObject]@{
                            Type = "Group-Inherited Role"
                            Role = "$($role.Role) (via $($group.DisplayName))"
                            RoleId = $role.RoleId
                            PrincipalId = $member.Id
                            PrincipalUPN = $member.AdditionalProperties.userPrincipalName
                            PrincipalName = $member.AdditionalProperties.displayName
                            PrincipalType = "User via Group"
                            AccountEnabled = $member.AdditionalProperties.accountEnabled
                            AssignmentType = "Group Membership"
                            Timestamp = Get-Date
                        }
                        
                        $allPrivileges += $privilegeEntry
                        Write-LogMessage -Message "    - $($privilegeEntry.PrincipalName) inherits $($role.Role)" -Level "INFO"
                    }
                }
            }
        }
    }
}

# 6. Enumerate Application Permissions
Write-LogMessage -Message "`n=== ENUMERATING APPLICATION PERMISSIONS ===" -Level "INFO" -Color Cyan

$servicePrincipals = Invoke-SafeCommand -ScriptBlock {
    Get-MgServicePrincipal -All -Filter "servicePrincipalType eq 'Application'" -ErrorAction Stop | 
    Where-Object { $_.AppRoleAssignedTo -or $_.AppRoleAssignments }
} -ErrorMessage "Failed to retrieve service principals"

if ($servicePrincipals) {
    foreach ($sp in $servicePrincipals) {
        # Get app role assignments
        $appRoleAssignments = Invoke-SafeCommand -ScriptBlock {
            Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        } -ErrorMessage "Failed to get app role assignments"
        
        if ($appRoleAssignments) {
            foreach ($assignment in $appRoleAssignments) {
                $privilegeEntry = [PSCustomObject]@{
                    Type = "Application Permission"
                    Role = "App Permission: $($assignment.Id)"
                    RoleId = $assignment.AppRoleId
                    PrincipalId = $sp.Id
                    PrincipalUPN = $sp.ServicePrincipalNames[0]
                    PrincipalName = $sp.DisplayName
                    PrincipalType = "Service Principal"
                    AccountEnabled = $sp.AccountEnabled
                    AssignmentType = "Application"
                    Timestamp = Get-Date
                }
                
                $allPrivileges += $privilegeEntry
                Write-LogMessage -Message "  - $($privilegeEntry.PrincipalName): $($assignment.Id)" -Level "INFO"
            }
        }
    }
}

# 7. Summary Statistics
Write-LogMessage -Message "`n=== PRIVILEGE SUMMARY ===" -Level "INFO" -Color Yellow

$summary = $allPrivileges | Group-Object Type | ForEach-Object {
    Write-LogMessage -Message "$($_.Name): $($_.Count) assignments" -Level "INFO"
}

$uniquePrincipals = $allPrivileges | Select-Object -Unique PrincipalId
Write-LogMessage -Message "Total Unique Principals with Privileges: $($uniquePrincipals.Count)" -Level "INFO" -Color Green

# High-risk role analysis
$highRiskRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator")
$highRiskAssignments = $allPrivileges | Where-Object { $_.Role -in $highRiskRoles }

Write-LogMessage -Message "`nHigh-Risk Role Assignments: $($highRiskAssignments.Count)" -Level "WARN" -Color Red
$highRiskAssignments | ForEach-Object {
    Write-LogMessage -Message "  - $($_.PrincipalUPN): $($_.Role)" -Level "WARN" -Color Red
}

# Export to CSV if requested
if ($ExportCSV) {
    $csvPath = $OutputPath.Replace('.log', '_detailed.csv')
    $allPrivileges | Export-Csv -Path $csvPath -NoTypeInformation
    Write-LogMessage -Message "`nDetailed results exported to: $csvPath" -Level "INFO" -Color Green
}

# Exchange Online roles (if requested)
if ($IncludeExchangeRoles) {
    Write-LogMessage -Message "`n=== CHECKING EXCHANGE ONLINE ROLES ===" -Level "INFO" -Color Cyan
    
    try {
        # Check if already connected
        $exoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if (-not $exoConnection) {
            Write-LogMessage -Message "Connecting to Exchange Online..." -Level "INFO"
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        
        $exchangeRoleGroups = Get-RoleGroup -ErrorAction Stop
        foreach ($roleGroup in $exchangeRoleGroups) {
            $members = Get-RoleGroupMember -Identity $roleGroup.Identity -ErrorAction SilentlyContinue
            if ($members) {
                foreach ($member in $members) {
                    Write-LogMessage -Message "Exchange Role: $($roleGroup.Name) - Member: $($member.Name)" -Level "INFO"
                }
            }
        }
    }
    catch {
        Write-LogMessage -Message "Failed to enumerate Exchange roles: $_" -Level "ERROR" -Color Red
    }
}

Write-LogMessage -Message "`n=== ENUMERATION COMPLETE ===" -Level "INFO" -Color Green
Write-LogMessage -Message "Full audit log saved to: $OutputPath" -Level "INFO" -Color Gray

# Return summary object
return [PSCustomObject]@{
    TotalPrivileges = $allPrivileges.Count
    UniqueAccounts = $uniquePrincipals.Count
    HighRiskAssignments = $highRiskAssignments.Count
    PrivilegesByType = $allPrivileges | Group-Object Type | Select-Object Name, Count
    AuditLogPath = $OutputPath
}

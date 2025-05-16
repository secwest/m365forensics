###############################################################################
# Windows 11 Pro Hardening Script - Self-elevating and PowerShell 7 compatible
# This script will:
# 1. Check for administrative privileges
# 2. Install PowerShell 7 if needed
# 3. Launch the hardening portion with PowerShell 7
#
# USAGE: powershell.exe -ExecutionPolicy Bypass -File .\Windows11Pro-Hardening.ps1
###############################################################################

param()

# ========================================================================================
# BOOTSTRAP SECTION - PowerShell 5.1 Compatible
# ========================================================================================

# Check if already in PowerShell 7 with admin rights
$inPs7 = $PSVersionTable.PSVersion.Major -ge 7
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Self-elevate if not running as admin
if (-not $isAdmin) {
    Write-Host "Requesting administrative privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# If in PS5.1 (or older) with admin rights, need to switch to PS7
if (-not $inPs7 -and $isAdmin) {
    Write-Host "Current PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "This script works best with PowerShell 7+" -ForegroundColor Yellow
    
    # Check if PS7 is already installed
    $ps7Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (-not (Test-Path $ps7Path)) {
        Write-Host "Installing PowerShell 7..." -ForegroundColor Yellow
        
        try {
            # Try using winget (Windows 10/11)
            winget install Microsoft.PowerShell --architecture x64 --accept-source-agreements --accept-package-agreements --disable-interactivity --silent
            Start-Sleep -Seconds 2
        }
        catch {
            Write-Host "Winget failed, trying direct MSI download..." -ForegroundColor Yellow
            
            # Alternative: Direct download of MSI
            $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/PowerShell-7.3.4-win-x64.msi"
            $msiPath = "$env:TEMP\PowerShell-7.msi"
            
            # Download MSI
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
            
            # Install MSI silently
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /quiet /norestart" -Wait
            Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Check if PS7 was installed successfully
    if (Test-Path $ps7Path) {
        Write-Host "Relaunching script with PowerShell 7..." -ForegroundColor Green
        # Launch the same script with PS7
        Start-Process -FilePath $ps7Path -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Wait
        exit
    }
    else {
        Write-Host "PowerShell 7 installation failed. Attempting to continue with PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Red
        # Let script continue to hardening section (though it might fail)
    }
}

# ========================================================================================
# MAIN HARDENING SECTION - PowerShell 7 Compatible
# ========================================================================================
Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║                 WINDOWS 11 PRO HARDENING SCRIPT                ║
║                                                                ║
║  This script applies Microsoft security baseline and           ║
║  additional hardening measures to your Windows 11 Pro system.  ║
║                                                                ║
║  PowerShell Version: $($PSVersionTable.PSVersion.ToString())
║  Running as Administrator: Yes                                 ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# -- Global variables ---------------------------------------------------------
$BaselineUrl = 'https://drive.google.com/uc?export=download&id=13AoBqDA_O07-PhrpTJpzdU1b2oS8rD11'
$BaselineSha = '2E3A61D0245C16BEA51A9EE78CBF0793C88046901CECC0039DB0DC84FAE7D7B7'
$LgpoUrl     = 'https://drive.google.com/uc?export=download&id=1Z9Jd1h4grAF8GSCevRxeUFQ8hy2AVBOO'
$LgpoSha     = 'CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55'

$BaselineZip = "$env:TEMP\Win11Baseline.zip"
$LgpoZip     = "$env:TEMP\LGPO.zip"
$ExtractDir  = "$env:TEMP\Win11Baseline"
$LgpoExtractDir = "$env:TEMP\LGPO_Extract"
$recoveryPath = "C:\RecoveryKeys"

# -- Set up logging -----------------------------------------------------------
$logDir = 'C:\HardeningLogs'
if (-not (Test-Path $logDir)) {
    New-Item $logDir -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "HardeningLog-$timestamp.txt"
$transcriptFile = Join-Path $logDir "Transcript-$timestamp.txt"

# Start transcript
Start-Transcript -Path $transcriptFile -Force | Out-Null

# -- Helper functions ---------------------------------------------------------
function Log {
    param($message, $type = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] "
    
    switch ($type) {
        "INFO" { 
            $logMessage += "[*] $message"
            Write-Host $logMessage 
        }
        "SUCCESS" { 
            $logMessage += "[+] $message"
            Write-Host $logMessage -ForegroundColor Green 
        }
        "WARN" { 
            $logMessage += "[!] $message"
            Write-Host $logMessage -ForegroundColor Yellow 
        }
        "ERROR" { 
            $logMessage += "[X] $message"
            Write-Host $logMessage -ForegroundColor Red 
        }
    }
    
    # Also log to file
    $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8
}

function RegSet {
    param($k, $n, $v, $t='DWord')
    try {
        if (-not (Test-Path $k)) {
            New-Item $k -Force -ErrorAction Stop | Out-Null
            Log "Created registry key: $k"
        }
        New-ItemProperty -Path $k -Name $n -Value $v -PropertyType $t -Force -ErrorAction Stop | Out-Null
        Log "Set registry value: $k\$n = $v"
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Failed to set registry value: $k\$n - $errMsg" "ERROR"
    }
}

function IsZip {
    param($path)
    try { 
        $bytes = [IO.File]::ReadAllBytes($path)
        if ($bytes.Length -lt 4) { return $false }
        
        # Check for ZIP signature (PK..)
        if ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and 
           $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
            return $true
        }
        return $false
    }
    catch { 
        $errMsg = $_.Exception.Message
        Log "Error checking if file is ZIP: $errMsg" "WARN"
        return $false 
    }
}

function DownloadWithRetry {
    param($url, $output, $maxRetries=3)
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            Log "Downloading $output (attempt $($retryCount+1)/$maxRetries)..."
            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction Stop
            $success = $true
        }
        catch {
            $retryCount++
            $errMsg = $_.Exception.Message
            if ($retryCount -ge $maxRetries) {
                Log "Failed to download after $maxRetries attempts: $errMsg" "ERROR"
                return $false
            }
            Log "Download attempt $retryCount failed, retrying in 5 seconds..." "WARN"
            Start-Sleep -Seconds 5
        }
    }
    return $true
}

function CheckTpm {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if (-not $tpm.TpmPresent) {
            Log "TPM not present - BitLocker with TPM+PIN not possible" "ERROR"
            return $false
        }
        if (-not $tpm.TpmReady) {
            Log "TPM present but not ready - attempting to initialize" "WARN"
            try {
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop | Out-Null
                $tpm = Get-Tpm
                if (-not $tpm.TpmReady) {
                    Log "Could not initialize TPM" "ERROR"
                    return $false
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Log "Error initializing TPM: $errMsg" "ERROR"
                return $false
            }
        }
        Log "TPM is ready" "SUCCESS"
        return $true
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Error checking TPM: $errMsg" "ERROR"
        return $false
    }
}

function VerifyHardening {
    Log "Verifying hardening settings..." "INFO"
    
    # Check BitLocker
    try {
        $blv = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'ProtectionOn') {
            Log "BitLocker enabled on C: drive" "SUCCESS"
        }
        else {
            Log "BitLocker not enabled on C: drive" "WARN"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Could not verify BitLocker status: $errMsg" "WARN"
    }
    
    # Check TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmReady) {
            Log "TPM is ready" "SUCCESS"
        }
        else {
            Log "TPM not ready" "WARN"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Could not verify TPM status: $errMsg" "WARN"
    }
    
    # Check Device Guard
    try {
        $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop
        if ($dg.VirtualizationBasedSecurityStatus -eq 1) {
            Log "Virtualization-based security is running" "SUCCESS"
        }
        else {
            Log "Virtualization-based security is not running" "WARN"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Could not verify Device Guard status: $errMsg" "WARN"
    }
    
    # Check Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled) {
            Log "Defender real-time protection enabled" "SUCCESS"
        }
        else {
            Log "Defender real-time protection disabled" "WARN"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Could not verify Defender status: $errMsg" "WARN"
    }
    
    # Check AnyDesk firewall rule
    try {
        $fw = Get-NetFirewallRule -DisplayName "Hardening - AnyDesk TCP 7070" -ErrorAction SilentlyContinue
        if ($fw) {
            Log "AnyDesk firewall rule exists" "SUCCESS"
        }
        else {
            Log "AnyDesk firewall rule missing" "WARN"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Could not verify firewall rules: $errMsg" "WARN"
    }
}

# -- Main hardening section ---------------------------------------------------
try {
    Log "Starting Windows 11 Pro hardening" "INFO"
    Log "PowerShell version: $($PSVersionTable.PSVersion.ToString())" "INFO"
    Log "Transcript: $transcriptFile" "INFO"
    Log "Log file: $logFile" "INFO"

    # Create recovery key directory
    if (-not (Test-Path $recoveryPath)) {
        New-Item $recoveryPath -ItemType Directory -Force | Out-Null
        Log "Created BitLocker recovery key directory" "SUCCESS"
    }

    # -- Download and verify files --
    $skip = $false
    foreach ($d in @(
        @{n='Baseline'; u=$BaselineUrl; o=$BaselineZip; s=$BaselineSha},
        @{n='LGPO'; u=$LgpoUrl; o=$LgpoZip; s=$LgpoSha}
    )) {
        if (-not (DownloadWithRetry -url $d.u -output $d.o)) {
            $skip = $true
            break
        }
        
        if (-not (IsZip $d.o)) {
            Log "$($d.n) is not a valid ZIP file" "WARN"
            $skip = $true
            break
        }
        
        $hash = (Get-FileHash $d.o -Algorithm SHA256).Hash.ToUpper()
        if ($hash -ne $d.s) {
            Log "$($d.n) SHA-256 mismatch" "WARN"
            Log "Expected: $($d.s)" "WARN"
            Log "Actual:   $hash" "WARN"
            $skip = $true
            break
        }
        
        Log "$($d.n) downloaded and verified" "SUCCESS"
    }

    # -- Extract files and apply baseline --
    if (-not $skip) {
        # Create extraction directories
        if (-not (Test-Path $ExtractDir)) {
            New-Item $ExtractDir -ItemType Directory -Force | Out-Null
        } else {
            Remove-Item -Path $ExtractDir\* -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        if (-not (Test-Path $LgpoExtractDir)) {
            New-Item $LgpoExtractDir -ItemType Directory -Force | Out-Null
        } else {
            Remove-Item -Path $LgpoExtractDir\* -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Extract files
        try {
            Log "Extracting Baseline to $ExtractDir..." "INFO"
            Expand-Archive $BaselineZip -DestinationPath $ExtractDir -Force -ErrorAction Stop
            
            Log "Extracting LGPO to $LgpoExtractDir..." "INFO"
            Expand-Archive $LgpoZip -DestinationPath $LgpoExtractDir -Force -ErrorAction Stop
            Log "Files extracted successfully" "SUCCESS"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log "PowerShell extraction failed, trying tar.exe fallback: $errMsg" "WARN"
            try {
                tar.exe -xf $BaselineZip -C $ExtractDir 
                tar.exe -xf $LgpoZip -C $LgpoExtractDir
                Log "Files extracted using tar.exe" "SUCCESS"
            }
            catch {
                $errMsg = $_.Exception.Message
                Log "Both extraction methods failed: $errMsg" "ERROR"
                $skip = $true
            }
        }
        
        # Find LGPO executable
        if (-not $skip) {
            Log "Searching for LGPO executable..." "INFO"
            
            # Various search patterns for LGPO
            $lgpoSearchResults = @(
                # First try the exact path we now know exists in the zip
                (Get-ChildItem -Path "$LgpoExtractDir\LGPO_30" -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                # Then try these other paths as fallbacks
                (Get-ChildItem -Path $LgpoExtractDir -Recurse -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                (Get-ChildItem -Path $LgpoExtractDir -Recurse -Filter "LGPO" -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq "" -or $_.Extension -eq ".exe" }),
                (Get-ChildItem -Path $ExtractDir -Recurse -Filter "LGPO.exe" -File -ErrorAction SilentlyContinue),
                (Get-ChildItem -Path $ExtractDir -Recurse -Filter "LGPO" -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq "" -or $_.Extension -eq ".exe" })
            )
            
            $lgpoExe = $null
            foreach ($result in $lgpoSearchResults) {
                if ($result.Count -gt 0) {
                    $lgpoExe = $result[0].FullName
                    break
                }
            }
            
            if ($lgpoExe) {
                Log "Found LGPO executable at: $lgpoExe" "SUCCESS"
                
                # Output the exact command that will be run
                Log "Will execute: & '$lgpoExe' /g <gpoDir>" "INFO"
                
                # Find GPO directory
                Log "Searching for GPO directory..." "INFO"
                $gpoSearchResults = @(
                    (Get-ChildItem -Path $ExtractDir -Recurse -Filter "MSFT-Win11-23H2-FINAL" -Directory -ErrorAction SilentlyContinue),
                    (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "MSFT-Win11*" }),
                    (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Win11*" -and $_.FullName -match "GPOs" }),
                    (Get-ChildItem -Path $ExtractDir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "GPOs" })
                )
                
                $gpoDir = $null
                foreach ($result in $gpoSearchResults) {
                    if ($result.Count -gt 0) {
                        $gpoDir = $result[0].FullName
                        break
                    }
                }
                
                if ($gpoDir) {
                    Log "Found GPO directory at: $gpoDir" "SUCCESS"
                    
                    # Apply baseline
                    Log "Applying security baseline..." "INFO"
                    Log "Command to execute: & '$lgpoExe' /g '$gpoDir'" "INFO"
                    try {
                        # Use Start-Process for more controlled execution
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName = $lgpoExe
                        $psi.Arguments = "/g `"$gpoDir`""
                        $psi.UseShellExecute = $false
                        $psi.RedirectStandardOutput = $true
                        $psi.RedirectStandardError = $true
                        
                        $process = [System.Diagnostics.Process]::Start($psi)
                        $stdout = $process.StandardOutput.ReadToEnd()
                        $stderr = $process.StandardError.ReadToEnd()
                        $process.WaitForExit()
                        
                        if ($process.ExitCode -eq 0) {
                            Log "Security baseline applied successfully" "SUCCESS"
                        } else {
                            Log "LGPO exited with code $($process.ExitCode)" "WARN"
                            if ($stdout) { Log "LGPO output: $stdout" "INFO" }
                            if ($stderr) { Log "LGPO errors: $stderr" "ERROR" }
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Log "Failed to apply security baseline: $errMsg" "ERROR"
                    }
                }
                else {
                    Log "Could not find GPO directory" "ERROR"
                }
            }
            else {
                Log "Could not find LGPO executable" "ERROR"
            }
        }
    }

    # -- BitLocker --
    Log "Checking BitLocker status..." "INFO"
    try {
        $blvStatus = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        if ($blvStatus.ProtectionStatus -ne 'ProtectionOn') {
            Log "BitLocker not enabled on C: drive, proceeding with setup" "INFO"
            
            if (CheckTpm) {
                $validPin = $false
                while (-not $validPin) {
                    $pin = Read-Host "Enter numeric BitLocker PIN (6-20 digits)" -AsSecureString
                    
                    # Convert SecureString to plain text for validation
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin)
                    $pinText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                    
                    # Match exactly 6-20 digits
                    if ($pinText -match "^\d{6,20}$") {
                        $validPin = $true
                    }
                    else {
                        Log "PIN must be 6-20 digits, numeric only" "WARN"
                    }
                }
                
                try {
                    Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                                 -TPMandPinProtector -Pin $pin -RecoveryKeyPath $recoveryPath -ErrorAction Stop
                    Log "BitLocker enabled successfully" "SUCCESS"
                    Log "BitLocker keys -> $recoveryPath (move offline IMMEDIATELY)" "WARN"
                }
                catch {
                    $errMsg = $_.Exception.Message
                    Log "Failed to enable BitLocker: $errMsg" "ERROR"
                }
            }
            else {
                Log "Skipping BitLocker - TPM requirements not met" "WARN"
            }
        }
        else {
            Log "BitLocker already enabled on C: drive" "SUCCESS"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Log "Error checking BitLocker status: $errMsg" "ERROR"
    }

    # -- Verification --
    VerifyHardening

    # -- Completion --
    $bannerText = @"
╔════════════════════════════════════════════════════════════════╗
║                 HARDENING COMPLETE                             ║
║                                                                ║
║  Please follow these steps:                                    ║
║                                                                ║
║  1. Copy BitLocker recovery keys:                              ║
║     -> C:\RecoveryKeys to offline media                        ║
║                                                                ║
║  2. Reboot TWICE (required for VBS/Credential Guard)           ║
║                                                                ║
║  3. Verify settings with these commands:                       ║
║     Get-BitLockerVolume                                        ║
║     Get-TPM                                                    ║
║     Get-CimInstance Win32_DeviceGuard                          ║
║     Get-MpComputerStatus                                       ║
║                                                                ║
║  Logs saved:                                                   ║
║     Console Log: $logFile                                      ║
║     Transcript: $transcriptFile                                ║
╚════════════════════════════════════════════════════════════════╝
"@

    Write-Host $bannerText -ForegroundColor Green
    
    # Add summary to log file
    @"

============================================================
SUMMARY
============================================================
- Hardening completed at: $(Get-Date)
- Console log saved to: $logFile
- PowerShell transcript saved to: $transcriptFile
- BitLocker recovery key location: $recoveryPath

IMPORTANT: 
1. Copy BitLocker recovery keys to offline media
2. Reboot TWICE to fully activate all settings
3. Run verification commands to confirm settings
============================================================
"@ | Out-File -FilePath $logFile -Append -Encoding utf8

}
catch {
    $errMsg = $_.Exception.Message
    Log "Uncaught error: $errMsg" "ERROR"
    Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
}
finally {
    Stop-Transcript
    Log "Script execution completed" "INFO"
}

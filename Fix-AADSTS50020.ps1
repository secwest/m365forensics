# Extended script with Office activation cleanup
# Run as Administrator for full effectiveness

# Function to remove Office licenses
function Remove-OfficeLicenses {
    $officePath = "${env:ProgramFiles(x86)}\Microsoft Office\Office16"
    if (-not (Test-Path $officePath)) {
        $officePath = "$env:ProgramFiles\Microsoft Office\Office16"
    }
    
    if (Test-Path $officePath) {
        Set-Location $officePath
        
        # List current licenses
        cscript ospp.vbs /dstatus
        
        # Remove all product keys
        $keys = cscript ospp.vbs /dstatus | Select-String "Last 5 characters of installed product key:" | ForEach-Object {
            ($_ -split ":")[1].Trim()
        }
        
        foreach ($key in $keys) {
            if ($key) {
                cscript ospp.vbs /unpkey:$key
            }
        }
    }
}

# Main cleanup
try {
    # All previous commands from the first script
    # ... (include all commands from above)
    
    # Additional Office cleanup if needed
    $response = Read-Host "Do you need to clear Office activation as well? (Y/N)"
    if ($response -eq 'Y') {
        Remove-OfficeLicenses
        
        # Clear additional Office registry keys
        $officeKeys = @(
            "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing",
            "HKCU:\Software\Microsoft\Office\16.0\Common\ServicesManagerCache"
        )
        
        foreach ($key in $officeKeys) {
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Write-Host "Cleanup completed successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
}

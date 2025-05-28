function Test-DisallowExploitProtectionOverride {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.91.2.1",
        "DisallowExploitProtectionOverride",
        "Ensure 'DisallowExploitProtectionOverride' is set to '1'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
        $regName = "DisallowExploitProtectionOverride"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $expectedValue"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $expectedValue"
                }
            } else {
                $check.Status = "FAIL"
                $check.Details = "$regName does not exist"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "Registry path does not exist: $regPath"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking registry: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

Export-ModuleMember -Function Test-*

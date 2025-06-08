using module .\SharedTypes.psm1

# Audit functions

function Test-LockoutBadCount {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.2.2",
        "LockoutBadCount",
        "Ensure 'LockoutBadCount' is from 1 to 5",
        7,
        "Lockout Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^LockoutBadCount\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -le 5 -and $value -gt 0) {
                $check.Status = "PASS"
                $check.Details = "Account lockout threshold is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Account lockout threshold is set to $value (Recommend from 1 to 5)"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "LockoutBadCount not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking LockoutBadCount: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-AllowAdministratorLockout {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.2.3",
        "AllowAdministratorLockout",
        "Ensure 'AllowAdministratorLockout' is set to '1'",
        7,
        "Lockout Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^AllowAdministratorLockout\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -eq 1) {
                $check.Status = "PASS"
                $check.Details = "AllowAdministratorLockout is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "AllowAdministratorLockout is set to $value, expected '1'"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "AllowAdministratorLockout not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking AllowAdministratorLockout: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-ResetLockoutCount {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.2.4",
        "ResetLockoutCount",
        "Ensure 'ResetLockoutCount' is set to 15 minutes or more",
        5,
        "Lockout Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^ResetLockoutCount\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -ge 15) {
                $check.Status = "PASS"
                $check.Details = "ResetLockoutCount is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "ResetLockoutCount is set to $value, recommend at least 15"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "ResetLockoutCount not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking ResetLockoutCount: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-LockoutDuration {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.2.1",
        "LockoutDuration",
        "Ensure 'LockoutDuration' is set to 15 minutes or more",
        5,
        "Lockout Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^LockoutDuration\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -ge 15) {
                $check.Status = "PASS"
                $check.Details = "LockoutDuration is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "LockoutDuration is set to $value, recommend at least 15"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "LockoutDuration not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking LockoutDuration: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

Export-ModuleMember -Function Test-*

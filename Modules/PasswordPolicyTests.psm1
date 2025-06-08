using module .\SharedTypes.psm1

# Audit functions

function Test-MinimumPasswordLength {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.4",
        "MinimumPasswordLength",
        "Minimum password length should be at least 14 characters",
        7,
        "Password Policy"
    )
    
    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^MinimumPasswordLength\s*=" }
        
        if ($line) {
            $length = [int]($line -split "=")[1].Trim()
            if ($length -ge 14) {
                $check.Status = "PASS"
                $check.Details = "Minimum password length is set to $length characters"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Minimum password length is set to $length characters (Required: 14 or more)"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "Minimum password length policy not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking minimum password length: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-PasswordComplexity {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.5",
        "PasswordComplexity",
        "Password must meet complexity requirements",
        7,
        "Password Policy"
    )
    
    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^PasswordComplexity\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -eq 1) {
                $check.Status = "PASS"
                $check.Details = "Password complexity requirements are enabled"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Password complexity requirements are disabled"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "Password complexity policy not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking password complexity requirements: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-PasswordHistorySize {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.1",
        "PasswordHistorySize",
        "Ensure 'PasswordHistorySize' is set to 24 or more",
        7,
        "Password Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^PasswordHistorySize\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -ge 24) {
                $check.Status = "PASS"
                $check.Details = "PasswordHistorySize is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "PasswordHistorySize is set to $value, recommend at least 24"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "PasswordHistorySize not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking PasswordHistorySize: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-ClearTextPassword {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.7",
        "ClearTextPassword",
        "Ensure 'ClearTextPassword' is set to '0''",
        10,
        "Password Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^ClearTextPassword\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -eq 0) {
                $check.Status = "PASS"
                $check.Details = "ClearTextPassword is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "ClearTextPassword is set to $value, must set to 0"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "ClearTextPassword not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking ClearTextPassword: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-MaximumPasswordAge {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.2",
        "MaximumPasswordAge",
        "Ensure 'MaximumPasswordAge' is set to 90 days or fewer'",
        7,
        "Password Policy"
    )

    try {
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^MaximumPasswordAge\s*=" }
        
        if ($line) {
            $value = [int]($line -split "=")[1].Trim()
            if ($value -ge 1 -and $value -le 90) {
                $check.Status = "PASS"
                $check.Details = "MaximumPasswordAge is set to $value"
            } else {
                $check.Status = "FAIL"
                $check.Details = "MaximumPasswordAge is set to $value, recommend 90 days or fewer"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "MaximumPasswordAge not found"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking MaximumPasswordAge: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

Export-ModuleMember -Function Test-*
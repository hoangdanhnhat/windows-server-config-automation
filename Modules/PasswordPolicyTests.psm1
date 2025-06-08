using module .\SharedTypes.psm1

# Audit functions

function Test-MinimumPasswordLength {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "1.1.4",
        "MinimumPasswordLength",
        "Minimum password length should be at least 14 characters",
        7,
        "Password Policy Test"
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
        "Password Policy Test"
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

Export-ModuleMember -Function Test-*
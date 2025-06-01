using module .\SharedTypes.psm1

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
                $check.Status = "ERROR"
                $check.Details = "$regName does not exist"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Registry path does not exist: $regPath"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking registry: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

function Test-RestrictRemoteSAM {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.10.11",
        "RestrictRemoteSAM",
        "Ensure 'DisallowExploitProtectionOverride' is set to 'O:BAG:BAD:(A;;RC;;;BA)'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "RestrictRemoteSAM"
        $expectedValue = "O:BAG:BAD:(A;;RC;;;BA)"
        
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
                $check.Status = "ERROR"
                $check.Details = "$regName does not exist"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Registry path does not exist: $regPath"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking registry: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

function Test-FilterAdministratorToken {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.1",
        "FilterAdministratorToken",
        "Ensure 'FilterAdministratorToken' is set to '1'",
        8,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "FilterAdministratorToken"
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
                $check.Status = "ERROR"
                $check.Details = "$regName does not exist"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Registry path does not exist: $regPath"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking registry: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

function Test-ConsentPromptBehaviorAdmin {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.2",
        "ConsentPromptBehaviorAdmin",
        "Ensure 'ConsentPromptBehaviorAdmin' is set to 1 or 2",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "ConsentPromptBehaviorAdmin"
        #expected value is [1,2]
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq 1 -or $value.$regName -eq 2) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected 1 or 2"
                }
            } else {
                $check.Status = "ERROR"
                $check.Details = "$regName does not exist"
            }
        } else {
            $check.Status = "ERROR"
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

# Windows Server Configuration Audit Tool
# Clean Version - No Complex String Operations

# Configuration Check Class
class ConfigCheck {
    [string]$CISID
    [string]$Name
    [string]$Description
    [int16]$Sensitivity  
    [string]$Status
    [string]$Details
    [string]$Category
    
    ConfigCheck([string]$CISID, [string]$name, [string]$desc, [int16]$Sensitivity, [string]$cat) {
        $this.CISID = $CISID
        $this.Name = $name
        $this.Description = $desc
        $this.Sensitivity = $Sensitivity
        $this.Category = $cat
        $this.Status = "NOT_CHECKED"
        $this.Details = ""
    }
}

# Results Class
class AuditResults {
    [System.Collections.ArrayList]$Checks
    [int]$Total
    [int]$Passed
    [int]$Failed
    [datetime]$StartTime
    
    AuditResults() {
        $this.Checks = New-Object System.Collections.ArrayList
        $this.StartTime = Get-Date
    }
    
    [void]AddCheck([ConfigCheck]$check) {
        $this.Checks.Add($check) | Out-Null
    }
    
    [void]UpdateStats() {
        $this.Total = $this.Checks.Count
        $this.Passed = ($this.Checks | Where-Object { $_.Status -eq "PASS" }).Count
        $this.Failed = ($this.Checks | Where-Object { $_.Status -eq "FAIL" }).Count
    }
}

# Check Functions
function Test-SeTcbPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.4",
        "SeTcbPrivilege", 
        "No accounts should have Act as part of OS privilege",
        10,
        "Security Privileges"
        )
    
    try {
        $privilege = "SeTcbPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with SeTcbPrivilege: $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have SeTcbPrivilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeIncreaseQuotaPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.6",
        "SeIncreaseQuotaPrivilege", 
        "Only approved accounts should have Adjust memory quotas privilege",
        7,
        "Security Privileges"
        )
    
    try {
        $privilege = "SeIncreaseQuotaPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544", 
                "*S-1-5-19", 
                "*S-1-5-20", 
                "Administrators", 
                "LOCAL SERVICE", 
                "NETWORK SERVICE"
                )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts: $($invalidAccounts -join ', ') | Full: $line"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have SeIncreaseQuotaPrivilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeBackupPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.11",
        "SeBackupPrivilege",
        "SeBackupPrivilege should be restricted",
        8,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeBackupPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",   # Administrators
                "Administrators", 
                "*S-1-5-32-551"    # Backup Operators
                )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts with '$privilege' are approved"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have '$privilege' privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeSystemTimePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.12",
        "SeSystemTimePrivilege",
        "Change the system time should be restricted",
        9,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeSystemTimePrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",   # Administrators
                "*S-1-5-19",       # LOCAL SERVICE
                "Administrators", 
                "LOCAL SERVICE"
                )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts with '$privilege' are approved"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have '$privilege' privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeTimeZonePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.13",
        "SeTimeZonePrivilege",
        "Change the time zone privilege should be restricted",
        1,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeTimeZonePrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",   # Administrators
                "*S-1-5-19",       # LOCAL SERVICE
                "Administrators",
                "BUILTIN\Administrators",
                "LOCAL SERVICE",
                "NT AUTHORITY\LOCAL SERVICE"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeCreatePagefilePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.14",
        "SeCreatePagefilePrivilege",
        "Create a pagefile privilege should be restricted",
        6,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeCreatePagefilePrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "BUILTIN\Administrators"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeCreateTokenPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.15",
        "SeCreateTokenPrivilege",
        "Create a token object privilege should not be assigned",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeCreateTokenPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeTrustedCredManAccessPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.1",
        "SeTrustedCredManAccessPrivilege",
        "Access Credential Manager as a trusted caller should not be assigned",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeTrustedCredManAccessPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeCreateGlobalPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.16",
        "SeCreateGlobalPrivilege",
        "Create global objects privilege should be restricted",
        7,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeCreateGlobalPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "*S-1-5-19",        # LOCAL SERVICE
                "*S-1-5-20",        # NETWORK SERVICE
                "*S-1-5-6",         # SERVICE
                "Administrators",
                "LOCAL SERVICE",
                "NETWORK SERVICE",
                "SERVICE"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeCreatePermanentPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.17",
        "SeCreatePermanentPrivilege",
        "Create permanent shared objects privilege should not be assigned",
        6,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeCreatePermanentPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeCreateSymbolicLinkPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.19",
        "SeCreateSymbolicLinkPrivilege",
        "Create symbolic links privilege should be restricted",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeCreateSymbolicLinkPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "NT VIRTUAL MACHINE\Virtual Machines"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeDebugPrivilege {
    param([AuditResults]$Results)

    $check = [ConfigCheck]::new(
        "2.2.20",
        "SeDebugPrivilege",
        "Debug privilege should be restricted",
        10,
        "Security Privileges"
    )

    try {
        $privilege = "SeDebugPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop

        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }

        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators"
            )
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}


function Test-SeDenyBatchLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.23",
        "SeDenyBatchLogonRight",
        "Deny log on as batch job should include Guests",
        5,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeDenyBatchLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-546",    # Guests
                "Guests",
                "BUILTIN\Guests"
            )
            
            if ($accounts | Where-Object { $_ -in $validAccounts }) {
                $check.Status = "PASS"
                $check.Details = "Guests group is denied batch logon"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Guests group is not denied batch logon. Current settings: $($accounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "No deny batch logon rights configured"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeDenyServiceLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.24",
        "SeDenyServiceLogonRight",
        "Deny log on as a service should include Guests",
        5,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeDenyServiceLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-546",    # Guests
                "Guests",
                "BUILTIN\Guests"
            )
            
            if ($accounts | Where-Object { $_ -in $validAccounts }) {
                $check.Status = "PASS"
                $check.Details = "Guests group is denied service logon"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Guests group is not denied service logon. Current settings: $($accounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "No deny service logon rights configured"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeEnableDelegationPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.29",
        "SeEnableDelegationPrivilege",
        "Enable computer and user accounts to be trusted for delegation should not be assigned",
        9,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeEnableDelegationPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeRemoteShutdownPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.30",
        "SeRemoteShutdownPrivilege",
        "Force shutdown from a remote system should be restricted",
        9,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeRemoteShutdownPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "BUILTIN\Administrators"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeAuditPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.31",
        "SeAuditPrivilege",
        "Generate security audits should be restricted",
        9,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeAuditPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-19",        # LOCAL SERVICE
                "*S-1-5-20",        # NETWORK SERVICE
                "LOCAL SERVICE",
                "NETWORK SERVICE",
                "NT AUTHORITY\LOCAL SERVICE",
                "NT AUTHORITY\NETWORK SERVICE"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeImpersonatePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.33",
        "SeImpersonatePrivilege",
        "Impersonate a client after authentication should be restricted",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeImpersonatePrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "*S-1-5-19",        # LOCAL SERVICE
                "*S-1-5-20",        # NETWORK SERVICE
                "*S-1-5-6",         # SERVICE
                "*S-1-5-32-568"     # IIS Users
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeIncreaseBasePriorityPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.34",
        "SeIncreaseBasePriorityPrivilege",
        "Increase scheduling priority should be restricted",
        8,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeIncreaseBasePriorityPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "*S-1-5-90-0",      # Window Manager
                "Window Manager\Window Manager Group"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeLoadDriverPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.35",
        "SeLoadDriverPrivilege",
        "Load and unload device drivers should be restricted",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeLoadDriverPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "BUILTIN\Administrators"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeLockMemoryPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.36",
        "SeLockMemoryPrivilege",
        "Lock pages in memory should not be assigned",
        9,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeLockMemoryPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeSecurityPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.39",
        "SeSecurityPrivilege",
        "Manage auditing and security log should be restricted (Member Server only)",
        10,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeSecurityPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "BUILTIN\Administrators"
            )
            
            $invalidAccounts = $accounts | Where-Object { $_ -notin $validAccounts }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeRelabelPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.40",
        "SeRelabelPrivilege",
        "Modify an object label should not be assigned",
        7,
        "Security Privileges"
    )
    
    try {
        $privilege = "SeRelabelPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Found accounts with $privilege : $line"
        } else {
            $check.Status = "PASS"
            $check.Details = "No accounts have $privilege"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking privilege: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

# Report Generation
function Show-Report {
    param([AuditResults]$Results)
    
    $Results.UpdateStats()
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "WINDOWS SERVER CONFIGURATION AUDIT REPORT" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "Scan Date: $($Results.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "SUMMARY:" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Host "Total Criteria Scanned: $($Results.Total)" -ForegroundColor White
    Write-Host "PASSED: $($Results.Passed)" -ForegroundColor Green
    Write-Host "FAILED: $($Results.Failed)" -ForegroundColor Red
    
    if ($Results.Total -gt 0) {
        $passRate = [math]::Round(($Results.Passed / $Results.Total) * 100, 1)
        $color = if($passRate -ge 80) { "Green" } elseif($passRate -ge 60) { "Yellow" } else { "Red" }
        Write-Host "Pass Rate: $passRate%" -ForegroundColor $color
    }
    
    Write-Host ""
    
    $failedChecks = $Results.Checks | Where-Object { $_.Status -eq "FAIL" }
    if ($failedChecks.Count -gt 0) {
        Write-Host "FAILED CRITERIA DETAILS:" -ForegroundColor Red
        Write-Host "----------------------------------------" -ForegroundColor Red
        
        foreach ($check in $failedChecks) {
            Write-Host ""
            Write-Host "X $($check.Name) - CISID: $($check.CISID) - Sensitivity: $($check.Sensitivity)" -ForegroundColor Red
            Write-Host "  Category: $($check.Category)" -ForegroundColor Gray
            Write-Host "  Description: $($check.Description)" -ForegroundColor Gray
            Write-Host "  Details: $($check.Details)" -ForegroundColor Yellow
        }
    }
    
    $passedChecks = $Results.Checks | Where-Object { $_.Status -eq "PASS" }
    if ($passedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "PASSED CRITERIA:" -ForegroundColor Green
        Write-Host "----------------------------------------" -ForegroundColor Green
        
        foreach ($check in $passedChecks) {
            Write-Host "V $($check.Name)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
}

function Export-ToCSV {
    param(
        [AuditResults]$Results,
        [string]$Path = "Reports\ServerAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    # Create Reports directory if it doesn't exist
    if (-not (Test-Path "Reports")) {
        New-Item -ItemType Directory -Path "Reports" | Out-Null
    }
    
    $Results.Checks | Select-Object Name, CISID, Category, Description, Sensitivity, Status, Details | Export-Csv -Path $Path -NoTypeInformation
    Write-Host "Results exported to: $Path" -ForegroundColor Cyan
}

function Start-Audit {
    param(
        [switch]$ExportCSV,
        [string]$CSVPath
    )
    
    Write-Host "Starting Windows Server Configuration Audit..." -ForegroundColor Green
    
    $results = [AuditResults]::new()
    
    Write-Host "Running security privilege checks..." -ForegroundColor Cyan
    Test-SeTcbPrivilege -Results $results
    Test-SeIncreaseQuotaPrivilege -Results $results
    Test-SeBackupPrivilege -Results $results
    Test-SeSystemTimePrivilege -Results $results
    Test-SeTimeZonePrivilege -Results $results
    Test-SeCreatePagefilePrivilege -Results $results
    Test-SeCreateTokenPrivilege -Results $results
    Test-SeTrustedCredManAccessPrivilege -Results $results
    Test-SeCreateGlobalPrivilege -Results $results
    Test-SeCreatePermanentPrivilege -Results $results
    Test-SeCreateSymbolicLinkPrivilege -Results $results
    Test-SeDebugPrivilege -Results $results
    Test-SeDenyBatchLogonRight -Results $results
    Test-SeDenyServiceLogonRight -Results $results
    Test-SeEnableDelegationPrivilege -Results $results
    Test-SeRemoteShutdownPrivilege -Results $results
    Test-SeAuditPrivilege -Results $results
    Test-SeImpersonatePrivilege -Results $results
    Test-SeIncreaseBasePriorityPrivilege -Results $results
    Test-SeLoadDriverPrivilege -Results $results
    Test-SeLockMemoryPrivilege -Results $results
    Test-SeSecurityPrivilege -Results $results
    Test-SeRelabelPrivilege -Results $results
    
    Show-Report -Results $results
    
    if ($ExportCSV) {
        if ($CSVPath) {
            # If custom path provided, ensure it's in the Reports folder
            $CSVPath = "Reports\$($CSVPath.TrimStart('\/'))"
            Export-ToCSV -Results $results -Path $CSVPath
        } else {
            Export-ToCSV -Results $results
        }
    }
    
    return $results
}

Write-Host "Windows Server Configuration Audit Tool Loaded" -ForegroundColor Green
Write-Host "Usage: Start-Audit or Start-Audit -ExportCSV" -ForegroundColor Yellow
Write-Host ""

Start-Audit -ExportCSV
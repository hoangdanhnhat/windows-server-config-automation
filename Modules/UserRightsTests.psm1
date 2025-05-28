# Check Functions
function Test-SeTcbPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.4",
        "SeTcbPrivilege", 
        "No accounts should have Act as part of OS privilege",
        10,
        "User Rights Test"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
            $check.Details = "No accounts have $privilege"
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

function Test-SeInteractiveLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.8",
        "SeInteractiveLogonRight",
        "Ensure 'Allow log on locally' is set to 'Administrators'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeInteractiveLogonRight"
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
            $check.Status = "FAIL"
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

function Test-SeRemoteInteractiveLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.10",
        "SeRemoteInteractiveLogonRight",
        "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeRemoteInteractiveLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "*S-1-5-32-555",    # Remote Desktop Users
                "Administrators",
                "Remote Desktop Users",
                "BUILTIN\Administrators",
                "BUILTIN\Remote Desktop Users"
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
            $check.Status = "FAIL"
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
            $check.Status = "FAIL"
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
            $check.Status = "FAIL"
            $check.Details = "No accounts have '$privilege'"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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

function Test-SeCreateTokenPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.15",
        "SeCreateTokenPrivilege",
        "Create a token object privilege should not be assigned",
        10,
        "User Rights Test"
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
        "User Rights Test"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
                "Guest",
                "BUILTIN\Guest"
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
        "User Rights Test"
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
                "Guest",
                "BUILTIN\Guest"
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

function Test-SeDenyNetworkLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.22",
        "SeDenyNetworkLogonRight",
        "Ensure 'Deny access to this computer from the network' includes 'Guests, Local account and member of Administrators group'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeDenyNetworkLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $requiredAccounts = @(
                "*S-1-5-32-546",    # Guests
                "*S-1-5-114",       # Local accounts and Members of the administrators group
                "Guests",
                "Local accounts and Members of the administrators group"
            )
            
            $missingAccounts = $requiredAccounts | Where-Object { 
                $req = $_
                -not ($accounts | Where-Object { $_ -like $req })
            }
            
            if ($missingAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "Required accounts are denied network logon"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Missing required accounts: $($missingAccounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "No deny network logon rights configured"
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

function Test-SeDenyInteractiveLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.25",
        "SeDenyInteractiveLogonRight",
        "Ensure 'Deny log on locally' includes 'Guests'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeDenyInteractiveLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $requiredAccounts = @(
                "*S-1-5-32-546",    # Guests
                "Guests",
                "BUILTIN\Guests"
            )
            
            if ($accounts | Where-Object { $_ -in $requiredAccounts }) {
                $check.Status = "PASS"
                $check.Details = "Guests group is denied interactive logon"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Guests group is not denied interactive logon. Current settings: $($accounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "No deny interactive logon rights configured"
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

function Test-SeDenyRemoteInteractiveLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.27",
        "SeDenyRemoteInteractiveLogonRight",
        "Ensure 'Deny log on through Remote Desktop Services' includes 'Guests, Local account'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeDenyRemoteInteractiveLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $requiredAccounts = @(
                "*S-1-5-32-546",    # Guests
                "*S-1-5-113",       # Local account
                "Guests",
                "Local account"
            )
            
            $missingAccounts = $requiredAccounts | Where-Object { 
                $req = $_
                -not ($accounts | Where-Object { $_ -like $req })
            }
            
            if ($missingAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "Required accounts are denied remote interactive logon"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Missing required accounts: $($missingAccounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
            $check.Details = "No deny remote interactive logon rights configured"
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
        "User Rights Test"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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
        "User Rights Test"
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
            $check.Status = "FAIL"
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
        "User Rights Test"
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

function Test-SeSystemEnvironmentPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.41",
        "SeSystemEnvironmentPrivilege",
        "Modify nonvolatile RAM environment values should be restricted to Administrators",
        9,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeSystemEnvironmentPrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeManageVolumePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.42",
        "SeManageVolumePrivilege",
        "Perform volume maintenance tasks should be restricted to Administrators",
        9,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeManageVolumePrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeProfileSingleProcessPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.43",
        "SeProfileSingleProcessPrivilege",
        "Profile single process privilege should be restricted to Administrators",
        7,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeProfileSingleProcessPrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeSystemProfilePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.44",
        "SeSystemProfilePrivilege",
        "Profile system performance privilege should be restricted to Administrators and WdiServiceHost",
        8,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeSystemProfilePrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "Administrators",
                "BUILTIN\Administrators",
                "*S-1-5-80-*",      # NT SERVICE\WdiServiceHost
                "NT SERVICE\WdiServiceHost"
            )
            
            $invalidAccounts = $accounts | Where-Object { 
                $acc = $_
                -not ($validAccounts | Where-Object { $acc -like $_ })
            }
            
            if ($invalidAccounts.Count -eq 0) {
                $check.Status = "PASS"
                $check.Details = "All accounts approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found: $($invalidAccounts -join ', ')"
            }
        } else {
            $check.Status = "FAIL"
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

function Test-SeAssignPrimaryTokenPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.45",
        "SeAssignPrimaryTokenPrivilege",
        "Ensure primary token privilege is restricted to LOCAL SERVICE and NETWORK SERVICE",
        8,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeAssignPrimaryTokenPrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeRestorePrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.46",
        "SeRestorePrivilege",
        "Restore privilege should be restricted to Administrators",
        9,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeRestorePrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeShutdownPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.47",
        "SeShutdownPrivilege",
        "System shutdown privilege should be restricted to Administrators",
        8,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeShutdownPrivilege"
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
            $check.Status = "FAIL"
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

function Test-SeTakeOwnershipPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.48",
        "SeTakeOwnershipPrivilege",
        "Take ownership privilege should be restricted to Administrators",
        9,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeTakeOwnershipPrivilege"
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
            $check.Status = "FAIL"
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


function Test-SeNetworkLogonRight {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.2.38",
        "SeNetworkLogonRight",
        "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'",
        5,
        "User Rights Test"
    )
    
    try {
        $privilege = "SeNetworkLogonRight"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @(
                "*S-1-5-32-544",    # Administrators
                "*S-1-5-11",        # Authenticated Users
                "Administrators",
                "Authenticated Users",
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
            $check.Status = "FAIL"
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

Export-ModuleMember -Function Test-*
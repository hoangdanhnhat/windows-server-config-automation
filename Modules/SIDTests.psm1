using module .\SharedTypes.psm1

# Audit function
function Test-GuestAccountStatus {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.1.1",
        "Guest Account Status",
        "Ensure Guest account is disabled",
        8,
        "Account Settings"
    )
    
    try {
        # Get Guest account information using WMI
        $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest'"
        
        if ($guestAccount) {
            if ($guestAccount.Disabled) {
                $check.Status = "PASS"
                $check.Details = "Guest account is properly disabled"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Guest account is enabled and should be disabled"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Could not locate Guest account"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking Guest account status: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

function Test-AdminAccountRenamed {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.1.3",
        "Administrator Account Name",
        "Ensure Administrator account has been renamed from its default name",
        8,
        "Account Settings"
    )
    
    try {
        # Check if running on a Domain Controller
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        
        if ($isDC) {
            # Domain Controller - use AD cmdlets
            if (!(Get-Module -Name ActiveDirectory)) {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            $adminAccount = Get-ADUser -Filter * -Properties SID | Where-Object { $_.SID.Value.EndsWith("-500") }
        } else {
            # Member server or workstation - use local user cmdlets
            $adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object -First 1
        }

        if ($adminAccount) {
            if ($isDC) {
                $accountName = $adminAccount.SamAccountName
            } else {
                $accountName = $adminAccount.Name
            }

            if ($accountName -ne "Administrator") {
                $check.Status = "PASS"
                $check.Details = "Administrator account has been renamed to: $accountName"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Administrator account is using default name and should be renamed"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Could not locate Administrator account"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking Administrator account name: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

function Test-GuestAccountRenamed {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.1.4",
        "Guest Account Name",
        "Ensure Guest account has been renamed from its default name",
        5,
        "Account Settings"
    )
    
    try {
        # Check if running on a Domain Controller
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        
        if ($isDC) {
            # Domain Controller - use AD cmdlets
            if (!(Get-Module -Name ActiveDirectory)) {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            $guestAccount = Get-ADUser -Filter * -Properties SID | Where-Object { $_.SID.Value.EndsWith("-501") }
        } else {
            # Member server or workstation - use local user cmdlets
            $guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" } | Select-Object -First 1
        }

        if ($guestAccount) {
            if ($isDC) {
                $accountName = $guestAccount.SamAccountName
            } else {
                $accountName = $guestAccount.Name
            }

            if ($accountName -ne "Guest") {
                $check.Status = "PASS"
                $check.Details = "Guest account has been renamed to: $accountName"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Guest account is using default name and should be renamed"
            }
        } else {
            $check.Status = "ERROR"
            $check.Details = "Could not locate Guest account"
        }
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking Guest account name: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

Export-ModuleMember -Function Test-*


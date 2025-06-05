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
        # Get Administrator account information using SID
        $adminSID = "S-1-5-21-*-500"
        $adminAccount = Get-WmiObject -Class Win32_UserAccount -Filter "SID like '$adminSID'"
        
        if ($adminAccount) {
            if ($adminAccount.Name -ne "Administrator") {
                $check.Status = "PASS"
                $check.Details = "Administrator account has been renamed"
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
        # Get Guest account information using SID
        $guestSID = "S-1-5-21-*-501"
        $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter "SID like '$guestSID'"
        
        if ($guestAccount) {
            if ($guestAccount.Name -ne "Guest") {
                $check.Status = "PASS"
                $check.Details = "Guest account has been renamed"
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


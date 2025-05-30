#!/usr/bin/env python3
"""
Windows Server Configuration Checks Definition File
This file contains all check definitions and custom PowerShell scripts
"""

from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class CheckDefinition:
    """Defines a configuration check to be performed"""
    check_id: str
    description: str
    category: str
    check_type: str  # 'privilege_not_assigned', 'privilege_restricted', 'custom'
    parameters: Dict[str, Any]
    recommendation: str = ""


# =============================================================================
# CHECK DEFINITIONS
# =============================================================================

CHECK_DEFINITIONS = [
    # Security Policy Checks
    CheckDefinition(
        check_id="2.2.4",
        description="Act as part of the operating system privilege should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={"privilege": "SeTcbPrivilege"},
        recommendation="Remove the 'SeTcbPrivilege' privilege from all accounts"
    ),
    
    CheckDefinition(
        check_id="2.2.6", 
        description="Adjust memory quotas for a process privilege should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege": "SeIncreaseQuotaPrivilege",
            "valid_accounts":["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"]
        },
        recommendation="Ensure only Administrators, LOCAL SERVICE, and NETWORK SERVICE have this privilege"
    ),

    CheckDefinition(
        check_id="2.2.11",
        description="SeBackupPrivilege should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeBackupPrivilege",
            "valid_accounts":["Administrators", "BUILTIN\Server Operators", "BUILTIN\Backup Operators"]        
        },
        recommendation="Ensure SeBackupPrivilege is set to Administrators"
    ),

    CheckDefinition(
        check_id="2.2.12",
        description="Change the system time should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeSystemTimePrivilege",
            "valid_accounts":["Administrators", "LOCAL SERVICE"]
        }
    ),

    CheckDefinition(
        check_id="2.2.13",
        description="Change the time zone should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeTimeZonePrivilege",
            "valid_accounts":["Administrators", "LOCAL SERVICE"]
        }
    ),

    CheckDefinition(
        check_id="2.2.14",
        description="Create a page file should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeCreatePagefilePrivilege",
            "valid_accounts":["Administrators"]
        }
    ),

    CheckDefinition(
        check_id="2.2.15",
        description="Create a token object should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege":"SeCreateTokenPrivilege",
        }
    ),

    CheckDefinition(
        check_id="2.2.1",
        description="Access Credential as a trusted caller should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege":"SeTrustedCredManAccessPrivilege",
        }  
    ),

    CheckDefinition(
        check_id="2.2.16",
        description="Create global object should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeCreateGlobalPrivilege",
            "valid_accounts":["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.17",
        description="Create permanent shared object should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege":"SeCreatePermanentPrivilege",
        }  
    ),

    CheckDefinition(
        check_id="2.2.19",
        description="Create symbolic links should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeCreateSymbolicLinkPrivilege",
            "valid_accounts": ["Administrators", "NT VIRTUAL MACHINE\Virtual machines"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.23",
        description="Deny log on as batch job should be include Guests",
        category="User Rights Test",
        check_type="privilege_denied",
        parameters={
            "privilege":"SeDenyBatchLogonRight",
            "valid_accounts": ["Guests"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.24",
        description="Deny log on as a service should include Guests",
        category="User Rights Test",
        check_type="privilege_denied",
        parameters={
            "privilege":"SeDenyServiceLogonRight",
            "valid_accounts": ["Guests"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.29",
        description="Enable computer and user accounts to be trusted for delegation should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege":"SeEnableDelegationPrivilege",
        }  
    ),

    CheckDefinition(
        check_id="2.2.30",
        description="Force shutdown from a remote system should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeRemoteShutdownPrivilege",
            "valid_accounts": ["Administrators"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.31",
        description="Generate security audits should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege":"SeAuditPrivilege",
            "valid_accounts": ["LOCAL SERVICE", "NETWORK SERVICE"]
        }  
    ),

    CheckDefinition(
        check_id="2.2.33",
        description="SeImpersonatePrivilege should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege": "SeImpersonatePrivilege",
            "valid_accounts": ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE", "IIS_IUSRS"]
        }
    ),

    CheckDefinition(
        check_id="2.2.34",
        description="Increase scheduling priority should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege": "SeIncreaseBasePriorityPrivilege",
            "valid_accounts": ["Administrators", "Window Manager\Window Manager Group"]
        }
    ),

    CheckDefinition(
        check_id="2.2.35",
        description="Load and unload device driver should be restricted",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege": "SeLoadDriverPrivilege",
            "valid_accounts": ["Administrators"]
        }
    ),

    CheckDefinition(
        check_id="2.2.36",
        description="Lock pages in memory should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege": "SeLockMemoryPrivilege",
        }
    ),

    CheckDefinition(
        check_id="2.2.39",
        description="Manage auditing and security log should be restricted (Member Server only)",
        category="User Rights Test",
        check_type="privilege_restricted",
        parameters={
            "privilege": "SeLockMemoryPrivilege",
            "valid_accounts": ["Administrators"]
        }
    ),

    CheckDefinition(
        check_id="2.2.40",
        description="Modify an object should not be assigned",
        category="User Rights Test",
        check_type="privilege_not_assigned",
        parameters={
            "privilege": "SeRelabelPrivilege",
        }
    ),

]


# =============================================================================
# CUSTOM POWERSHELL SCRIPTS
# =============================================================================

CUSTOM_SCRIPTS = {
    "check_password_length": '''
    try {
        secedit /export /cfg C:\\secpol.cfg | Out-Null
        $content = Get-Content C:\\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^MinimumPasswordLength\\s*=" }
        
        if ($line) {
            $length = ($line -split "=")[1].Trim()
            if ([int]$length -ge 8) {
                Write-Output "PASS"
            } else {
                Write-Output "FAIL"
                Write-Output "Current minimum password length: $length (Required: 8 or more)"
            }
        } else {
            Write-Output "FAIL"
            Write-Output "Minimum password length policy not found"
        }
    } catch {
        Write-Output "ERROR"
        Write-Output $_.Exception.Message
    }
    ''',
    
    "check_password_age": '''
    try {
        secedit /export /cfg C:\\secpol.cfg | Out-Null
        $content = Get-Content C:\\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^MaximumPasswordAge\\s*=" }
        
        if ($line) {
            $age = ($line -split "=")[1].Trim()
            if ([int]$age -le 90 -and [int]$age -gt 0) {
                Write-Output "PASS"
            } else {
                Write-Output "FAIL"
                Write-Output "Current maximum password age: $age days (Required: 1-90 days)"
            }
        } else {
            Write-Output "FAIL"
            Write-Output "Maximum password age policy not found"
        }
    } catch {
        Write-Output "ERROR"
        Write-Output $_.Exception.Message
    }
    ''',
    
    "check_audit_logon": '''
    try {
        $auditPolicy = auditpol /get /category:"Logon/Logoff" /r | ConvertFrom-Csv
        $logonEvents = $auditPolicy | Where-Object { $_.Subcategory -eq "Logon" }
        
        if ($logonEvents) {
            $setting = $logonEvents.'Inclusion Setting'
            if ($setting -eq "Success and Failure" -or $setting -eq "Success,Failure") {
                Write-Output "PASS"
            } else {
                Write-Output "FAIL"
                Write-Output "Current logon audit setting: $setting (Required: Success and Failure)"
            }
        } else {
            Write-Output "FAIL"
            Write-Output "Logon audit policy not found"
        }
    } catch {
        Write-Output "ERROR" 
        Write-Output $_.Exception.Message
    }
    ''',
    
    "check_unnecessary_services": '''
    try {
        # List of services that should typically be disabled on a secure server
        $unnecessaryServices = @(
            "Fax",
            "Messenger", 
            "NetMeeting Remote Desktop Sharing",
            "Remote Registry",
            "Routing and Remote Access",
            "Simple Mail Transfer Protocol (SMTP)",
            "Telnet",
            "World Wide Web Publishing Service"
        )
        
        $runningUnnecessary = @()
        
        foreach ($serviceName in $unnecessaryServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                $runningUnnecessary += $serviceName
            }
        }
        
        if ($runningUnnecessary.Count -eq 0) {
            Write-Output "PASS"
        } else {
            Write-Output "FAIL"
            Write-Output "Running unnecessary services: $($runningUnnecessary -join ', ')"
        }
    } catch {
        Write-Output "ERROR"
        Write-Output $_.Exception.Message
    }
    ''',
    
    "check_network_shares": '''
    try {
        $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }
        $systemShares = @("ADMIN$", "C$", "IPC$")
        $userShares = $shares | Where-Object { $_.Name -notin $systemShares }
        
        if ($userShares.Count -eq 0) {
            Write-Output "PASS"
        } else {
            Write-Output "FAIL"
            $shareNames = $userShares | ForEach-Object { $_.Name }
            Write-Output "Non-administrative shares found: $($shareNames -join ', ')"
            Write-Output "Review these shares and remove if not necessary"
        }
    } catch {
        Write-Output "ERROR"
        Write-Output $_.Exception.Message
    }
    '''
}


# =============================================================================
# HELPER FUNCTIONS FOR ADDING NEW CHECKS
# =============================================================================

def add_privilege_check(check_id: str, description: str, privilege: str, 
                       should_not_be_assigned: bool = True, valid_accounts: List[str] = None,
                       recommendation: str = ""):
    """
    Helper function to easily add new privilege checks
    
    Args:
        check_id: Unique identifier for the check
        description: Human readable description
        privilege: Windows privilege name (e.g., "SeDebugPrivilege")
        should_not_be_assigned: If True, privilege should not be assigned to anyone
        valid_accounts: List of accounts that can have this privilege (if should_not_be_assigned is False)
        recommendation: Recommendation text for failed checks
    """
    if should_not_be_assigned:
        check_type = "privilege_not_assigned"
        parameters = {"privilege": privilege}
    else:
        check_type = "privilege_restricted"
        parameters = {"privilege": privilege, "valid_accounts": valid_accounts or []}
    
    return CheckDefinition(
        check_id=check_id,
        description=description,
        category="Security Policy",
        check_type=check_type,
        parameters=parameters,
        recommendation=recommendation
    )


def add_custom_check(check_id: str, description: str, category: str,
                    script_name: str, powershell_script: str, recommendation: str = ""):
    """
    Helper function to easily add new custom checks
    
    Args:
        check_id: Unique identifier for the check
        description: Human readable description  
        category: Check category
        script_name: Name to reference the script
        powershell_script: PowerShell script content
        recommendation: Recommendation text for failed checks
    """
    # Add script to CUSTOM_SCRIPTS dictionary
    CUSTOM_SCRIPTS[script_name] = powershell_script
    
    return CheckDefinition(
        check_id=check_id,
        description=description,
        category=category,
        check_type="custom",
        parameters={"script_name": script_name},
        recommendation=recommendation
    )


# =============================================================================
# EXAMPLE OF HOW TO ADD NEW CHECKS
# =============================================================================

# Example 1: Add a new privilege check
# new_privilege_check = add_privilege_check(
#     check_id="SEC-999",
#     description="Create token privilege should not be assigned",
#     privilege="SeCreateTokenPrivilege", 
#     should_not_be_assigned=True,
#     recommendation="Remove SeCreateTokenPrivilege from all accounts"
# )
# CHECK_DEFINITIONS.append(new_privilege_check)

# Example 2: Add a new custom check
# new_custom_script = '''
# try {
#     # Your PowerShell code here
#     Write-Output "PASS"  # or "FAIL" with details
# } catch {
#     Write-Output "ERROR"
#     Write-Output $_.Exception.Message
# }
# '''
# 
# new_custom_check = add_custom_check(
#     check_id="CUS-001",
#     description="Custom security check description",
#     category="Custom Checks",
#     script_name="my_custom_check",
#     powershell_script=new_custom_script,
#     recommendation="Fix the custom issue"
# )
# CHECK_DEFINITIONS.append(new_custom_check)
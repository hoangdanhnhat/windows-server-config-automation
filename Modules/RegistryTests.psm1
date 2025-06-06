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

function Test-ConsentPromptBehaviorUser {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.3",
        "ConsentPromptBehaviorUser",
        "Ensure 'ConsentPromptBehaviorUser' is set 0",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "ConsentPromptBehaviorUser"
        $expectedValue = 0
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected 0"
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

function Test-EnableInstallerDetection {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.4",
        "EnableInstallerDetection",
        "Ensure 'EnableInstallerDetection' is set 1",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "EnableInstallerDetection"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

function Test-EnableSecureUIAPaths {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.5",
        "EnableSecureUIAPaths",
        "Ensure 'EnableSecureUIAPaths' is set 1",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "EnableSecureUIAPaths"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

function Test-EnableLUA {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.6",
        "EnableLUA",
        "Ensure 'EnableLUA' is set 1",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "EnableLUA"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

function Test-PromptOnSecureDesktop {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.7",
        "PromptOnSecureDesktop",
        "Ensure 'PromptOnSecureDesktop' is set 1",
        9,
        "Registry Test"
    )
      try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "PromptOnSecureDesktop"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

function Test-EnableVirtualization {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.17.8",
        "EnableVirtualization",
        "Ensure 'EnableVirtualization' is set to '1'",
        9,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "EnableVirtualization"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

function Test-RestrictDriverInstallationToAdministrators {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.7.10",
        "RestrictDriverInstallationToAdministrators",
        "Ensure 'RestrictDriverInstallationToAdministrators' is set to '1'",
        8,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $regName = "RestrictDriverInstallationToAdministrators"
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

function Test-fAllowUnsolicited {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.9.35.1",
        "fAllowUnsolicited",
        "Ensure 'fAllowUnsolicited' is set to '0'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services"
        $regName = "fAllowUnsolicited"
        $expectedValue = 0
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
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

function Test-fAllowToGetHelp {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.9.35.2",
        "fAllowToGetHelp",
        "Ensure 'fAllowToGetHelp' is set to '0'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services"
        $regName = "fAllowToGetHelp"
        $expectedValue = 0
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
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

function Test-EnumerateAdministrators {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.15.2",
        "EnumerateAdministrators",
        "Ensure 'EnumerateAdministrators' is set to '0'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
        $regName = "EnumerateAdministrators"
        $expectedValue = 0
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName is set to $($value.$regName)"
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

function Test-DisableOneSettingsDownloads {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.16.3",
        "DisableOneSettingsDownloads",
        "Ensure 'DisableOneSettingsDownloads' is set to '1'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        $regName = "DisableOneSettingsDownloads"
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

function Test-DoNotShowFeedbackNotifications {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.16.4",
        "DoNotShowFeedbackNotifications",
        "Ensure 'DoNotShowFeedbackNotifications' is set to '1'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        $regName = "DoNotShowFeedbackNotifications"
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

function Test-NoInplaceSharing {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "19.7.26.1",
        "NoInplaceSharing",
        "Ensure 'NoInplaceSharing' is set to '1'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $regName = "NoInplaceSharing"
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

function Test-LocalAccountFilterPolicy {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.4.1",
        "LocalAccountTokenFilterPolicy",
        "Ensure 'LocalAccountTokenFilterPolicy' is set to '0'",
        7,
        "Registry Test"
    )
    
    try {
        $regPath = "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "LocalAccountTokenFilterPolicy"
        $expectedValue = 0
        
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

function Test-InactivityTimeoutSecs {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.3",
        "InactivityTimeoutSecs",
        "Ensure 'InactivityTimeoutSecs' is greater than 0",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "InactivityTimeoutSecs"
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -gt 0) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value is greater than 0"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName)"
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

function Test-AutoDisconnect {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.9.1",
        "AutoDisconnect",
        "Ensure 'AutoDisconnect' is greater than 0",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "Registry::HKEY_USERS\*\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $regName = "InactivityTimeoutSecs"
        $expectedValue = 15
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -lt $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value is less than $($expectedValue)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected less than $($expectedValue)"
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

function Test-enableforcedlogoff {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.9.4",
        "enableforcedlogoff",
        "Ensure 'enableforcedlogoff' is set to 1",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "Registry::HKEY_USERS\*\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $regName = "enableforcedlogoff"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -lt $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value set to $($expectedValue)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue)"
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

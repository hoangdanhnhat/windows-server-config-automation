using module .\SharedTypes.psm1

function Test-DisallowExploitProtectionOverride {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.92.2.1",
        "DisallowExploitProtectionOverride",
        "Ensure 'DisallowExploitProtectionOverride' is set to '1'",
        9,
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
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
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
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
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
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
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
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
        "Ensure 'InactivityTimeoutSecs' is greater than 0 and less than 900",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "InactivityTimeoutSecs"
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -gt 0 -and $value.$regName -lt 900) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value is greater than 0 and smaller than 900"
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
        "Ensure 'AutoDisconnect' value is less than 15 minutes",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $regName = "AutoDisconnect"
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
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $regName = "enableforcedlogoff"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-LimitBlankPasswordUse {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.1.2",
        "LimitBlankPasswordUse",
        "Ensure 'LimitBlankPasswordUse' is set to '1'",
        8,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "LimitBlankPasswordUse"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-DontDisplayLastUserName {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.2",
        "DontDisplayLastUserName",
        "Ensure 'DontDisplayLastUserName' is set to '1'",
        7,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "DontDisplayLastUserName"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-DisableCAD {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.1",
        "DisableCAD",
        "Ensure 'DisableCAD' is set to '0'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "DisableCAD"
        $expectedValue = 0
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-LegalNoticeText {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.4",
        "LegalNoticeText",
        "Ensure 'LegalNoticeText' is set",
        2,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "LegalNoticeText"
        $notExpectedValue = ''
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -ne $notExpectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is not set"
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

function Test-LegalNoticeCaption {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.5",
        "LegalNoticeCaption",
        "Ensure 'LegalNoticeCaption' is set",
        2,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "LegalNoticeCaption"
        $notExpectedValue = ''
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -ne $notExpectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value is set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is not set"
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

function Test-UserAuthentication {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.57.3.9.4",
        "UserAuthentication",
        "Ensure 'UserAuthentication' is set to '1'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        $regName = "UserAuthentication"
        $expectedValue = 1
        
        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-SMBServerNameHardeningLevel {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.9.5",
        "SMBServerNameHardeningLevel",
        "Ensure 'SMBServerNameHardeningLevel' is set to '1' or '2'",
        8,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $regName = "SMBServerNameHardeningLevel"
        $expectedValue = (1, 2)

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -in $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value set to $($expectedValue)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue -join ", ")"
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

function Test-ShutdownWithoutLogon {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.13.1",
        "ShutdownWithoutLogon",
        "Ensure 'ShutdownWithoutLogon' is set to '0'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $regName = "ShutdownWithoutLogon"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-AutoAdminLogon {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.5.1",
        "AutoAdminLogon",
        "Ensure 'AutoAdminLogon' is set to '0'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "AutoAdminLogon"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-DCSettingIndex {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.9.33.6.3",
        "DCSettingIndex",
        "Ensure 'DCSettingIndex' is set to '1'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5f7d2daa51f51"
        $regName = "DCSettingIndex"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-ACSettingIndex {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.9.33.6.4",
        "ACSettingIndex",
        "Ensure 'ACSettingIndex' is set to '1'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5f7d2daa51f51"
        $regName = "ACSettingIndex"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-EnableAuthEpResolution {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.9.36.1",
        "EnableAuthEpResolution",
        "Ensure 'EnableAuthEpResolution' is set to '1'",
        6,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        $regName = "EnableAuthEpResolution"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-RequirePinForPairing {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "18.10.14.1",
        "RequirePinForPairing",
        "Ensure 'RequirePinForPairing' is set to '1'",
        3,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
        $regName = "RequirePinForPairing"
        $expectedValue = (1,2)

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -in $expectedValue) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value set to $($expectedValue)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected $($expectedValue -join ", ")"
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

function Test-ForceGuest {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.10.13",
        "ForceGuest",
        "Ensure 'ForceGuest' is set to '0'",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regName = "ForceGuest"
        $expectedValue = 0

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -eq $expectedValue) {
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

function Test-PasswordExpiryWarning  {
    param([AuditResults]$Results)
    
    $check = [ConfigCheck]::new(
        "2.3.7.7",
        "PasswordExpiryWarning ",
        "Ensure 'PasswordExpiryWarning ' is set from 5 days to 14 days",
        5,
        "Registry Test"
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $regName = "PasswordExpiryWarning"

        if (Test-Path $regPath) {
            $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                if ($value.$regName -ge 5 -and $value.$regName -le 14) {
                    $check.Status = "PASS"
                    $check.Details = "$regName value set to $($value.$regName)"
                } else {
                    $check.Status = "FAIL"
                    $check.Details = "$regName is set to $($value.$regName), expected from 5 to 14 days"
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

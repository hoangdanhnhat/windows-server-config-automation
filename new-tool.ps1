# Windows Server Configuration Audit Tool

# Configuration Check Class
class ConfigCheck {
    [string]$Name
    [string]$Description  
    [string]$Status
    [string]$Details
    [string]$Category
    
    ConfigCheck([string]$name, [string]$desc, [string]$cat) {
        $this.Name = $name
        $this.Description = $desc
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
    
    $check = [ConfigCheck]::new("SeTcbPrivilege Check", "No accounts should have Act as part of OS privilege", "Security Privileges")
    
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
    
    $check = [ConfigCheck]::new("SeIncreaseQuotaPrivilege Check", "Only approved accounts should have Adjust memory quotas privilege", "Security Privileges")
    
    try {
        $privilege = "SeIncreaseQuotaPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $accounts = $line -replace "^$privilege\s*=\s*", "" -split ',' | ForEach-Object { $_.Trim() }
            $validAccounts = @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "Administrators", "LOCAL SERVICE", "NETWORK SERVICE")
            
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

# Report Generation
function Show-Report {
    param([AuditResults]$Results)
    
    $Results.UpdateStats()
    
    Write-Host ""
    $separator = "=" * 70
    Write-Host $separator -ForegroundColor Green
    Write-Host "WINDOWS SERVER CONFIGURATION AUDIT REPORT" -ForegroundColor Green
    Write-Host $separator -ForegroundColor Green
    Write-Host "Scan Date: $($Results.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host ""
    
    # Summary
    Write-Host "SUMMARY:" -ForegroundColor Yellow
    $summSep = "-" * 40
    Write-Host $summSep -ForegroundColor Yellow
    Write-Host "Total Criteria Scanned: $($Results.Total)" -ForegroundColor White
    Write-Host "PASSED: $($Results.Passed)" -ForegroundColor Green
    Write-Host "FAILED: $($Results.Failed)" -ForegroundColor Red
    
    if ($Results.Total -gt 0) {
        $passRate = [math]::Round(($Results.Passed / $Results.Total) * 100, 1)
        $color = if($passRate -ge 80) { "Green" } elseif($passRate -ge 60) { "Yellow" } else { "Red" }
        Write-Host "Pass Rate: $passRate%" -ForegroundColor $color
    }
    
    Write-Host ""
    
    # Failed Details
    $failedChecks = $Results.Checks | Where-Object { $_.Status -eq "FAIL" }
    if ($failedChecks.Count -gt 0) {
        Write-Host "FAILED CRITERIA DETAILS:" -ForegroundColor Red
        $failSep = "-" * 40
        Write-Host $failSep -ForegroundColor Red
        
        foreach ($check in $failedChecks) {
            Write-Host ""
            Write-Host "X $($check.Name)" -ForegroundColor Red
            Write-Host "  Category: $($check.Category)" -ForegroundColor Gray
            Write-Host "  Description: $($check.Description)" -ForegroundColor Gray
            Write-Host "  Details: $($check.Details)" -ForegroundColor Yellow
        }
    }
    
    # Passed Summary
    $passedChecks = $Results.Checks | Where-Object { $_.Status -eq "PASS" }
    if ($passedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "PASSED CRITERIA:" -ForegroundColor Green
        $passSep = "-" * 40
        Write-Host $passSep -ForegroundColor Green
        
        foreach ($check in $passedChecks) {
            Write-Host "✓ $($check.Name)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host $separator -ForegroundColor Green
}

# Export to CSV
function Export-ToCSV {
    param(
        [AuditResults]$Results,
        [string]$Path = "ServerAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    $Results.Checks | Select-Object Name, Category, Description, Status, Details | Export-Csv -Path $Path -NoTypeInformation
    Write-Host "Results exported to: $Path" -ForegroundColor Cyan
}

# Main Function
function Start-Audit {
    param(
        [switch]$ExportCSV,
        [string]$CSVPath
    )
    
    Write-Host "Starting Windows Server Configuration Audit..." -ForegroundColor Green
    
    # Initialize
    $results = [AuditResults]::new()
    
    # Run Checks
    Write-Host "Running security privilege checks..." -ForegroundColor Cyan
    Test-SeTcbPrivilege -Results $results
    Test-SeIncreaseQuotaPrivilege -Results $results
    
    # Show Report
    Show-Report -Results $results
    
    # Export if requested
    if ($ExportCSV) {
        if ($CSVPath) {
            Export-ToCSV -Results $results -Path $CSVPath
        } else {
            Export-ToCSV -Results $results
        }
    }
    
    return $results
}

# Auto-run when script is executed directly
Write-Host "Windows Server Configuration Audit Tool Loaded" -ForegroundColor Green
Write-Host "Usage: Start-Audit [-ExportCSV] [-CSVPath 'path']" -ForegroundColor Yellow
Write-Host ""

# Uncomment the line below to auto-run
Start-Audit -ExportCSV
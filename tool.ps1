# Windows Server Configuration Audit Tool
# Author: Your Name
# Description: Automated tool to check Windows Server configuration compliance

# Define the main configuration class
class ConfigurationCheck {
    [string]$Name
    [string]$Description
    [string]$Status
    [string]$Details
    [string]$Category
    
    ConfigurationCheck([string]$name, [string]$description, [string]$category) {
        $this.Name = $name
        $this.Description = $description
        $this.Category = $category
        $this.Status = "NOT_CHECKED"
        $this.Details = ""
    }
}

# Main audit results class
class AuditResults {
    [System.Collections.ArrayList]$Checks
    [int]$TotalChecks
    [int]$PassedChecks
    [int]$FailedChecks
    [datetime]$StartTime
    [datetime]$EndTime
    
    AuditResults() {
        $this.Checks = New-Object System.Collections.ArrayList
        $this.StartTime = Get-Date
    }
    
    [void]AddCheck([ConfigurationCheck]$check) {
        $this.Checks.Add($check) | Out-Null
    }
    
    [void]UpdateStatistics() {
        $this.TotalChecks = $this.Checks.Count
        $this.PassedChecks = ($this.Checks | Where-Object { $_.Status -eq "PASS" }).Count
        $this.FailedChecks = ($this.Checks | Where-Object { $_.Status -eq "FAIL" }).Count
        $this.EndTime = Get-Date
    }
}

# Individual check functions
function Test-SeTcbPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigurationCheck]::new(
        "SeTcbPrivilege Check",
        "Verify no accounts have 'Act as part of the operating system' privilege",
        "Security Privileges"
    )
    
    try {
        $privilege = "SeTcbPrivilege"
        secedit /export /cfg C:\secpol.cfg | Out-Null
        $content = Get-Content C:\secpol.cfg -ErrorAction Stop
        
        $line = $content | Where-Object { $_ -match "^$privilege\s*=" }
        
        if ($line) {
            $check.Status = "FAIL"
            $check.Details = "Accounts found with '$privilege' privilege: $line"
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
        # Clean up temporary file
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

function Test-SeIncreaseQuotaPrivilege {
    param([AuditResults]$Results)
    
    $check = [ConfigurationCheck]::new(
        "SeIncreaseQuotaPrivilege Check",
        "Verify only approved accounts have 'Adjust memory quotas for a process' privilege",
        "Security Privileges"
    )
    
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
                $check.Details = "All accounts with '$privilege' are approved: $($accounts -join ', ')"
            } else {
                $check.Status = "FAIL"
                $check.Details = "Invalid accounts found with '$privilege': $($invalidAccounts -join ', ') | Full line: $line"
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
        # Clean up temporary file
        if (Test-Path C:\secpol.cfg) {
            Remove-Item C:\secpol.cfg -Force -ErrorAction SilentlyContinue
        }
    }
    
    $Results.AddCheck($check)
}

# Add more check functions here following the same pattern
function Test-PasswordPolicy {
    param([AuditResults]$Results)
    
    $check = [ConfigurationCheck]::new(
        "Password Policy Check",
        "Verify password complexity requirements",
        "Password Policy"
    )
    
    try {
        # Example additional check - replace with your actual logic
        $policy = Get-LocalUser | Select-Object Name, PasswordRequired
        $check.Status = "PASS"
        $check.Details = "Password policy check completed"
    }
    catch {
        $check.Status = "ERROR"
        $check.Details = "Error checking password policy: $($_.Exception.Message)"
    }
    
    $Results.AddCheck($check)
}

# Function to generate detailed report
function Generate-Report {
    param([AuditResults]$Results)
    
    $Results.UpdateStatistics()
    
    Write-Host "`n" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "WINDOWS SERVER CONFIGURATION AUDIT REPORT" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "Scan Date: $($Results.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round(($Results.EndTime - $Results.StartTime).TotalSeconds, 2)) seconds" -ForegroundColor Cyan
    Write-Host ""
    
    # Summary Statistics
    Write-Host "SUMMARY STATISTICS:" -ForegroundColor Yellow
    Write-Host ("-" * 50) -ForegroundColor Yellow
    Write-Host "Total Criteria Scanned: $($Results.TotalChecks)" -ForegroundColor White
    Write-Host "PASSED: $($Results.PassedChecks)" -ForegroundColor Green
    Write-Host "FAILED: $($Results.FailedChecks)" -ForegroundColor Red
    
    if ($Results.TotalChecks -gt 0) {
        $passRate = [math]::Round(($Results.PassedChecks / $Results.TotalChecks) * 100, 1)
        Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if($passRate -ge 80) { "Green" } elseif($passRate -ge 60) { "Yellow" } else { "Red" })
    }
    
    Write-Host ""
    
    # Failed Checks Details
    $failedChecks = $Results.Checks | Where-Object { $_.Status -eq "FAIL" }
    if ($failedChecks.Count -gt 0) {
        Write-Host "FAILED CRITERIA DETAILS:" -ForegroundColor Red
        Write-Host ("-" * 50) -ForegroundColor Red
        
        foreach ($check in $failedChecks) {
            Write-Host ""
            Write-Host "✗ $($check.Name)" -ForegroundColor Red
            Write-Host "  Category: $($check.Category)" -ForegroundColor Gray
            Write-Host "  Description: $($check.Description)" -ForegroundColor Gray
            Write-Host "  Details: $($check.Details)" -ForegroundColor Yellow
        }
    }
    
    # Error Checks
    $errorChecks = $Results.Checks | Where-Object { $_.Status -eq "ERROR" }
    if ($errorChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "ERROR CHECKS:" -ForegroundColor Magenta
        Write-Host ("-" * 50) -ForegroundColor Magenta
        
        foreach ($check in $errorChecks) {
            Write-Host ""
            Write-Host "⚠ $($check.Name)" -ForegroundColor Magenta
            Write-Host "  Details: $($check.Details)" -ForegroundColor Yellow
        }
    }
    
    # Passed Checks Summary
    $passedChecks = $Results.Checks | Where-Object { $_.Status -eq "PASS" }
    if ($passedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "PASSED CRITERIA:" -ForegroundColor Green
        Write-Host ("-" * 50) -ForegroundColor Green
        
        foreach ($check in $passedChecks) {
            Write-Host "✓ $($check.Name)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
}

# Function to export results to CSV
function Export-ResultsToCSV {
    param(
        [AuditResults]$Results,
        [string]$FilePath = ".\ServerAuditResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    $Results.Checks | Select-Object Name, Category, Description, Status, Details | Export-Csv -Path $FilePath -NoTypeInformation
    Write-Host "Results exported to: $FilePath" -ForegroundColor Cyan
}

# Main execution function
function Start-ServerConfigurationAudit {
    param(
        [switch]$ExportToCsv,
        [string]$CsvPath
    )
    
    Write-Host "Starting Windows Server Configuration Audit..." -ForegroundColor Green
    Write-Host "Please wait while checks are performed..." -ForegroundColor Yellow
    
    # Initialize results
    $auditResults = [AuditResults]::new()
    
    # Execute all checks
    Write-Host "Running privilege checks..." -ForegroundColor Cyan
    Test-SeTcbPrivilege -Results $auditResults
    Test-SeIncreaseQuotaPrivilege -Results $auditResults
    
    # Add more checks here
    Write-Host "Running additional checks..." -ForegroundColor Cyan
    Test-PasswordPolicy -Results $auditResults
    
    # Generate report
    Generate-Report -Results $auditResults
    
    # Export to CSV if requested
    if ($ExportToCsv) {
        if ($CsvPath) {
            Export-ResultsToCSV -Results $auditResults -FilePath $CsvPath
        } else {
            Export-ResultsToCSV -Results $auditResults
        }
    }
    
    return $auditResults
}

# Usage Examples:
# Start-ServerConfigurationAudit
# Start-ServerConfigurationAudit -ExportToCsv
# Start-ServerConfigurationAudit -ExportToCsv -CsvPath "C:\Reports\audit.csv"

# Run the audit
if ($MyInvocation.InvocationName -eq '&') {
    # Script is being run directly
    Start-ServerConfigurationAudit -ExportToCsv
}
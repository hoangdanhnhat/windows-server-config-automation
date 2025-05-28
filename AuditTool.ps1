# Windows Server Configuration Audit Tool

$ModulePath = Join-Path $PSScriptRoot "Modules"
Import-Module (Join-Path $ModulePath "UserRightsTests.psm1") -Force
Import-Module (Join-Path $ModulePath "RegistryTests.psm1") -Force

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


# Report Generation
function Show-Report {
    param([AuditResults]$Results)
    
    $Results.UpdateStats()
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "        WINDOWS SERVER CONFIGURATION AUDIT REPORT" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "Scan Date: $($Results.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "               SUMMARY:" -ForegroundColor Yellow
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
        Write-Host "        FAILED CRITERIA DETAILS:" -ForegroundColor Red
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
        Write-Host "           PASSED CRITERIA:" -ForegroundColor Green
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

    # Get all exported functions from UserRightsTests module
    $userRightsFunctions = Get-Command -Module UserRightsTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $userRightsFunctions) {
        & $function.Name -Results $results
    }
    
    Write-Host "Running registry checks..." -ForegroundColor Cyan
    
    # Get all exported functions from RegistryTests module
    $registryFunctions = Get-Command -Module RegistryTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $registryFunctions) {
        & $function.Name -Results $results
    }

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
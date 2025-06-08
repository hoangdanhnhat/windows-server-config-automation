# Windows Server Configuration Audit Tool
using module .\Modules\SharedTypes.psm1

$ModulePath = Join-Path $PSScriptRoot "Modules"

# Import shared types first
Import-Module (Join-Path $ModulePath "SharedTypes.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $ModulePath "UserRightsTests.psm1") -Force
Import-Module (Join-Path $ModulePath "RegistryTests.psm1") -Force
Import-Module (Join-Path $ModulePath "SIDTests.psm1") -Force
Import-Module (Join-Path $ModulePath "PasswordPolicyTests.psm1") -Force
Import-Module (Join-Path $ModulePath "LockoutPolicyTests.psm1") -Force

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
    
    Write-Host "Running User Rights Assignment checks..." -ForegroundColor Cyan

    # Get all exported functions from UserRightsTests module
    $userRightsFunctions = Get-Command -Module UserRightsTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $userRightsFunctions) {
        & $function.Name -Results $results
    }

    Write-Host "Running password policy checks..." -ForegroundColor Cyan

    # Get all exported functions from PasswordPolicyTests module
    $passwordPolicyFunctions = Get-Command -Module PasswordPolicyTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $passwordPolicyFunctions) {
        & $function.Name -Results $results
    }
    
    Write-Host "Running registry checks..." -ForegroundColor Cyan
    
    # Get all exported functions from RegistryTests module
    $registryFunctions = Get-Command -Module RegistryTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $registryFunctions) {
        & $function.Name -Results $results
    }

    Write-Host "Running User SID checks..." -ForegroundColor Cyan

    # Get all exported functions from SIDTests module
    $SIDFunction = Get-Command -Module SIDTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $SIDFunction) {
        & $function.Name -Results $results
    }

    Write-Host "Running Lockout Policy checks..." -ForegroundColor Cyan

    # Get all exported functions from LockoutPolicyTests module
    $lockoutPolicyFunctions = Get-Command -Module LockoutPolicyTests | Where-Object { $_.Name -like 'Test-*' }
    foreach ($function in $lockoutPolicyFunctions) {
        & $function.Name -Results $results
    }

    if ($ExportCSV) {
        if ($CSVPath) {
            # If custom path provided, ensure it's in the Reports folder
            $CSVPath = "Reports\$($CSVPath.TrimStart('\/'))"
            Export-ToCSV -Results $results -Path $CSVPath
        } else {
            Export-ToCSV -Results $results
        }
    }
    
    # Update and display summary
    $results.UpdateStats()
    Write-Host "`nAudit Summary:" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "Total Criteria Checked: $($results.Total)" -ForegroundColor White
    Write-Host "Passed              : $($results.Passed)" -ForegroundColor Green
    Write-Host "Failed              : $($results.Failed)" -ForegroundColor Red
    Write-Host "Error               : $($results.Errors)" -ForegroundColor Cyan
    $passRate = if ($results.Total -gt 0) { [math]::Round(($results.Passed / $results.Total) * 100, 2) } else { 0 }
    Write-Host "Pass Rate           : ${passRate}%" -ForegroundColor $(if ($passRate -ge 80) { "Green" } elseif ($passRate -ge 60) { "Yellow" } else { "Red" })
    Write-Host ""
    
    return $results
}

Write-Host "Windows Server Configuration Audit Tool Loaded" -ForegroundColor Green
Write-Host "Usage: Start-Audit or Start-Audit -ExportCSV" -ForegroundColor Yellow
Write-Host ""

Start-Audit -ExportCSV | Out-Null
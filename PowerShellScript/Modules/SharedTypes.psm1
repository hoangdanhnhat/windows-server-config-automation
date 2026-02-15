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

class AuditResults {    
    [System.Collections.ArrayList]$Checks
    [int]$Total
    [int]$Passed
    [int]$Failed
    [int]$Errors
    [datetime]$StartTime
    
    AuditResults() {
        $this.Checks = New-Object System.Collections.ArrayList
        $this.StartTime = Get-Date
        $this.Total = 0
        $this.Passed = 0
        $this.Failed = 0
        $this.Errors = 0
    }
    
    [void]AddCheck([ConfigCheck]$check) {
        $this.Checks.Add($check) | Out-Null
    }
    
    [void]UpdateStats() {
        $this.Total = $this.Checks.Count
        $this.Passed = ($this.Checks | Where-Object { $_.Status -eq "PASS" }).Count
        $this.Failed = ($this.Checks | Where-Object { $_.Status -eq "FAIL" }).Count
        $this.Errors = ($this.Checks | Where-Object { $_.Status -eq "ERROR" }).Count
    }
}

Export-ModuleMember -Function * -Alias *

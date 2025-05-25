#!/usr/bin/env python3
"""
Windows Server Configuration Automation Tool - Main Framework
Checks Windows Server member & domain configuration against security standards
"""

import subprocess
import json
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import importlib.util
import sys


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """Represents the result of a single configuration check"""
    check_id: str
    description: str
    status: CheckStatus
    details: str = ""
    recommendation: str = ""
    category: str = ""


@dataclass
class CheckDefinition:
    """Defines a configuration check to be performed"""
    check_id: str
    description: str
    category: str
    check_type: str  # 'privilege_not_assigned', 'privilege_restricted', 'custom'
    parameters: Dict[str, Any]
    recommendation: str = ""


class WindowsConfigChecker:
    """Main class for Windows server configuration checking"""
    
    def __init__(self, checks_module_path: str = "windows_checks.py"):
        self.results: List[CheckResult] = []
        self.temp_files: List[str] = []
        self.checks_module_path = checks_module_path
        self.check_definitions: List[CheckDefinition] = []
        self.custom_scripts: Dict[str, str] = {}
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean up temporary files
        self.cleanup()
    
    def cleanup(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                print(f"Warning: Could not remove temp file {temp_file}: {e}")
    
    def load_checks(self):
        """Load check definitions and custom scripts from external module"""
        try:
            if not os.path.exists(self.checks_module_path):
                print(f"Warning: Checks module '{self.checks_module_path}' not found. Using default checks.")
                self._load_default_checks()
                return
            
            # Load the checks module dynamically
            spec = importlib.util.spec_from_file_location("windows_checks", self.checks_module_path)
            checks_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(checks_module)
            
            # Load check definitions
            if hasattr(checks_module, 'CHECK_DEFINITIONS'):
                self.check_definitions = checks_module.CHECK_DEFINITIONS
            else:
                print("Warning: CHECK_DEFINITIONS not found in checks module. Using default checks.")
                self._load_default_checks()
            
            # Load custom scripts
            if hasattr(checks_module, 'CUSTOM_SCRIPTS'):
                self.custom_scripts = checks_module.CUSTOM_SCRIPTS
            
            print(f"Loaded {len(self.check_definitions)} check definitions from {self.checks_module_path}")
            
        except Exception as e:
            print(f"Error loading checks module: {e}")
            print("Using default checks.")
            self._load_default_checks()
    
    def _load_default_checks(self):
        """Load default check definitions if external module is not available"""
        self.check_definitions = [
            CheckDefinition(
                check_id="SEC-001",
                description="Act as part of the operating system privilege should not be assigned",
                category="Security Policy",
                check_type="privilege_not_assigned",
                parameters={"privilege": "SeTcbPrivilege"},
                recommendation="Remove the 'SeTcbPrivilege' privilege from all accounts"
            ),
            CheckDefinition(
                check_id="SEC-002", 
                description="Adjust memory quotas for a process privilege should be restricted",
                category="Security Policy",
                check_type="privilege_restricted",
                parameters={
                    "privilege": "SeIncreaseQuotaPrivilege",
                    "valid_accounts": ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"]
                },
                recommendation="Ensure only Administrators, LOCAL SERVICE, and NETWORK SERVICE have this privilege"
            )
        ]
    
    def run_powershell_script(self, script: str) -> Tuple[str, str, int]:
        """Execute PowerShell script and return output, error, and return code"""
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(script)
                script_path = f.name
                self.temp_files.append(script_path)
            
            # Execute PowerShell script
            cmd = [
                'powershell.exe',
                '-ExecutionPolicy', 'Bypass',
                '-NoProfile',
                '-File', script_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=30
            )
            
            return result.stdout.strip(), result.stderr.strip(), result.returncode
            
        except subprocess.TimeoutExpired:
            return "", "Script execution timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def check_privilege_not_assigned(self, check_def: CheckDefinition) -> CheckResult:
        """Check that a specific privilege is not assigned to any account"""
        privilege = check_def.parameters.get("privilege", "")
        
        script = f'''
        try {{
            $privilege = "{privilege}"
            secedit /export /cfg C:\\secpol.cfg | Out-Null
            $content = Get-Content C:\\secpol.cfg -ErrorAction Stop
            
            $line = $content | Where-Object {{ $_ -match "^$privilege\\s*=" }}
            
            if ($line) {{
                Write-Output "FAIL"
                Write-Output $line
            }} else {{
                Write-Output "PASS"
            }}
        }} catch {{
            Write-Output "ERROR"
            Write-Output $_.Exception.Message
        }}
        '''
        
        return self._process_script_result(script, check_def, privilege)
    
    def check_privilege_restricted(self, check_def: CheckDefinition) -> CheckResult:
        """Check that a privilege is only assigned to specific valid accounts"""
        privilege = check_def.parameters.get("privilege", "")
        valid_accounts = check_def.parameters.get("valid_accounts", [])
        valid_accounts_str = "', '".join(valid_accounts)
        
        script = f'''
        try {{
            $privilege = "{privilege}"
            secedit /export /cfg C:\\secpol.cfg | Out-Null
            $content = Get-Content C:\\secpol.cfg -ErrorAction Stop
            
            $line = $content | Where-Object {{ $_ -match "^$privilege\\s*=" }}
            
            if ($line) {{
                $accounts = $line -replace "^$privilege\\s*=\\s*", "" -split ',' | ForEach-Object {{ $_.Trim() }}
                
                # Convert SIDs to friendly names for comparison
                $friendlyNames = @()
                foreach ($account in $accounts) {{
                    if ($account.StartsWith("*S-")) {{
                        try {{
                            $sid = $account.Substring(1)  # Remove the * prefix
                            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
                            $friendlyName = $objSID.Translate([System.Security.Principal.NTAccount]).Value
                            $friendlyNames += $friendlyName
                        }} catch {{
                            $friendlyNames += $account  # Keep original if translation fails
                        }}
                    }} else {{
                        $friendlyNames += $account
                    }}
                }}
                
                $validAccounts = @('{valid_accounts_str}')
                
                # Check both friendly names and common variations
                $validVariations = @()
                foreach ($valid in $validAccounts) {{
                    $validVariations += $valid
                    if ($valid -eq "Administrators") {{
                        $validVariations += "BUILTIN\\Administrators"
                        $validVariations += $env:COMPUTERNAME + "\\Administrators"
                    }}
                    if ($valid -eq "LOCAL SERVICE") {{
                        $validVariations += "NT AUTHORITY\\LOCAL SERVICE"
                    }}
                    if ($valid -eq "NETWORK SERVICE") {{
                        $validVariations += "NT AUTHORITY\\NETWORK SERVICE"
                    }}
                }}
                
                $invalidAccounts = $friendlyNames | Where-Object {{ $_ -notin $validVariations }}
                
                if ($invalidAccounts.Count -eq 0) {{
                    Write-Output "PASS"
                    Write-Output "Valid accounts found: $($friendlyNames -join ', ')"
                }} else {{
                    Write-Output "FAIL"
                    Write-Output "Policy line: $line"
                    Write-Output "Friendly names: $($friendlyNames -join ', ')"
                    Write-Output "Invalid accounts: $($invalidAccounts -join ', ')"
                }}
            }} else {{
                Write-Output "PASS"
                Write-Output "Privilege not assigned to any accounts"
            }}
        }} catch {{
            Write-Output "ERROR"
            Write-Output $_.Exception.Message
        }}
        '''
        
        return self._process_script_result(script, check_def, privilege)
    
    def check_custom_script(self, check_def: CheckDefinition) -> CheckResult:
        """Execute a custom PowerShell script"""
        script_name = check_def.parameters.get("script_name", "")
        
        if script_name not in self.custom_scripts:
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.ERROR,
                details=f"Custom script '{script_name}' not found",
                category=check_def.category
            )
        
        script = self.custom_scripts[script_name]
        return self._process_script_result(script, check_def)
    
    def _process_script_result(self, script: str, check_def: CheckDefinition, context: str = "") -> CheckResult:
        """Process the result of a PowerShell script execution"""
        output, error, return_code = self.run_powershell_script(script)
        
        if return_code != 0 or error:
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.ERROR,
                details=f"Script execution failed: {error}",
                category=check_def.category
            )
        
        lines = output.split('\n')
        if not lines:
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.ERROR,
                details="No output from script",
                category=check_def.category
            )
        
        status_line = lines[0].strip()
        
        if status_line == "PASS":
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.PASS,
                category=check_def.category
            )
        elif status_line == "FAIL":
            details_lines = lines[1:] if len(lines) > 1 else ["Check failed"]
            details = "\n".join(details_lines)
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.FAIL,
                details=details,
                recommendation=check_def.recommendation,
                category=check_def.category
            )
        else:
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.ERROR,
                details=f"Unexpected output: {output}",
                category=check_def.category
            )
    
    def run_single_check(self, check_def: CheckDefinition) -> CheckResult:
        """Execute a single check based on its definition"""
        print(f"Running check [{check_def.check_id}]: {check_def.description}")
        
        try:
            if check_def.check_type == "privilege_not_assigned":
                return self.check_privilege_not_assigned(check_def)
            elif check_def.check_type == "privilege_restricted":
                return self.check_privilege_restricted(check_def)
            elif check_def.check_type == "custom":
                return self.check_custom_script(check_def)
            else:
                return CheckResult(
                    check_id=check_def.check_id,
                    description=check_def.description,
                    status=CheckStatus.ERROR,
                    details=f"Unknown check type: {check_def.check_type}",
                    category=check_def.category
                )
        except Exception as e:
            return CheckResult(
                check_id=check_def.check_id,
                description=check_def.description,
                status=CheckStatus.ERROR,
                details=f"Exception during check execution: {str(e)}",
                category=check_def.category
            )
    
    def run_all_checks(self):
        """Execute all configuration checks"""
        print("Starting Windows Server Configuration Check...")
        print("=" * 60)
        
        self.load_checks()
        
        for check_def in self.check_definitions:
            result = self.run_single_check(check_def)
            self.results.append(result)
            
            # Print immediate status
            status_symbol = "✓" if result.status == CheckStatus.PASS else "✗" if result.status == CheckStatus.FAIL else "!"
            print(f"  {status_symbol} [{result.check_id}] {result.status.value}")
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_checks = len(self.results)
        pass_count = len([r for r in self.results if r.status == CheckStatus.PASS])
        fail_count = len([r for r in self.results if r.status == CheckStatus.FAIL])
        error_count = len([r for r in self.results if r.status == CheckStatus.ERROR])
        
        return {
            "total_checks": total_checks,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "error_count": error_count,
            "success_rate": round((pass_count / total_checks * 100), 2) if total_checks > 0 else 0
        }
    
    def print_results(self):
        """Print detailed results to console"""
        summary = self.generate_summary()
        
        print("\n" + "=" * 60)
        print("CONFIGURATION CHECK RESULTS")
        print("=" * 60)
        
        print(f"Total Criteria Scanned: {summary['total_checks']}")
        print(f"PASS: {summary['pass_count']}")
        print(f"FAIL: {summary['fail_count']}")
        print(f"ERROR: {summary['error_count']}")
        print(f"Success Rate: {summary['success_rate']}%")
        
        # Print failed checks details
        failed_checks = [r for r in self.results if r.status == CheckStatus.FAIL]
        if failed_checks:
            print("\n" + "-" * 60)
            print("FAILED CRITERIA DETAILS:")
            print("-" * 60)
            
            for i, result in enumerate(failed_checks, 1):
                print(f"\n{i}. [{result.check_id}] {result.description}")
                print(f"   Status: {result.status.value}")
                if result.details:
                    print(f"   Details: {result.details}")
                if result.recommendation:
                    print(f"   Recommendation: {result.recommendation}")
        
        # Print error checks if any
        error_checks = [r for r in self.results if r.status == CheckStatus.ERROR]
        if error_checks:
            print("\n" + "-" * 60)
            print("ERROR CRITERIA DETAILS:")
            print("-" * 60)
            
            for i, result in enumerate(error_checks, 1):
                print(f"\n{i}. [{result.check_id}] {result.description}")
                print(f"   Status: {result.status.value}")
                print(f"   Error: {result.details}")
    
    def export_to_json(self, filename: str = None):
        """Export results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"windows_config_check_{timestamp}.json"
        
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.generate_summary(),
            "results": [asdict(result) for result in self.results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"\nResults exported to: {filename}")
        return filename


def main():
    """Main execution function"""
    try:
        with WindowsConfigChecker() as checker:
            checker.run_all_checks()
            checker.print_results()
            checker.export_to_json()
            
    except KeyboardInterrupt:
        print("\nCheck interrupted by user")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
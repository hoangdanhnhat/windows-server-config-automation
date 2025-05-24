#!/usr/bin/env python3
"""
Windows Server Configuration Automation Tool
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


class WindowsConfigChecker:
    """Main class for Windows server configuration checking"""
    
    def __init__(self):
        self.results: List[CheckResult] = []
        self.temp_files: List[str] = []
        
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
    
    def run_powershell_script(self, script: str) -> Tuple[str, str, int]:
        """
        Execute PowerShell script and return output, error, and return code
        """
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
    
    def check_privilege_not_assigned(self, privilege: str, check_id: str, description: str) -> CheckResult:
        """
        Check that a specific privilege is not assigned to any account
        Based on your first script
        """
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
        
        output, error, return_code = self.run_powershell_script(script)
        
        if return_code != 0 or error:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details=f"Script execution failed: {error}",
                category="Security Policy"
            )
        
        lines = output.split('\n')
        if not lines:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details="No output from script",
                category="Security Policy"
            )
        
        status_line = lines[0].strip()
        
        if status_line == "PASS":
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.PASS,
                category="Security Policy"
            )
        elif status_line == "FAIL":
            details = lines[1] if len(lines) > 1 else "Privilege is assigned"
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.FAIL,
                details=f"Accounts found with privilege '{privilege}': {details}",
                recommendation=f"Remove the '{privilege}' privilege from all accounts",
                category="Security Policy"
            )
        else:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details=f"Unexpected output: {output}",
                category="Security Policy"
            )
    
    def check_privilege_restricted_accounts(self, privilege: str, valid_accounts: List[str], 
                                          check_id: str, description: str) -> CheckResult:
        """
        Check that a privilege is only assigned to specific valid accounts
        Based on your second script
        """
        valid_accounts_str = "', '".join(valid_accounts)
        script = f'''
        try {{
            $privilege = "{privilege}"
            secedit /export /cfg C:\\secpol.cfg | Out-Null
            $content = Get-Content C:\\secpol.cfg -ErrorAction Stop
            
            $line = $content | Where-Object {{ $_ -match "^$privilege\\s*=" }}
            
            if ($line) {{
                $accounts = $line -replace "^$privilege\\s*=\\s*", "" -split ',' | ForEach-Object {{ $_.Trim() }}
                $validAccounts = @('{valid_accounts_str}')
                $invalidAccounts = $accounts | Where-Object {{ $_ -notin $validAccounts }}
                
                if ($invalidAccounts.Count -eq 0) {{
                    Write-Output "PASS"
                }} else {{
                    Write-Output "FAIL"
                    Write-Output $line
                    Write-Output ("Invalid accounts: " + ($invalidAccounts -join ', '))
                }}
            }} else {{
                Write-Output "PASS"
            }}
        }} catch {{
            Write-Output "ERROR"
            Write-Output $_.Exception.Message
        }}
        '''
        
        output, error, return_code = self.run_powershell_script(script)
        
        if return_code != 0 or error:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details=f"Script execution failed: {error}",
                category="Security Policy"
            )
        
        lines = output.split('\n')
        if not lines:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details="No output from script",
                category="Security Policy"
            )
        
        status_line = lines[0].strip()
        
        if status_line == "PASS":
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.PASS,
                category="Security Policy"
            )
        elif status_line == "FAIL":
            policy_line = lines[1] if len(lines) > 1 else ""
            invalid_accounts = lines[2] if len(lines) > 2 else ""
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.FAIL,
                details=f"Policy: {policy_line}\n{invalid_accounts}",
                recommendation=f"Ensure only these accounts have '{privilege}' privilege: {', '.join(valid_accounts)}",
                category="Security Policy"
            )
        else:
            return CheckResult(
                check_id=check_id,
                description=description,
                status=CheckStatus.ERROR,
                details=f"Unexpected output: {output}",
                category="Security Policy"
            )
    
    def run_all_checks(self):
        """Execute all configuration checks"""
        print("Starting Windows Server Configuration Check...")
        print("=" * 60)
        
        # Check 1: SeTcbPrivilege should not be assigned
        result1 = self.check_privilege_not_assigned(
            privilege="SeTcbPrivilege",
            check_id="SEC-001",
            description="Act as part of the operating system privilege should not be assigned"
        )
        self.results.append(result1)
        
        # Check 2: SeIncreaseQuotaPrivilege should only be assigned to specific accounts
        result2 = self.check_privilege_restricted_accounts(
            privilege="SeIncreaseQuotaPrivilege",
            valid_accounts=["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"],
            check_id="SEC-002",
            description="Adjust memory quotas for a process privilege should be restricted"
        )
        self.results.append(result2)
        
        # Add more checks here as needed
        # Example of how to add more checks:
        # result3 = self.check_privilege_not_assigned(
        #     privilege="SeDebugPrivilege",
        #     check_id="SEC-003",
        #     description="Debug programs privilege should not be assigned"
        # )
        # self.results.append(result3)
        
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
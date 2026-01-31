import os
from datetime import datetime
from colorama import Fore, Style

class TXTReporter:
    """Generates simple TXT report with parameters and payloads"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.output_dir = 'reports'
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(self, recon_data, vulnerabilities, duration):
        """Generate TXT report"""
        print(f"{Fore.CYAN}[*] Generating TXT report...{Style.RESET_ALL}")
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"access_audit_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        # Build report content
        report_content = self._build_report(recon_data, vulnerabilities, duration)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Report saved: {filepath}")
        return filepath
    
    def _build_report(self, recon_data, vulnerabilities, duration):
        """Build complete TXT report"""
        
        report = f"""
{'='*80}
                    ACCESS CONTROL AUDIT REPORT
{'='*80}

Target: {self.target_url}
Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Scan Duration: {duration:.2f} seconds
Tool: Smart Access Control Auditor v2.0

{'='*80}
                        SUMMARY
{'='*80}

Endpoints Found: {recon_data['total_endpoints']}
Parameters Found: {recon_data['total_parameters']}
Admin Panels Found: {len(recon_data['admin_panels'])}
Potential Vulnerabilities: {len(vulnerabilities)}

{'='*80}
                    DISCOVERED ENDPOINTS
{'='*80}

"""
        
        # Add endpoints
        if recon_data['endpoints']:
            for endpoint in recon_data['endpoints'][:50]:  # Show first 50
                report += f"- {endpoint}\n"
            if len(recon_data['endpoints']) > 50:
                report += f"... and {len(recon_data['endpoints']) - 50} more endpoints\n"
        else:
            report += "No endpoints discovered\n"
        
        report += f"""
{'='*80}
                    DISCOVERED PARAMETERS
{'='*80}

Total Parameters: {recon_data['total_parameters']}

"""
        
        # Add categorized parameters
        categorized = recon_data.get('categorized_params', {})
        
        if categorized.get('user_related'):
            report += "[USER RELATED PARAMETERS]\n"
            for param in categorized['user_related']:
                report += f"  - {param}\n"
                # Add payloads for user-related parameters
                report += f"    Test payloads: 1, 0, -1, 999, admin, ../\n"
            report += "\n"
        
        if categorized.get('resource_related'):
            report += "[RESOURCE RELATED PARAMETERS]\n"
            for param in categorized['resource_related']:
                report += f"  - {param}\n"
                report += f"    Test payloads: 1, 2, 100, test, null\n"
            report += "\n"
        
        if categorized.get('business_logic'):
            report += "[BUSINESS LOGIC PARAMETERS]\n"
            for param in categorized['business_logic']:
                report += f"  - {param}\n"
                param_lower = str(param).lower()
                if 'amount' in param_lower or 'price' in param_lower:
                    report += f"    Test payloads: 0, -1, 999999, 0.01, 1000000\n"
                elif 'quantity' in param_lower:
                    report += f"    Test payloads: 0, -1, 999999, 1e9\n"
                elif 'discount' in param_lower:
                    report += f"    Test payloads: 100, 101, -10, 999\n"
                else:
                    report += f"    Test payloads: test, 1, 0, true, false\n"
            report += "\n"
        
        if categorized.get('access_control'):
            report += "[ACCESS CONTROL PARAMETERS]\n"
            for param in categorized['access_control']:
                report += f"  - {param}\n"
                report += f"    Test payloads: admin, administrator, superuser, root, 1, true\n"
            report += "\n"
        
        if categorized.get('sensitive'):
            report += "[SENSITIVE PARAMETERS]\n"
            for param in categorized['sensitive']:
                report += f"  - {param}\n"
                report += f"    CAUTION: Handle with care! Test with dummy values only.\n"
            report += "\n"
        
        # Add admin panels
        if recon_data['admin_panels']:
            report += f"""
{'='*80}
                    ADMIN PANELS FOUND
{'='*80}

"""
            for panel in recon_data['admin_panels']:
                report += f"URL: {panel['url']}\n"
                report += f"Status: {panel['status']}\n"
                report += f"Title: {panel['title']}\n"
                report += f"Test: Check if proper authentication is required\n\n"
        
        # Add forms
        if recon_data['forms']:
            report += f"""
{'='*80}
                    FORMS DISCOVERED
{'='*80}

"""
            for i, form in enumerate(recon_data['forms'][:10], 1):  # Show first 10
                report += f"Form #{i}:\n"
                report += f"  Action: {form['action']}\n"
                report += f"  Method: {form['method']}\n"
                if form['parameters']:
                    report += f"  Parameters:\n"
                    for param in form['parameters']:
                        report += f"    - {param['name']} (type: {param['type']})\n"
                report += "\n"
        
        # Add vulnerabilities
        if vulnerabilities:
            report += f"""
{'='*80}
                    POTENTIAL VULNERABILITIES
{'='*80}

"""
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'Medium')
                report += f"[{severity}] {vuln['type']}\n"
                report += f"Description: {vuln['description']}\n"
                
                if 'parameters' in vuln and vuln['parameters']:
                    report += f"Affected Parameters: {', '.join(vuln['parameters'][:5])}\n"
                
                if 'panels' in vuln and vuln['panels']:
                    report += "Affected URLs:\n"
                    for panel in vuln['panels']:
                        report += f"  - {panel['url']} (Status: {panel['status']})\n"
                
                # Add test cases
                report += "Recommended Tests:\n"
                report += self._get_test_cases(vuln['type'])
                report += "\n" + "-"*40 + "\n\n"
        
        # Add payloads section
        report += f"""
{'='*80}
                    TEST PAYLOADS
{'='*80}

[IDOR TEST PAYLOADS]
- Numeric IDs: 1, 0, -1, 999, 1000, 9999
- Special IDs: admin, root, superuser, test
- Path traversal: ../, ../../etc/passwd, ..%2f..%2fetc%2fpasswd

[BUSINESS LOGIC PAYLOADS]
- Price manipulation: 0, -0.01, 999999, 0.001
- Quantity manipulation: 0, -1, 999999, 1e9
- Discount manipulation: 100, 101, -10, 999
- Status manipulation: approved, completed, paid, admin

[ACCESS CONTROL PAYLOADS]
- Role escalation: admin, administrator, superuser, root, 1, true
- Permission bypass: *, all, write, delete, super
- Boolean values: true, false, 1, 0, yes, no

[GENERAL TEST PAYLOADS]
- Empty values: '', null, undefined
- Special chars: ', ", <, >, &, ;, --
- SQL injection: ' OR '1'='1, ' OR 1=1--
- XSS test: <script>alert(1)</script>, <img src=x onerror=alert(1)>

{'='*80}
                        NOTES
{'='*80}

1. This is a reconnaissance report only
2. All findings need manual verification
3. Only test on systems you own or have permission to test
4. Report any vulnerabilities responsibly

{'='*80}
                        END OF REPORT
{'='*80}
"""
        
        return report
    
    def _get_test_cases(self, vuln_type):
        """Get test cases for vulnerability type"""
        test_cases = {
            'Potential IDOR': [
                "1. Test with different numeric IDs (1, 2, 100, 999)",
                "2. Test with special IDs (admin, root, test)",
                "3. Test with negative IDs (-1, -100)",
                "4. Test with very large IDs (999999)",
                "5. Check if you can access other users' resources"
            ],
            'Business Logic Parameters': [
                "1. Test price/amount parameters with 0 or negative values",
                "2. Test quantity parameters with extremely high values",
                "3. Test discount parameters with values > 100",
                "4. Test status parameters with unauthorized states",
                "5. Test for race conditions in multi-step processes"
            ],
            'Admin Panels Discovered': [
                "1. Try to access without authentication",
                "2. Try common default credentials (admin/admin)",
                "3. Check for directory listing",
                "4. Look for information disclosure",
                "5. Test for brute force protection"
            ],
            'Sensitive Parameters': [
                "1. Test with dummy values only",
                "2. Check if values are properly encrypted",
                "3. Test for information disclosure in errors",
                "4. Check if sensitive data is logged",
                "5. Verify proper access controls"
            ]
        }
        
        if vuln_type in test_cases:
            return "\n".join([f"  {tc}" for tc in test_cases[vuln_type]])
        else:
            return "  Test with various input values and boundary conditions"

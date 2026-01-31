#!/usr/bin/env python3
"""
Smart Access Control Auditor - TXT Report Version
Simple reconnaissance with TXT report output
"""

import argparse
import sys
import time
from colorama import init, Fore, Style

# Import scanner modules
from scanner.recon_engine import ReconEngine
from scanner.txt_reporter import TXTReporter

init()  # Initialize colorama

def print_banner():
    """Print application banner"""
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════╗
    ║   Smart Access Control Auditor                   ║
    ║   Simple Reconnaissance & Parameter Discovery    ║
    ╚══════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "    Version: 2.0 | TXT Report Output | Educational Use" + Style.RESET_ALL)
    print()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Simple reconnaissance and parameter discovery for web applications'
    )
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawling depth (default: 2)')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.target:
        print(Fore.RED + "[!] Please provide a target URL" + Style.RESET_ALL)
        print(Fore.YELLOW + "Usage: python main.py https://example.com" + Style.RESET_ALL)
        print(Fore.YELLOW + "       python main.py http://localhost:5000" + Style.RESET_ALL)
        sys.exit(1)
    
    try:
        start_time = time.time()
        
        # Step 1: Reconnaissance
        print(f"{Fore.YELLOW}[1/3] Starting reconnaissance...{Style.RESET_ALL}")
        recon_engine = ReconEngine(args.target)
        recon_data = recon_engine.run_recon()
        
        # Print reconnaissance summary
        print(f"\n{Fore.GREEN}Reconnaissance Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}✓{Style.RESET_ALL} Endpoints found: {recon_data['total_endpoints']}")
        print(f"  {Fore.CYAN}✓{Style.RESET_ALL} Parameters found: {recon_data['total_parameters']}")
        print(f"  {Fore.CYAN}✓{Style.RESET_ALL} Admin panels: {len(recon_data['admin_panels'])}")
        
        # Step 2: Analyze for vulnerabilities
        print(f"\n{Fore.YELLOW}[2/3] Analyzing for vulnerabilities...{Style.RESET_ALL}")
        
        # Find potential vulnerabilities
        potential_vulns = []
        categorized = recon_data.get('categorized_params', {})
        
        # Check for IDOR parameters
        idor_params = categorized.get('user_related', []) + categorized.get('resource_related', [])
        if idor_params:
            potential_vulns.append({
                'type': 'Potential IDOR',
                'severity': 'High',
                'description': f'Found {len(idor_params)} ID-like parameters that could lead to Insecure Direct Object References',
                'parameters': idor_params[:10]
            })
        
        # Check for business logic parameters
        biz_params = categorized.get('business_logic', [])
        if biz_params:
            potential_vulns.append({
                'type': 'Business Logic Parameters',
                'severity': 'Medium',
                'description': f'Found {len(biz_params)} business logic parameters that could be manipulated',
                'parameters': biz_params[:10]
            })
        
        # Check for admin panels
        if recon_data['admin_panels']:
            accessible = any(panel['status'] == 200 for panel in recon_data['admin_panels'])
            potential_vulns.append({
                'type': 'Admin Panels Discovered',
                'severity': 'Critical' if accessible else 'Medium',
                'description': f'Found {len(recon_data["admin_panels"])} admin panels',
                'panels': recon_data['admin_panels']
            })
        
        # Check for access control parameters
        access_params = categorized.get('access_control', [])
        if access_params:
            potential_vulns.append({
                'type': 'Access Control Parameters',
                'severity': 'High',
                'description': f'Found {len(access_params)} access control parameters that could be modified',
                'parameters': access_params[:10]
            })
        
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Potential vulnerabilities identified: {len(potential_vulns)}")
        
        # Step 3: Generate TXT report
        print(f"\n{Fore.YELLOW}[3/3] Generating TXT report...{Style.RESET_ALL}")
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Generate report
        reporter = TXTReporter(args.target)
        report_path = reporter.generate_report(recon_data, potential_vulns, duration)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN COMPLETE!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}📊 Scan Results:{Style.RESET_ALL}")
        print(f"  Target URL: {args.target}")
        print(f"  Scan duration: {duration:.2f} seconds")
        print(f"  Endpoints discovered: {recon_data['total_endpoints']}")
        print(f"  Parameters discovered: {recon_data['total_parameters']}")
        print(f"  Potential vulnerabilities: {len(potential_vulns)}")
        
        print(f"\n{Fore.CYAN}📄 Report Generated:{Style.RESET_ALL}")
        print(f"  File: {report_path}")
        print(f"  Size: Check reports/ folder")
        
        print(f"\n{Fore.YELLOW}🔍 Key Findings:{Style.RESET_ALL}")
        for finding in potential_vulns:
            color = Fore.RED if finding['severity'] in ['Critical', 'High'] else Fore.YELLOW
            print(f"  {color}[{finding['severity']}] {finding['type']}{Style.RESET_ALL}")
            print(f"     {finding['description']}")
        
        print(f"\n{Fore.BLUE}🚀 What to do next:{Style.RESET_ALL}")
        print(f"  1. Open {report_path} to see complete results")
        print(f"  2. Review all discovered parameters")
        print(f"  3. Use the provided payloads for manual testing")
        print(f"  4. Check admin panels for proper access controls")
        
        print(f"\n{Fore.GREEN}✅ Done! TXT report generated successfully.{Style.RESET_ALL}")
        
        # Show quick preview
        print(f"\n{Fore.MAGENTA}📋 Quick Preview:{Style.RESET_ALL}")
        if idor_params:
            print(f"  IDOR Parameters: {', '.join(idor_params[:3])}...")
        if biz_params:
            print(f"  Business Logic: {', '.join(biz_params[:3])}...")
        if access_params:
            print(f"  Access Control: {', '.join(access_params[:3])}...")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()

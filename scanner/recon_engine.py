import requests
import re
import time
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style

class ReconEngine:
    """Simplified reconnaissance engine"""
    
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Results storage
        self.results = {
            'endpoints': set(),
            'parameters': set(),
            'forms': [],
            'admin_panels': []
        }
    
    def run_recon(self):
        """Run comprehensive reconnaissance"""
        print(f"{Fore.CYAN}[*] Running reconnaissance...{Style.RESET_ALL}")
        
        # Step 1: Basic crawling
        print(f"  {Fore.YELLOW}[→] Crawling website...{Style.RESET_ALL}")
        self._crawl_website()
        
        # Step 2: Check common endpoints
        print(f"  {Fore.YELLOW}[→] Checking common paths...{Style.RESET_ALL}")
        self._check_common_paths()
        
        # Step 3: Categorize parameters
        print(f"  {Fore.YELLOW}[→] Categorizing findings...{Style.RESET_ALL}")
        categorized = self._categorize_parameters()
        
        # Prepare final results
        final_results = {
            'endpoints': sorted(list(self.results['endpoints'])),
            'parameters': sorted(list(self.results['parameters'])),
            'admin_panels': self.results['admin_panels'],
            'forms': self.results['forms'],
            'total_endpoints': len(self.results['endpoints']),
            'total_parameters': len(self.results['parameters']),
            'categorized_params': categorized
        }
        
        return final_results
    
    def _crawl_website(self, max_pages=30):
        """Crawl the website"""
        to_visit = [self.base_url]
        visited = set()
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    # Parse URL
                    parsed = urlparse(url)
                    self.results['endpoints'].add(parsed.path)
                    
                    # Extract query parameters
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        self.results['parameters'].update(params.keys())
                    
                    # Parse HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = self._make_absolute(url, href)
                        if absolute_url and absolute_url.startswith(self.base_url):
                            if absolute_url not in visited:
                                to_visit.append(absolute_url)
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        self._extract_form(form, url)
                            
            except Exception:
                continue
    
    def _check_common_paths(self):
        """Check for common paths"""
        common_paths = [
            '/admin', '/admin/login', '/admin/dashboard', '/dashboard',
            '/user', '/users', '/profile', '/account', '/settings',
            '/api', '/api/v1', '/api/v2', '/api/users', '/api/admin',
            '/login', '/logout', '/register', '/signup', '/signin',
            '/config', '/configuration', '/env', '/.env'
        ]
        
        for path in common_paths:
            url = self.base_url + path
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code < 400:  # 2xx or 3xx
                    self.results['endpoints'].add(path)
                    
                    # Check if admin panel
                    if 'admin' in path.lower():
                        title = self._extract_title(response.text)
                        self.results['admin_panels'].append({
                            'url': url,
                            'status': response.status_code,
                            'title': title
                        })
                        
            except Exception:
                continue
    
    def _extract_form(self, form, base_url):
        """Extract form information"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        form_data = {
            'action': self._make_absolute(base_url, action),
            'method': method,
            'parameters': []
        }
        
        # Extract input fields
        for input_tag in form.find_all(['input', 'select', 'textarea']):
            name = input_tag.get('name')
            if name:
                param_type = input_tag.get('type', 'text')
                form_data['parameters'].append({
                    'name': name,
                    'type': param_type
                })
                self.results['parameters'].add(name)
        
        self.results['forms'].append(form_data)
    
    def _categorize_parameters(self):
        """Categorize parameters by type"""
        categorized = {
            'user_related': [],
            'resource_related': [],
            'business_logic': [],
            'access_control': [],
            'sensitive': []
        }
        
        for param in self.results['parameters']:
            param_str = str(param).lower()
            
            # User related
            if any(keyword in param_str for keyword in ['user', 'id', 'uid', 'account', 'profile']):
                categorized['user_related'].append(param)
            
            # Resource related
            elif any(keyword in param_str for keyword in ['doc', 'file', 'order', 'invoice', 'product']):
                categorized['resource_related'].append(param)
            
            # Business logic
            elif any(keyword in param_str for keyword in ['amount', 'price', 'quantity', 'discount', 'status']):
                categorized['business_logic'].append(param)
            
            # Access control
            elif any(keyword in param_str for keyword in ['role', 'permission', 'access', 'privilege', 'admin']):
                categorized['access_control'].append(param)
            
            # Sensitive
            elif any(keyword in param_str for keyword in ['password', 'token', 'secret', 'key', 'credit']):
                categorized['sensitive'].append(param)
        
        return categorized
    
    def _make_absolute(self, base_url, href):
        """Convert relative URL to absolute"""
        if not href or href.startswith('#') or href.startswith('javascript:'):
            return None
        
        if href.startswith('http'):
            return href
        
        return urljoin(base_url, href)
    
    def _extract_title(self, html):
        """Extract page title"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else 'No title'
        except:
            return 'No title'

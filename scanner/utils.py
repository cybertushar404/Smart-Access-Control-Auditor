import re
from colorama import Fore, Style

def print_status(message, status="info"):
    """Print status messages with colors"""
    colors = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "debug": Fore.MAGENTA
    }
    
    prefix = {
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[-]",
        "debug": "[DEBUG]"
    }
    
    color = colors.get(status, Fore.WHITE)
    print(f"{color}{prefix.get(status, '[*]')} {message}{Style.RESET_ALL}")

def extract_params_from_url(url):
    """Extract parameters from URL"""
    import urllib.parse as urlparse
    parsed = urlparse.urlparse(url)
    params = urlparse.parse_qs(parsed.query)
    return list(params.keys())

def is_sensitive_param(param_name):
    """Check if parameter is sensitive"""
    sensitive_keywords = [
        'password', 'token', 'secret', 'key', 'auth',
        'credit', 'card', 'ssn', 'phone', 'email'
    ]
    
    param_lower = param_name.lower()
    return any(keyword in param_lower for keyword in sensitive_keywords)

def is_business_logic_param(param_name):
    """Check if parameter is related to business logic"""
    business_keywords = [
        'amount', 'price', 'quantity', 'discount', 'coupon',
        'balance', 'limit', 'threshold', 'status', 'role'
    ]
    
    param_lower = param_name.lower()
    return any(keyword in param_lower for keyword in business_keywords)

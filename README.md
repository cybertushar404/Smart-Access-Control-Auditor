# 🔒 Smart Access Control Auditor

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Tool](https://img.shields.io/badge/Security-Tool-red.svg)](https://github.com/yourusername/smart-access-auditor)

A powerful reconnaissance tool for discovering access control vulnerabilities and business logic flaws in web applications. Designed for cybersecurity students and professionals to learn about broken authorization issues.

## 📋 Features

- **🔍 Smart Reconnaissance**: Automated discovery of endpoints and parameters
- **🎯 Parameter Analysis**: Categorizes parameters by type (User, Business, Access, etc.)
- **🚨 Vulnerability Detection**: Identifies potential IDOR, privilege escalation, and business logic flaws
- **📄 Clean TXT Reports**: Easy-to-read output with actionable payloads
- **⚡ Fast & Lightweight**: Minimal dependencies, quick scanning
- **🎓 Educational Focus**: Perfect for learning web application security

## 📸 Screenshots
<img width="584" height="493" alt="image" src="https://github.com/user-attachments/assets/d620cf52-2af2-4633-b8b1-7c35496d81c2" />


## 🚀 Quick Start

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)

## 🔧 Project Structure
```
smart-access-auditor/
├── main.py                      # Main entry point
├── requirements.txt             # Python dependencies
├── scanner/                     # Core scanner modules
│   ├── __init__.py             # Package file
│   ├── recon_engine.py         # Reconnaissance engine
│   └── txt_reporter.py         # TXT report generator
├── reports/                     # Generated reports folder
```

## How It Works
Step-by-Step Process:
- Crawling: Visits web pages and extracts links (BFS algorithm)
- Parameter Extraction: Parses URLs and forms for parameters
- Categorization: Classifies parameters by security relevance
- Analysis: Identifies potential vulnerability patterns
- Reporting: Generates comprehensive TXT report with findings

##Technical Details:
- Uses requests for HTTP operations
- Uses BeautifulSoup for HTML parsing
- Implements BFS (Breadth-First Search) for crawling
- Custom pattern matching for parameter classification
- Rate limiting to avoid overwhelming servers

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/cybertushar404/Smart-Access-Control-Auditor.git
cd smart-access-auditor
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the tool:
```# Test on a demo vulnerable site
python main.py http://demo.testfire.net/

# Test on your local app
python main.py http://localhost:5000

# Test on any website (with permission)
python main.py https://example.com -d 3
```
## Detailed Usage
```
python main.py <target_url>
```
## Options
```
python main.py <target_url> [options]

Options:
  -d, --depth INTEGER  Crawling depth (default: 2)
                       Higher depth = more thorough but slower scan
  
Examples:
  python main.py https://example.com           # Basic scan
  python main.py https://example.com -d 3      # Deeper scan
  python main.py http://localhost:8080         # Local application
```

### Output
The tool generates a comprehensive TXT report in the reports/ folder with:

- Discovered endpoints and parameters
- Categorized parameters (User, Business, Access, etc.)
- Potential vulnerabilities
- Test payloads for manual testing
- Security recommendations

## What It Finds
1. Parameter Discovery
- User-related parameters (id, user_id, account, etc.)
- Business logic parameters (amount, price, quantity, discount)
- Access control parameters (role, permission, access, privilege)
- Sensitive parameters (password, token, secret, key)

2. Vulnerability Detection
- IDOR (Insecure Direct Object References): Parameters that could allow access to unauthorized resources
- Business Logic Flaws: Parameters that could be manipulated for financial gain
- Access Control Issues: Admin panels without proper authentication
- Privilege Escalation: Parameters that could modify user roles/permissions

3. Reconnaissance
- Endpoint discovery through crawling
- Common admin panel detection
- Form parameter extraction
- URL parameter analysis

## Ethical Usage
✅ DO:
- Test only websites you own or have explicit permission to test
- Use for educational purposes and authorized security assessments
- Report any discovered vulnerabilities responsibly to the website owner
- Respect robots.txt and rate limits

❌ DON'T:
- Test websites without permission
- Use for malicious purposes
- Perform denial-of-service attacks
- Violate laws or terms of service

📚 Learning Resources
Related Topics to Study:
- OWASP Top 10: Focus on A01:2021-Broken Access Control
- IDOR Vulnerabilities: Understanding and testing methodology
- Business Logic Flaws: Real-world examples and patterns
- Web Crawling Ethics: Legal and ethical considerations
- Parameter Tampering: Techniques and defenses

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
For Educational Purposes Only

This tool is designed for:
- Learning about web application security
- Authorized security assessments
- Educational demonstrations

The author is not responsible for any misuse of this tool. Always obtain proper authorization before testing any website.

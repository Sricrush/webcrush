# webcrush
Multi-domain Web Application  SSL/TLS Security Scanner (Headers + Cookies + SSLyze)
# Web + SSL/TLS Security Scanner

A Bash-based security scanner** for web applications that performs comprehensive HTTP header, cookie, OPTIONS method, and SSL/TLS vulnerability checks. 

This tool is built for Kali Linux / Linux environments and leverages curl for web testing and SSLyze for SSL/TLS analysis. It supports scanning multiple domains, either via a file input or command-line arguments.

## Features

- ✅ Checks Security Headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`  
- ✅ Detects Server and X-Powered-By header disclosures  
- ✅ Checks OPTIONS HTTP method 
- ✅ Scans cookie flags (`Secure` and `HttpOnly`)  
- ✅ Prints header and OPTIONS POC commands  
- ✅ SSL/TLS Vulnerability Scan using SSLyze:
  - Weak TLS versions (1.0, 1.1)  
  - Weak ciphers (CBC_SHA, 3DES_EDE)  
  - Heartbleed, ROBOT, OpenSSL CCS injection, compression attacks  
- ✅ Supports multiple domains from command-line, file, or manual input  
- ✅ Outputs full SSLyze results and highlights vulnerabilities  

## 🔧 Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/web-ssl-tester.git
```
### Move into the Directory
```bash
cd web-ssl-tester
```
### Make the Script Executable
```bash
chmod +x web_ssl_scanner.sh
```
## Usage
### Single domain
```bash
./web_ssl_scanner.sh https://example.com
```
### Multiple domains
```bash
./web_ssl_scanner.sh https://example1.com https://example2.com
```
### Domains from file
```bash
./web_ssl_scanner.sh -f domains.txt
```

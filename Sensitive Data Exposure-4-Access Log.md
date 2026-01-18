# Juice-Shop Write-Up: Access Log

## Challenge Overview
**Title:** Access Log  
**Category:** Sensitive Data Exposure  
**Difficulty:** ⭐⭐⭐⭐ (4/6)

This challenge exploits inadequate access controls on server log files. While the application requires support team authentication, it fails to implement proper authorization for highly sensitive system logs, allowing any support team member to access files containing user behavior, IP addresses, and system information.

---

## Tools Used
* **Web Browser:** Used for authentication and accessing discovered files
* **Dirbuster / Gobuster:** Directory enumeration tools for discovering hidden paths
* **Text Editor:** For analyzing log file contents

---

## Methodology and Solution

### Prerequisite: Support Team Access
1. **Support Account Login:**
   * **Prerequisite:** Must complete "Login Support Team" challenge first
   * Logged in using support credentials: `support@juice-sh.op`
   * Verified successful authentication
   * Note: Refer to "Login Support Team" challenge for credential discovery method

### Directory Enumeration
1. **Unauthenticated Reconnaissance:**
   * Performed initial directory scan without authentication
   * Discovered common directories: `/assets`, `/api`, `/rest`, `/ftp`
   * Could not locate access logs without proper credentials

2. **Authenticated Enumeration:**
   * Configured Dirbuster with support team session cookie
   * Extracted token from browser Developer Tools → Storage → Cookies
   * Used wordlist: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
   * Added file extensions: `log, txt, zip`

**Gobuster Command Example:**
```bash
gobuster dir -u http://localhost:3000 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -c 'token=YOUR_SUPPORT_TOKEN_HERE' \
  -t 20 \
  -x log,txt \
  -r
```

### Log File Discovery
1. **Support Directory Found:**
   * Enumeration revealed `/support` directory (200 OK when authenticated)
   * Continued recursive scan within `/support`
   * Discovered `/support/logs` subdirectory
   * Directory listing was enabled, showing available log files

2. **Accessing the Logs:**
   * Navigated to: `http://localhost:3000/support/logs`
   * Found `access.log` file in directory listing
   * Downloaded log by accessing: `http://localhost:3000/support/logs/access.log`

3. **Log File Analysis:**
   * Opened downloaded access.log file
   * Examined contents revealing:
     - User IP addresses
     - Request paths and API endpoints
     - User agents and timestamps
     - Authentication attempts
     - Error responses

**Example Log Entries:**
```
127.0.0.1 - - [15/Dec/2025:10:23:45 +0000] "GET /rest/products/search?q=apple HTTP/1.1" 200 1543
127.0.0.1 - - [15/Dec/2025:10:24:12 +0000] "POST /api/Users/login HTTP/1.1" 401 87
```

* Challenge completed upon accessing the log file!

---

## Solution Explanation

The vulnerability exists because the application stores sensitive server logs in a predictable directory structure (`/support/logs`) with inadequate access controls. While authentication is required, any support team member can access system logs without elevated privileges.

**Security Failures:**
- **Weak Authorization:** Support role sufficient to access system logs (should require admin/security role)
- **Predictable Paths:** `/support/logs` follows obvious naming convention, easily discoverable
- **Directory Listing Enabled:** All log files visible in directory
- **Sensitive Data Exposure:** Logs contain IP addresses, user behavior, API endpoints, and potential PII

**Attack Impact:** Attackers with support access gain reconnaissance data including application architecture, user behavior patterns, and potential vulnerabilities through error patterns.

---

## Remediation

To prevent unauthorized access to sensitive log files:

* **Role-Based Access Control:** Restrict log access to security administrators only, not general support team. Implement proper RBAC with elevated privileges required for system files.

* **Secure Storage Location:** Store logs outside the web root directory. Use centralized logging systems (ELK Stack, Splunk) instead of file-based logs accessible via HTTP.

* **Disable Directory Listing:** Prevent directory browsing by disabling autoindex in web server configuration.

* **Log Sanitization:** Redact sensitive information (IP addresses, emails, tokens) from logs before they can be accessed. Implement data minimization principles.

* **Access Auditing:** Log all attempts to access log files with user ID, timestamp, and IP address. Alert on suspicious access patterns.

* **Web Server Configuration:** Configure nginx/Apache to explicitly deny access to log directories and sensitive file extensions (.log, .bak, etc.).

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 45 Minutes
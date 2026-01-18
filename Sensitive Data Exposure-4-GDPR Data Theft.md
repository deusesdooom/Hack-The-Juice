# Juice-Shop Write-Up: GDPR Data Theft

## Challenge Overview
**Title:** GDPR Data Theft  
**Category:** Sensitive Data Exposure  
**Difficulty:** ⭐⭐⭐⭐ (4/6)

This challenge exploits a business logic flaw in the GDPR data export feature where the application uses obfuscated email addresses instead of unique user IDs for identification, allowing attackers to craft collision emails and steal other users' personal data.

---

## Tools Used
* **Web Browser:** Used for accessing the application and testing features
* **Browser Developer Tools:** For analyzing JavaScript code and network requests
* **Text Editor:** For crafting collision email addresses

---

## Methodology and Solution

### Initial Discovery
1. **Understanding the Feature:**
   * Logged into Juice Shop account
   * Found GDPR data export functionality in Privacy & Security section
   * Tested legitimate data export for own account
   * Observed the exported data includes personal info, orders, addresses, and reviews

### Analyzing the Vulnerability
1. **Client-Side Code Review:**
   * Opened Browser Developer Tools (F12)
   * Examined JavaScript files (main.js)
   * Discovered the application uses email obfuscation in the export process
   * Found obfuscation pattern: `first_char***@first_chars***extension`

2. **Pattern Analysis:**
   * Monitored Network tab during data export
   * Captured POST request showing obfuscated email format
   * Example patterns observed:
     ```
     admin@juice-sh.op → a***@ju***op
     alice.smith@juice-sh.op → a***@ju***op
     ```
   * **Key Discovery:** Multiple emails produce the same obfuscated pattern!

### Identifying the Attack Vector
1. **Logic Flaw Recognition:**
   * Server matches users based on obfuscated email pattern, not user ID
   * Multiple different emails can create identical obfuscation
   * Attack plan:
     1. Identify target user's obfuscated email pattern
     2. Create email that produces same pattern
     3. Register new account with collision email
     4. Request data export
     5. Receive target user's data

### Exploitation
1. **Target Selection:**
   * Selected target: `admin@juice-sh.op`
   * Obfuscated pattern: `a***@ju***op`

2. **Crafting Collision Email:**
   * Designed email matching the pattern requirements:
     - Starts with 'a'
     - Domain structure: `ju___op`
   * Crafted email: `a123@ju456op`

3. **Account Registration:**
   * Created new account with crafted email: `a123@ju456op`
   * Completed registration with password and required fields

4. **Data Export Request:**
   * Logged in with new collision account
   * Navigated to GDPR data export feature
   * Clicked "Request Data Export"
   * Downloaded the exported JSON file

5. **Verification:**
   * Opened exported data file
   * **Critical Discovery:** File contained admin's personal data, not own account data
   * Successfully accessed:
     - Admin's email (admin@juice-sh.op)
     - Admin's orders and purchase history
     - Admin's addresses
     - Admin's wallet balance
   * Challenge completed!

---

## Solution Explanation

The vulnerability exists because the application uses obfuscated email patterns instead of unique user IDs to identify whose data to export. The obfuscation algorithm creates a many-to-one mapping where multiple distinct email addresses produce identical patterns.

**Example:**
- Target: `admin@juice-sh.op` → `a***@ju***op`
- Attacker: `a123@ju456op` → `a***@ju***op` (same pattern!)

When the attacker requests a data export, the server matches the obfuscated pattern and returns the wrong user's data.

**Vulnerability Type:** Business Logic Flaw + Broken Access Control - The server fails to verify that the authenticated user matches the data being exported.

---

## Remediation

To prevent this critical vulnerability:

* **Use Unique User IDs:** Always derive user identity from the authenticated session's user ID, never from email addresses or obfuscated patterns
* **Server-Side Authorization:** Verify that the authenticated user has permission to access the requested data
* **Remove Obfuscation from Logic:** Use obfuscation only for display purposes in the UI, never in backend authorization logic
* **Password Re-Authentication:** Require users to re-enter their password before exporting sensitive data
* **Audit Logging:** Log all data export requests with user ID, IP address, and timestamp to detect suspicious patterns

**Key Principle:** Authentication (proving who you are) ≠ Authorization (proving you can access specific data). Always validate both.

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 120 Minutes
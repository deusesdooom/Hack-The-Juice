# Broken Access Control - Product Tampering

**Difficulty Level:** ⭐⭐⭐ (3/6)

---

## Overview

This challenge demonstrates a broken access control vulnerability where users can modify product information through an unprotected API endpoint. The goal is to change the href link in the OWASP SSL Advanced Forensic Tool (O-Saft) product description to point to `https://owasp.slack.com`, showcasing how lack of proper authorization allows unauthorized data manipulation.

---

## Methodology

### Step 1: Finding the Target
**Technique:** Application Reconnaissance  
**Tools Used:** Web Browser, Firefox Developer Tools

- Navigated to the Juice Shop product catalog
- Located the OWASP SSL Advanced Forensic Tool (O-Saft) product
- Clicked on the product to view its details
- Noticed the product description had a "More..." link
- Observed the original link destination and product ID in the URL

### Step 2: Testing for XSS
**Technique:** Initial Vulnerability Probing  
**Tools Used:** Web Browser

- First thought: Maybe I can inject HTML/JavaScript through reviews
- Tried submitting an XSS payload in the review field:
  ```html
  <script>alert(1)</script>
  ```
- The payload was rendered as plain text - XSS wasn't the way
- Realized I needed to find another approach to modify the product

### Step 3: Exploring Admin Access
**Technique:** Privilege Assessment  
**Tools Used:** Web Browser

- Logged in as administrator (using previously discovered SQL injection)
- Explored the admin panel at `/administration`
- Found I could only view users and feedback
- **No "Edit Product" button anywhere in the UI**
- This was suspicious - how do admins actually edit products?

### Step 4: Discovering Hidden Paths
**Technique:** Directory Enumeration  
**Tools Used:** Gobuster

- Decided to search for hidden directories and endpoints
- Ran Gobuster against the application:
  ```bash
  gobuster dir -u http://192.168.1.202:3000 -w /usr/share/wordlists/dirb/common.txt --wildcard -b 200
  ```
- Discovered several interesting paths:
  - `/api/`
  - `/rest/`
  - `/assets/`
- Some paths gave "500 Error: Unexpected path" when accessed

### Step 5: Finding the API Structure
**Technique:** Network Traffic Analysis  
**Tools Used:** Firefox Developer Tools (Network Tab)

- Opened Firefox Developer Tools and switched to Network tab
- Submitted a product review while monitoring traffic
- **Key Discovery:** Found the REST API endpoint structure:
  ```
  http://192.168.1.202:3000/rest/products/9/reviews
  ```
- Noted that product ID 9 is the O-Saft product
- Realized the API follows RESTful conventions

### Step 6: Testing with POSTMAN
**Technique:** API Exploration  
**Tools Used:** POSTMAN

- Opened POSTMAN to test the discovered endpoint
- Tried getting the reviews:
  ```
  GET http://192.168.1.202:3000/rest/products/9/reviews
  ```
- Success! Got the review data back
- Tried accessing the description:
  ```
  GET http://192.168.1.202:3000/rest/products/9/description
  ```
- Got "Unexpected path" error - dead end

### Step 7: Attempting API Brute-force
**Technique:** Endpoint Discovery  
**Tools Used:** Gobuster

- Tried brute-forcing more endpoints:
  ```bash
  gobuster dir -u http://192.168.1.202:3000/rest/products/9/ -w wordlist.txt
  ```
- Only found `/reviews` before the service got unstable
- This approach wasn't working well

### Step 8: Switching to /api/ Path
**Technique:** Alternative API Discovery  
**Tools Used:** Firefox Developer Tools, POSTMAN

- Remembered seeing a DELETE request to `/api/` when deleting feedback as admin
- Switched focus from `/rest/` to `/api/` endpoints
- Tested the new path:
  ```
  GET http://192.168.1.202:3000/api/products/9
  ```
- **Success!** Retrieved full product information including the description field

### Step 9: Testing HTTP Methods
**Technique:** HTTP Verb Tampering  
**Tools Used:** POSTMAN

- Now I had the right endpoint - time to test modification
- Tried different HTTP methods on `/api/products/9`:
  - GET: Retrieved product data ✅
  - POST: Not appropriate for updates
  - PUT: Used for updating resources ✅
- **Discovery:** PUT method worked for modifying products!

### Step 10: Modifying the Product
**Technique:** API Parameter Tampering  
**Tools Used:** POSTMAN

- Crafted a PUT request to change the description:
  ```http
  PUT /api/products/9 HTTP/1.1
  Host: 192.168.1.202:3000
  Content-Type: application/json
  Authorization: Bearer [admin-token]

  {
    "description": "Modified description with <a href=\"https://www.owasp.slack.com\">More...</a>"
  }
  ```
- Sent the request - it worked!
- Checked the product page and saw my changes

### Step 11: Fine-Tuning the Exploit
**Technique:** Precision Targeting  
**Tools Used:** POSTMAN

- Challenge still wasn't marked as complete
- Re-read the requirements: href must be exactly `https://owasp.slack.com`
- **Mistake found:** I used `https://www.owasp.slack.com` (with www)
- Corrected the PUT request:
  ```http
  PUT /api/products/9 HTTP/1.1
  Host: 192.168.1.202:3000
  Content-Type: application/json
  Authorization: Bearer [admin-token]

  {
    "description": "O-Saft is an easy to use tool to show information about SSL certificate and tests the SSL connection according given list of ciphers and various SSL configurations. <a href=\"https://owasp.slack.com\" target=\"_blank\">More...</a>"
  }
  ```

### Step 12: Challenge Completion
**Technique:** Verification  
**Tools Used:** Web Browser

- Refreshed the O-Saft product page
- Clicked the "More..." link
- Verified it redirected to `https://owasp.slack.com`
- Challenge completed!

---

## Vulnerabilities Identified

### Primary Vulnerability
- **Type:** Broken Access Control (Missing Function-Level Authorization)
- **CWE Reference:** CWE-285 - Improper Authorization
- **Affected Component:** Products API endpoint (`/api/products/{id}`), authorization middleware
- **Severity Level:** 🔴 **CRITICAL**

**Explanation:**

The application exposes an API endpoint that allows modification of product data without proper authorization checks. Even though an admin session was used in this case, the vulnerability demonstrates multiple security failures:

Key security failures:
- **No Role-Based Access Control (RBAC):** The API doesn't verify if the authenticated user has permissions to modify product data
- **Missing Object-Level Authorization:** No validation that the user should have access to modify this specific product
- **Unprotected PUT Endpoint:** Critical modification operations lack proper authorization middleware
- **Trust in Authentication Alone:** Having a valid token doesn't mean you should be able to modify products

**Attack Vector:**

An attacker with any valid user account could potentially:
- Discover the `/api/products/{id}` endpoint through enumeration
- Use PUT requests to modify product information
- Change product descriptions, prices, images, or availability
- Inject malicious links or XSS payloads into product data

### Secondary Vulnerabilities
- **Insufficient Input Validation:** HTML content in description field isn't properly sanitized, could enable stored XSS
- **Information Disclosure:** API endpoint reveals full product structure, helping attackers plan further attacks
- **Predictable Resource IDs:** Sequential product IDs (1, 2, 3...) make enumeration trivial

---

## Risk Assessment

### Business Impact

**Potential Consequences:**

1. **Revenue Loss:**
   - Attackers can modify product prices to $0.01
   - Change product availability to prevent sales
   - Redirect product links to competitor websites
   - Massive financial impact during high-traffic periods

2. **Reputational Damage:**
   - Malicious links could redirect customers to phishing sites
   - Offensive or inappropriate content in product descriptions
   - Complete loss of customer trust in platform security
   - Long-term brand damage from tampered product information

3. **Legal & Compliance:**
   - False advertising if product information is manipulated
   - Consumer protection law violations
   - PCI-DSS compliance issues
   - Liability for damages from malicious redirects

4. **Data Integrity:**
   - Product catalog becomes completely unreliable
   - Inventory management systems receive corrupted data
   - Business decisions based on false information
   - Difficulty identifying which products were tampered with

5. **Security Escalation:**
   - Stored XSS vulnerabilities through HTML injection
   - Product descriptions could contain malicious JavaScript
   - Could be chained with other vulnerabilities for greater impact

**Attack Scenarios:**

1. **Price Manipulation:**
   ```
   - Find high-value products (laptops, phones, etc.)
   - Change prices to $0.01
   - Use automated purchasing before detection
   - Massive financial loss for business
   ```

2. **Competitor Sabotage:**
   ```
   - Modify all product descriptions
   - Add negative fake reviews
   - Redirect product links to competitor site
   - Drive all traffic away from business
   ```

3. **Phishing Campaign:**
   ```
   - Target popular products
   - Change "More..." links to phishing pages
   - Steal customer credentials and payment info
   - Mass identity theft
   ```

4. **SEO Poisoning:**
   ```
   - Inject keyword spam into descriptions
   - Add malicious links for search ranking
   - Manipulate search engine results
   - Damage site's search reputation
   ```

---

## Remediation

To prevent this vulnerability in real applications, the following measures should be implemented:

**Core Fix:**
The API endpoint must implement proper role-based access control (RBAC) to ensure only authorized users with specific permissions can modify product data. Authentication alone is not sufficient - the system must verify that the authenticated user has the "product_manager" or similar role before allowing modifications.

**Security Practices:**

- **Implement Role-Based Access Control (RBAC):** Define clear roles (admin, product_manager, customer) and restrict product modification to authorized roles only. Verify user roles before allowing any product updates. Implement the principle of least privilege - users should only have the minimum permissions needed for their job function.

- **Apply Defense in Depth:** Don't rely on authentication alone - require both authentication AND authorization. Validate permissions at multiple layers (API gateway, application logic, database level). Use security headers to prevent common attacks.

- **Input Validation & Sanitization:** Whitelist only allowed fields for updates (name, description, price, etc.). Validate data types and acceptable ranges for all inputs. Sanitize HTML content to prevent stored XSS attacks. Restrict allowed HTML tags to safe ones only (no script tags, no event handlers).

- **Audit Logging:** Log all product modifications with user ID, timestamp, IP address, and what was changed. Implement real-time alerting for suspicious patterns like mass product modifications. Maintain immutable audit logs for forensic analysis and compliance.

- **API Security Best Practices:** Implement rate limiting to prevent automated attacks and enumeration. Use API versioning to maintain compatibility while fixing security issues. Consider using an API gateway for centralized security controls. Document which roles have access to which API endpoints.

- **Security Testing:** Include authorization tests in your CI/CD pipeline to catch regressions. Perform regular penetration testing with different user roles. Test that regular users cannot access admin functions. Use automated security scanners to find unprotected endpoints.

---

## References

- [OWASP Top 10 2021 - A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP API Security Top 10 - API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

---

## Learning Outcomes

- **API Security Fundamentals:** Learned how RESTful APIs can be exploited when they lack proper authorization checks through hands-on testing
- **Authorization vs Authentication:** Understood the critical difference between proving who you are (authentication) and proving what you're allowed to do (authorization)
- **Enumeration Techniques:** Gained practical experience with directory enumeration using Gobuster and manual API exploration with POSTMAN
- **HTTP Methods Understanding:** Learned how different HTTP methods (GET, PUT, POST, DELETE) should be protected based on their impact and functionality
- **Defense in Depth:** Recognized that multiple security layers are necessary - authentication alone is never sufficient
- **Tool Proficiency:** Developed hands-on skills with POSTMAN for API testing and Firefox Developer Tools for network traffic analysis
- **Real-World Impact:** Appreciated how broken access control can lead to data manipulation, financial loss, and serious business disruption

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 90 Minutes
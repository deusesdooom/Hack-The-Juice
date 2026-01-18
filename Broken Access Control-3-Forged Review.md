# Broken Access Control - Forged Review

**Difficulty Level:** ⭐⭐⭐ (3/6)

---

## Overview

This challenge demonstrates a broken access control vulnerability where users can forge product reviews by impersonating other users through API request manipulation. The application fails to properly verify that the person submitting a review is actually the authenticated user, allowing attackers to post reviews under someone else's name.

---

## Methodology

### Step 1: Setting Up
**Technique:** Initial Reconnaissance  
**Tools Used:** Web Browser

- Created a new user account on Juice Shop
- Browsed the product catalog
- Selected a product to test the review functionality
- This gave me a baseline understanding of how reviews work

### Step 2: Capturing the Review Request
**Technique:** HTTP Traffic Interception  
**Tools Used:** Burp Suite Proxy

- Configured browser to route traffic through Burp Suite (127.0.0.1:8080)
- Enabled Intercept mode in Burp Suite
- Wrote and submitted a legitimate product review
- Captured the HTTP request in transit

### Step 3: Analyzing the Request
**Technique:** API Endpoint Analysis  
**Tools Used:** Burp Suite Intercept

- Examined the intercepted PUT request to the review API
- Identified key parameters in the request payload:
  - `message` - the review content
  - `author` or `email` - the user submitting the review
- **Key Discovery:** The author field is controlled by the client!

### Step 4: Forging the Review
**Technique:** Parameter Tampering  
**Tools Used:** Burp Suite Repeater

- Right-clicked the intercepted request → "Send to Repeater"
- Modified the request parameters:
  - Changed the `author`/`email` field to target another user (e.g., victim@juice-sh.op)
  - Updated the review message content
- Sent the manipulated request to the server

Example modified request:
```http
PUT /api/reviews HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "message": "This is a forged review!",
  "author": "victim@juice-sh.op"
}
```

### Step 5: Confirming the Exploit
**Technique:** Verification  
**Tools Used:** Web Browser

- Turned off Burp Suite intercept
- Refreshed the product page in the browser
- Verified the forged review appeared under the victim's name
- Challenge completed successfully!

---

## Vulnerabilities Identified

### Primary Vulnerability
- **Type:** Broken Access Control (Insecure Direct Object Reference)
- **CWE Reference:** CWE-639 - Authorization Bypass Through User-Controlled Key
- **Affected Component:** Review API endpoint (`/api/reviews`), authorization middleware
- **Severity Level:** 🔴 **HIGH**

**Explanation:**

The application fails to verify that the authenticated user is authorized to submit reviews on behalf of the specified author. The server trusts the client-supplied `author` field without validating it against the authenticated session.

Key security failures:
- **No Server-Side Authorization Checks:** The server doesn't verify the authenticated user matches the claimed author
- **Trusts Client-Supplied Identity Data:** User identity comes from the request body instead of the session token
- **Missing Object-Level Access Control:** No validation that the user owns the resource they're creating
- **Session-Data Mismatch:** The authentication token and author field aren't cross-validated

### Secondary Vulnerabilities
- **Potential Input Validation Issues:** If review content isn't sanitized, could enable XSS attacks
- **Audit Trail Compromise:** Security logs become unreliable when user attribution can be forged

---

## Risk Assessment

### Business Impact

**Potential Consequences:**

1. **Data Integrity:**
   - Attackers can create fake reviews impersonating legitimate customers
   - Product ratings can be artificially inflated or deflated
   - Review system becomes completely unreliable

2. **Reputational Damage:**
   - Loss of customer trust in the review system
   - Brand credibility severely damaged
   - Customers may choose competitors with trustworthy reviews

3. **Legal & Compliance:**
   - Violations of consumer protection laws
   - False advertising concerns if fake reviews mislead customers
   - Potential lawsuits from affected parties

4. **Financial Loss:**
   - Reduced sales due to customer distrust
   - Cost of cleaning up fraudulent reviews
   - Lost revenue from damaged reputation

**Attack Scenarios:**

- **Competitor Sabotage:** A competitor posts negative reviews on popular products while impersonating verified customers, driving sales down
- **Fake Promotion:** Attackers post glowing reviews under multiple user identities to artificially boost low-quality products
- **Reputation Attack:** Malicious users target specific products with coordinated fake negative reviews

---

## Remediation

To prevent this vulnerability in real applications, the following measures should be implemented:

**Core Fix:**
The server must derive the review author from the authenticated session or JWT token, never from the request body. The API should automatically assign the authenticated user's identity to the review, completely ignoring any client-supplied author fields.

**Security Practices:**

- **Server-Side Authorization:** Always validate that the authenticated user has permission to perform the action. User identity must come from verified session data, not request parameters that can be manipulated.

- **Secure Session Management:** Implement robust session handling that securely maps session tokens to user accounts. All actions should be authorized based on the verified session owner, not client-provided data.

- **Input Validation & Sanitization:** Validate and sanitize all review content to prevent XSS and injection attacks. Implement character limits and content filtering to maintain review quality.

- **Audit and Monitoring:** Log all review submissions with user ID, timestamp, IP address, and any modifications. Regularly audit logs to detect suspicious patterns like multiple reviews from the same IP or unusual review volumes.

- **Role-Based Access Control (RBAC):** Ensure users can only perform actions within their assigned roles and permissions. Implement additional checks for sensitive operations.

- **Rate Limiting:** Implement rate limiting on review submissions to prevent spam and automated attacks.

---

## Evidence & Artifacts

### Screenshots
**Figure 1: Intercepted PUT Request**  
![Intercept](fr2.png)

**Figure 2: Modify the Author Parameter**  
![Review Submission](fr3.png)

**Figure 3: Verify Review Submission**  
![Repeater](fr4.png)

**Figure 4: Edit Existing Reviews**  
![Modified](fr5.png)

**Figure 5: Identify Review IDs**  
![Modified](fr6.png)

**Figure 6: Manipulate Review by ID**  
![Modified](fr7.png)

**Figure 7: Challenge Completion**  
![Result](fr8.png)

---

## References

- [OWASP Top 10 2021 - A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

## Learning Outcomes

- **Understanding Broken Access Control:** Learned how applications fail to validate user authorization at the API level through hands-on exploitation
- **Authentication vs Authorization:** Understood the critical difference between proving identity (authentication) and proving permissions (authorization)
- **API Security Testing:** Gained practical experience using Burp Suite Proxy and Repeater for intercepting and manipulating HTTP requests
- **Server-Side Validation Importance:** Recognized that all authorization checks must happen server-side, as client-side controls can be easily bypassed
- **Real-World Business Impact:** Appreciated how access control vulnerabilities can compromise data integrity, damage reputation, and harm business operations

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 35 Minutes
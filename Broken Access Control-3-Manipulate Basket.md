# Broken Access Control - Manipulate Basket

**Difficulty Level:** ⭐⭐⭐ (3/6)

---

## Overview

This challenge demonstrates a broken access control vulnerability where users can manipulate other users' shopping baskets by exploiting Insecure Direct Object Reference (IDOR). By intercepting and modifying API requests, attackers can add items to any user's basket without authorization, compromising both data integrity and user experience.

---

## Methodology

### Step 1: Understanding the Basket System
**Technique:** Application Reconnaissance  
**Tools Used:** Web Browser, Developer Tools

- Logged into Juice Shop with my user account
- Navigated to the shopping section
- Added several products to my basket
- Observed how the basket functions normally
- Examined my basket ID in the application

### Step 2: Capturing Basket Requests
**Technique:** HTTP Request Interception  
**Tools Used:** Burp Suite Proxy

- Configured browser to route traffic through Burp Suite (127.0.0.1:8080)
- Enabled Intercept mode
- Added a product to my basket
- Captured the POST request to `/api/BasketItems/`

Normal request structure:
```http
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: Bearer <token>

{
  "ProductId": 1,
  "BasketId": "5",
  "quantity": 1
}
```

### Step 3: Analyzing the Request
**Technique:** API Analysis  
**Tools Used:** Burp Suite Repeater

- Sent the captured request to Burp Repeater
- Identified key parameters in the request:
  - `ProductId` - which product to add
  - `BasketId` - which basket to add it to
  - `quantity` - how many items to add
- **Key Discovery:** The `BasketId` is controlled by the client!
- Noticed basket IDs appear to be sequential integers

### Step 4: Identifying Target Basket IDs
**Technique:** Information Gathering  
**Tools Used:** Web Browser, Burp Suite

- Observed that basket IDs are sequential (1, 2, 3, 4, 5...)
- My basket ID was visible in the application or API responses
- Hypothesized that other users have different basket IDs
- Prepared to test access to basket ID different from my own

### Step 5: Exploiting the IDOR Vulnerability
**Technique:** Basket ID Manipulation  
**Tools Used:** Burp Suite Repeater

- Modified the `BasketId` parameter to a different value
- Tested with basket IDs adjacent to mine (if mine was 5, tried 3, 4, 6, 7)
- Sent the modified request

Example exploitation:
```http
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: Bearer <my-token>

{
  "ProductId": 1,
  "BasketId": "3",  # Another user's basket ID
  "quantity": 1
}
```

### Step 6: Verifying the Exploit
**Technique:** Impact Verification  
**Tools Used:** Web Browser

- Checked if the request was successful (200/201 response)
- Verified that the item was added to the target basket
- Confirmed no authorization error was returned
- **Success:** I was able to add items to another user's basket!

### Step 7: Challenge Completion
**Technique:** Exploitation Confirmation  
**Tools Used:** Web Browser

- Successfully manipulated another user's basket
- Received challenge completion notification
- Confirmed the IDOR vulnerability allowed unauthorized basket access

---

## Vulnerabilities Identified

### Primary Vulnerability
- **Type:** Insecure Direct Object Reference (IDOR) - Broken Access Control
- **CWE Reference:** CWE-639 - Authorization Bypass Through User-Controlled Key
- **Affected Component:** Basket management API (`/api/BasketItems/`), authorization middleware
- **Severity Level:** 🔴 **HIGH**

**Explanation:**

The application fails to verify that the authenticated user has permission to modify the specified basket. The server trusts the client-supplied `BasketId` parameter without validating it against the authenticated user's session.

Key security failures:
- **No Basket Ownership Verification:** Server doesn't check if the basket belongs to the authenticated user
- **Client-Controlled Resource Access:** Basket ID comes from request body instead of session
- **Predictable Identifiers:** Sequential basket IDs make enumeration easy
- **Missing Authorization Checks:** No validation that user owns the resource they're modifying

### Secondary Vulnerabilities
- **Basket ID Enumeration:** Sequential IDs allow attackers to easily guess valid basket IDs
- **Potential Privacy Violation:** Attackers can view or infer basket contents of other users
- **Audit Trail Issues:** Logs may incorrectly attribute actions to the authenticated user

---

## Risk Assessment

### Business Impact

**Potential Consequences:**

1. **Customer Experience Damage:**
   - Victims find unwanted items in their baskets
   - Confusion and frustration during checkout
   - Customers may abandon purchases entirely
   - Loss of trust in the platform

2. **Financial Impact:**
   - Victims charged for items they didn't add
   - Increased customer service costs handling complaints
   - Potential refunds and chargebacks
   - Revenue loss from abandoned carts

3. **Reputational Damage:**
   - News of vulnerability damages brand credibility
   - Loss of customer confidence
   - Competitive disadvantage
   - Negative reviews and social media backlash

4. **Privacy Concerns:**
   - Attackers can infer shopping habits
   - Personal preferences exposed
   - Potential GDPR/privacy law violations
   - User data confidentiality compromised

5. **Operational Disruption:**
   - Inventory tracking becomes unreliable
   - Customer support overwhelmed with complaints
   - Difficult to distinguish legitimate from malicious activity
   - Order fulfillment complications

**Attack Scenarios:**

1. **Basket Stuffing:**
   ```
   - Enumerate basket IDs (1-1000)
   - Add expensive or unwanted items to random baskets
   - Victims discover inflated totals at checkout
   - Mass customer dissatisfaction
   ```

2. **Competitor Sabotage:**
   ```
   - Systematically add items to active baskets
   - Cause cart abandonment through confusion
   - Drive customers to competitor sites
   - Damage business metrics
   ```

3. **Targeted Harassment:**
   ```
   - Identify specific user's basket ID
   - Repeatedly add/remove items
   - Disrupt their shopping experience
   - Personal attack on victim
   ```

4. **Data Mining:**
   ```
   - Enumerate all basket IDs
   - Analyze shopping patterns
   - Extract competitive intelligence
   - Sell data to third parties
   ```

---

## Remediation

To prevent this vulnerability in real applications, the following measures should be implemented:

**Core Fix:**
The server must derive the basket ID from the authenticated user's session rather than accepting it from the client. Each user should only be able to access and modify their own basket, with strict server-side authorization checks.

**Security Practices:**

- **Server-Side Authorization:** Always verify that the basket being modified belongs to the authenticated user. Derive the basket ID from the user's session token, not from request parameters. Reject any attempts to access baskets that don't belong to the authenticated user.

- **Secure Session Management:** Link each basket to a user session securely. Use server-side session storage to map users to their baskets. Never trust client-provided basket IDs for authorization decisions.

- **Non-Sequential Identifiers:** Use UUIDs or GUIDs for basket IDs instead of sequential integers. This prevents enumeration attacks where attackers can guess valid basket IDs. Make basket identifiers unpredictable and difficult to enumerate.

- **Audit and Monitoring:** Log all basket operations with user ID, basket ID, timestamp, and IP address. Implement anomaly detection to flag suspicious patterns like one user accessing multiple baskets. Alert security teams when unauthorized access attempts are detected.

- **Role-Based Access Control (RBAC):** Ensure users can only perform actions on resources they own. Implement proper permission checks before allowing any basket modifications. Validate resource ownership at every API endpoint.

- **Rate Limiting:** Implement rate limiting on basket operations to prevent automated enumeration attacks. Limit the number of basket operations per user per time period.

---

## References

- [OWASP Top 10 2021 - A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Testing Guide - Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

---

## Learning Outcomes

- **Understanding IDOR Vulnerabilities:** Learned how applications fail to properly validate resource ownership, allowing unauthorized access to other users' data
- **Access Control vs Authorization:** Understood the difference between being authenticated (logged in) and being authorized (having permission) to access specific resources
- **API Security Testing:** Gained practical experience using Burp Suite to intercept and modify API requests to test authorization controls
- **Sequential ID Risks:** Recognized how predictable identifiers enable enumeration attacks and unauthorized access
- **Server-Side Validation Importance:** Understood that authorization decisions must always be made server-side based on session data, never client-provided parameters
- **Real-World Impact:** Appreciated how IDOR vulnerabilities can compromise user privacy, damage customer trust, and harm business operations

---

**Challenge Completed:** December 2024  
**Time Taken:** 30 Minutes
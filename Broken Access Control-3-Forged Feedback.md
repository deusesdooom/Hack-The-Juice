# Broken Access Control - Forged Feedback

**Difficulty Level:** ⭐⭐⭐ (3/6)

---

## Overview

This challenge demonstrates a broken access control vulnerability where users can forge feedback submissions by impersonating other users through API request manipulation. The application fails to properly validate who is submitting feedback, allowing attackers to submit feedback under someone else's identity.

---

## Methodology

### Step 1: Understanding the Feedback Feature
**Technique:** Application Analysis  
**Tools Used:** Web Browser

- Logged into my Juice Shop account
- Found the feedback submission form in the Contact/Support section
- Examined the form fields and submission process
- Noticed the form includes user identification fields

### Step 2: Submitting Normal Feedback
**Technique:** Baseline Testing  
**Tools Used:** Web Browser

- Submitted legitimate feedback using my own account
- Observed how the feedback system works
- Confirmed the feedback was attributed to my account
- This established a baseline for comparison

### Step 3: Intercepting the Request
**Technique:** HTTP Traffic Interception  
**Tools Used:** Burp Suite Proxy

- Configured browser to use Burp Suite proxy (127.0.0.1:8080)
- Turned on Intercept mode in Burp Suite
- Submitted another feedback to capture the HTTP request
- Analyzed the intercepted traffic

### Step 4: Analyzing the API Request
**Technique:** Request Structure Analysis  
**Tools Used:** Burp Suite

- Examined the POST request to the feedback API endpoint
- Identified key parameters:
  - `comment` or `message` - the feedback text
  - `author` or `email` - user identification
  - `rating` - feedback rating
- Found the API endpoint (likely `/api/feedbacks`)
- **Key Discovery:** The author field is sent from the client side!

### Step 5: Finding a Target User
**Technique:** Information Gathering  
**Tools Used:** Web Browser

- Looked for other user email addresses in the application
- Checked existing feedback, reviews, or user profiles
- Selected a target email (e.g., victim@juice-sh.op)

### Step 6: Forging the Feedback
**Technique:** Parameter Tampering  
**Tools Used:** Burp Suite Repeater

- Sent the intercepted request to Burp Repeater
- Modified the `author` or `email` field to the target user's email
- Kept the rest of the request structure valid
- Sent the modified request

Example modified request:
```http
POST /api/feedbacks HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "comment": "This is forged feedback!",
  "rating": 5,
  "author": "victim@juice-sh.op"
}
```

### Step 7: Confirming Success
**Technique:** Verification  
**Tools Used:** Web Browser

- Turned off Burp Suite intercept
- Checked the feedback list or admin panel
- Verified the forged feedback appeared under the victim's name
- Challenge completed!

---

## Vulnerabilities Identified

### Primary Vulnerability
- **Type:** Broken Access Control (Insecure Direct Object Reference)
- **CWE Reference:** CWE-639 - Authorization Bypass Through User-Controlled Key
- **Affected Component:** Feedback API endpoint (`/api/feedbacks`), authorization middleware, user attribution system
- **Severity Level:** 🔴 **HIGH**

**Explanation:**

The application fails to enforce proper authorization controls when processing feedback submissions. The server accepts and trusts the client-supplied `author` or `email` field without validating it against the authenticated user's session credentials.

Critical security failures:
- **Missing Authorization Checks:** No server-side verification that authenticated user matches the claimed author
- **Client-Controlled Identity:** User identity derived from request body instead of session/token
- **Lack of Object-Level Access Control:** No validation of ownership before creating resources
- **Session-Data Mismatch:** Authentication token and author field not cross-validated

### Secondary Vulnerabilities
- **Potential Input Validation Issues:** If feedback content isn't sanitized, could enable XSS attacks
- **Audit Trail Compromise:** Forensic logs become unreliable when user attribution can be forged

---

## Risk Assessment

### Business Impact

**Potential Consequences:**

1. **Reputational Damage:**
   - Attackers can submit false complaints or praise under customer names
   - Customer trust in the feedback system is destroyed
   - Brand credibility is severely damaged

2. **Legal & Compliance Risks:**
   - Fraudulent impersonation may violate consumer protection laws
   - GDPR violations if personal data is misused
   - Potential defamation liability

3. **Operational Disruption:**
   - Customer service teams waste resources on fake feedback
   - Legitimate complaints may be dismissed as forgeries
   - Difficult to distinguish real from fake communications

4. **Data Integrity:**
   - Business decisions based on corrupted feedback data
   - Product improvements guided by false information
   - Customer satisfaction metrics become meaningless

**Attack Scenarios:**

- **Competitor Sabotage:** A competitor submits negative feedback impersonating customers to damage reputation
- **Internal Threat:** Employee forges positive feedback to manipulate performance metrics
- **Social Engineering:** Attacker uses forged feedback to request unauthorized account changes

---

## Remediation

To prevent this vulnerability in real applications, the following measures should be implemented:

**Core Fix:**
The server must derive the user's identity from the authenticated session or JWT token, never from the request body. The API should automatically assign the authenticated user's email/ID to the feedback, ignoring any client-supplied author fields.

**Security Practices:**

- **Server-Side Authorization:** Always validate that the authenticated user has permission to perform the action. User identity should come from the session token, not from request parameters.

- **Secure Session Management:** Implement proper session handling that securely maps session IDs to user accounts. Ensure all actions are authorized based on the verified session owner.

- **Input Validation & Sanitization:** Validate and sanitize all user inputs to prevent XSS and injection attacks. Implement rate limiting to prevent spam.

- **Audit and Monitoring:** Log all feedback submissions with user ID, timestamp, and IP address. Regularly audit logs to detect suspicious patterns or unauthorized actions.

- **Role-Based Access Control (RBAC):** Ensure users can only perform actions within their assigned roles and permissions.

---

## Evidence & Artifacts

### Screenshots

**Figure 1: Feedback Form Interface**  
![Feedback Form](forged_feedback1.png)

**Figure 2: Modified Request in Repeater**  
![Result](forged_feedback2.png)

---

## References

- [OWASP Top 10 2021 - A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

## Learning Outcomes

- **Understanding Broken Access Control:** Learned how applications fail to validate user authorization at the API level through hands-on exploitation
- **Authentication vs Authorization:** Understood the difference between proving identity (authentication) and proving permissions (authorization)
- **API Security Testing:** Gained practical experience using Burp Suite to intercept and manipulate HTTP requests
- **Server-Side Validation Importance:** Recognized that all authorization checks must happen server-side, not client-side
- **Real-World Impact:** Appreciated how access control vulnerabilities can compromise data integrity and harm business operations

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 35 Minutes
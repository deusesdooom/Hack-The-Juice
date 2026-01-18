# Broken Authentication - Change Bender's Password

**Difficulty Level:** ⭐⭐⭐⭐ (4/6)

---

## Overview

This challenge demonstrates a broken authentication vulnerability where weak security questions allow attackers to bypass password reset mechanisms by leveraging publicly available information about users.

---

## Methodology

### Step 1: Target Identification
**Technique:** Reconnaissance  
**Tools Used:** Web Browser

- Navigated to the Juice Shop login page
- Located the "Forgot Password?" link
- Identified the target user email: `bender@juice-sh.op`

### Step 2: Security Question Discovery
**Technique:** Enumeration  
**Tools Used:** Web Browser

- Entered Bender's email address in the password reset form
- Submitted the form to reveal the security question
- Security question displayed: **"Company you first worked for as an adult"**

### Step 3: OSINT Research
**Technique:** Open Source Intelligence (OSINT)  
**Tools Used:** Search Engine, Futurama Wiki

- Researched Bender's character background from the "Futurama" television series
- Initial attempt: Tried "Suicide Booth Incorporation" (Bender's canonical first employer)
- Result: Failed - answer rejected by the system

### Step 4: Answer Refinement
**Technique:** OSINT Cross-referencing  
**Tools Used:** Futurama Episode References, Search Engine

- Re-examined the series details for alternative company names
- Discovered the company's informal nickname used in the show
- Identified the answer: **"Stop'n'Drop"** (the colloquial name for the suicide booth company)

### Step 5: Password Reset Execution
**Technique:** Authentication Bypass  
**Tools Used:** Web Browser

- Entered "Stop'n'Drop" as the security question answer
- Successfully bypassed the security question verification
- System allowed password reset for Bender's account
- Set a new password and gained unauthorized access

---

## Vulnerabilities Identified

### Primary Vulnerability
- **Type:** Broken Authentication - Weak Security Questions
- **CWE Reference:** CWE-640 - Weak Password Recovery Mechanism for Forgotten Password
- **Affected Component:** Password reset mechanism, authentication system
- **Severity Level:** 🔴 **HIGH**

**Explanation:**

The application relies on security questions that can be answered using publicly available information. This creates multiple security weaknesses:

Key security failures:
- Security question based on pop culture reference (easily discoverable via OSINT)
- No rate limiting on security question attempts
- No additional verification factors (email confirmation, MFA)
- Predictable answers that don't require personal knowledge of the user

### Secondary Vulnerability
- **Type:** Information Disclosure
- **CWE Reference:** CWE-204 - Observable Response Discrepancy
- **Severity Level:** 🟡 **MEDIUM**

The system reveals whether an email exists in the database by displaying the security question, enabling user enumeration.

---

## Risk Assessment

### Business Impact

**Potential Consequences:**

1. **Account Takeover:** Attackers can gain unauthorized access to user accounts by researching publicly available information
2. **Data Breach:** Compromised accounts may contain sensitive personal information, payment details, or order history
3. **Reputational Damage:** Customers lose trust in the platform's security measures
4. **Regulatory Compliance:** Violations of data protection regulations (GDPR, CCPA) due to inadequate authentication controls
5. **Financial Loss:** Unauthorized purchases, fraudulent transactions using stored payment methods

**Attack Scenario:**

An attacker targets high-profile users or administrators by researching their public social media profiles, Wikipedia pages, or other open sources to answer security questions and gain unauthorized access to their accounts.

---

## Recommended Actions

### Remediation Fixes

#### 1. Eliminate Security Questions
```javascript
// BEFORE (Vulnerable - Security Questions)
app.post('/rest/user/reset-password', (req, res) => {
    const { email, securityAnswer } = req.body;
    const user = db.users.findByEmail(email);
    
    if (user.securityAnswer === securityAnswer) {
        // Allow password reset - INSECURE!
        return res.status(200).json({ resetToken: generateToken() });
    }
});

// AFTER (Secure - Email-based Reset)
app.post('/rest/user/reset-password', async (req, res) => {
    const { email } = req.body;
    const user = await db.users.findByEmail(email);
    
    if (!user) {
        // Return same response regardless of user existence (prevent enumeration)
        return res.status(200).json({ 
            message: 'If this email exists, a reset link has been sent' 
        });
    }
    
    // Generate secure, time-limited token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = Date.now() + 3600000; // 1 hour
    
    await db.users.update(user.id, {
        resetToken: hashToken(resetToken),
        resetTokenExpiry: tokenExpiry
    });
    
    // Send email with reset link
    await emailService.sendPasswordReset(user.email, resetToken);
    
    return res.status(200).json({ 
        message: 'If this email exists, a reset link has been sent' 
    });
});
```

#### 2. Implement Multi-Factor Authentication
```javascript
// Add MFA verification to password reset flow
app.post('/rest/user/verify-reset', async (req, res) => {
    const { email, resetToken, mfaCode } = req.body;
    const user = await db.users.findByEmail(email);
    
    // Verify token validity
    if (!isValidResetToken(user, resetToken)) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Verify MFA code
    if (!verifyMFACode(user, mfaCode)) {
        return res.status(401).json({ error: 'Invalid MFA code' });
    }
    
    // Allow password reset
    return res.status(200).json({ verified: true });
});
```

### Security Best Practices

1. **Email-Based Password Reset:**
   - Send time-limited, single-use reset links to verified email addresses
   - Use cryptographically secure random tokens (minimum 32 bytes)
   - Expire tokens after 1 hour or after use
   - Hash tokens before storing in the database

2. **Multi-Factor Authentication (MFA):**
   - Implement MFA using authenticator apps (TOTP) or SMS codes
   - Require MFA verification before allowing password changes
   - Provide backup codes for account recovery

3. **Rate Limiting:**
   - Limit password reset attempts per email address (e.g., 3 attempts per hour)
   - Implement CAPTCHA after multiple failed attempts
   - Monitor for suspicious patterns and automated attacks

4. **User Enumeration Prevention:**
   - Return identical responses whether the email exists or not
   - Use consistent response times to prevent timing attacks
   - Log all reset attempts for security monitoring

5. **Account Recovery Security:**
   - Notify users via email when password reset is requested
   - Provide option to cancel reset if not initiated by user
   - Require re-authentication for sensitive account changes

6. **Security Awareness:**
   - Educate users about creating strong, unique passwords
   - Encourage use of password managers
   - Warn users never to share security question answers publicly

---

## Evidence & Artifacts

### Screenshots

**Figure 1: Password Reset Page**  
![Password Reset Page](./screenshots/01-forgot-password.png)

**Figure 2: Security Question Revealed**  
![Security Question](./screenshots/02-security-question.png)

**Figure 3: OSINT Research - Futurama Wiki**  
![OSINT Research](./screenshots/03-osint-research.png)

**Figure 4: Failed Attempt - "Suicide Booth Incorporation"**  
![Failed Attempt](./screenshots/04-failed-attempt.png)

**Figure 5: Successful Answer - "Stop'n'Drop"**  
![Successful Answer](./screenshots/05-successful-answer.png)

**Figure 6: Password Reset Success**  
![Password Reset](./screenshots/06-password-reset-success.png)

**Figure 7: Challenge Completion**  
![Challenge Solved](./screenshots/07-challenge-completion.png)

---

## References

- [OWASP Top 10 2021 - A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [NIST Digital Identity Guidelines - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Learning Outcomes

- Understanding how weak security questions compromise authentication security
- Practical experience with OSINT techniques for gathering publicly available information
- Importance of implementing secure password recovery mechanisms
- Recognition that pop culture references and easily discoverable facts should never be used for authentication
- Knowledge of modern best practices: email-based resets and multi-factor authentication

---

**Challenge Completed:** December 15th 2024  
**Time Taken:** 25 Minutes
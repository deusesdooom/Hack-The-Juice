# OWASP Juice Shop - Penetration Testing Project

## Table of Contents
- [Project Overview](#project-overview)
- [About OWASP Juice Shop](#about-owasp-juice-shop)
- [Learning Journey](#learning-journey)
- [Tools & Technologies](#tools--technologies)
- [Methodologies](#methodologies)
- [OWASP Top 10 Categories](#owasp-top-10-categories)
- [Completed Challenges](#completed-challenges)
- [Resources](#resources)

---

## Project Overview

This project documents my penetration testing work on the OWASP Juice Shop, a vulnerable web application designed for security training. I completed 10 security challenges across various OWASP Top 10 categories, documenting vulnerabilities, exploitation techniques, and remediation strategies.

**Objectives:**
- Identify and exploit common web application vulnerabilities
- Understand real-world security risks and their business impact
- Practice ethical hacking methodologies and tools
- Document findings professionally for security reports

---

## About OWASP Juice Shop

**OWASP Juice Shop** is a modern, intentionally insecure web application maintained by the Open Web Application Security Project (OWASP). It serves as a training platform for security professionals, developers, and students.

### Key Features:
- **Modern Tech Stack:** Built with Node.js, Express, and Angular
- **Real-world Scenarios:** Contains realistic vulnerabilities found in production applications
- **Progressive Difficulty:** Challenges range from 1-star (easy) to 6-star (extremely difficult)
- **OWASP Top 10 Coverage:** Includes vulnerabilities from all OWASP Top 10 categories
- **Safe Environment:** Legal and ethical platform for practicing penetration testing

### Application Architecture:
- **Frontend:** Angular-based single-page application (SPA)
- **Backend:** RESTful API built with Node.js and Express
- **Database:** SQLite for data persistence
- **Authentication:** JWT-based session management

---

## Learning Journey

### Background
My interest in cybersecurity began through my high school journey. I was particularly drawn to the offensive security side - understanding how systems can be compromised to better defend them.

### How I Learned
1. **Theoretical Foundation:**
   - Studied OWASP Top 10 vulnerabilities documentation
   - Completed online courses on web application security
   - Read articles and watched tutorials on common attack vectors

2. **Hands-on Practice:**
   - Experimented with different attack techniques
   - Used trial and error to understand vulnerability mechanics
   - Documented each successful exploit for future reference

3. **Tools Mastery:**
   - Learned to use Burp Suite for HTTP traffic analysis
   - Practiced request interception and manipulation
   - Explored browser developer tools for client-side analysis
   - Studied SQL injection and XSS payloads

### Key Learning Moments:
- Understanding the difference between client-side and server-side validation
- Realizing how seemingly small misconfigurations can lead to major breaches
- Learning to think like an attacker to identify security weaknesses
- Recognizing patterns across different vulnerability types

---

## Tools & Technologies

### Primary Tools

#### 1. **Burp Suite Community Edition**
**Purpose:** Web application security testing platform

**Key Features Used:**
- **Proxy:** Intercepts HTTP/HTTPS traffic between browser and application
- **Repeater:** Manually modifies and resends requests for testing
- **Intruder:** Automates customized attacks (used for brute force challenges)
- **Decoder:** Encodes/decodes data in various formats

**Why Burp Suite?**
Industry-standard tool for web penetration testing, allows complete control over HTTP requests and responses.

#### 2. **Web Browser (Chrome)**
**Purpose:** Interface with the application and client-side analysis

**Tools Used:**
- **Developer Tools:** Inspect HTML/CSS/JavaScript, monitor network traffic
- **Console:** Execute JavaScript, test XSS payloads
- **Network Tab:** Analyze API calls and responses
- **Storage Inspector:** View cookies, local storage, session storage

#### 3. **OWASP Juice Shop**
**Purpose:** Target application for security testing

### Supporting Tools

- **Text Editor (VS Code):** Writing scripts and analyzing code
- **cURL:** Command-line HTTP requests for testing
- **SQLMap:** Automated SQL injection testing (for learning purposes)
- **Online Resources:** CyberChef for encoding/decoding, hash crackers

---

## Methodologies

### General Approach

For each challenge, I followed a structured penetration testing methodology:

#### 1. **Reconnaissance**
- Explore the application thoroughly
- Identify potential attack surfaces
- Map out functionality and user flows
- Note interesting behaviors or anomalies

#### 2. **Enumeration**
- Analyze HTTP requests and responses
- Inspect client-side code (JavaScript, HTML)
- Identify API endpoints and parameters
- Look for hidden functionality or comments in source code

#### 3. **Vulnerability Analysis**
- Test inputs for injection vulnerabilities
- Check for broken access control
- Examine authentication mechanisms
- Test for XSS, CSRF, and other client-side attacks

#### 4. **Exploitation**
- Craft specific payloads based on identified vulnerabilities
- Use tools like Burp Suite to manipulate requests
- Document successful exploitation steps
- Capture evidence (screenshots, logs)

#### 5. **Post-Exploitation Analysis**
- Assess the impact of the vulnerability
- Determine severity level
- Consider business and security implications

#### 6. **Documentation**
- Write detailed methodology
- Explain vulnerabilities and risks
- Propose remediation strategies
- Include evidence and artifacts

### Specific Techniques Used

**OSINT (Open Source Intelligence):**
- Searching source code comments
- Analyzing JavaScript files for leaked information
- Finding hidden routes and endpoints

**Parameter Tampering:**
- Modifying request parameters (IDs, prices, user identifiers)
- Testing authorization checks
- Bypassing client-side validation

**Injection Attacks:**
- SQL injection for database manipulation
- NoSQL injection for MongoDB queries
- Command injection attempts

**Authentication Testing:**
- Password guessing and brute force
- Session manipulation
- JWT token analysis

**Access Control Testing:**
- Horizontal privilege escalation (accessing other users' data)
- Vertical privilege escalation (accessing admin functions)
- IDOR (Insecure Direct Object Reference) exploitation

---

## OWASP Top 10 Categories

The OWASP Top 10 represents the most critical security risks to web applications. Here are the categories relevant to my challenges:

### A01:2021 - Broken Access Control
**Description:** Failures in enforcing proper access restrictions, allowing users to access unauthorized resources or perform unauthorized actions.

**Common Issues:**
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Horizontal/vertical privilege escalation
- Force browsing to protected resources

**My Challenges:** Forged Review, Product Tampering, Access Log, Manipulate Basket, Forged Feedback

---

### A02:2021 - Sensitive Data Exposure
**Description:** Failures related to cryptography, often leading to sensitive data exposure.

**Common Issues:**
- Weak encryption algorithms
- Missing encryption on sensitive data
- Improper key management
- Use of deprecated cryptographic functions

**My Challenges:** GDPR Data Theft, Retrieve Blueprint

---

### A03:2021 - Injection
**Description:** User-supplied data is not validated, filtered, or sanitized, allowing attackers to inject malicious code.

**Common Issues:**
- SQL injection
- NoSQL injection
- Command injection
- LDAP injection

**My Challenges:** NoSQL Manipulation

---

### A07:2021 - Broken Authentification
**Description:** Failures in confirming user identity, authentication, and session management.

**Common Issues:**
- Weak passwords
- Credential stuffing
- Session fixation
- Missing multi-factor authentication

**My Challenges:** Change Benders Password

---

### A08:2021 - Improper Input validation
**Description:** Code and infrastructure that does not protect against integrity violations.

**Common Issues:**
- Unsigned or unverified software updates
- Insecure deserialization
- CI/CD pipeline without integrity verification

**My Challenges:** Payback Time

---

## Completed Challenges

Below are the 10 challenges I completed, organized by difficulty level:

| # | Challenge Name | Category | Difficulty | Key Vulnerability |
|---|----------------|----------|------------|-------------------|
| 1 | Forged Review | Broken Access Control | ⭐⭐⭐ | Authorization Bypass |
| 2 | Forged Feedback | Broken Access Control | ⭐⭐⭐ | CAPTCHA Bypass |
| 3 | Product Tampering | Broken Access Control | ⭐⭐⭐ | Price Manipulation |
| 4 | Access Log | Sensitive Data Exposure | ⭐⭐⭐⭐ | Path Traversal |
| 5 | Payback Time | Improper Input validation | ⭐⭐⭐ | Negative Quantity |
| 6 | GDPR Data Theft | Sensitive Data Exposure | ⭐⭐⭐⭐ | Data Export Abuse |
| 7 | Change Benders Password | Broken Authentification | ⭐⭐⭐⭐ | Security Question Bypass |
| 8 | NoSQL Manipulation | Injection | ⭐⭐⭐⭐ | NoSQL Injection |
| 9 | Retrieve Blueprint | Sensitive Data Exposure | ⭐⭐⭐⭐⭐ | File Access |
| 10 | Manipulate Basket | Broken Access Control | ⭐⭐⭐ | Basket Tampering |

Each challenge has its own detailed documentation in separate markdown files following the naming convention: `Category-Difficulty-ChallengeName.md`

---

## Resources

### Documentation & Learning
- [OWASP Juice Shop Official Docs](https://pwning.owasp-juice.shop/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)

### Tools
- [Burp Suite Community](https://portswigger.net/burp/communitydownload)
- [OWASP Juice Shop GitHub](https://github.com/juice-shop/juice-shop)

### Reference Materials
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

---

## Conclusion

This project provided hands-on experience with real-world web application vulnerabilities in a safe, legal environment. Through systematic exploitation and documentation, I gained practical skills in:

- **Offensive Security:** Identifying and exploiting vulnerabilities
- **Security Analysis:** Understanding the root causes of security flaws
- **Risk Assessment:** Evaluating business impact of security issues
- **Professional Documentation:** Communicating technical findings clearly

The lessons learned from OWASP Juice Shop are directly applicable to securing real-world applications and conducting professional penetration tests.

---

**Author:** [Mehdi Ben Khadra]  
**Date:** [03/01/2026]  
**Contact:** [mehdi.ben-khadra@epitech.eu]
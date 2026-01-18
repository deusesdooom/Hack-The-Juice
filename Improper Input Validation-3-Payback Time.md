# Juice-Shop Write-Up: Payback Time

## Challenge Overview
**Title:** Payback Time  
**Category:** Improper Input Validation  
**Difficulty:** ⭐⭐⭐ (3/6)

This challenge exploits missing server-side input validation in the checkout process. By manipulating the quantity field to a negative value, attackers can place orders with negative totals, effectively transferring money from the store to their account instead of making a payment.

---

## Tools Used
* **Web Browser:** Used for accessing the application and completing checkout
* **Burp Suite:** HTTP proxy for intercepting and manipulating API requests
* **Burp Repeater:** For modifying basket item requests
* **FoxyProxy:** Browser extension for easy proxy switching

---

## Methodology and Solution

### Understanding the Shopping Process
1. **Application Reconnaissance:**
   * Created user account and logged in
   * Browsed product catalog to find expensive items
   * Added items to shopping basket
   * Observed checkout workflow: Add items → Review basket → Select address → Choose payment → Complete order

### Traffic Interception Setup
1. **Proxy Configuration:**
   * Configured FoxyProxy to route traffic through Burp Suite (127.0.0.1:8080)
   * Enabled Burp Suite Proxy Intercept mode
   * Verified traffic capture functionality

### Analyzing Normal Requests
1. **Baseline Request Capture:**
   * Added one unit of expensive product to basket
   * Captured POST request to `/api/BasketItems/`
   * Analyzed request structure:

```http
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "ProductId": 10,
  "BasketId": 5,
  "quantity": 1
}
```

### Identifying the Vulnerability
1. **Parameter Analysis:**
   * Observed `quantity` field accepts integer values
   * Noted client-side UI prevents negative quantities
   * Hypothesized server may lack validation
   * Attack vector: Manipulate quantity to negative value

### Exploitation
1. **Negative Quantity Injection:**
   * Sent captured request to Burp Repeater
   * Modified quantity to negative value:

```http
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "ProductId": 10,
  "BasketId": 5,
  "quantity": -111
}
```

2. **Server Accepts Invalid Input:**
   * Sent modified request
   * Received 200 OK response
   * Server accepted negative quantity without validation

3. **Basket Verification:**
   * Disabled Burp intercept
   * Viewed shopping basket in browser
   * **Result:** Item showed quantity -111, total was negative (e.g., -$5,548.89)

4. **Order Placement:**
   * Proceeded to checkout with negative total
   * Added delivery address
   * Selected payment method
   * Clicked "Place Order"
   * Order successfully processed despite negative total
   * Challenge completed!

---

## Solution Explanation

The vulnerability exists because the application validates quantity only on the client-side (UI) but not on the server-side. When users interact through the web interface, JavaScript prevents entering negative values. However, by intercepting the API request directly, attackers can bypass client-side validation and send negative quantities.

**How it works:**
- Order total = price × quantity
- Normal: $49.99 × 1 = $49.99 (customer pays)
- Exploited: $49.99 × (-111) = -$5,548.89 (customer "earns" money)

**Vulnerability Type:** Improper Input Validation + Business Logic Flaw - The server trusts client-side validation and fails to verify that quantity is a positive integer before processing orders.

---

## Remediation

To prevent this critical vulnerability:

* **Server-Side Input Validation:** Always validate ALL user inputs on the server, regardless of client-side checks. Verify that quantity is a positive integer (quantity > 0).

* **Range Validation:** Implement minimum and maximum bounds for quantity (e.g., 1 ≤ quantity ≤ 100) to prevent both negative values and unreasonably large orders.

* **Business Logic Validation:** Validate that order totals are positive before processing. Add checks like `if (total <= 0) { reject order }`.

* **Database Constraints:** Add CHECK constraints at the database level to enforce positive values for quantities, prices, and totals as a secondary defense layer.

* **Use Validation Libraries:** Implement input validation using libraries like Joi, express-validator, or class-validator to ensure consistent validation across all endpoints.

* **Never Trust Client-Side:** Client-side validation is only for user experience, never for security. All security validation must occur server-side.

* **Monitoring and Alerting:** Log and alert on attempts to use negative quantities or place orders with negative totals to detect exploitation attempts.

---

**Challenge Completed:** December 15th, 2025  
**Time Taken:** 30 Minutes
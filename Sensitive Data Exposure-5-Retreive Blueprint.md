# Juice-Shop Write-Up: Retrieve Blueprint

## Challenge Overview
**Title:** Retrieve Blueprint  
**Category:** Forensic/Recon  
**Difficulty:** ⭐⭐⭐⭐⭐ (5/6)

This challenge requires locating and retrieving a hidden 3D blueprint file related to the OWASP Juice Shop project through steganography analysis and path enumeration.

---

## Tools Used
* **Aperisolve:** Tool for analyzing images to extract hidden metadata and embedded information (__https://www.aperisolve.com/__)
* **Web Browser:** Used for accessing URLs and inspecting web content
* **wget:** Command-line utility for downloading files from the web

---

## Methodology and Solution

### Initial Reconnaissance
1. **Image Analysis:**
   * Started with the OWASP Juice Shop Logo (3D-printed) product from the home page
   * Downloaded the product image `3d_keychain.jpg` from `assets/public/images/products/3d_keychain.jpg`
   * Uploaded image to Aperisolve to extract hidden metadata and strings

### Extracting Information
1. **Follow Up on Clues:**
   * Investigated strings found in the image, specifically URLs and mentions of software (OpenSCAD)
   * Checked Imgur and Adobe links found in metadata, which led to dead ends
   * Noted references to STL file format (3D printing standard)

### GitHub Repository Discovery
1. **Exploring Related Resources:**
   * Used Google search to find OWASP SWAG GitHub repository
   * Located `JuiceShop_KeyChain.stl` file in the repository
   * Observed the naming convention used for 3D models
   * Repository link: __https://github.com/OWASP/owasp-swag/blob/master/projects/juice-shop/3d/JuiceShop_KeyChain.stl__

### Hypothesis and Path Guessing
1. **Guessing File Paths:**
   * Based on image storage path and STL format, hypothesized potential URLs for blueprint files
   * Used common naming conventions and trial-and-error approach
   * Tested simplified filename: `JuiceShop.stl`

### Successful Retrieval
1. **Downloading the Blueprint:**
   * Successfully retrieved blueprint using wget with guessed URL:
   ```bash
   wget http://localhost:3000/assets/public/images/products/JuiceShop.stl
   ```
   * File downloaded without authentication - challenge solved!

---

## Solution Explanation

The challenge was resolved by combining image steganography analysis, OSINT research, and systematic path enumeration. The key was discovering that sensitive blueprint files were stored in the same public directory as product images with predictable filenames.

**Vulnerability:** Sensitive files (blueprints) stored in publicly accessible directories without authentication or access controls.

---

## Remediation

To prevent unauthorized access to sensitive files like blueprints:

* **Secure File Storage:** Move sensitive files outside public directories and use randomized, non-predictable file names (UUIDs)
* **Access Controls:** Implement authentication and authorization checks before allowing file downloads
* **Metadata Sanitization:** Remove all embedded metadata from public images to prevent information leakage

---

**Challenge Completed:** December 2024  
**Time Taken:** 55 Minutes
# Web Security Hardening Audit Report

## 1. Executive Posture Summary
- **Target URL:** `https://example.com`
- **Resolved Endpoint:** `https://example.com/` (HTTP `200`)
- **Audit Timestamp:** `2026-11-17 06:20:00 UTC`
- **Overall Security Score:** **`25 / 100` (Grade: `F`)**

---

## 2. SSL/TLS Transport & Certificate Inspection

| TLS Attribute         | Observed Value              |
|-----------------------|-----------------------------|
| Certificate Status    | **VALID**                   |
| Negotiated Protocol   | `TLSv1.3`                   |
| Cipher Suite          | `TLS_AES_256_GCM_SHA384`    |
| Common Name (CN)      | `www.example.org`           |
| Issuing Authority (CA)| DigiCert Inc                |
| Valid From            | 2026-01-15 00:00:00 UTC     |
| Expiration Date       | 2027-01-15 23:59:59 UTC     |
| Days Until Expiration | `59 days`                   |
| TLS Posture Points    | `25 / 25`                   |

---

## 3. HTTP Security Headers Assessment

| Security Header             | Status      | Risk Severity   | Score   | Observed Header Value   |
|-----------------------------|-------------|-----------------|---------|-------------------------|
| `Strict-Transport-Security` | **MISSING** | HIGH            | 0/20    | `Not Present`           |
| `Content-Security-Policy`   | **MISSING** | HIGH            | 0/25    | `Not Present`           |
| `X-Frame-Options`           | **MISSING** | MEDIUM          | 0/10    | `Not Present`           |
| `X-Content-Type-Options`    | **MISSING** | MEDIUM          | 0/10    | `Not Present`           |
| `Referrer-Policy`           | **MISSING** | LOW             | 0/5     | `Not Present`           |
| `Permissions-Policy`        | **MISSING** | LOW             | 0/5     | `Not Present`           |

---

## 4. Server Information Disclosure Check

| Header   | Exposed Value        | Hardening Recommendation                                   |
|----------|----------------------|------------------------------------------------------------|
| `Server` | `ECAcc (sed/584B)`   | Strip or obfuscate banner to hinder attacker fingerprinting.|

---

## 5. Educational Remediation Guide
Below are defensive explanations and recommended server configurations for any `MISSING` or `WEAK` security controls identified during this audit:

### 1. `Strict-Transport-Security` (MISSING — HIGH Risk)
- **Why It Matters:** Enforces HTTPS connections and prevents SSL-stripping and protocol downgrade attacks.
- **Audit Finding:** Add the `Strict-Transport-Security` header to web server responses.
- **Recommended Configuration:**
  ```http
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

### 2. `Content-Security-Policy` (MISSING — HIGH Risk)
- **Why It Matters:** Restricts trusted sources for scripts, styles, and media to mitigate Cross-Site Scripting (XSS) and data injection.
- **Audit Finding:** Add the `Content-Security-Policy` header to web server responses.
- **Recommended Configuration:**
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';
  ```

### 3. `X-Frame-Options` (MISSING — MEDIUM Risk)
- **Why It Matters:** Controls whether the site can be embedded in `<frame>` or `<iframe>` elements, preventing Clickjacking.
- **Audit Finding:** Add the `X-Frame-Options` header to web server responses.
- **Recommended Configuration:**
  ```http
  X-Frame-Options: DENY
  ```

### 4. `X-Content-Type-Options` (MISSING — MEDIUM Risk)
- **Why It Matters:** Blocks browsers from MIME-sniffing responses away from the declared Content-Type.
- **Audit Finding:** Add the `X-Content-Type-Options` header to web server responses.
- **Recommended Configuration:**
  ```http
  X-Content-Type-Options: nosniff
  ```

### 5. `Referrer-Policy` (MISSING — LOW Risk)
- **Why It Matters:** Controls how much referrer URL information is shared during cross-origin navigations.
- **Audit Finding:** Add the `Referrer-Policy` header to web server responses.
- **Recommended Configuration:**
  ```http
  Referrer-Policy: strict-origin-when-cross-origin
  ```

### 6. `Permissions-Policy` (MISSING — LOW Risk)
- **Why It Matters:** Restricts browser access to sensitive hardware APIs (camera, microphone, geolocation).
- **Audit Finding:** Add the `Permissions-Policy` header to web server responses.
- **Recommended Configuration:**
  ```http
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  ```

# HTTP Security Headers & TLS Auditor

A command-line Web Security Hardening tool built in Python using `requests`, `ssl`, and `socket`. It inspects target web applications for missing or weakly configured defensive HTTP response headers, verifies SSL/TLS certificate validity and protocol strength, computes a 100-point security posture score, and exports an educational Markdown remediation report.

---

## Project Overview

Modern web applications rely on browser-enforced HTTP response headers and strong Transport Layer Security (TLS) configurations to defend against client-side attacks and network interception. This tool automates passive security posture checks and produces developer-friendly remediation guidance ready for pull requests, security tickets, or compliance reviews.

### Key Capabilities
- **HTTP Security Header Inspection:** Evaluates presence and directive quality for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **SSL/TLS Socket Verification:** Establishes a direct TLS handshake to inspect the negotiated protocol version (`TLSv1.2`/`TLSv1.3`), cipher suite, Certificate Authority (CA), and days remaining until expiration.
- **Information Disclosure Detection:** Flags verbose server banners (`Server`, `X-Powered-By`, `X-AspNet-Version`) that aid attacker reconnaissance.
- **Educational Markdown Reporting:** Generates a structured report (`sample_report.md`) explaining *why* each control matters alongside copy-pasteable HTTP hardening directives.

---

## Defensive Purpose of Evaluated Headers

| HTTP Header | Primary Attack Mitigated | Defensive Mechanism |
| :--- | :--- | :--- |
| **`Strict-Transport-Security` (HSTS)** | SSL Stripping & Man-in-the-Middle (MitM) | Forces browsers to communicate exclusively over HTTPS for a defined `max-age` window. |
| **`Content-Security-Policy` (CSP)** | Cross-Site Scripting (XSS) & Data Injection | Whitelists approved origins for JavaScript, CSS, images, and frames, blocking unauthorized inline execution. |
| **`X-Frame-Options`** | Clickjacking / UI Redressing | Prevents malicious sites from embedding your application inside hidden `<iframe>` overlays. |
| **`X-Content-Type-Options`** | MIME-Confusion / Drive-by Downloads | Instructs browsers (`nosniff`) to strictly obey the declared `Content-Type` header. |
| **`Referrer-Policy`** | Sensitive URL / Token Leakage | Limits the URL path or origin data sent in the `Referer` header when navigating to external domains. |
| **`Permissions-Policy`** | Unauthorized Hardware API Abuse | Explicitly disables browser access to sensitive features like `camera`, `microphone`, and `geolocation`. |

---

## Risk Scoring Methodology

The auditor calculates an objective **100-point posture score** divided between Transport Security (`25 points`) and HTTP Response Hardening (`75 points`):

| Control Category | Maximum Points | Scoring Rules |
| :--- | :--- | :--- |
| **TLS Certificate Validity** | `15 pts` | Awarded if the X.509 certificate chain is trusted and within its `notBefore` / `notAfter` validity window. |
| **Modern TLS Protocol** | `10 pts` | Awarded if the server negotiates `TLSv1.2` or `TLSv1.3`. |
| **Content-Security-Policy** | `25 pts` | Full points if present without `'unsafe-inline'` or `'unsafe-eval'`; half points (`12 pts`) if weakened. |
| **Strict-Transport-Security** | `20 pts` | Full points if `max-age >= 15552000` (180 days); half points (`10 pts`) if `max-age` is too short. |
| **X-Frame-Options** | `10 pts` | Full points for `DENY` or `SAMEORIGIN`. |
| **X-Content-Type-Options** | `10 pts` | Full points for `nosniff`. |
| **Referrer-Policy** | `5 pts` | Full points when present. |
| **Permissions-Policy** | `5 pts` | Full points when present. |

### Grade Scale
- **Grade A (`90 – 100`):** Strong web hardening and modern TLS posture.
- **Grade B (`80 – 89`):** Good baseline security with minor directive improvements needed.
- **Grade C (`65 – 79`):** Moderate exposure; one or more core headers missing or weakened.
- **Grade D (`50 – 64`):** Significant hardening gaps; vulnerable to common client-side attacks.
- **Grade F (`0 – 49`):** Critical lack of defensive headers or invalid TLS configuration.

---

## Installation & Usage Guide

### 1. Clone the Repository & Install Dependencies

```bash
[https://github.com/sandeshhalabhavi12-bot/cybersecurity.git](https://github.com/sandeshhalabhavi12-bot/cybersecurity.git)
cd code-nova-cybersecurity-task3
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run an Audit Against a Target Domain

```bash
python3 security_auditor.py -u https://example.com -o sample_report.md
```

### 3. CLI Arguments

| Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `-u` | `--url` | *(Required)* | Target domain or full URL to inspect (defaults to `https://` if omitted). |
| `-o` | `--output` | `audit_report.md` | Output file path for the generated Markdown remediation report. |
| `-t` | `--timeout` | `10` | Connection timeout in seconds for HTTP requests and TLS sockets. |

---

## Screenshots

### Terminal Execution
![CLI Audit Execution](Screenshot%202026-11-17%20120341.png)

### Generated Remediation Report
![Markdown Audit Report](Screenshot%202026-11-17%20120413.png)
### Terminal Execution
![CLI Audit Execution](docs/screenshots/cli_audit.png)

### Generated Remediation Report
![Markdown Audit Report](docs/screenshots/remediation_report.png)

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

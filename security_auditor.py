#!/usr/bin/env python3
"""
HTTP Security Headers & TLS Auditor
Author: Web Security Hardening Specialist
Description: Inspects target web endpoints for critical HTTP defensive response headers,
             verifies SSL/TLS certificate validity/expiration, calculates a weighted
             security posture score, and generates an educational remediation report.
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

try:
    import requests
    from tabulate import tabulate
except ImportError as exc:
    print(f"[!] Missing required dependency: {exc.name}. Run: pip install -r requirements.txt")
    sys.exit(1)


class SecurityAuditor:
    """Evaluates HTTP security headers and TLS certificate posture for a target URL."""

    HEADER_SPECS: Dict[str, Dict[str, Any]] = {
        "Strict-Transport-Security": {
            "weight": 20,
            "severity": "HIGH",
            "purpose": "Enforces HTTPS connections and prevents SSL-stripping and protocol downgrade attacks.",
            "recommended": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "weight": 25,
            "severity": "HIGH",
            "purpose": "Restricts trusted sources for scripts, styles, and media to mitigate Cross-Site Scripting (XSS) and data injection.",
            "recommended": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
        },
        "X-Frame-Options": {
            "weight": 10,
            "severity": "MEDIUM",
            "purpose": "Controls whether the site can be embedded in <frame> or <iframe> elements, preventing Clickjacking.",
            "recommended": "X-Frame-Options: DENY",
        },
        "X-Content-Type-Options": {
            "weight": 10,
            "severity": "MEDIUM",
            "purpose": "Blocks browsers from MIME-sniffing responses away from the declared Content-Type.",
            "recommended": "X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "weight": 5,
            "severity": "LOW",
            "purpose": "Controls how much referrer URL information is shared during cross-origin navigations.",
            "recommended": "Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "weight": 5,
            "severity": "LOW",
            "purpose": "Restricts browser access to sensitive hardware APIs (camera, microphone, geolocation).",
            "recommended": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
    }

    DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

    def __init__(self, target_url: str, timeout: int = 10):
        self.raw_url = target_url.strip()
        if not self.raw_url.startswith(("http://", "https://")):
            self.raw_url = f"https://{self.raw_url}"

        parsed = urlparse(self.raw_url)
        self.scheme = parsed.scheme.lower()
        self.hostname = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

        self.timeout = timeout
        self.http_status: int = 0
        self.final_url: str = self.raw_url
        self.response_headers: Dict[str, str] = {}
        self.header_results: List[Dict[str, Any]] = []
        self.disclosure_findings: List[Dict[str, str]] = []
        self.tls_info: Dict[str, Any] = {}
        self.score: int = 0
        self.max_score: int = 100
        self.grade: str = "F"

    def inspect_http_headers(self) -> None:
        """Fetches HTTP response headers and evaluates security policy presence and quality."""
        req_headers = {"User-Agent": "WebSecurityHardeningAuditor/1.0"}
        response = requests.get(
            self.raw_url,
            headers=req_headers,
            timeout=self.timeout,
            allow_redirects=True,
        )
        self.http_status = response.status_code
        self.final_url = response.url
        self.response_headers = {k.lower(): v for k, v in response.headers.items()}

        earned_header_points = 0

        for header_name, spec in self.HEADER_SPECS.items():
            raw_val = self.response_headers.get(header_name.lower())
            weight = spec["weight"]

            if raw_val:
                quality_ok, note = self._validate_header_directives(header_name, raw_val)
                if quality_ok:
                    points = weight
                    status = "PASS"
                else:
                    points = max(1, weight // 2)
                    status = "WEAK"
                earned_header_points += points
                self.header_results.append(
                    {
                        "header": header_name,
                        "status": status,
                        "value": raw_val,
                        "points": f"{points}/{weight}",
                        "severity": "INFO" if status == "PASS" else spec["severity"],
                        "purpose": spec["purpose"],
                        "remediation": note if not quality_ok else "Properly configured.",
                        "recommended": spec["recommended"],
                    }
                )
            else:
                self.header_results.append(
                    {
                        "header": header_name,
                        "status": "MISSING",
                        "value": "Not Present",
                        "points": f"0/{weight}",
                        "severity": spec["severity"],
                        "purpose": spec["purpose"],
                        "remediation": f"Add the `{header_name}` header to web server responses.",
                        "recommended": spec["recommended"],
                    }
                )

        for disc_header in self.DISCLOSURE_HEADERS:
            val = self.response_headers.get(disc_header.lower())
            if val:
                self.disclosure_findings.append({"header": disc_header, "value": val})

        self.score += earned_header_points

    @staticmethod
    def _validate_header_directives(header_name: str, value: str) -> Tuple[bool, str]:
        """Checks whether present security headers contain safe, non-permissive directives."""
        val_lower = value.lower()

        if header_name == "Strict-Transport-Security":
            if "max-age=" not in val_lower:
                return False, "HSTS header is missing a valid `max-age` directive."
            try:
                max_age_part = [p.strip() for p in val_lower.split(";") if p.strip().startswith("max-age=")][0]
                seconds = int(max_age_part.split("=")[1])
                if seconds < 15552000:
                    return False, f"HSTS `max-age` ({seconds}s) is below recommended 15552000s (180 days)."
            except (IndexError, ValueError):
                return False, "Unable to parse numeric `max-age` directive in HSTS."

        elif header_name == "Content-Security-Policy":
            if "'unsafe-inline'" in val_lower or "'unsafe-eval'" in val_lower:
                return False, "CSP contains `'unsafe-inline'` or `'unsafe-eval'`, weakening XSS protection."

        elif header_name == "X-Frame-Options":
            if val_lower.strip() not in ("deny", "sameorigin"):
                return False, f"Unrecognized or deprecated X-Frame-Options value: `{value}`."

        elif header_name == "X-Content-Type-Options":
            if val_lower.strip() != "nosniff":
                return False, f"Expected `nosniff`, found `{value}`."

        return True, "Configured."

    def inspect_tls_certificate(self) -> None:
        """Connects via TLS socket to validate certificate dates, issuer, and TLS protocol version."""
        final_parsed = urlparse(self.final_url)
        host = final_parsed.hostname or self.hostname
        port = final_parsed.port or 443

        if final_parsed.scheme != "https":
            self.tls_info = {
                "enabled": False,
                "protocol": "None (Plaintext HTTP)",
                "cipher": "None",
                "subject": "N/A",
                "issuer": "N/A",
                "not_before": "N/A",
                "not_after": "N/A",
                "days_remaining": 0,
                "valid": False,
                "points": 0,
                "error": "Target did not redirect to HTTPS; traffic is unencrypted.",
            }
            return

        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version() or "Unknown"
                    cipher_info = tls_sock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else "Unknown"

                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    subject_cn = subject_dict.get("commonName", host)
                    issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown CA"))

                    not_before_str = cert.get("notBefore", "")
                    not_after_str = cert.get("notAfter", "")
                    not_before_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

                    now_utc = datetime.now(timezone.utc)
                    days_remaining = (not_after_dt - now_utc).days
                    is_valid = (not_before_dt <= now_utc <= not_after_dt) and (days_remaining > 0)

                    tls_points = 0
                    if is_valid:
                        tls_points += 15
                    if protocol in ("TLSv1.3", "TLSv1.2"):
                        tls_points += 10

                    self.score += tls_points
                    self.tls_info = {
                        "enabled": True,
                        "protocol": protocol,
                        "cipher": cipher_name,
                        "subject": subject_cn,
                        "issuer": issuer_org,
                        "not_before": not_before_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "not_after": not_after_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "days_remaining": days_remaining,
                        "valid": is_valid,
                        "points": tls_points,
                        "error": None,
                    }
        except ssl.SSLCertVerificationError as ssl_err:
            self.tls_info = {
                "enabled": True,
                "protocol": "Handshake Failed",
                "cipher": "N/A",
                "subject": host,
                "issuer": "Untrusted / Invalid",
                "not_before": "N/A",
                "not_after": "N/A",
                "days_remaining": 0,
                "valid": False,
                "points": 0,
                "error": f"Certificate verification failed: {ssl_err.verify_message}",
            }
        except Exception as err:
            self.tls_info = {
                "enabled": False,
                "protocol": "Error",
                "cipher": "N/A",
                "subject": host,
                "issuer": "N/A",
                "not_before": "N/A",
                "not_after": "N/A",
                "days_remaining": 0,
                "valid": False,
                "points": 0,
                "error": str(err),
            }

    def calculate_grade(self) -> None:
        """Maps numerical posture score (0-100) to a letter grade."""
        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 80:
            self.grade = "B"
        elif self.score >= 65:
            self.grade = "C"
        elif self.score >= 50:
            self.grade = "D"
        else:
            self.grade = "F"

    def run(self) -> None:
        """Executes the full HTTP header and TLS audit pipeline."""
        self.inspect_http_headers()
        self.inspect_tls_certificate()
        self.calculate_grade()

    def generate_markdown_report(self, output_path: str) -> str:
        """Generates a comprehensive educational remediation report in Markdown."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "# Web Security Hardening Audit Report",
            "",
            "## 1. Executive Posture Summary",
            f"- **Target URL:** `{self.raw_url}`",
            f"- **Resolved Endpoint:** `{self.final_url}` (HTTP `{self.http_status}`)",
            f"- **Audit Timestamp:** `{timestamp}`",
            f"- **Overall Security Score:** **`{self.score} / {self.max_score}` (Grade: `{self.grade}`)**",
            "",
            "---",
            "",
            "## 2. SSL/TLS Transport & Certificate Inspection",
        ]

        if self.tls_info.get("enabled") and not self.tls_info.get("error"):
            tls_table = [
                ["Certificate Status", "**VALID**" if self.tls_info["valid"] else "**EXPIRED / INVALID**"],
                ["Negotiated Protocol", f"`{self.tls_info['protocol']}`"],
                ["Cipher Suite", f"`{self.tls_info['cipher']}`"],
                ["Common Name (CN)", f"`{self.tls_info['subject']}`"],
                ["Issuing Authority (CA)", self.tls_info["issuer"]],
                ["Valid From", self.tls_info["not_before"]],
                ["Expiration Date", self.tls_info["not_after"]],
                ["Days Until Expiration", f"`{self.tls_info['days_remaining']} days`"],
                ["TLS Posture Points", f"`{self.tls_info['points']} / 25`"],
            ]
            lines.append(tabulate(tls_table, headers=["TLS Attribute", "Observed Value"], tablefmt="github"))
        else:
            lines.append(f"> **[CRITICAL TLS FINDING]:** {self.tls_info.get('error', 'TLS connection could not be established.')}")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 3. HTTP Security Headers Assessment",
            ]
        )

        header_rows = []
        for item in self.header_results:
            val_display = item["value"] if len(item["value"]) <= 45 else f"{item['value'][:42]}..."
            header_rows.append(
                [
                    f"`{item['header']}`",
                    f"**{item['status']}**",
                    item["severity"],
                    item["points"],
                    f"`{val_display}`",
                ]
            )

        lines.append(
            tabulate(
                header_rows,
                headers=["Security Header", "Status", "Risk Severity", "Score", "Observed Header Value"],
                tablefmt="github",
            )
        )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Server Information Disclosure Check",
            ]
        )

        if self.disclosure_findings:
            disc_rows = [[f"`{d['header']}`", f"`{d['value']}`", "Strip or obfuscate banner to hinder attacker fingerprinting."] for d in self.disclosure_findings]
            lines.append(tabulate(disc_rows, headers=["Header", "Exposed Value", "Hardening Recommendation"], tablefmt="github"))
        else:
            lines.append("_No verbose server version headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) detected._")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 5. Educational Remediation Guide",
                "Below are defensive explanations and recommended server configurations for any `MISSING` or `WEAK` security controls identified during this audit:",
                "",
            ]
        )

        actionable = [h for h in self.header_results if h["status"] in ("MISSING", "WEAK")]
        if actionable:
            for idx, item in enumerate(actionable, start=1):
                lines.extend(
                    [
                        f"### {idx}. `{item['header']}` ({item['status']} — {item['severity']} Risk)",
                        f"- **Why It Matters:** {item['purpose']}",
                        f"- **Audit Finding:** {item['remediation']}",
                        "- **Recommended Configuration:**",
                        "  ```http",
                        f"  {item['recommended']}",
                        "  ```",
                        "",
                    ]
                )
        else:
            lines.append("_All evaluated HTTP security headers are present and meet baseline hardening criteria!_")

        report_text = "
".join(lines)
        Path(output_path).write_text(report_text, encoding="utf-8")
        return report_text


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HTTP Security Headers & TLS Auditor — Web Hardening Assessment Tool"
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target domain or URL to audit (e.g., https://example.com)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="audit_report.md",
        help="Destination path for the generated Markdown report (default: audit_report.md)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Network request and socket timeout in seconds (default: 10)",
    )

    args = parser.parse_args()
    print(f"[*] Starting HTTP Security Headers & TLS Audit for: {args.url}")

    auditor = SecurityAuditor(target_url=args.url, timeout=args.timeout)
    try:
        auditor.run()
        auditor.generate_markdown_report(args.output)
    except requests.exceptions.RequestException as req_err:
        print(f"[!] Network error while connecting to {args.url}: {req_err}")
        sys.exit(1)

    print(f"[+] Audit Complete | Score: {auditor.score}/100 (Grade: {auditor.grade})")
    print(f"[+] TLS Protocol: {auditor.tls_info.get('protocol')} | Cert Valid: {auditor.tls_info.get('valid')}")
    print(f"[+] Educational remediation report exported to: {args.output}")


if __name__ == "__main__":
    main()

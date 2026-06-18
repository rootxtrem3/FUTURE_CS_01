# Future Interns — Cyber Security Tasks (2026)

This repository contains deliverables for three Cyber Security internship tasks completed for **Future Interns**.

## 📋 Task Overview

| Task | Title | Description |
|------|-------|-------------|
| **Task 1** | Vulnerability Assessment Report | Read-only security analysis of a live website |
| **Task 2** | Phishing Email Detection & Awareness System | Analysis of phishing email samples and prevention guidelines |
| **Task 3** | API Security Risk Analysis | API security audit of a public REST API |

---

## 🔹 Task 1 — Vulnerability Assessment Report

**Target:** `https://example.com`

A read-only passive security assessment analyzing HTTP security headers, SSL/TLS configuration, and information disclosure risks.

**8 findings identified:**
- 1 High — Missing Content-Security-Policy
- 4 Medium — Missing X-Frame-Options, HSTS, X-Content-Type-Options, no HTTP→HTTPS redirect
- 3 Low — Server disclosure, missing Referrer-Policy, missing Permissions-Policy

📂 `vulnerability-report/`

---

## 🔹 Task 2 — Phishing Email Detection & Awareness System

**Samples analyzed:** 3 phishing/suspicious emails

Analysis of real-world phishing emails including header inspection, domain reputation checks, URL analysis, and content-based indicator identification.

**Classifications:**
- 2 Phishing — Credential harvesting, HR impersonation
- 1 Suspicious — Brand impersonation (Microsoft 365 lookalike)

📂 `phishing-report/`

---

## 🔹 Task 3 — API Security Risk Analysis

**Target:** `https://jsonplaceholder.typicode.com`

An API security audit following the OWASP API Security Top 10 framework, testing endpoints for authentication, authorization, data exposure, rate limiting, and input validation issues.

**7 risks identified:**
- 3 High — Missing authentication, excessive data exposure, broken object-level authorization
- 2 Medium — Weak rate limiting, missing input validation
- 2 Low — Sensitive data in URLs, permissive CORS

📂 `api-security-report/`

---

## 🛠️ Tools & Technologies Used

| Tool | Used In | Purpose |
|------|---------|---------|
| **curl** | All tasks | HTTP/S request testing and header analysis |
| **Playwright** | All tasks | PDF generation and screenshot capture |
| **docx** | All tasks | Word document generation |
| **openssl** | Task 1 | SSL/TLS certificate analysis |
| **host/dig** | Task 1 | DNS resolution |
| **OWASP API Security Top 10** | Task 3 | Risk classification framework |
| **OWASP WSTG** | Task 1 | Testing methodology reference |

## 👤 Analyst

**Ebasa Getu** — Future Interns Cyber Security Internship (2026)

## 📬 Submission

Each task directory contains its own README with detailed methodology, scope, and reproduction instructions.

---

*Deliverables prepared for Future Interns — Cyber Security Tasks 1, 2 & 3 (2026)*

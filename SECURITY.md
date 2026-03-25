# Security Policy

## Supported Versions

Only the latest released version of ORES receives security fixes. We encourage all users to stay current with releases.

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| older   | No        |

## Reporting a Vulnerability

The ORES maintainers take security issues seriously. We appreciate the efforts of security researchers and users who responsibly disclose vulnerabilities. We commit to working with you to understand and resolve confirmed issues quickly.

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussion threads.** Doing so gives attackers advance notice before a fix is available.

### How to Report

Send a detailed report to:

**security@rig.security**

Encrypt your message using our PGP key if you are disclosing sensitive technical details. The fingerprint is published on our website at https://www.rig.security/security.

### What to Include

A high-quality report helps us triage and respond faster. Please include as many of the following as are applicable:

- **Summary:** A one-paragraph description of the vulnerability and its impact.
- **Affected component:** Which package, binary, or API surface is affected.
- **Vulnerability type:** CWE category, CVSS vector, or a plain-English description of the class of bug.
- **ORES version:** The release tag or commit SHA you tested against.
- **Environment:** Operating system, Go version, and deployment mode (CLI, daemon, WASM).
- **Steps to reproduce:** A minimal, self-contained proof of concept. Code is ideal; screenshots are acceptable.
- **Expected vs. actual behavior:** What should happen, and what does happen.
- **Suggested fix (optional):** If you have a patch or know where the flaw lives, share it.

### Response SLA

| Milestone | Target |
|-----------|--------|
| Acknowledgement of receipt | 48 hours |
| Initial severity assessment | 5 business days |
| Status update | Every 7 days until resolved |
| Fix released (critical/high) | 30 days from confirmation |
| Fix released (medium/low) | 90 days from confirmation |

If you have not received an acknowledgement within 48 hours, please follow up with a second email referencing your original message.

### Coordinated Disclosure

We follow [coordinated vulnerability disclosure](https://vuls.cert.org/confluence/display/CVD). Once a fix is available, we will:

1. Release a patched version.
2. Publish a GitHub Security Advisory (GHSA) with CVE assignment where applicable.
3. Credit the reporter in the advisory (unless you prefer to remain anonymous).
4. Add an entry to [CHANGELOG.md](CHANGELOG.md) under the relevant release.

We ask that you:

- Give us a reasonable amount of time to fix the issue before public disclosure.
- Not exploit the vulnerability beyond the minimum necessary to demonstrate the impact.
- Not access or modify data belonging to other users.

### Out of Scope

The following are generally outside the scope of this policy:

- Vulnerabilities in third-party dependencies that are not exploitable through ORES's public API surface. Please report those directly to the upstream project.
- Theoretical vulnerabilities with no demonstrated impact.
- Issues requiring physical access to the machine running ORES.
- Social engineering attacks targeting maintainers or contributors.
- Denial-of-service via resource exhaustion from untrusted inputs (file it as a regular issue instead).

### Safe Harbor

Rig Security will not pursue legal action against researchers who:

- Disclose in good faith following this policy.
- Make no attempt to access, modify, or exfiltrate data beyond what is necessary.
- Report findings before any public disclosure.
- Do not violate the privacy of other users.

We consider security research conducted under these terms to be authorized, lawful, and welcomed.

## Security-Sensitive Design Decisions

ORES is a **deterministic scoring engine** that does not connect to external networks at runtime. All signal data is provided by the caller. This design eliminates an entire class of supply-chain and SSRF risks that affect online scoring services.

Nonetheless, several areas deserve particular attention from a security perspective:

- **Protobuf deserialization:** Malformed or oversized input may cause unexpected behavior. The daemon enforces a 1 MB request body limit by default (`ORES_MAX_REQUEST_BYTES`). Adjust this limit based on your deployment needs.
- **WASM sandbox:** The WASM build runs inside a WASI host. Ensure your WASI runtime is up to date.
- **Score integrity:** ORES scores are advisory. Do not rely on them as the sole input to automated, irreversible security decisions.
- **Transport security:** The daemon supports built-in TLS and mutual TLS (mTLS) via `ORES_TLS_CERT`, `ORES_TLS_KEY`, and `ORES_TLS_CLIENT_CA` environment variables. When TLS is not configured, the daemon serves plain HTTP. Deploy behind a TLS-terminating proxy or enable built-in TLS for production use.

## Contact

Primary: security@rig.security
Website: https://www.rig.security/security
GitHub Security Advisories: https://github.com/rigsecurity/ores/security/advisories

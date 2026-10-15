# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| master  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send details to security@example.com (replace with your actual security contact)
2. **Subject**: `[SECURITY] Nextcloud Sentinel - Brief description`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Scope

We are interested in vulnerabilities related to:

- **Kill Switch bypass**: Ways to disable or circumvent the protection beyond those already documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- **False negative scenarios**: Ransomware patterns that evade detection
- **Data exposure**: Threat logs or backups leaking sensitive information
- **Privilege escalation**: Unauthorized access through Sentinel components
- **Denial of service**: Crashing the sync client or exhausting resources

### Out of Scope

- Vulnerabilities in upstream Nextcloud Desktop Client (report to [Nextcloud](https://nextcloud.com/security/))
- Vulnerabilities requiring physical access to the machine
- Social engineering attacks
- Issues in third-party dependencies (report to respective maintainers)

### Safe Harbor

We support responsible disclosure. If you:

- Act in good faith
- Avoid privacy violations, data destruction, or service disruption
- Give us reasonable time to fix before public disclosure

We will:

- Not pursue legal action
- Work with you to understand and resolve the issue
- Credit you in the security advisory (if desired)

## Security Best Practices for Users

### Kill Switch Configuration

1. **Enable Auto-Backup**: Ensures you have recovery options
2. **Use "Standard" or "Paranoid" preset**: Better protection
3. **Monitor the Dashboard**: Check for threat alerts regularly
4. **Keep Sentinel Updated**: Security patches are released regularly

### Canary Files

Consider adding canary files in critical directories:

```
Documents/.sentinel-canary
Photos/.sentinel-canary
```

If these files are modified or deleted, Sentinel will trigger immediately.

### Server-Side Protection

Sentinel protects the sync direction (local -> server). Also consider:

- Nextcloud server-side ransomware protection apps
- Regular server backups
- Version history enabled on your Nextcloud server

---

*The fire crackles. Security is a shared responsibility.*

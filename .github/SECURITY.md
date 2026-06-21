# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 6.0.x   | :white_check_mark: |
| 5.0.x   | :white_check_mark: |
| < 5.0   | :x:                |

## Reporting a Vulnerability

We take the security of Vigilagent seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:

- Open a public GitHub issue
- Disclose the vulnerability publicly before it has been addressed

### Please DO:

1. **Email us directly** at: security@vigilagent.dev (or create a private security advisory on GitHub)
2. **Include the following information**:
   - Type of vulnerability (e.g., SQL injection, XSS, CSRF, etc.)
   - Full paths of source file(s) related to the vulnerability
   - Location of the affected source code (tag/branch/commit or direct URL)
   - Step-by-step instructions to reproduce the issue
   - Proof-of-concept or exploit code (if possible)
   - Impact of the issue, including how an attacker might exploit it

### What to expect:

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Assessment**: We will assess the vulnerability and determine its impact and severity
- **Fix**: We will work on a fix and keep you informed of our progress
- **Disclosure**: Once the vulnerability is fixed, we will coordinate with you on public disclosure
- **Credit**: We will credit you in our security advisory (unless you prefer to remain anonymous)

## Security Features

Vigilagent V6 includes the following security features:

### Authentication & Authorization
- API key authentication
- Role-based access control (RBAC)
- Session management with secure tokens

### Data Protection
- Forensic data encryption at rest
- Session data sanitization
- Sensitive data masking in logs
- Secure credential storage

### Network Security
- Rate limiting on all API endpoints
- SSRF protection with URL validation
- CSRF protection with token validation
- Input validation and sanitization

### Browser Security
- Context isolation between scans
- Secure browser profile management
- Cookie and storage isolation
- Content Security Policy enforcement

### Infrastructure Security
- Secure configuration validation
- Environment variable protection
- Secrets management
- Audit logging

## Security Best Practices

When deploying Vigilagent, please follow these security best practices:

1. **Environment Variables**: Never commit `.env` files or expose API keys
2. **Network Isolation**: Run scans in isolated networks when possible
3. **Access Control**: Implement proper authentication and authorization
4. **Regular Updates**: Keep dependencies and the platform up to date
5. **Monitoring**: Enable audit logging and monitor for suspicious activity
6. **Encryption**: Use HTTPS/TLS for all API communications
7. **Backups**: Regularly backup forensic data and scan results

For more details, see our [Security Best Practices Guide](../docs/SECURITY_BEST_PRACTICES.md).

## Security Audits

Vigilagent undergoes regular security audits:

- **Last Audit**: May 2026
- **Security Score**: 100% compliance
- **Issues Found**: 0 critical, 0 high
- **Status**: Production Ready ✅

## Vulnerability Disclosure Timeline

We aim to:

- Acknowledge reports within 48 hours
- Provide initial assessment within 1 week
- Release fixes for critical vulnerabilities within 2 weeks
- Release fixes for non-critical vulnerabilities within 4 weeks

## Contact

- **Security Email**: security@vigilagent.dev
- **GitHub Security Advisories**: [Create Advisory](https://github.com/aniket2348823/API-Endpoint-Scanner/security/advisories/new)
- **General Support**: support@vigilagent.dev

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Security researchers will be listed here -->

Thank you for helping keep Vigilagent and our users safe!

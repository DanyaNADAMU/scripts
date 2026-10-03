# Security Policy

## Reporting a Vulnerability
If you discover a security vulnerability in this project, please send an email to git@nada.mu.

## Commit Signatures & Verification
All official commits and releases in this repository are cryptographically signed using SSH keys and timestamped into the Bitcoin blockchain via OpenTimestamps.

To verify signatures locally:
```bash
git config gpg.ssh.allowedSignersFile .allowed_signers
git log --show-signature
```

Official Project Domain: https://nada.mu

# Security Policy

## Supported versions

Security fixes are provided for the latest release on `main`.

## Reporting

Use GitHub's **Report a vulnerability** private reporting form in the repository Security tab. Do not open a public issue and do not include credentials, configurations, inventory databases, known-hosts files, or device output.

Include the affected version, impact, reproduction steps using synthetic data, and a suggested mitigation when available. Maintainers will acknowledge the report through GitHub and coordinate disclosure after a fix is ready.

## Dependency note

Netmiko 4.7 currently requires Paramiko below version 5. The dependency audit therefore carries a narrow exception for `PYSEC-2026-2858` until a compatible Netmiko release is available. NERD does not use SSH agent or automatic key discovery, requires explicit credentials, and verifies enrolled host keys. The exception must be removed when the upstream constraint changes.

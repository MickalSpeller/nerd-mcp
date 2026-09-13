# Public Release Preparation Report

## Scope

NERD MCP 1.7.0 is prepared as a sanitized Apache-2.0 GitHub release. Publication and remote repository creation have not been performed.

## Repository cleanup

Removed from the release: development topology and configuration exports, working inventory and databases, live results, personal paths, private lab data, and the development README. The architectural package layers and complete tests remain.

Added public guides, license, security and contribution policies, changelog, editor settings, expanded ignore rules, Dependabot, issue and pull-request templates, SHA-pinned workflows, version reporting, and write opt-in tests.

## Data substitutions

Development names, locations, addresses, serials, topology, timestamps, and personal paths were replaced with fictional entities and synthetic serials. Examples use RFC 5737 networks 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24.

## Security results

- detect-secrets: 0 findings after narrowly marking deliberate synthetic redaction fixtures.
- Explicit searches: 0 matches for API-key formats, personal paths, the private lab subnet, development locations, or development project references.
- Runtime state, known hosts, exports, environments, and build output are ignored.
- MCP regression confirms no device-write or save effect is exposed.
- Writes require local CLI --enable-writes and exact approvals.
- The dependency audit is clean except documented PYSEC-2026-2858. Netmiko 4.7 requires Paramiko below 5; NERD disables SSH agent/key discovery and requires verified host keys. CI carries only this explicit exception.

## Validation results

- Full suite: 453 passed.
- Focused post-sanitization suite: 108 passed.
- Synthetic inventory import and mock inspection: passed.
- Internal Markdown links: 0 broken.
- pip check in development and clean wheel environments: passed.
- Source distribution and wheel created; wheel archive integrity passed with 93 entries.
- Wheel installed into a separate clean environment; both entry points reported nerd-mcp 1.7.0.
- MCP stdio discovery and execution are covered by passing subprocess tests.
- Git whitespace check: passed.

## Known limitations

- Cisco IOS/IOS-XE writes are experimental and opt-in. Other platforms remain read-only until live transaction, rollback, and verification requirements pass.
- OpenAI chat needs a funded API account and sends relevant retrieved output to the configured model.
- Live device testing was not repeated during public sanitation.
- Python 3.11 and 3.13 run in GitHub Actions; local validation used Python 3.12.
- Paramiko 4 remains constrained by Netmiko 4.7 as described in SECURITY.md.

## GitHub settings required after repository creation

Enable secret scanning and push protection, private vulnerability reporting, Dependabot alerts and security updates, and read-only workflow permissions. Protect main with pull requests and required CI, CodeQL, dependency-review, and secret-scan checks; disable force pushes and branch deletion. See [docs/GITHUB_SECURITY.md](docs/GITHUB_SECURITY.md).

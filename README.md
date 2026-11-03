# lh-sys-integrity

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sys-integrity/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sys-integrity/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise host file integrity & rootkit indicator auditor developed by **Logihertz Systems (OPC) Private Limited**.

Verifies cryptographic SHA-256 baseline manifests against live filesystem states, inspects /etc/ld.so.preload hooks, systemd unit overrides, cron persistence jobs, and binary drift to detect host tampering and rootkits.

---

## Key Features

- **Cryptographic Hash Baseline Generation**: Generates deterministic JSON baseline manifests recording SHA-256, SHA-512, or BLAKE2b hashes and inode metadata.
- **Filesystem Integrity Verification**: Detects unauthorized binary modifications, injected files, deleted files, and permission tampering.
- **Timestomping Detection**: Flags suspicious file modification timestamps where mtime is older than ctime or baseline recording.
- **Dynamic Linker & Preload Auditing**: Audits `/etc/ld.so.preload`, `/etc/ld.so.conf`, and kernel modules for userland rootkit hooks.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `FIM001_CONTENT_MODIFIED` | `CRITICAL` | Cryptographic hash mismatch: file content modified since baseline state |
| `FIM002_FILE_INJECTED` | `CRITICAL` | Unauthorized file injected into monitored directory hierarchy |
| `FIM003_FILE_DELETED` | `HIGH` | Critical system binary or configuration file deleted from directory |
| `FIM004_PERM_TAMPERED` | `HIGH` | File access permission mode altered from baseline state |
| `FIM005_OWNERSHIP_TAMPERED` | `HIGH` | File UID or GID ownership modified from baseline state |
| `FIM006_TIMESTOMPING_DETECTED` | `HIGH` | Suspicious modification timestamp anomaly (mtime older than ctime) |
| `FIM007_TYPE_DRIFT` | `HIGH` | Inode type changed (regular file replaced by symlink or socket) |
| `FIM008_MANIFEST_TAMPERED` | `CRITICAL` | Cryptographic baseline manifest signature or integrity hash invalid |
| `PRELOAD001_LD_PRELOAD_ACTIVE` | `CRITICAL` | Active userland rootkit hook detected in /etc/ld.so.preload |
| `PRELOAD002_PRELOAD_FILE_WRITABLE` | `CRITICAL` | Insecure writable permissions detected on dynamic linker preload config |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sys-integrity.git
cd lh-sys-integrity

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-fim` (also accessible via `lh-fim`).

```bash
# Initialize a cryptographic baseline manifest for /usr/bin
lh-fim init /usr/bin/ --algorithm sha256 --output baseline.json

# Verify filesystem integrity against an existing baseline
lh-fim verify /usr/bin/ --baseline baseline.json

# Audit dynamic linker preload configurations for rootkits
lh-fim audit-preload --root / --format json

# Export verification findings to OASIS SARIF v2.1.0
lh-fim verify /usr/bin/ --baseline baseline.json --format sarif --output fim.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).

# Security Rules Reference: lh-sys-integrity

An enterprise host file integrity monitoring & rootkit detection cli developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-sys-integrity`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `FIM001_CONTENT_MODIFIED` | `CRITICAL` | Integrity Tampering | Cryptographic Hash Mismatch: File Content Modified |
| `FIM002_FILE_INJECTED` | `CRITICAL` | Intrusion Detection | Unauthorized File Injected into Monitored Path |
| `FIM003_FILE_DELETED` | `HIGH` | Integrity Tampering | Critical System File Deleted from Monitored Path |
| `FIM004_PERM_TAMPERED` | `HIGH` | Permission Drift | File Access Permission Mode Altered from Baseline |
| `FIM005_OWNERSHIP_TAMPERED` | `HIGH` | Ownership Drift | File UID or GID Ownership Modified from Baseline |
| `FIM006_TIMESTOMPING_DETECTED` | `HIGH` | Antiforensics | Suspicious Timestamp Anomaly: mtime Older Than ctime |
| `FIM007_TYPE_DRIFT` | `HIGH` | Integrity Drift | Inode Type Changed (Regular File Replaced by Symlink/Socket) |
| `FIM008_MANIFEST_TAMPERED` | `CRITICAL` | Baseline Tampering | Baseline Manifest Signature or Integrity Hash Invalid |
| `PRELOAD001_LD_PRELOAD_ACTIVE` | `CRITICAL` | Rootkit Detection | Active Userland Rootkit Hook in /etc/ld.so.preload |
| `PRELOAD002_PRELOAD_FILE_WRITABLE` | `CRITICAL` | Configuration Security | Insecure Writable Permissions on Dynamic Linker Config |

---

## Granular Rule Specifications

### `FIM001_CONTENT_MODIFIED`: Cryptographic Hash Mismatch: File Content Modified

- **Severity**: `CRITICAL`
- **Category**: `Integrity Tampering`
- **Description**: Cryptographic digest of file differs from baseline manifest recording.
- **Remediation**: Investigate unauthorized file modification, restore clean binary from trusted package repository.

---

### `FIM002_FILE_INJECTED`: Unauthorized File Injected into Monitored Path

- **Severity**: `CRITICAL`
- **Category**: `Intrusion Detection`
- **Description**: Newly created file found in monitored directory that was not present in baseline.
- **Remediation**: Quarantine injected file, inspect for malware or webshell payloads, and review system access logs.

---

### `FIM003_FILE_DELETED`: Critical System File Deleted from Monitored Path

- **Severity**: `HIGH`
- **Category**: `Integrity Tampering`
- **Description**: Monitored system binary or configuration file has been deleted from path.
- **Remediation**: Restore deleted file from trusted system backup and audit deletion event.

---

### `FIM004_PERM_TAMPERED`: File Access Permission Mode Altered from Baseline

- **Severity**: `HIGH`
- **Category**: `Permission Drift`
- **Description**: File access mode altered (e.g. executable or write permission added).
- **Remediation**: Restore original restrictive permission mode using chmod.

---

### `FIM005_OWNERSHIP_TAMPERED`: File UID or GID Ownership Modified from Baseline

- **Severity**: `HIGH`
- **Category**: `Ownership Drift`
- **Description**: File owner UID or GID modified since baseline recording.
- **Remediation**: Revert ownership back to authorized system user (chown root:root).

---

### `FIM006_TIMESTOMPING_DETECTED`: Suspicious Timestamp Anomaly: mtime Older Than ctime

- **Severity**: `HIGH`
- **Category**: `Antiforensics`
- **Description**: File modification timestamp artificially rolled back to conceal tampering.
- **Remediation**: Treat host as potentially compromised; perform memory forensics and review system audit trails.

---

### `FIM007_TYPE_DRIFT`: Inode Type Changed (Regular File Replaced by Symlink/Socket)

- **Severity**: `HIGH`
- **Category**: `Integrity Drift`
- **Description**: Monitored regular file replaced by symbolic link, named pipe, or socket.
- **Remediation**: Remove rogue symlink and restore authentic file content.

---

### `FIM008_MANIFEST_TAMPERED`: Baseline Manifest Signature or Integrity Hash Invalid

- **Severity**: `CRITICAL`
- **Category**: `Baseline Tampering`
- **Description**: Cryptographic baseline manifest checksum or digital signature verification failed.
- **Remediation**: Re-initialize baseline from trusted offline build artifacts and verify storage integrity.

---

### `PRELOAD001_LD_PRELOAD_ACTIVE`: Active Userland Rootkit Hook in /etc/ld.so.preload

- **Severity**: `CRITICAL`
- **Category**: `Rootkit Detection`
- **Description**: Shared library configured in /etc/ld.so.preload hooking system calls across processes.
- **Remediation**: Investigate and remove unauthorized shared library from /etc/ld.so.preload immediately.

---

### `PRELOAD002_PRELOAD_FILE_WRITABLE`: Insecure Writable Permissions on Dynamic Linker Config

- **Severity**: `CRITICAL`
- **Category**: `Configuration Security`
- **Description**: /etc/ld.so.preload or /etc/ld.so.conf is writable by non-root users.
- **Remediation**: Set strict root-only permissions (chmod 644, chown root:root) on dynamic linker configs.

---

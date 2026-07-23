# Local System Hardening Auditor

A defensive security compliance and system auditing tool designed to inspect local Linux system configurations, file permissions, and active service exposures.

## 🚀 Features Implemented
* **Day 1:** Established file permission inspection rules to detect overly permissive or world-writable critical system files (`/etc/passwd`, `/etc/shadow`).
* **Day 2:** Added local socket binding inspection modules to evaluate whether common management ports are active or exposed locally.

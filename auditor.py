# Day 3: Local System Hardening Auditor - Final Compliance Exporter
import os
import stat
import socket
import json
from datetime import datetime

print("--- Local System Hardening Auditor Initialized ---")
print("Executing System Compliance Audit...\n")

report_data = {
    "audit_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "file_permission_checks": [],
    "service_exposure_checks": [],
    "summary": {"pass": 0, "warn": 0, "high_risk": 0}
}

# --- SECTION 1: File Permission Audit ---
TARGET_PATHS = {
    "/etc/passwd": 0o644,
    "/etc/shadow": 0o600,
    "/etc/hosts": 0o644,
}

def check_file_permissions(filepath, max_octal_mode):
    if not os.path.exists(filepath):
        return {"path": filepath, "status": "SKIP", "details": "Path does not exist"}
    
    file_stat = os.stat(filepath)
    current_mode = stat.S_IMODE(file_stat.st_mode)
    current_octal = oct(current_mode)
    expected_octal = oct(max_octal_mode)
    
    is_world_writable = bool(current_mode & stat.S_IWOTH)
    
    if is_world_writable:
        report_data["summary"]["high_risk"] += 1
        return {
            "path": filepath,
            "status": "HIGH_RISK",
            "current_mode": current_octal,
            "expected_mode": f"<= {expected_octal}",
            "finding": "File is WORLD-WRITABLE"
        }
    elif current_mode > max_octal_mode:
        report_data["summary"]["warn"] += 1
        return {
            "path": filepath,
            "status": "WARN",
            "current_mode": current_octal,
            "expected_mode": f"<= {expected_octal}",
            "finding": "Permissions looser than recommended baseline"
        }
    else:
        report_data["summary"]["pass"] += 1
        return {
            "path": filepath,
            "status": "PASS",
            "current_mode": current_octal,
            "expected_mode": f"<= {expected_octal}",
            "finding": "Permissions align with security baseline"
        }

print("=== 1. File Permission Controls ===")
for path, expected_mode in TARGET_PATHS.items():
    res = check_file_permissions(path, expected_mode)
    report_data["file_permission_checks"].append(res)
    print(f"[{res['status']}] {path}: {res['finding']}")


# --- SECTION 2: Network Interface Exposure Audit ---
CHECK_PORTS = [22, 80, 443, 3306, 5432, 8080, 27017]

def check_socket_binding(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        res_local = s.connect_ex(("127.0.0.1", port))
    
    if res_local == 0:
        report_data["summary"]["warn"] += 1
        return {"port": port, "status": "EXPOSED", "finding": "Active local service listening"}
    else:
        report_data["summary"]["pass"] += 1
        return {"port": port, "status": "CLOSED", "finding": "Port inactive or closed locally"}

print("\n=== 2. Local Service Binding Audit ===")
for port in CHECK_PORTS:
    res = check_socket_binding(port)
    report_data["service_exposure_checks"].append(res)
    print(f"[{res['status']}] Port {port}: {res['finding']}")

# --- SECTION 3: Export Compliance Findings ---
report_file = "compliance_report.json"
with open(report_file, "w", encoding="utf-8") as f:
    json.dump(report_data, f, indent=4)

print(f"\n[+] System Compliance Report generated successfully: '{report_file}'")

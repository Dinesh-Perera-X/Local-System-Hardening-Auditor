# Day 2: Local System Hardening Auditor - Permission & Interface Inspector
import os
import stat
import socket

print("--- Local System Hardening Auditor Initialized ---")
print("Executing System Compliance Audit...\n")

# --- SECTION 1: File Permission Audit ---
TARGET_PATHS = {
    "/etc/passwd": 0o644,
    "/etc/shadow": 0o600,
    "/etc/hosts": 0o644,
}

def check_file_permissions(filepath, max_octal_mode):
    if not os.path.exists(filepath):
        return f"[SKIP] Path does not exist: {filepath}"
    
    file_stat = os.stat(filepath)
    current_mode = stat.S_IMODE(file_stat.st_mode)
    current_octal = oct(current_mode)
    expected_octal = oct(max_octal_mode)
    
    is_world_writable = bool(current_mode & stat.S_IWOTH)
    
    if is_world_writable:
        return f"🚨 [HIGH RISK] {filepath} is WORLD-WRITABLE! ({current_octal} > {expected_octal})"
    elif current_mode > max_octal_mode:
        return f"⚠️ [WARN] {filepath} permissions looser than recommended: {current_octal} (Expected <= {expected_octal})"
    else:
        return f"✅ [PASS] {filepath} permissions secure: {current_octal}"

print("=== 1. File Permission Controls ===")
for path, expected_mode in TARGET_PATHS.items():
    print(check_file_permissions(path, expected_mode))


# --- SECTION 2: Network Interface Exposure Audit ---
# Common management ports to evaluate
CHECK_PORTS = [22, 80, 443, 3306, 5432, 8080, 27017]

def check_socket_binding(port):
    """
    Tests whether common service ports are bound to wildcard (0.0.0.0) 
    or isolated localhost (127.0.0.1) interfaces.
    """
    # Test binding to localhost
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        res_local = s.connect_ex(("127.0.0.1", port))
    
    if res_local == 0:
        return f"⚠️ [EXPOSED] Port {port} is active and accepting connections."
    else:
        return f"✅ [PASS] Port {port} is inactive / closed locally."

print("\n=== 2. Local Service Binding Audit ===")
for port in CHECK_PORTS:
    print(check_socket_binding(port))

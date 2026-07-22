# Day 1: Local System Hardening Auditor - File Permission Inspector
import os
import stat

print("--- Local System Hardening Auditor Initialized ---")
print("Scanning critical system path permissions...\n")

# Define target paths and their maximum secure permission masks (in octal)
# e.g., 0o644 means Owner: RW, Group: R, Others: R
TARGET_PATHS = {
    "/etc/passwd": 0o644,
    "/etc/shadow": 0o600,
    "/etc/hosts": 0o644,
}

def check_file_permissions(filepath, max_octal_mode):
    if not os.path.exists(filepath):
        return f"[SKIP] Path does not exist: {filepath}"
    
    # Get physical file status
    file_stat = os.stat(filepath)
    # Extract permission bits only
    current_mode = stat.S_IMODE(file_stat.st_mode)
    
    # Octal string representation for readable logs
    current_octal = oct(current_mode)
    expected_octal = oct(max_octal_mode)
    
    # Check if 'others' (world) have write access bit set (0o002)
    is_world_writable = bool(current_mode & stat.S_IWOTH)
    
    if is_world_writable:
        return f"🚨 [HIGH RISK] {filepath} is WORLD-WRITABLE! ({current_octal} > {expected_octal})"
    elif current_mode > max_octal_mode:
        return f"⚠️ [WARN] {filepath} permissions are looser than recommended: {current_octal} (Expected <= {expected_octal})"
    else:
        return f"✅ [PASS] {filepath} permissions secure: {current_octal}"

# Run the audit across defined targets
for path, expected_mode in TARGET_PATHS.items():
    result = check_file_permissions(path, expected_mode)
    print(result)

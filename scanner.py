import hashlib, os

# Hash of the official EICAR antivirus test file
EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

SUSPICIOUS_EXT = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".js"}
SUSPICIOUS_STRINGS = [
    b"powershell -enc", b"cmd.exe /c", b"GetAsyncKeyState",
    b"CreateRemoteThread", b"vssadmin delete shadows", b"X5O!P%@AP",
]

def load_signatures(path="signatures.txt"):
    sigs = {EICAR_HASH: "EICAR-Test-File"}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    h, _, name = line.partition(",")
                    sigs[h.lower()] = name or "Malware"
    return sigs

SIGNATURES = load_signatures()

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_file(path):
    """Returns None if clean, otherwise (threat_name, detection_method)."""
    try:
        if not os.path.isfile(path):
            return None
        # 1. Signature-based detection
        digest = sha256(path)
        if digest in SIGNATURES:
            return SIGNATURES[digest], "Signature"
        # 2. Heuristic: double extension
        parts = os.path.basename(path).lower().split(".")
        if len(parts) >= 3 and "." + parts[-1] in SUSPICIOUS_EXT:
            return "Double-Extension-Trick", "Heuristic"
        # 3. Pattern matching inside the file
        with open(path, "rb") as f:
            data = f.read(2 * 1024 * 1024).lower()
        for s in SUSPICIOUS_STRINGS:
            if s.lower() in data:
                return f"Suspicious code: {s.decode()}", "Pattern"
    except (PermissionError, OSError):
        return None
    return None

def scan_folder(folder, on_progress=None):
    files = [os.path.join(r, f) for r, _, fs in os.walk(folder) for f in fs]
    threats = []
    for i, p in enumerate(files, 1):
        result = scan_file(p)
        if result:
            threats.append((p, *result))
        if on_progress:
            on_progress(i, len(files), p)
    return threats

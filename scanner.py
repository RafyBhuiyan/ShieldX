import hashlib
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def load_signatures(path=None):
    """Loads SHA-256 signatures strictly from signatures.txt."""
    if path is None:
        path = os.path.join(BASE, "signatures.txt")
    sigs = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    clean = line.split("#")[0].strip()
                    if clean:
                        h, _, name = clean.partition(",")
                        sigs[h.strip().lower()] = name.strip() or "Malware"
    return sigs

def load_suspicious_extensions(path=None):
    """Loads suspicious file extensions strictly from suspicious_extensions.txt."""
    if path is None:
        path = os.path.join(BASE, "suspicious_extensions.txt")
    exts = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ext = line.split("#")[0].strip().lower()
                if ext:
                    if not ext.startswith("."):
                        ext = "." + ext
                    exts.add(ext)
    return exts

def load_suspicious_strings(path=None):
    """Loads suspicious code substrings and threat labels strictly from suspicious_strings.txt."""
    if path is None:
        path = os.path.join(BASE, "suspicious_strings.txt")
    patterns = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                clean = line.split("#")[0].strip()
                if not clean:
                    continue
                pattern, _, label = clean.partition(",")
                pattern = pattern.strip()
                label = label.strip() or f"Suspicious code: {pattern}"
                if pattern:
                    patterns[pattern.lower().encode()] = label
    return patterns

# Load all rules strictly from dataset files
SIGNATURES = load_signatures()
SUSPICIOUS_EXT = load_suspicious_extensions()
SUSPICIOUS_STRINGS = load_suspicious_strings()

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
        for pattern_bytes, label in SUSPICIOUS_STRINGS.items():
            if pattern_bytes in data:
                return label, "Pattern"
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

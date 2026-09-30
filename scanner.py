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
                    pat_low = pattern.lower()
                    # Store UTF-8, UTF-16 LE (Windows default for PowerShell/Notepad), and UTF-16 BE
                    patterns[pat_low.encode("utf-8")] = label
                    patterns[pat_low.encode("utf-16le")] = label
                    patterns[pat_low.encode("utf-16be")] = label
    return patterns

def load_suspicious_strings_text(path=None):
    """Loads lowercase text patterns for decoded string searches."""
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
                    patterns[pattern.lower()] = label
    return patterns

# Load all rules strictly from dataset files
SIGNATURES = load_signatures()
SUSPICIOUS_EXT = load_suspicious_extensions()
SUSPICIOUS_STRINGS = load_suspicious_strings()
SUSPICIOUS_STRINGS_TEXT = load_suspicious_strings_text()

def read_file_safely(path, max_pattern_bytes=2 * 1024 * 1024, retries=5, delay=0.1):
    """Safely reads file SHA-256 and content buffer with retries for Windows file locks."""
    import time
    for _ in range(retries):
        try:
            h = hashlib.sha256()
            sample = bytearray()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
                    if len(sample) < max_pattern_bytes:
                        needed = max_pattern_bytes - len(sample)
                        sample.extend(chunk[:needed])
            return h.hexdigest(), bytes(sample)
        except (PermissionError, OSError):
            time.sleep(delay)
    return None, None

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

        # 1. Heuristic: double extension
        parts = os.path.basename(path).lower().split(".")
        if len(parts) >= 3 and "." + parts[-1] in SUSPICIOUS_EXT:
            return "Double-Extension-Trick", "Heuristic"

        # Safely read hash and sample bytes with retry for Windows file locks
        digest, data = read_file_safely(path)
        if digest is None or data is None:
            return None

        # 2. Signature-based detection
        if digest in SIGNATURES:
            return SIGNATURES[digest], "Signature"

        # 3. Fast binary pattern matching (UTF-8, UTF-16 LE, UTF-16 BE)
        data_lower = data.lower()
        for pattern_bytes, label in SUSPICIOUS_STRINGS.items():
            if pattern_bytes in data_lower:
                return label, "Pattern"

        # 4. Decoded text pattern matching fallback (handles BOMs, Latin-1, CP1252)
        for enc in ("utf-8", "utf-16", "cp1252", "latin-1"):
            try:
                decoded = data.decode(enc, errors="ignore").lower()
                for pattern_text, label in SUSPICIOUS_STRINGS_TEXT.items():
                    if pattern_text in decoded:
                        return label, "Pattern"
            except (UnicodeDecodeError, LookupError):
                continue

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

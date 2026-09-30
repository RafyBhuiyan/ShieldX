# 🛡️ ShieldX Antivirus

ShieldX is a lightweight, modern desktop antivirus and malware detection application built with Python and CustomTkinter. It features multi-layered scanning (signatures, heuristics, and pattern matching), background folder monitoring for real-time defense, and a safe XOR-encrypted quarantine management system.

---

## 🚀 Features

- **Multi-Layered Detection Engine**:
  - **Signature Matching**: Verifies file SHA-256 digests against known threat databases and standard EICAR test definitions.
  - **Heuristic Analysis**: Detects masquerading tricks such as dangerous double extensions (e.g., `document.pdf.exe`).
  - **Pattern Matching**: Scans the first 2 MB of files for malicious scripts, commands, and suspicious API patterns (e.g., encoded PowerShell, shadow copy deletion, memory injection hooks).
- **Real-Time Protection**: Continuously monitors designated folders (such as `Downloads`) for newly created or downloaded files using background file-system event observers (`watchdog`).
- **Secure Quarantine Vault**:
  - Automatically isolates threats and obfuscates their contents using XOR encryption (`KEY = 0x5A`) with a `.q` extension to prevent accidental execution.
  - Keeps an index of threat history and allows users to safely restore or permanently delete files.
- **Modern Dark-Mode UI**: Clean, responsive interface built with CustomTkinter.

---

## 📋 Prerequisites

- **Python 3.10 or higher** (Python 3.11+ recommended)
- **pip** package manager
- **Supported OS**: Windows, macOS, or Linux (Windows recommended for full API heuristic coverage)

---

## 🛠️ Setup Instructions

Follow these step-by-step instructions to get ShieldX up and running on your system:

### 1. Clone or Download the Project
If cloning via Git:
```bash
git clone https://github.com/RafyBhuiyan/ShieldX.git
cd ShieldX
```
Or simply open your terminal (Command Prompt, PowerShell, or Bash) in the project directory:
```powershell
cd C:\Users\<YourUser>\Downloads\ShieldX
```

### 2. (Recommended) Create and Activate a Virtual Environment
Using a virtual environment prevents conflicts with existing Python packages.

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is disabled in PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, or use Command Prompt: `.\.venv\Scripts\activate.bat`)*

**On macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
Install all required packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

Alternatively, install the core dependencies directly:
```bash
pip install customtkinter watchdog
```

---

## ▶️ Running the Application

Launch the ShieldX GUI by running:

```bash
python app.py
```

---

## 📖 How to Use

### 1. On-Demand Scan (Scan Tab)
1. Go to the **Scan** tab.
2. Click **"Choose Folder & Scan"** and select the directory you wish to inspect.
3. The progress bar displays real-time scan status.
4. Any identified threats will be listed with their detection method (`[Signature]`, `[Heuristic]`, or `[Pattern]`).
5. Click **"Quarantine All Threats"** to safely neutralize and isolate all flagged files.

### 2. Real-Time Protection (Real-Time Protection Tab)
1. Navigate to the **Real-Time Protection** tab.
2. Set the folder path you want ShieldX to guard (defaults to your `Downloads` directory).
3. Toggle the **Real-Time Protection** switch to **ON**.
4. ShieldX will now watch the folder in the background. Whenever a new file is created or downloaded, it automatically scans and immediately quarantines any detected threats while alerting you.

### 3. Quarantine Management (Quarantine Tab)
1. Navigate to the **Quarantine** tab.
2. View all isolated threats, the original file paths, and quarantine timestamps.
3. **Restore**: Decrypts the file and restores it back to its original location (useful for false positives).
4. **Delete**: Permanently and securely removes the quarantined file from disk.

### 4. Customizing Detection Rules
ShieldX externalizes all detection definitions into simple text files so you can expand them without modifying code:

* **SHA-256 Signatures (`signatures.txt`)**:
  ```text
  # format: sha256_hash,malware_name
  368ad37fbb239f78dabf5c0b820cd3a8ae40438f696f0121bd1993a20aef3702,Trojan.Demo
  ```
* **Suspicious File Extensions (`suspicious_extensions.txt`)**:
  ```text
  .exe
  .scr
  .vbs
  ```
* **Suspicious Strings & Patterns (`suspicious_strings.txt`)**:
  ```text
  # format: pattern,threat_label
  powershell -enc,Obfuscated PowerShell execution
  vssadmin delete shadows,Ransomware: Shadow copy deletion
  ```

---

## 🧪 Testing the Scanner (Safe Verification)

You can verify the scanner safely using either:
1. **EICAR Standard Anti-Virus Test File**: ShieldX includes built-in signature recognition for the standard benign EICAR test string hash (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`).
2. **Double Extension Test**: Create a dummy file named `test.pdf.exe` and run a scan on that folder. ShieldX will detect it via the heuristic rule.
3. **Suspicious Pattern Test**: Create a text file containing `powershell -enc` or `vssadmin delete shadows` to verify pattern scanning.

---

## 📂 Project Structure

```
ShieldX/
├── app.py                      # Main CustomTkinter desktop user interface
├── scanner.py                  # Detection engine (hashes, heuristics, string rules)
├── monitor.py                  # Watchdog real-time filesystem observer
├── quarantine.py               # XOR obfuscation, isolation, index & recovery manager
├── signatures.txt              # Known malware hash signatures
├── suspicious_extensions.txt   # Target file extensions for heuristic double-extension checks
├── suspicious_strings.txt      # Malicious command & code pattern database
├── requirements.txt            # Python package dependencies
├── readme.md                   # Documentation and setup instructions
└── quarantine/                 # Directory storing safely encrypted quarantined files
```

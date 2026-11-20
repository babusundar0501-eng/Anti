# Anti — Security Scanner & EDR Research Project

Anti is an early-stage, cross-platform **on-demand file scanner**. Its working core uses Python's standard library and needs no pip packages.

> **Important:** Anti is not yet a full antivirus or EDR product. It does not provide kernel-level protection, automatic process blocking, guaranteed zero-day detection, or always-on real-time protection. Keep Microsoft Defender (Windows) or your platform's built-in security enabled.

## Working features

- Quick scan: Desktop, Downloads and Documents folders where present.
- Long scan: current user's home directory.
- PC scan: detected drive roots on Windows or the root filesystem on macOS/Linux. This can take a long time and produce permission errors.
- Custom scan: a file or folder selected by path.
- File checks: SHA-256 hashes, PE/ELF magic bytes and executable/document extension mismatch detection.
- Heuristic triage: checks PE samples for multiple process-injection API names and unusually high entropy. These are clues, not proof of malware.
- EICAR test detection: recognizes the harmless standard antivirus test string.
- Reversible quarantine: optionally moves only critical-confidence findings into a private quarantine folder. It never automatically deletes files.
- JSON report: ~/.anti/last_scan.json (Windows: %USERPROFILE%\\.anti\\last_scan.json).

## Requirements

Python 3.10+, Windows/macOS/Linux. No third-party packages for the core scanner.

## Windows

    py -3 anti.py quick
    py -3 anti.py long
    py -3 anti.py pc
    py -3 anti.py scan "C:\\Users\\YourName\\Downloads"
    py -3 anti.py scan "C:\\Users\\YourName\\Downloads" --quarantine

Or use run.bat quick.

## macOS and Linux

    python3 anti.py quick
    python3 anti.py long
    python3 anti.py pc
    python3 anti.py scan ~/Downloads

## Quarantine

List items with python anti.py quarantine. Restore using the exact ID printed:

    python anti.py restore ITEM_ID

Restoration is blocked if the original destination already exists.

## Tests

Run python -m unittest discover -s tests -v. Tests use temporary harmless files and the EICAR test string, never live malware.

## Limitations

- Entropy alone cannot identify malware; legitimate installers and compressed files may also have high entropy.
- API-name checks are static clues and can be bypassed or occur in legitimate software.
- EICAR is a test signature, not a maintained malware-signature database.
- This version does not inspect all process memory, block network traffic, prevent ransomware, or defend against administrator/root-level attackers.
- A clean result means only that configured checks found no indicator. It does not certify a file is safe.
- Scanning protected locations may require elevated permissions. Prefer least privilege.

## Experimental legacy modules

main.cpp, header.rs, guard.ps1 and 1.py are experimental samples. They are not connected to the scanner's verdict pipeline and are not production protection.

## Roadmap

1. Maintained signature database with cryptographically verified updates.
2. Isolated test harness and larger benign/malicious test corpus.
3. Reliable file-system event monitoring and process attribution.
4. Independently reviewed tamper-resistant service/driver design.
5. Desktop dashboard and auditable quarantine controls.
6. Platform-specific validation on Windows, macOS and Linux.

Security claims must be backed by reproducible tests.

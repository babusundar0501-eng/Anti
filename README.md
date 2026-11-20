*NEXT GEN EDR ANTIVIRUS*


Next-Gen Multi-Language Endpoint Detection & Response (EDR) Suite is a modular, multi-layered security framework designed to defend systems against modern malware, ransomware, and fileless attacks without relying solely on traditional virus signatures.

*OVERVIEW*

Instead of a single monolithic scanner, this suite divides defense across specialized mini-engines—each written in the programming language best suited for its security layer:
• Core Behavioral & Memory Engine (nextgen_edr.cpp – C++17): Uses native Windows APIs to scan live process memory (RAM) for injected shellcode, calculates Shannon entropy to catch encrypted zero-day payloads, inspects .exe import tables for process-injection APIs, and deploys hidden canary files to trap ransomware in real time.
• Network & C2 Beaconing Guard (net_sentinel.py – Python): Monitors active TCP/UDP sockets to detect unauthorized outbound connections from system binaries (such as notepad.exe or cmd.exe) and flags traffic on high-risk reverse-shell ports.
• Registry & Persistence Watcher (persistence_guard.ps1 – PowerShell): Continuously audits Windows startup Run keys against a clean baseline to catch malware attempting to survive system reboots.
• Binary Magic-Byte Inspector (header_inspector.rs – Rust): Provides memory-safe binary verification to detect spoofed files (such as executables disguised as .pdf or .jpg documents) before they are opened.

Key Capabilities

• Signatureless Zero-Day Detection: Identifies unknown threats through byte randomness (entropy), API call heuristics, and behavioral tripwires.
• Fileless Malware Hunting: Inspects executable private memory regions inside running processes to catch threats that never touch the hard drive.
• Automated Threat Isolation: Immediately moves suspicious files into a locked quarantine directory to prevent execution.
(Note: This project is an architectural prototype intended for cybersecurity research, red/blue team labs, and educational use.)

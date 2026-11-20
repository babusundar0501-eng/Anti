import time
import psutil

# Processes that should NEVER make external internet connections
SUSPICIOUS_NETWORK_PROCS = {
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe", "wscript.exe", "cscript.exe"
}

# Common C2 / Metasploit / Reverse Shell ports
HIGH_RISK_PORTS = {4444, 5555, 6666, 1337, 31337, 8081, 9001}

def monitor_network():
    print("[NET-SENTINEL] Active: Monitoring live TCP/UDP sockets...")
    seen_connections = set()

    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                conn_id = (conn.pid, conn.raddr.ip, conn.raddr.port)
                if conn_id in seen_connections:
                    continue
                seen_connections.add(conn_id)

                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                # Check 1: Living-off-the-Land / Injection Alert
                if proc_name in SUSPICIOUS_NETWORK_PROCS:
                    print(f"\033[91m[CRITICAL C2 ALERT] {proc_name} (PID {conn.pid}) connected to {conn.raddr.ip}:{conn.raddr.port}\033[0m")

                # Check 2: High-Risk Reverse Shell Port
                elif conn.raddr.port in HIGH_RISK_PORTS:
                    print(f"\033[93m[PORT ALERT] {proc_name} (PID {conn.pid}) using high-risk port {conn.raddr.port}\033[0m")

        time.sleep(1)

if __name__ == "__main__":
    monitor_network()

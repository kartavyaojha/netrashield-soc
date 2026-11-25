"""
Multi-threaded UDP/TCP Syslog listener on Port 5140 with WebSocket broadcasting
"""
import socket
import threading
import time
import asyncio
import re
from typing import List, Set, Optional, Callable
from .parser import ECSNormalizer

ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def sanitize_syslog_payload(text: str) -> str:
    """
    Strips ANSI escape sequences and non-printable control characters
    to prevent terminal injection and log spoofing.
    """
    clean = ANSI_ESCAPE_RE.sub('', text)
    clean = ''.join(c for c in clean if c.isprintable() or c in '\t ')
    return clean[:4096]

class SyslogServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5140):
        self.host = host
        self.port = port
        self.running = False
        self.udp_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.subscribers: Set[asyncio.Queue] = set()
        self.recent_logs: List[str] = []
        self.max_history = 500
        self.on_log_callback: Optional[Callable[[str], None]] = None

    def start(self) -> bool:
        if self.running:
            return True
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.host, self.port))
            self.running = True

            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            self.broadcast_line(f"[INFO] NetraShield Syslog UDP Listener active on {self.host}:{self.port}")
            return True
        except Exception as e:
            self.running = False
            self.broadcast_line(f"[ERROR] Failed to start Syslog UDP Listener: {e}")
            return False

    def stop(self) -> bool:
        if not self.running:
            return True
        self.running = False
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None
        self.broadcast_line("[INFO] NetraShield Syslog UDP Listener stopped")
        return True

    def _listen_loop(self):
        while self.running:
            try:
                if not self.udp_sock:
                    break
                data, addr = self.udp_sock.recvfrom(4096)
                if not data:
                    continue
                raw_msg = data.decode("utf-8", errors="replace").strip()
                self._handle_incoming_log(raw_msg, addr[0])
            except Exception:
                if not self.running:
                    break

    def _handle_incoming_log(self, raw_msg: str, client_ip: str):
        # Sanitize against terminal injection, ANSI escape codes, and oversized payloads
        clean_msg = sanitize_syslog_payload(raw_msg).strip()
        if not clean_msg:
            return

        # Format with timestamp & severity tag
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        tag = "[INFO]"
        lower = clean_msg.lower()
        if any(w in lower for w in ["failed", "unauthorized", "alert", "attack", "malware", "drop", "deny"]):
            tag = "[ALERT]"
        elif any(w in lower for w in ["warn", "invalid", "retry", "timeout"]):
            tag = "[WARN]"

        formatted = f"{now} {tag} [{client_ip}] {clean_msg}"
        self.broadcast_line(formatted)

    def broadcast_line(self, line: str):
        self.recent_logs.append(line)
        if len(self.recent_logs) > self.max_history:
            self.recent_logs.pop(0)

        # Call registered callback
        if self.on_log_callback:
            try:
                self.on_log_callback(line)
            except Exception:
                pass

        # Push to async queues
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(line)
            except Exception:
                pass

    def simulate_attack_burst(self) -> int:
        """
        Sends simulated attack burst packets to localhost:5140.
        """
        burst_payloads = [
            "<14>Nov 24 21:00:01 srv-gateway sshd[4012]: Failed password for root from 45.154.255.89 port 34912 ssh2",
            "<14>Nov 24 21:00:02 srv-gateway sshd[4013]: Failed password for invalid user admin from 45.154.255.89 port 34913 ssh2",
            "<14>Nov 24 21:00:03 srv-gateway sshd[4014]: Failed password for invalid user postgres from 45.154.255.89 port 34914 ssh2",
            "<13>Nov 24 21:00:04 border-fw kernel: [ALERT] IPTABLES DROP IN=eth0 OUT= SRC=185.220.101.42 DST=192.168.1.100 PROTO=TCP SPT=4444 DPT=8080 [SYN_FLOOD]",
            "<11>Nov 24 21:00:05 endpoint-ids osqueryd[882]: [ALERT] T1059.001 PowerShell encoded download cradle observed invoking 185.220.101.42",
            "<14>Nov 24 21:00:06 auth-svr pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=91.240.118.172",
            "<12>Nov 24 21:00:07 dns-sensor named[1090]: [WARN] Dynamic DGA C2 query resolved: c2-sync-agent.online -> 91.240.118.172"
        ]

        sent = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for p in burst_payloads:
                sock.sendto(p.encode("utf-8"), (self.host, self.port))
                sent += 1
                time.sleep(0.05)
        except Exception as e:
            # If socket isn't open or errored, push directly to broadcast
            for p in burst_payloads:
                self._handle_incoming_log(p, "127.0.0.1")
                sent += 1
        finally:
            sock.close()
        return sent

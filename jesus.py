# ──────────────────────────────────────────────
# Backstory(writen at 2:27 AM with rage)
#
# Delinquent students, careless ad curious, begain to toy with power they barely understood
# tables vanished, databases and tables crumbled with a single reckless command, their learning
# dissolved into nothingness..
#
# Laughter echoed where structure once stood.
#
# But amongt this, One student did not falther.. He did not bend to the chaos. THE CHOSEN ONE
#
# while others broke, playing god amongst. HE SUFFERED WHERE HE SHOULDNT
#
# CALLED A SINNER FOR SINS HE DID NOT DO!
#
# He built, while otheres erased, he made something greater. Even greater than himself. SQL JESUS
#
# A silent guardian. SQL JESUS WILL DIE FOR YOUR SINS!
#
# When the delinquents struck again, SQL JESUS ANSWERED, AND HE BLOCKED THE HANDS OF THE SINNERS FROM
# EVER REACHING THE OTHERS...l
#
# AND IT ECHOED THROUGH THE LAB!
#
# NO MORE DELETED TABLES, NO MORE LOST DATA
#
# SQL JESUS DESCIDES WHAT LIVES AND WHAT DIES FOR HE IS THE RULER OF THE DATABASES
#
# TIME WASTED : 9 Hours 32 Mins : 11.768 Sec
#
# MADE WITH SPITE and RAGE by Govind (mln) Menon
# ──────────────────────────────────────────────

"""
SQL Jesus -- MySQL proxy with dashboard.
Single file. Run as Administrator.

    python jesus.py
"""

import logging
import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
from collections import defaultdict
from datetime import datetime, timezone
from tkinter import font as tkfont
from tkinter import ttk

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 3306
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3307
LOG_FILE = "proxy.log"
MAX_THREADS = 50
PROXY_CERT = "proxy-cert.pem"
PROXY_KEY = "proxy-key.pem"

# ──────────────────────────────────────────────
# Blocked SQL patterns
# ──────────────────────────────────────────────
BLOCKED_PATTERNS = [
    r"\bDROP\s+(DATABASE|SCHEMA|TABLE|VIEW|PROCEDURE|FUNCTION|TRIGGER|EVENT|INDEX)\b",
    r"\bTRUNCATE\b",
    r"\bALTER\s+TABLE\b",
    r"\bRENAME\s+TABLE\b",
    r"\bGRANT\b",
    r"\bREVOKE\b",
    r"\bCREATE\s+USER\b",
    r"\bDROP\s+USER\b",
    r"\bALTER\s+USER\b",
    r"\bFLUSH\s+PRIVILEGES\b",
    r"\bSHUTDOWN\b",
    r"\bRESET\s+MASTER\b",
    r"\bRESET\s+SLAVE\b",
    r"\bPURGE\b",
    r"\bLOAD\s+DATA\s+INFILE\b",
    r"\bINTO\s+OUTFILE\b",
    r"\bINTO\s+DUMPFILE\b",
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in BLOCKED_PATTERNS]

# ──────────────────────────────────────────────
# Shared state (proxy engine -> dashboard)
# ──────────────────────────────────────────────
ui_queue = queue.Queue()
stats_lock = threading.Lock()
stats = {
    "total": 0,
    "blocked": 0,
    "allowed": 0,
    "connections": 0,
    "active": 0,
}
blocked_ips = defaultdict(int)
_server_sock = None
_proxy_thread = None


def push(event: dict):
    ui_queue.put(event)


def inc(key, n=1):
    with stats_lock:
        stats[key] += n


# ──────────────────────────────────────────────
# Logging -- also feeds the UI queue
# ──────────────────────────────────────────────
class UIQueueHandler(logging.Handler):
    def emit(self, record):
        push({"type": "log", "level": record.levelname, "msg": self.format(record)})


log = logging.getLogger("sql_jesus")
log.setLevel(logging.DEBUG)
_fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s")

_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setFormatter(_fmt)
log.addHandler(_fh)

_sh = logging.StreamHandler()
_sh.setFormatter(_fmt)
log.addHandler(_sh)

_uh = UIQueueHandler()
_uh.setFormatter(_fmt)
log.addHandler(_uh)


# ──────────────────────────────────────────────
# SSL cert auto-generation
# ──────────────────────────────────────────────
def ensure_ssl_cert():
    if os.path.exists(PROXY_CERT) and os.path.exists(PROXY_KEY):
        return
    log.info("Generating SSL cert...")
    try:
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mysql-proxy")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        with open(PROXY_KEY, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(PROXY_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info("SSL cert generated.")
        return
    except ImportError:
        pass
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        PROXY_KEY,
        "-out",
        PROXY_CERT,
        "-days",
        "3650",
        "-nodes",
        "-subj",
        "/CN=mysql-proxy",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            log.info("SSL cert generated via openssl.")
        else:
            log.error("openssl failed: %s", r.stderr)
            sys.exit(1)
    except FileNotFoundError:
        log.error("No openssl and no cryptography lib. Run: pip install cryptography")
        sys.exit(1)


# ──────────────────────────────────────────────
# Proxy helpers
# ──────────────────────────────────────────────
def is_blocked(sql: str) -> str | None:
    for pattern, original in zip(COMPILED_PATTERNS, BLOCKED_PATTERNS):
        if pattern.search(sql):
            return original
    return None


def make_error_packet(message: str) -> bytes:
    msg = message.encode("utf-8")
    payload = bytes([0xFF]) + (1064).to_bytes(2, "little") + b"#HY000" + msg
    return len(payload).to_bytes(3, "little") + b"\x01" + payload


def recv_all(sock, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def read_packet(sock) -> bytes | None:
    header = recv_all(sock, 4)
    if header is None:
        return None
    plen = int.from_bytes(header[:3], "little")
    if plen == 0:
        return header
    payload = recv_all(sock, plen)
    if payload is None:
        return None
    return header + payload


CLIENT_SSL = 0x00000800


def client_wants_ssl(pkt: bytes) -> bool:
    if len(pkt) < 8:
        return False
    return bool(int.from_bytes(pkt[4:8], "little") & CLIENT_SSL)


def make_server_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=PROXY_CERT, keyfile=PROXY_KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_client_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ──────────────────────────────────────────────
# Per-connection handler
# ──────────────────────────────────────────────
def handle_client(client_sock: socket.socket, client_addr: tuple):
    addr = f"{client_addr[0]}:{client_addr[1]}"
    ip = client_addr[0]
    log.info("CONNECT  | %s", addr)
    inc("connections")
    inc("active")
    push({"type": "connect", "addr": addr})

    try:
        raw_server = socket.create_connection((MYSQL_HOST, MYSQL_PORT), timeout=10)
    except OSError as exc:
        log.error("Cannot reach MySQL: %s", exc)
        client_sock.close()
        inc("active", -1)
        return

    client_sock.settimeout(300)
    raw_server.settimeout(300)

    def close_both(c, s):
        try:
            c.close()
        except:
            pass
        try:
            s.close()
        except:
            pass

    greeting = read_packet(raw_server)
    if greeting is None:
        close_both(client_sock, raw_server)
        inc("active", -1)
        return

    try:
        client_sock.sendall(greeting)
    except OSError:
        close_both(client_sock, raw_server)
        inc("active", -1)
        return

    client_resp = read_packet(client_sock)
    if client_resp is None:
        close_both(client_sock, raw_server)
        inc("active", -1)
        return

    if client_wants_ssl(client_resp):
        try:
            raw_server.sendall(client_resp)
            server_sock = make_client_ssl_ctx().wrap_socket(
                raw_server, server_hostname=MYSQL_HOST
            )
            client_conn = make_server_ssl_ctx().wrap_socket(
                client_sock, server_side=True
            )
        except ssl.SSLError as exc:
            log.error("SSL upgrade failed: %s", exc)
            close_both(client_sock, raw_server)
            inc("active", -1)
            return
    else:
        server_sock = raw_server
        client_conn = client_sock
        try:
            server_sock.sendall(client_resp)
        except OSError:
            close_both(client_conn, server_sock)
            inc("active", -1)
            return

    auth_done = threading.Event()
    client_spoke = threading.Event()

    def server_to_client():
        while True:
            pkt = read_packet(server_sock)
            if pkt is None:
                break
            first = pkt[4] if len(pkt) > 4 else None
            if not auth_done.is_set() and client_spoke.is_set() and first == 0x00:
                auth_done.set()
            try:
                client_conn.sendall(pkt)
            except OSError:
                break
        auth_done.set()
        close_both(client_conn, server_sock)

    def client_to_server():
        client_spoke.set()
        while True:
            pkt = read_packet(client_conn)
            if pkt is None:
                break

            seq = pkt[3]
            cmd = pkt[4] if len(pkt) > 4 else 0

            if not auth_done.is_set():
                try:
                    server_sock.sendall(pkt)
                except OSError:
                    break
                continue

            if seq == 0x00 and cmd == 0x03:
                try:
                    sql = pkt[5:].decode("utf-8", errors="replace")
                    sql = sql.lstrip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09").strip()
                except Exception:
                    sql = ""

                inc("total")
                blocked_by = is_blocked(sql)
                if blocked_by:
                    inc("blocked")
                    with stats_lock:
                        blocked_ips[ip] += 1
                    log.warning("BLOCKED | %s | %.120s", addr, sql)
                    push(
                        {
                            "type": "blocked",
                            "addr": addr,
                            "ip": ip,
                            "sql": sql,
                            "rule": blocked_by,
                            "time": datetime.now().strftime("%H:%M:%S"),
                        }
                    )
                    try:
                        client_conn.sendall(
                            make_error_packet(
                                "[SQL JESUS] : I shield the innocent from your hands of sin..."
                            )
                        )
                    except OSError:
                        break
                    continue
                else:
                    inc("allowed")
                    log.info("ALLOWED | %s | %.120s", addr, sql)
                    push(
                        {
                            "type": "allowed",
                            "addr": addr,
                            "sql": sql,
                            "time": datetime.now().strftime("%H:%M:%S"),
                        }
                    )

            try:
                server_sock.sendall(pkt)
            except OSError:
                break

        close_both(client_conn, server_sock)

    t_s2c = threading.Thread(target=server_to_client, daemon=True)
    t_c2s = threading.Thread(target=client_to_server, daemon=True)
    t_s2c.start()
    t_c2s.start()
    t_s2c.join()
    t_c2s.join()
    inc("active", -1)
    push({"type": "disconnect", "addr": addr})
    log.info("CLOSE    | %s", addr)


# ──────────────────────────────────────────────
# Proxy server loop
# ──────────────────────────────────────────────
def proxy_loop():
    global _server_sock
    ensure_ssl_cert()
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((PROXY_HOST, PROXY_PORT))
        srv.listen(MAX_THREADS)
        _server_sock = srv
        log.info("Proxy listening on %s:%d", PROXY_HOST, PROXY_PORT)
        push({"type": "status", "running": True})
        active = 0
        while True:
            try:
                cs, ca = srv.accept()
            except OSError:
                break
            if active >= MAX_THREADS:
                cs.close()
                continue
            active += 1

            def run(s=cs, a=ca):
                nonlocal active
                handle_client(s, a)
                active -= 1

            threading.Thread(target=run, daemon=True).start()
    except OSError as exc:
        log.error("Proxy error: %s", exc)
    finally:
        push({"type": "status", "running": False})
        log.info("Proxy stopped.")


def start_proxy():
    global _proxy_thread
    _proxy_thread = threading.Thread(target=proxy_loop, daemon=True)
    _proxy_thread.start()


def stop_proxy():
    global _server_sock
    if _server_sock:
        try:
            _server_sock.close()
        except OSError:
            pass
        _server_sock = None


# ──────────────────────────────────────────────
# Custom slim scrollbar
# ──────────────────────────────────────────────
class SlimScrollbar(tk.Canvas):
    TRACK = "#1a1a1a"
    THUMB = "#444444"
    HOVER = "#666666"

    def __init__(self, master, orient="vertical", command=None, **kw):
        kw.setdefault("bg", self.TRACK)
        kw.setdefault("highlightthickness", 0)
        kw.setdefault("bd", 0)
        kw.setdefault("relief", "flat")
        if orient == "vertical":
            kw.setdefault("width", 6)
        else:
            kw.setdefault("height", 6)
        super().__init__(master, **kw)
        self._orient = orient
        self._command = command
        self._thumb = None
        self._pos = (0.0, 1.0)
        self._drag_y = None
        self._drag_x = None
        self.bind("<Configure>", self._redraw)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Enter>", lambda e: self._set_thumb_color(self.HOVER))
        self.bind("<Leave>", lambda e: self._set_thumb_color(self.THUMB))

    def set(self, first, last):
        self._pos = (float(first), float(last))
        self._redraw()

    def _redraw(self, event=None):
        self.delete("thumb")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 1 or h < 1:
            return
        first, last = self._pos
        pad = 2
        if self._orient == "vertical":
            self._thumb = self.create_rectangle(
                pad,
                first * h + pad,
                w - pad,
                last * h - pad,
                fill=self.THUMB,
                outline="",
                tags="thumb",
                width=0,
            )
        else:
            self._thumb = self.create_rectangle(
                first * w + pad,
                pad,
                last * w - pad,
                h - pad,
                fill=self.THUMB,
                outline="",
                tags="thumb",
                width=0,
            )

    def _set_thumb_color(self, color):
        if self._thumb:
            self.itemconfig(self._thumb, fill=color)

    def _on_press(self, event):
        self._drag_y = event.y
        self._drag_x = event.x

    def _on_drag(self, event):
        if self._command is None:
            return
        first, last = self._pos
        size = last - first
        if self._orient == "vertical":
            delta = (event.y - self._drag_y) / max(self.winfo_height(), 1)
            self._drag_y = event.y
        else:
            delta = (event.x - self._drag_x) / max(self.winfo_width(), 1)
            self._drag_x = event.x
        self._command("moveto", max(0.0, min(1.0 - size, first + delta)))

    def _on_release(self, event):
        self._drag_y = None
        self._drag_x = None


# ──────────────────────────────────────────────
# Dashboard UI
# ──────────────────────────────────────────────
class Dashboard(tk.Tk):
    BG = "#000000"
    SURFACE = "#111111"
    SURFACE2 = "#1a1a1a"
    ACCENT = "#ffffff"
    TEXT = "#ededed"
    MUTED = "#555555"
    BORDER = "#222222"

    def __init__(self):
        super().__init__()
        self.title("SQL Jesus -- Proxy Dashboard")
        self.configure(bg=self.BG)
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.proxy_running = False
        self._build_ui()
        self._poll()

    def _build_ui(self):
        mono = tkfont.Font(family="Consolas", size=9)

        # top bar
        topbar = tk.Frame(self, bg=self.SURFACE, height=56)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)
        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x", side="top")

        title_frame = tk.Frame(topbar, bg=self.SURFACE)
        title_frame.pack(side="left", padx=20)
        tk.Label(
            title_frame,
            text="\u271d",
            bg=self.SURFACE,
            fg=self.ACCENT,
            font=("Georgia", 22, "italic"),
        ).pack(side="left", padx=(0, 6))
        tk.Label(
            title_frame,
            text="SQL Jesus",
            bg=self.SURFACE,
            fg=self.ACCENT,
            font=("Georgia", 16, "italic"),
        ).pack(side="left")

        self.status_dot = tk.Label(
            topbar, text="\u25cf", bg=self.SURFACE, fg="#333333", font=("Segoe UI", 14)
        )
        self.status_dot.pack(side="left")
        self.status_lbl = tk.Label(
            topbar,
            text="Stopped",
            bg=self.SURFACE,
            fg=self.MUTED,
            font=("Segoe UI", 10),
        )
        self.status_lbl.pack(side="left", padx=(4, 20))

        self.toggle_btn = tk.Button(
            topbar,
            text="\u25b6  Start Proxy",
            bg="#ffffff",
            fg="#000000",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=16,
            pady=6,
            cursor="hand2",
            command=self._toggle_proxy,
        )
        self.toggle_btn.pack(side="right", padx=20, pady=10)

        # stat cards
        cards = tk.Frame(self, bg=self.BG)
        cards.pack(fill="x", padx=16, pady=(12, 0))
        self.stat_vars = {}
        defs = [
            ("total", "Total Queries", self.TEXT),
            ("allowed", "Allowed", self.TEXT),
            ("blocked", "Blocked", "#ff4444"),
            ("connections", "Connections", "#888888"),
            ("active", "Active Now", self.TEXT),
        ]
        for key, label, colour in defs:
            border = tk.Frame(cards, bg=self.BORDER, padx=1, pady=1)
            border.pack(side="left", expand=True, fill="both", padx=6)
            card = tk.Frame(border, bg=self.SURFACE2, padx=18, pady=12)
            card.pack(fill="both", expand=True)
            v = tk.StringVar(value="0")
            self.stat_vars[key] = v
            tk.Label(
                card,
                textvariable=v,
                bg=self.SURFACE2,
                fg=colour,
                font=("Segoe UI", 26, "bold"),
            ).pack(anchor="w")
            tk.Label(
                card, text=label, bg=self.SURFACE2, fg=self.MUTED, font=("Segoe UI", 9)
            ).pack(anchor="w")

        # main area — vertical split: log on top, blocked table below
        main = tk.Frame(self, bg=self.BG)
        main.pack(fill="both", expand=True, padx=16, pady=12)

        # top: live log
        tk.Label(
            main,
            text="Live feed",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 4))

        log_border = tk.Frame(main, bg=self.BORDER, padx=1, pady=1)
        log_border.pack(fill="both", expand=True)
        log_frame = tk.Frame(log_border, bg=self.SURFACE)
        log_frame.pack(fill="both", expand=True)

        self.log_box = tk.Text(
            log_frame,
            bg=self.SURFACE,
            fg=self.TEXT,
            font=mono,
            relief="flat",
            bd=0,
            state="disabled",
            wrap="none",
            insertbackground=self.TEXT,
        )
        log_vsb = SlimScrollbar(
            log_frame, orient="vertical", command=self.log_box.yview
        )
        log_hsb = SlimScrollbar(
            log_frame, orient="horizontal", command=self.log_box.xview
        )
        self.log_box.configure(yscrollcommand=log_vsb.set, xscrollcommand=log_hsb.set)
        log_vsb.pack(side="right", fill="y")
        log_hsb.pack(side="bottom", fill="x")
        self.log_box.pack(fill="both", expand=True)

        self.log_box.tag_config("BLOCKED", foreground="#ff4444")
        self.log_box.tag_config("ALLOWED", foreground="#aaaaaa")
        self.log_box.tag_config("INFO", foreground=self.TEXT)
        self.log_box.tag_config("DEBUG", foreground=self.MUTED)
        self.log_box.tag_config("WARNING", foreground="#cccccc")
        self.log_box.tag_config("ERROR", foreground="#ffffff")

        # bottom: blocked attempts (full width) + repeat offenders side by side
        bottom = tk.Frame(main, bg=self.BG)
        bottom.pack(fill="x", pady=(12, 0))

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Dark.Treeview",
            background=self.SURFACE,
            foreground=self.TEXT,
            fieldbackground=self.SURFACE,
            rowheight=24,
            font=("Consolas", 9),
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=self.SURFACE2,
            foreground=self.MUTED,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", "#333333")],
            foreground=[("selected", "#ffffff")],
        )

        # blocked attempts — left side of bottom strip
        blocked_col = tk.Frame(bottom, bg=self.BG)
        blocked_col.pack(side="left", fill="both", expand=True)
        tk.Label(
            blocked_col,
            text="Blocked attempts",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 4))

        tree_border = tk.Frame(blocked_col, bg=self.BORDER, padx=1, pady=1)
        tree_border.pack(fill="both", expand=True)
        tree_frame = tk.Frame(tree_border, bg=self.SURFACE)
        tree_frame.pack(fill="both", expand=True)

        cols = ("time", "ip", "sql", "rule")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            style="Dark.Treeview",
            height=7,
            selectmode="browse",
        )
        self.tree.heading("time", text="Time")
        self.tree.heading("ip", text="IP")
        self.tree.heading("sql", text="Query")
        self.tree.heading("rule", text="Rule")
        self.tree.column("time", width=70, stretch=False)
        self.tree.column("ip", width=120, stretch=False)
        self.tree.column("sql", width=400)
        self.tree.column("rule", width=200, stretch=False)

        tree_vsb = SlimScrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_vsb.set)
        tree_vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # repeat offenders -- right side of bottom strip
        offenders_col = tk.Frame(bottom, bg=self.BG, width=220)
        offenders_col.pack(side="right", fill="y", padx=(14, 0))
        offenders_col.pack_propagate(False)
        tk.Label(
            offenders_col,
            text="Repeat offenders",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 4))

        ip_border = tk.Frame(offenders_col, bg=self.BORDER, padx=1, pady=1)
        ip_border.pack(fill="both", expand=True)
        ip_frame = tk.Frame(ip_border, bg=self.SURFACE)
        ip_frame.pack(fill="both", expand=True)

        cols2 = ("ip", "count")
        self.ip_tree = ttk.Treeview(
            ip_frame,
            columns=cols2,
            show="headings",
            style="Dark.Treeview",
            height=7,
            selectmode="none",
        )
        self.ip_tree.heading("ip", text="Student IP")
        self.ip_tree.heading("count", text="Blocks")
        self.ip_tree.column("ip", width=140)
        self.ip_tree.column("count", width=50, stretch=False)
        self.ip_tree.pack(fill="both", expand=True)

    def _toggle_proxy(self):
        if not self.proxy_running:
            start_proxy()
            self.toggle_btn.config(
                text="\u23f9  Stop Proxy", bg="#333333", fg="#ffffff"
            )
        else:
            stop_proxy()
            self.toggle_btn.config(
                text="\u25b6  Start Proxy", bg="#ffffff", fg="#000000"
            )
            self._set_status(False)

    def _set_status(self, running: bool):
        self.proxy_running = running
        if running:
            self.status_dot.config(fg="#ffffff")
            self.status_lbl.config(text="Running  --  listening on :3306", fg="#ededed")
        else:
            self.status_dot.config(fg="#333333")
            self.status_lbl.config(text="Stopped", fg=self.MUTED)

    def _append_log(self, msg: str, tag: str = "INFO"):
        self.log_box.config(state="normal")
        self.log_box.insert("end", msg + "\n", tag)
        self.log_box.see("end")
        lines = int(self.log_box.index("end-1c").split(".")[0])
        if lines > 2000:
            self.log_box.delete("1.0", f"{lines - 2000}.0")
        self.log_box.config(state="disabled")

    def _add_blocked(self, event: dict):
        sql_short = event["sql"][:60] + ("\u2026" if len(event["sql"]) > 60 else "")
        rule_short = event["rule"].replace(r"\b", "").replace(r"\s+", " ")[:30]
        self.tree.insert(
            "", 0, values=(event["time"], event["ip"], sql_short, rule_short)
        )
        rows = self.tree.get_children()
        if len(rows) > 200:
            self.tree.delete(rows[-1])

    def _refresh_ip_table(self):
        for row in self.ip_tree.get_children():
            self.ip_tree.delete(row)
        with stats_lock:
            sorted_ips = sorted(blocked_ips.items(), key=lambda x: -x[1])
        for ip, count in sorted_ips[:10]:
            self.ip_tree.insert("", "end", values=(ip, count))

    def _refresh_stats(self):
        with stats_lock:
            snap = dict(stats)
        for key, var in self.stat_vars.items():
            var.set(str(snap.get(key, 0)))

    def _poll(self):
        dirty_ips = False
        try:
            while True:
                event = ui_queue.get_nowait()
                etype = event.get("type")
                if etype == "log":
                    lvl = event.get("level", "INFO")
                    msg = event.get("msg", "")
                    tag = (
                        "BLOCKED"
                        if "BLOCKED" in msg
                        else "ALLOWED"
                        if "ALLOWED" in msg
                        else lvl
                    )
                    self._append_log(msg, tag)
                elif etype == "blocked":
                    self._add_blocked(event)
                    dirty_ips = True
                elif etype == "status":
                    self._set_status(event.get("running", False))
        except queue.Empty:
            pass

        self._refresh_stats()
        if dirty_ips:
            self._refresh_ip_table()
        self.after(150, self._poll)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app = Dashboard()
    app.mainloop()

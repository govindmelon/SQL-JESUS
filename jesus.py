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
A TCP proxy that sits between students and MySQL, blocking destructive
SQL statements. Handles SSL termination automatically — generates its
own cert on first run, no manual openssl commands needed.

    Students connect to:  <server-ip>:3306  (proxy, standard port)
    Real MySQL runs on:   127.0.0.1:3307    (hidden, LAN-unreachable)

Setup (one-time):
    1. In my.ini under [mysqld]:
           port         = 3307
           bind-address = 127.0.0.1
    2. Restart MySQL:   net stop MySQL80 && net start MySQL80
    3. Run proxy:       python jesus.py   (as Administrator)

That's it. The proxy generates proxy-cert.pem and proxy-key.pem
automatically on first run if they don't exist.

To bypass the proxy (run a DROP yourself):
    mysql -h 127.0.0.1 -P 3307 -u root -p

Log file: proxy.log
"""

import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from datetime import (
    datetime,  # its a fragment, from darker times ignore it and don't ask questions..
)

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
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("mysql_proxy")


# ──────────────────────────────────────────────
# Auto-generate SSL cert if missing
# ──────────────────────────────────────────────
def ensure_ssl_cert():
    """
    Generate a self-signed cert using Python's cryptography library if available,
    otherwise fall back to calling openssl on the command line.
    Either way this is fully automatic — no manual steps needed.
    """
    if os.path.exists(PROXY_CERT) and os.path.exists(PROXY_KEY):
        log.debug("SSL cert already exists, skipping generation.")
        return

    log.info("SSL cert not found — generating automatically...")

    # Try pure-Python generation first (cryptography library)
    try:
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "mysql-proxy"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
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
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(PROXY_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info(
            "SSL cert generated via cryptography library -> %s / %s",
            PROXY_CERT,
            PROXY_KEY,
        )
        return

    except ImportError:
        log.debug("cryptography library not available, trying openssl CLI...")
    except Exception as exc:
        log.warning("cryptography library failed: %s — trying openssl CLI...", exc)

    # Fall back to openssl CLI
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
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log.info(
                "SSL cert generated via openssl CLI -> %s / %s", PROXY_CERT, PROXY_KEY
            )
        else:
            log.error("openssl failed:\n%s", result.stderr)
            log.error("Install openssl or run: pip install cryptography")
            sys.exit(1)
    except FileNotFoundError:
        log.error("openssl not found on PATH and cryptography library not installed.")
        log.error("Fix with one of:")
        log.error("  pip install cryptography")
        log.error("  Install Git for Windows (includes openssl)")
        sys.exit(1)


# ──────────────────────────────────────────────
# Helpers
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
    """Read exactly n bytes. Returns None on disconnect."""
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
    """Read one complete MySQL wire-protocol packet (raw or SSL socket)."""
    header = recv_all(sock, 4)
    if header is None:
        return None
    payload_len = int.from_bytes(header[:3], "little")
    if payload_len == 0:
        return header
    payload = recv_all(sock, payload_len)
    if payload is None:
        return None
    return header + payload


# ──────────────────────────────────────────────
# SSL contexts
# ──────────────────────────────────────────────
def make_server_ssl_ctx() -> ssl.SSLContext:
    """SSL context the proxy uses when accepting connections from clients."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=PROXY_CERT, keyfile=PROXY_KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_client_ssl_ctx() -> ssl.SSLContext:
    """SSL context the proxy uses when connecting to MySQL."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ──────────────────────────────────────────────
# MySQL capability flag for SSL
# ──────────────────────────────────────────────
CLIENT_SSL = 0x00000800


def client_wants_ssl(pkt: bytes) -> bool:
    """Return True if the client's capability flags have the SSL bit set."""
    if len(pkt) < 8:
        return False
    caps = int.from_bytes(pkt[4:8], "little")
    return bool(caps & CLIENT_SSL)


# ──────────────────────────────────────────────
# Per-connection handler
#
# MySQL SSL handshake:
#   [plaintext]
#   S->C  seq=0  Server greeting (0x0a)
#   C->S  seq=1  SSL Request (32 bytes, capability flags only, SSL bit set)
#   [both upgrade to SSL]
#   C->S  seq=2  Full auth packet (user, password hash, db)
#   S->C  seq=2  OK / ERR / auth-switch
#   ... possible caching_sha2 extra round trips ...
#   S->C         Final OK (0x00) — auth complete
#   [query phase — COM_QUERY seq=0 cmd=0x03]
# ──────────────────────────────────────────────
def handle_client(client_sock: socket.socket, client_addr: tuple):
    addr = f"{client_addr[0]}:{client_addr[1]}"
    log.info("CONNECT  | %s", addr)

    try:
        raw_server = socket.create_connection((MYSQL_HOST, MYSQL_PORT), timeout=10)
    except OSError as exc:
        log.error("Cannot reach MySQL at %s:%d — %s", MYSQL_HOST, MYSQL_PORT, exc)
        client_sock.close()
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

    # ── Step 1: read server greeting (plaintext) ──
    greeting = read_packet(raw_server)
    if greeting is None:
        log.error("No greeting from MySQL | %s", addr)
        close_both(client_sock, raw_server)
        return
    log.debug("GREETING | %s | seq=%d len=%d", addr, greeting[3], len(greeting))

    # ── Step 2: forward greeting to client (plaintext) ──
    try:
        client_sock.sendall(greeting)
    except OSError:
        close_both(client_sock, raw_server)
        return

    # ── Step 3: read client's first response ──
    client_resp = read_packet(client_sock)
    if client_resp is None:
        close_both(client_sock, raw_server)
        return
    log.debug(
        "CLIENT RESP | %s | seq=%d len=%d wants_ssl=%s",
        addr,
        client_resp[3],
        len(client_resp),
        client_wants_ssl(client_resp),
    )

    # ── Step 4: handle SSL upgrade if client wants it ──
    if client_wants_ssl(client_resp):
        # Forward the SSL request to MySQL so it also upgrades
        try:
            raw_server.sendall(client_resp)
        except OSError:
            close_both(client_sock, raw_server)
            return

        # Upgrade proxy↔MySQL to SSL
        try:
            server_ssl_ctx = make_client_ssl_ctx()
            server_sock = server_ssl_ctx.wrap_socket(
                raw_server, server_hostname=MYSQL_HOST
            )
        except ssl.SSLError as exc:
            log.error("SSL upgrade to MySQL failed: %s | %s", exc, addr)
            close_both(client_sock, raw_server)
            return

        # Upgrade proxy↔client to SSL
        try:
            client_ssl_ctx = make_server_ssl_ctx()
            client_conn = client_ssl_ctx.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError as exc:
            log.error("SSL upgrade to client failed: %s | %s", exc, addr)
            close_both(client_sock, server_sock)
            return

        log.debug("SSL UPGRADE COMPLETE | %s", addr)
    else:
        # No SSL — both stay as plain sockets
        server_sock = raw_server
        client_conn = client_sock
        # Forward the non-SSL client response directly to MySQL
        try:
            server_sock.sendall(client_resp)
        except OSError:
            close_both(client_conn, server_sock)
            return

    # ── Step 5: finish auth phase, then enter query phase ──
    # From here both sides are either plain or SSL — read_packet works either way.
    auth_done = threading.Event()
    client_spoke = threading.Event()

    def server_to_client():
        while True:
            pkt = read_packet(server_sock)
            if pkt is None:
                break
            first = pkt[4] if len(pkt) > 4 else None
            log.debug(
                "S->C | %s | seq=%d first=0x%02x len=%d",
                addr,
                pkt[3],
                first or 0,
                len(pkt),
            )

            # Auth OK: server sends 0x00 after client has spoken at least once
            if not auth_done.is_set() and client_spoke.is_set() and first == 0x00:
                auth_done.set()
                log.debug("AUTH COMPLETE | %s", addr)

            try:
                client_conn.sendall(pkt)
            except OSError:
                break

        auth_done.set()
        close_both(client_conn, server_sock)

    def client_to_server():
        client_spoke.set()  # client already spoke (sent SSL request / first response)

        while True:
            pkt = read_packet(client_conn)
            if pkt is None:
                break

            seq = pkt[3]
            cmd = pkt[4] if len(pkt) > 4 else 0

            if not auth_done.is_set():
                # Auth phase — forward everything, no inspection
                log.debug(
                    "C->S [auth] | %s | seq=%d cmd=0x%02x len=%d",
                    addr,
                    seq,
                    cmd,
                    len(pkt),
                )
                try:
                    server_sock.sendall(pkt)
                except OSError:
                    break
                continue

            # Query phase — inspect COM_QUERY packets
            log.debug(
                "C->S [query] | %s | seq=%d cmd=0x%02x len=%d", addr, seq, cmd, len(pkt)
            )

            if seq == 0x00 and cmd == 0x03:
                try:
                    sql = pkt[5:].decode("utf-8", errors="replace")
                    # Strip any leading non-printable bytes (can appear with some clients)
                    sql = sql.lstrip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09").strip()
                except Exception:
                    sql = ""

                blocked_by = is_blocked(sql)
                if blocked_by:
                    log.warning("BLOCKED | %s | %s | %.120s", addr, blocked_by, sql)
                    try:
                        client_conn.sendall(
                            make_error_packet(
                                f"[SQL JESUS] Thou shalt not. Blocked: {blocked_by}"
                            )
                        )
                    except OSError:
                        break
                    continue
                else:
                    log.info("ALLOWED | %s | %.120s", addr, sql)

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
    log.info("CLOSE    | %s", addr)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    ensure_ssl_cert()

    log.info("=" * 60)
    log.info("MySQL Proxy starting (intercept mode + SSL termination)")
    log.info("  Proxy on  %s:%d  <- students connect here", PROXY_HOST, PROXY_PORT)
    log.info("  MySQL on  %s:%d  <- hidden, localhost only", MYSQL_HOST, MYSQL_PORT)
    log.info("  SSL cert: %s", os.path.abspath(PROXY_CERT))
    log.info("  Log file: %s", os.path.abspath(LOG_FILE))
    log.info("=" * 60)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(MAX_THREADS)

    active = 0
    try:
        while True:
            client_sock, client_addr = server.accept()
            if active >= MAX_THREADS:
                log.warning("Max connections reached, rejecting %s", client_addr)
                client_sock.close()
                continue
            active += 1

            def run(cs=client_sock, ca=client_addr):
                nonlocal active
                handle_client(cs, ca)
                active -= 1

            threading.Thread(target=run, daemon=True).start()

    except KeyboardInterrupt:
        log.info("Proxy stopped by user.")
    finally:
        server.close()


if __name__ == "__main__":
    main()

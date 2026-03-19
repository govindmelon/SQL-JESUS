# ✝ SQL Jesus

> *"He built, while others erased. A silent guardian. SQL JESUS WILL DIE FOR YOUR SINS."*

A MySQL proxy with a desktop dashboard that sits silently between students and your database, intercepting and blocking destructive SQL queries before they ever reach MySQL. Students connect normally, they never know it's there.

---

## The Problem

CS lab. Root access for everyone. One reckless `DROP DATABASE` and the whole class loses their work. SQL Jesus blocks those hands.

---

## How It Works

```
Student MySQL client
        |
        | :3306  (standard MySQL port — students connect here as always)
        v
  [ SQL Jesus Proxy ]  <-- inspects every query
        |
        | :3307  (MySQL moved here, localhost only)
        v
   Real MySQL server
```

The proxy occupies port 3306 so students connect with the exact same command they always use. MySQL is moved to 3307 and bound to `127.0.0.1` — completely unreachable from the network. There is no bypass path.

SSL is handled transparently via termination — the proxy generates its own cert on first run, handles the SSL handshake with the client, and opens a separate SSL connection to MySQL. Students' connections stay encrypted end-to-end.

---

## Setup

### 1. Move MySQL to port 3307

Edit `C:\ProgramData\MySQL\MySQL Server 8.0\my.ini` (adjust version number as needed):

```ini
[mysqld]
port         = 3307
bind-address = 127.0.0.1
```

Restart MySQL:

```bash
net stop MySQL80
net start MySQL80
```

### 2. Install the one dependency

```bash
pip install cryptography
```

This lets SQL Jesus generate its own SSL cert automatically. No OpenSSL installation needed.

### 3. Run as Administrator

```bash
python jesus.py
```

Right-click Command Prompt and choose **Run as Administrator** — binding to port 3306 requires it on Windows.

That's it. The dashboard opens, hit **Start Proxy**, and SQL Jesus is live.

---

## Dashboard

The dashboard shows everything in real time:

- **Stat cards** — total queries, allowed, blocked (in red), active connections
- **Live feed** — every query flowing through the proxy, colour-coded
- **Blocked attempts table** — full log of every blocked query with timestamp, student IP, the SQL they tried, and which rule caught it
- **Repeat offenders** — student IPs ranked by block count, so you can identify who keeps trying

---

## What Gets Blocked

By default, SQL Jesus blocks:

| Category | Commands |
|---|---|
| Schema destruction | `DROP DATABASE`, `DROP TABLE`, `DROP VIEW`, `TRUNCATE` |
| Structure changes | `ALTER TABLE`, `RENAME TABLE` |
| User management | `CREATE USER`, `DROP USER`, `ALTER USER`, `GRANT`, `REVOKE`, `FLUSH PRIVILEGES` |
| Server commands | `SHUTDOWN`, `RESET MASTER`, `RESET SLAVE`, `PURGE` |
| File access | `LOAD DATA INFILE`, `INTO OUTFILE`, `INTO DUMPFILE` |

To customise, edit the `BLOCKED_PATTERNS` list near the top of `jesus.py`. Each entry is a Python regex. Comment out `ALTER TABLE` if your exercises need it.

---

## Bypassing the Proxy (for you)

When you need to run a `DROP` yourself, connect directly to MySQL on port 3307 — this bypasses the proxy entirely:

```bash
mysql -h 127.0.0.1 -P 3307 -u root -p
```

Students have no way to reach port 3307 since it's bound to `127.0.0.1` only.

---

## Files

| File | Purpose |
|---|---|
| `jesus.py` | Everything — proxy engine + dashboard, single file |
| `proxy.log` | Full log of all connections, allowed and blocked queries |
| `proxy-cert.pem` | Auto-generated SSL cert (created on first run) |
| `proxy-key.pem` | Auto-generated SSL key (created on first run) |

---

## Requirements

- Python 3.10+
- `pip install cryptography`
- Windows: run as Administrator
- MySQL 8.x moved to port 3307 (see setup above)

---

*Made with spite and rage by Govind (mln) Menon. Time wasted: 9 hours, 32 minutes, 11.768 seconds. Special thanks ChatGPT & Jishnu*

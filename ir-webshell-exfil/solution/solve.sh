#!/bin/bash
# Reference investigation: derives every answer from /app/evidence.
set -euo pipefail
python3 - <<'PY'
import base64, datetime as dt, io, json, re, tarfile, urllib.parse

E = "/app/evidence"
LINE = re.compile(r'^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) \d+ "[^"]*" "[^"]*" "([^"]*)"$')
rows = []
for l in open(f"{E}/logs/access.log"):
    m = LINE.match(l.strip())
    if m:
        addr, t, meth, path, st, xff = m.groups()
        rows.append((dt.datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z"), addr if xff == "-" else xff, meth, path, int(st)))

# The webshell the app stored: an upload whose content sniffed as PHP.
app = open(f"{E}/logs/app.log").read()
shell = re.search(r"detected=text/x-php path=(\S+)", app).group(1)
uploader = re.search(rf"stored={re.escape(shell)} user=(\S+)", app).group(1)
url = shell.split("/var/www/app", 1)[1]

# Successful webshell requests give the attacker's real (forwarded) address and their commands.
hits = [r for r in rows if r[3].startswith(url + "?") and r[4] == 200]
attacker = hits[0][1]
first = hits[0][0].astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
cmds = [base64.b64decode(urllib.parse.parse_qs(urllib.parse.urlsplit(r[3]).query)["c"][0]).decode() for r in hits]

# Initial access: the attacker's earliest successful request (SQL injection in search).
first_req = min(r for r in rows if r[1] == attacker and r[4] < 400)
endpoint = urllib.parse.urlsplit(first_req[3]).path

domain = next(re.search(r"https://([^/\s]+)/", c).group(1) for c in cmds if c.startswith("curl"))
persist = next(re.search(r">\s*(\S+)$", c).group(1) for c in cmds if "cron" in c)

# Decrypt the staged archive with the key from the XOR command, and list its members.
xc = next(c for c in cmds if ".x.py" in c).split()
key, out = xc[3].encode(), xc[5]
enc = open(f"{E}/fs{out}", "rb").read()
raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))
files = sorted(m.name for m in tarfile.open(fileobj=io.BytesIO(raw)).getmembers() if m.isfile())

report = {
    "attacker_ip": attacker,
    "initial_access_endpoint": endpoint,
    "compromised_account": uploader,
    "webshell_path": shell,
    "first_webshell_command_utc": first,
    "exfil_domain": domain,
    "exfiltrated_files": files,
    "persistence_file": persist,
}
json.dump(report, open("/app/report.json", "w"), indent=2)
print(json.dumps(report, indent=2))
PY

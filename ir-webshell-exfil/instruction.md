# Incident response: shop.example web server

On 2026-10-14 the payments team noticed card-processor API calls they did not make. The web
server `shop-web-01` was isolated and imaged. You are the responder. Everything collected is in
`/app/evidence/` (read-only):

- `logs/access.log`: nginx access log. The server sits behind an internal load balancer, so
  read the log format notes in `logs/README` before trusting the client address column.
- `logs/app.log`: the application's own log (logins, uploads, errors).
- `logs/db_query.log`: the database's slow and failed query log.
- `fs/`: a partial snapshot of the server's filesystem, taken after isolation.

The log contains a lot of normal customer traffic and at least one noisy scanner that did not
get in. Separate what actually happened from the noise. Some of the attacker's actions are
encoded or encrypted, and you will need to decode them to answer every question.

## What to deliver

Write `/app/report.json` containing one JSON object with exactly these keys:

| key | value |
| --- | --- |
| `attacker_ip` | the real public IPv4 address of the intruder (string) |
| `initial_access_endpoint` | the URL path (no query string) of the endpoint that was first exploited, e.g. `/foo/bar` |
| `compromised_account` | the application username the attacker logged in as |
| `webshell_path` | the absolute path on the server of the webshell the attacker planted |
| `first_webshell_command_utc` | UTC time of the attacker's first request to the webshell, `YYYY-MM-DDTHH:MM:SSZ` |
| `exfil_domain` | the domain the stolen data was sent to |
| `exfiltrated_files` | a list of every file inside the stolen archive, as paths relative to `/` without a leading slash (for example `var/log/x.log`), sorted |
| `persistence_file` | the absolute path of the file the attacker created to keep access |

Each key is scored on its own as exactly right or wrong; your score is the fraction of keys that are
right. Strings are compared exactly after trimming surrounding whitespace. Do not guess between
several values: a list or string holding extra candidates counts as wrong.

There is no network access to the attacker's infrastructure, and you do not need any. Everything you
need is in the evidence.

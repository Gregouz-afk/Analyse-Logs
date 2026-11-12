"""Règles de détection : brute-force, password spraying, scans web, attaques web,
connexions anormales et activités Windows suspectes."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import unquote

from .parsers import Event

SEVERITIES = ["critique", "haute", "moyenne", "basse"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEFAULT_CONFIG = {
    "bruteforce_threshold": 5,        # échecs ...
    "bruteforce_window_min": 10,      # ... dans cette fenêtre (minutes)
    "distributed_min_ips": 5,         # un même compte attaqué depuis N IP
    "distributed_min_failures": 20,
    "spray_distinct_users": 5,        # une IP qui essaie N comptes différents
    "scan_404_threshold": 20,         # N réponses 404 ...
    "scan_window_min": 5,             # ... dans cette fenêtre
    "web_login_threshold": 10,        # POST sur une page de login / 401
    "web_login_window_min": 5,
    "business_hours": [7, 20],        # connexions hors de [7h, 20h[ signalées
    "new_ip_min_history": 3,          # connexions déjà vues avant de signaler une nouvelle IP
    "whitelist_ips": ["127.0.0.1", "::1"],
}

SCANNER_UA = re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|"
                        r"feroxbuster|ffuf|wfuzz|acunetix|nessus|openvas|hydra|jaeles|whatweb)", re.I)
SENSITIVE_PATH = re.compile(r"(/\.env|/\.git/|/\.svn/|/\.ht(access|passwd)|wp-config\.php|/phpmyadmin|"
                            r"/pma/|/adminer|/server-status|/\.aws/|/\.ssh/|/actuator|/etc/passwd|"
                            r"\.(sql|bak|old|swp)(\.gz)?$|/backup)", re.I)
LOGIN_PATH = re.compile(r"(login|signin|logon|wp-login\.php|xmlrpc\.php|/auth\b|/session)", re.I)
WEB_ATTACKS = {
    "Injection SQL": re.compile(r"(union\s+(all\s+)?select|'\s*or\s+'?\d+'?\s*=\s*'?\d+|information_schema|"
                                r"sleep\(\s*\d+\s*\)|benchmark\(|\bwaitfor\s+delay)", re.I),
    "XSS": re.compile(r"(<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg[^>]*on\w+)", re.I),
    "Traversée de répertoires": re.compile(r"(\.\./|\.\.\\){2,}"),
    "Injection de commande": re.compile(r"(;\s*(cat|wget|curl|id|uname|whoami)\b|\|\s*(id|whoami)\b|\$\(|`)", re.I),
    "Log4Shell (JNDI)": re.compile(r"\$\{\s*jndi:", re.I),
}


@dataclass
class Alert:
    severity: str
    category: str
    title: str
    source: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    ip: str | None = None
    user: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "category": self.category, "title": self.title,
            "source": self.source, "ip": self.ip, "user": self.user, "count": self.count,
            "first_seen": self.first_seen.isoformat(sep=" ", timespec="seconds"),
            "last_seen": self.last_seen.isoformat(sep=" ", timespec="seconds"),
            "evidence": self.evidence,
        }


def max_in_window(events: list[Event], window: timedelta) -> tuple[int, list[Event]]:
    """Plus grand nombre d'événements tenant dans une fenêtre glissante (events triés)."""
    best, bi, bj, i = 0, 0, -1, 0
    for j, e in enumerate(events):
        while e.timestamp - events[i].timestamp > window:
            i += 1
        if j - i + 1 > best:
            best, bi, bj = j - i + 1, i, j
    return best, events[bi:bj + 1]


def is_public(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except (ValueError, TypeError):
        return False


def _top(counter: Counter, n: int = 3) -> str:
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n))


class Detector:
    def __init__(self, events: list[Event], config: dict | None = None):
        self.cfg = {**DEFAULT_CONFIG, **(config or {})}
        wl = set(self.cfg["whitelist_ips"])
        self.events = sorted((e for e in events if e.ip not in wl), key=lambda e: e.timestamp)
        self.alerts: list[Alert] = []

    # ------------------------------------------------------------------ helpers
    def add(self, severity, category, title, source, evs, ip=None, user=None, count=None):
        self.alerts.append(Alert(severity, category, title, source,
                                 evs[0].timestamp, evs[-1].timestamp,
                                 count if count is not None else len(evs), ip, user,
                                 [e.raw for e in evs[:6]] + (["…"] if len(evs) > 6 else [])))

    def by(self, pred, key):
        groups = defaultdict(list)
        for e in self.events:
            if pred(e):
                groups[key(e)].append(e)
        return groups

    def run(self) -> list[Alert]:
        for rule in (self.bruteforce, self.distributed_bruteforce, self.password_spraying,
                     self.web_scans, self.web_attacks, self.web_login_bruteforce,
                     self.anomalous_logins, self.windows_suspicious):
            rule()
        self.alerts.sort(key=lambda a: (SEV_RANK[a.severity], a.first_seen))
        return self.alerts

    # ------------------------------------------------------------------ authentification
    def bruteforce(self):
        thr, wmin = self.cfg["bruteforce_threshold"], self.cfg["bruteforce_window_min"]
        fails = self.by(lambda e: e.action == "login_failed" and e.ip, lambda e: (e.source, e.ip))
        succ = self.by(lambda e: e.action == "login_success" and e.ip, lambda e: (e.source, e.ip))
        for (src, ip), evs in fails.items():
            peak, _ = max_in_window(evs, timedelta(minutes=wmin))
            if peak < thr:
                continue
            users = Counter(e.user for e in evs)
            if len(users) < self.cfg["spray_distinct_users"]:   # sinon c'est du spraying (règle dédiée)
                self.add("haute" if peak >= thr * 4 else "moyenne", "Brute-force",
                         f"{len(evs)} échecs de connexion depuis {ip} (pic : {peak} en {wmin} min) "
                         f"— comptes visés : {_top(users)}", src, evs, ip=ip, user=users.most_common(1)[0][0])
            # Succès depuis la même IP pendant ou juste après la rafale d'échecs
            limit = evs[-1].timestamp + timedelta(minutes=wmin)
            after = [s for s in succ.get((src, ip), []) if evs[0].timestamp <= s.timestamp <= limit]
            if after:
                s = after[0]
                n_before = sum(e.timestamp <= s.timestamp for e in evs)
                ev = [e for e in evs if e.timestamp <= s.timestamp][-5:] + [s]
                if is_public(ip) or n_before >= thr * 4:
                    self.add("critique", "Brute-force réussi",
                             f"Connexion RÉUSSIE de « {s.user} » depuis {ip} après {n_before} échecs",
                             src, ev, ip=ip, user=s.user, count=n_before + 1)
                else:
                    self.add("moyenne", "Brute-force réussi",
                             f"Connexion de « {s.user} » depuis {ip} (réseau interne) après {n_before} échecs "
                             "— probable erreur de mot de passe, à vérifier", src, ev, ip=ip, user=s.user,
                             count=n_before + 1)

    def distributed_bruteforce(self):
        fails = self.by(lambda e: e.action == "login_failed" and e.user, lambda e: (e.source, e.user))
        for (src, user), evs in fails.items():
            ips = Counter(e.ip for e in evs if e.ip)
            if len(ips) >= self.cfg["distributed_min_ips"] and len(evs) >= self.cfg["distributed_min_failures"]:
                self.add("haute", "Brute-force distribué",
                         f"Compte « {user} » attaqué depuis {len(ips)} IP différentes ({len(evs)} échecs)",
                         src, evs, user=user)

    def password_spraying(self):
        fails = self.by(lambda e: e.action == "login_failed" and e.ip, lambda e: (e.source, e.ip))
        for (src, ip), evs in fails.items():
            users = Counter(e.user for e in evs)
            if len(users) >= self.cfg["spray_distinct_users"]:
                self.add("haute", "Password spraying",
                         f"{ip} a essayé {len(users)} comptes différents : {', '.join(list(users)[:8])}"
                         f"{'…' if len(users) > 8 else ''}", src, evs, ip=ip)

    # ------------------------------------------------------------------ web
    def web_scans(self):
        http = self.by(lambda e: e.action == "http", lambda e: e.ip)
        thr, wmin = self.cfg["scan_404_threshold"], self.cfg["scan_window_min"]
        for ip, evs in http.items():
            nf = [e for e in evs if e.status == 404]
            peak, _ = max_in_window(nf, timedelta(minutes=wmin)) if nf else (0, [])
            if peak >= thr:
                self.add("haute" if peak >= thr * 5 else "moyenne", "Scan web",
                         f"Énumération : {len(nf)} réponses 404 pour {ip} "
                         f"({len({e.path for e in nf})} chemins distincts, pic {peak} en {wmin} min)",
                         "apache", nf, ip=ip)
            tools = defaultdict(list)
            for e in evs:
                if e.user_agent and (m := SCANNER_UA.search(e.user_agent)):
                    tools[m.group(1).lower()].append(e)
            for tool, tev in tools.items():
                self.add("haute", "Scan web", f"Outil de scan détecté ({tool}) depuis {ip} — {len(tev)} requêtes",
                         "apache", tev, ip=ip)
            sens = [e for e in evs if e.path and SENSITIVE_PATH.search(unquote(e.path))]
            spaths = list(dict.fromkeys((e.path or "").split("?")[0] for e in sens))
            if len(spaths) >= 3:
                self.add("moyenne", "Scan web", f"Recherche de fichiers sensibles depuis {ip} "
                         f"({len(spaths)} chemins, ex. {', '.join(spaths[:4])})", "apache", sens, ip=ip)
            exposed = {}
            for e in sens:
                if e.status == 200:
                    exposed.setdefault(e.path, e)
            for e in exposed.values():
                self.add("critique", "Fichier sensible exposé",
                         f"{e.path} renvoyé avec succès (200) à {ip}", "apache", [e], ip=ip)

    def web_attacks(self):
        hits = defaultdict(list)
        for e in self.events:
            if e.action != "http":
                continue
            target = unquote(unquote(e.path or "")) + " " + (e.user_agent or "")
            for name, rx in WEB_ATTACKS.items():
                if rx.search(target):
                    hits[(e.ip, name)].append(e)
        for (ip, name), evs in hits.items():
            ok = sum(1 for e in evs if e.status and e.status < 400)
            self.add("haute", "Attaque web", f"{name} : {len(evs)} requête(s) depuis {ip}"
                     + (f" dont {ok} avec réponse 2xx/3xx" if ok else ""), "apache", evs, ip=ip)

    def web_login_bruteforce(self):
        thr, wmin = self.cfg["web_login_threshold"], self.cfg["web_login_window_min"]
        tries = self.by(lambda e: e.action == "http" and (e.status == 401 or
                        (e.method == "POST" and e.path and LOGIN_PATH.search(e.path))), lambda e: e.ip)
        for ip, evs in tries.items():
            peak, _ = max_in_window(evs, timedelta(minutes=wmin))
            if peak >= thr:
                paths = Counter((e.path or "").split("?")[0] for e in evs)
                self.add("haute", "Brute-force web", f"{len(evs)} tentatives de login web depuis {ip} "
                         f"sur {_top(paths, 2)}", "apache", evs, ip=ip)

    # ------------------------------------------------------------------ connexions anormales
    def anomalous_logins(self):
        start, end = self.cfg["business_hours"]
        seen, history = defaultdict(set), Counter()
        off_hours, root, rdp = defaultdict(list), defaultdict(list), defaultdict(list)
        for e in self.events:
            if e.action != "login_success":
                continue
            key = (e.source, e.user)
            if not start <= e.timestamp.hour < end:
                off_hours[(e.source, e.user, e.ip)].append(e)
            if e.ip and history[key] >= self.cfg["new_ip_min_history"] and e.ip not in seen[key]:
                self.add("haute" if is_public(e.ip) else "moyenne", "Connexion anormale",
                         f"Nouvelle IP pour « {e.user} » : {e.ip} (jamais vue sur {history[key]} connexions)",
                         e.source, [e], ip=e.ip, user=e.user)
            if e.ip:
                seen[key].add(e.ip)
            history[key] += 1
            if e.source == "auth" and e.user == "root":
                root[e.ip].append(e)
            if e.source == "windows" and e.detail == "LogonType=10" and is_public(e.ip):
                rdp[(e.ip, e.user)].append(e)
        for (src, user, ip), evs in off_hours.items():
            when = ", ".join(sorted({e.timestamp.strftime("%d/%m %H:%M") for e in evs})[:3])
            self.add("moyenne" if is_public(ip) else "basse", "Connexion anormale",
                     f"Connexion hors horaires ({start}h-{end}h) de « {user} » depuis {ip or 'local'} : {when}",
                     src, evs, ip=ip, user=user)
        for ip, evs in root.items():
            self.add("moyenne", "Connexion anormale", f"Connexion SSH directe en root depuis {ip}",
                     "auth", evs, ip=ip, user="root")
        for (ip, user), evs in rdp.items():
            self.add("haute", "Connexion anormale", f"Session RDP de « {user} » depuis l'IP publique {ip}",
                     "windows", evs, ip=ip, user=user)

    # ------------------------------------------------------------------ Windows
    def windows_suspicious(self):
        for e in self.events:
            if e.action == "account_locked":
                self.add("moyenne", "Activité Windows", f"Compte verrouillé : {e.user} ({e.host})", "windows", [e], user=e.user)
            elif e.action == "account_created":
                self.add("moyenne", "Activité Windows", f"Compte créé : {e.user} ({e.detail})", "windows", [e], user=e.user)
            elif e.action == "group_change":
                admin = re.search(r"admin", e.detail or "", re.I)
                self.add("haute" if admin else "basse", "Activité Windows",
                         f"{e.user} {e.detail}", "windows", [e], user=e.user)
            elif e.action == "log_cleared":
                self.add("critique", "Activité Windows", f"Journal de sécurité effacé par {e.user} sur {e.host}",
                         "windows", [e], user=e.user)


def detect(events: list[Event], config: dict | None = None) -> list[Alert]:
    return Detector(events, config).run()

"""Parsers : transforment des fichiers de logs en une liste d'objets Event normalisés.

Formats pris en charge :
  - auth.log / secure (sshd)   : syslog classique ("Nov 12 10:01:02") ou ISO 8601
  - Apache / Nginx             : format "combined" ou "common"
  - Événements Windows         : export XML (wevtutil / Get-WinEvent .ToXml()) ou .evtx
                                  (le .evtx nécessite `pip install python-evtx`)
"""
from __future__ import annotations

import gzip
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class Event:
    timestamp: datetime
    source: str            # "auth" | "apache" | "windows"
    action: str            # login_failed | login_success | invalid_user | http | account_locked
                           # account_created | group_change | log_cleared
    ip: str | None = None
    user: str | None = None
    host: str | None = None
    status: int | None = None
    method: str | None = None
    path: str | None = None
    user_agent: str | None = None
    detail: str | None = None
    raw: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat(sep=" ", timespec="seconds")
        return d


# --------------------------------------------------------------------------- utilitaires

def to_local_naive(dt: datetime) -> datetime:
    """Ramène toutes les dates en heure locale sans fuseau pour pouvoir les comparer."""
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def parse_iso(s: str) -> datetime:
    s = s.strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)          # Windows met 7 décimales
    return to_local_naive(datetime.fromisoformat(s))


def read_text(path: Path) -> str:
    data = gzip.open(path, "rb").read() if path.suffix == ".gz" else path.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):     # redirection PowerShell 5 = UTF-16
        return data.decode("utf-16")
    return data.decode("utf-8-sig", errors="replace")


# --------------------------------------------------------------------------- auth.log

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
SSH_FAILED = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+)")
SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
SSH_INVALID = re.compile(r"Invalid user (?P<user>.*?) from (?P<ip>\S+)")


def _syslog_time(s: str, now: datetime) -> datetime:
    if s[0].isdigit():
        return parse_iso(s)
    dt = datetime.strptime(f"{now.year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")
    if dt > now + timedelta(days=2):               # pas d'année dans syslog : log de l'an dernier
        dt = dt.replace(year=now.year - 1)
    return dt


def parse_auth(text: str) -> list[Event]:
    now = datetime.now()
    events = []
    for line in text.splitlines():
        m = SYSLOG_RE.match(line)
        if not m:
            continue
        msg = m["msg"]
        if (f := SSH_FAILED.search(msg)):
            action, user, ip = "login_failed", f["user"], f["ip"]
            detail = f["method"] + (" (utilisateur inexistant)" if f["invalid"] else "")
        elif (f := SSH_ACCEPTED.search(msg)):
            action, user, ip, detail = "login_success", f["user"], f["ip"], f["method"]
        elif (f := SSH_INVALID.search(msg)):
            action, user, ip, detail = "invalid_user", f["user"], f["ip"], None
        else:
            continue
        try:
            ts = _syslog_time(m["ts"], now)
        except ValueError:
            continue
        events.append(Event(ts, "auth", action, ip=ip, user=user or None, host=m["host"],
                            detail=detail, raw=line))
    return events


# --------------------------------------------------------------------------- Apache / Nginx

APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)


def parse_apache(text: str) -> list[Event]:
    events = []
    for line in text.splitlines():
        m = APACHE_RE.match(line)
        if not m:
            continue
        try:
            ts = to_local_naive(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"))
        except ValueError:
            continue
        parts = m["req"].split()
        method, path = (parts[0], parts[1]) if len(parts) >= 2 else (None, m["req"])
        events.append(Event(ts, "apache", "http", ip=m["ip"],
                            user=None if m["user"] == "-" else m["user"],
                            status=int(m["status"]), method=method, path=path,
                            user_agent=m["ua"], detail=m["size"], raw=line))
    return events


# --------------------------------------------------------------------------- Windows

IGNORED_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-", ""}
INTERACTIVE_LOGON_TYPES = {"2", "3", "7", "8", "10", "11"}   # on ignore services / batch


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _windows_event(ev: ET.Element) -> Event | None:
    system = next((c for c in ev if _local(c.tag) == "System"), None)
    if system is None:
        return None
    sysd = {_local(c.tag): c for c in system}
    try:
        eid = int(sysd["EventID"].text)
        ts = parse_iso(sysd["TimeCreated"].attrib["SystemTime"])
    except (KeyError, ValueError, TypeError):
        return None
    host = sysd["Computer"].text if "Computer" in sysd else None

    data: dict[str, str] = {}
    for block in ev:
        if _local(block.tag) not in ("EventData", "UserData"):
            continue
        for el in block.iter():
            if _local(el.tag) == "Data" and "Name" in el.attrib:
                data[el.attrib["Name"]] = (el.text or "").strip()
            elif len(el) == 0 and el.text:
                data[_local(el.tag)] = el.text.strip()

    user = data.get("TargetUserName")
    ip = data.get("IpAddress")
    ip = None if ip in (None, "-", "", "::1", "127.0.0.1") else ip.removeprefix("::ffff:")
    lt = data.get("LogonType", "")
    raw = f"EventID={eid} " + " ".join(f"{k}={v}" for k, v in data.items()
                                       if k in ("TargetUserName", "TargetDomainName", "IpAddress",
                                                "LogonType", "WorkstationName", "SubjectUserName",
                                                "MemberName", "Status", "SubStatus"))

    if eid == 4625:
        return Event(ts, "windows", "login_failed", ip=ip, user=user, host=host,
                     detail=f"LogonType={lt}", raw=raw)
    if eid == 4624:
        if (user or "").upper() in IGNORED_ACCOUNTS or (user or "").endswith("$") \
                or lt not in INTERACTIVE_LOGON_TYPES or (user or "").upper().startswith(("DWM-", "UMFD-")):
            return None
        return Event(ts, "windows", "login_success", ip=ip, user=user, host=host,
                     detail=f"LogonType={lt}", raw=raw)
    if eid == 4740:
        return Event(ts, "windows", "account_locked", user=user, host=host, raw=raw)
    if eid == 4720:
        return Event(ts, "windows", "account_created", user=user, host=host,
                     detail=f"créé par {data.get('SubjectUserName', '?')}", raw=raw)
    if eid in (4728, 4732, 4756):
        member = data.get("MemberName") or data.get("MemberSid")
        if member and (cn := re.match(r"CN=([^,]+)", member)):
            member = cn.group(1)                      # "CN=jdoe,CN=Users,DC=..." -> "jdoe"
        return Event(ts, "windows", "group_change", user=member, host=host,
                     detail=f"ajouté au groupe {user} par {data.get('SubjectUserName', '?')}", raw=raw)
    if eid == 1102:
        return Event(ts, "windows", "log_cleared", user=data.get("SubjectUserName"), host=host,
                     detail="journal Sécurité effacé", raw=raw)
    return None


def parse_windows_xml(text: str) -> list[Event]:
    text = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    if not text.startswith("<Events"):
        text = f"<Events>{text}</Events>"         # wevtutil n'ajoute pas d'élément racine
    root = ET.fromstring(text)
    return [e for ev in root.iter() if _local(ev.tag) == "Event" and (e := _windows_event(ev))]


def parse_evtx(path: Path) -> list[Event]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError:
        raise SystemExit("Lecture .evtx : installez python-evtx (pip install python-evtx) "
                         "ou exportez en XML avec wevtutil.")
    with Evtx(str(path)) as log:
        xml = "".join(rec.xml() for rec in log.records())
    return parse_windows_xml(xml)


# --------------------------------------------------------------------------- détection du type

PARSERS = {"auth": parse_auth, "apache": parse_apache, "windows": parse_windows_xml}


def detect_kind(path: Path, text: str) -> str | None:
    if path.suffix.lower() in (".xml", ".evtx"):
        return "windows"
    lines = [l for l in text.splitlines()[:50] if l.strip()]
    if any("<Event" in l for l in lines[:5]):
        return "windows"
    apache = sum(bool(APACHE_RE.match(l)) for l in lines)
    syslog = sum(bool(SYSLOG_RE.match(l)) for l in lines)
    if max(apache, syslog) == 0:
        return None
    return "apache" if apache >= syslog else "auth"


def load_file(path: Path, kind: str | None = None) -> tuple[str | None, list[Event]]:
    if path.suffix.lower() == ".evtx":
        return "windows", parse_evtx(path)
    text = read_text(path)
    kind = kind or detect_kind(path, text)
    if kind is None:
        return None, []
    return kind, PARSERS[kind](text)

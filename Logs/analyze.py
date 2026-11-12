#!/usr/bin/env python3
"""Point d'entrée : analyse des fichiers de logs et génère le tableau de bord.

Exemples :
  python analyze.py samples/
  python analyze.py /var/log/auth.log /var/log/apache2/access.log -o rapport.html --open
  python analyze.py security.xml --config config.json --json alertes.json --csv alertes.csv
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import sys
import webbrowser
from collections import Counter
from pathlib import Path

from loganalyzer.dashboard import build_data, write_dashboard
from loganalyzer.detectors import SEVERITIES, detect
from loganalyzer.parsers import PARSERS, load_file


def expand(inputs: list[str]) -> list[Path]:
    paths = []
    for item in inputs:
        matches = glob.glob(item) or [item]          # globs aussi sous Windows
        for m in map(Path, matches):
            if m.is_dir():
                paths += sorted(p for p in m.iterdir() if p.is_file())
            elif m.exists():
                paths.append(m)
            else:
                print(f"[!] Introuvable : {m}", file=sys.stderr)
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse de logs : brute-force, scans, connexions anormales.")
    ap.add_argument("inputs", nargs="+", help="fichiers, dossiers ou motifs (auth.log, access.log, .xml, .evtx)")
    ap.add_argument("-t", "--type", choices=list(PARSERS), help="forcer le type de log (sinon détection auto)")
    ap.add_argument("-o", "--output", default="rapport.html", help="tableau de bord HTML (défaut : rapport.html)")
    ap.add_argument("--json", help="exporter les alertes en JSON")
    ap.add_argument("--csv", help="exporter les alertes en CSV")
    ap.add_argument("-c", "--config", help="fichier JSON pour ajuster les seuils")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="basse", help="filtrer les alertes")
    ap.add_argument("--open", action="store_true", help="ouvrir le tableau de bord dans le navigateur")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    config = json.loads(Path(args.config).read_text(encoding="utf-8")) if args.config else None

    events, files = [], []
    for path in expand(args.inputs):
        try:
            kind, evs = load_file(path, args.type)
        except Exception as exc:                     # un fichier illisible ne bloque pas les autres
            print(f"[!] {path.name} : erreur de lecture ({exc})", file=sys.stderr)
            continue
        if kind is None:
            print(f"[-] {path.name} : format non reconnu, ignoré")
            continue
        print(f"[+] {path.name:<28} {kind:<8} {len(evs):>7} événements")
        files.append({"name": path.name, "kind": kind, "events": len(evs)})
        events += evs

    if not events:
        print("Aucun événement exploitable.")
        return 1

    alerts = detect(events, config)
    limit = SEVERITIES.index(args.min_severity)
    alerts = [a for a in alerts if SEVERITIES.index(a.severity) <= limit]

    counts = Counter(a.severity for a in alerts)
    print(f"\n{len(alerts)} alertes : " + " | ".join(f"{s} {counts.get(s, 0)}" for s in SEVERITIES))
    for a in alerts[:15]:
        print(f"  [{a.severity.upper():<8}] {a.category:<22} {a.title}")
    if len(alerts) > 15:
        print(f"  … et {len(alerts) - 15} autres (voir le tableau de bord)")

    out = Path(args.output)
    write_dashboard(out, build_data(events, alerts, files))
    print(f"\nTableau de bord : {out.resolve()}")

    if args.json:
        Path(args.json).write_text(json.dumps([a.to_dict() for a in alerts], ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"Export JSON     : {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["severite", "categorie", "description", "source", "ip", "compte", "debut", "fin", "nb"])
            for a in alerts:
                w.writerow([a.severity, a.category, a.title, a.source, a.ip, a.user,
                            a.first_seen, a.last_seen, a.count])
        print(f"Export CSV      : {args.csv}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

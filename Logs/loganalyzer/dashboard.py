"""Génère un tableau de bord HTML autonome (aucune dépendance, fonctionne hors ligne)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from .detectors import SEV_RANK, SEVERITIES, Alert
from .parsers import Event

BUCKETS = [(1, "1 min"), (5, "5 min"), (15, "15 min"), (60, "1 h"), (360, "6 h"), (1440, "1 jour")]


def build_data(events: list[Event], alerts: list[Alert], files: list[dict]) -> dict:
    sev = Counter(a.severity for a in alerts)
    data = {
        "generated": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "files": files,
        "kpi": {
            "events": len(events),
            "alerts": len(alerts),
            **{s: sev.get(s, 0) for s in SEVERITIES},
            "ips": len({e.ip for e in events if e.ip}),
            "failed": sum(e.action == "login_failed" for e in events),
            "success": sum(e.action == "login_success" for e in events),
            "http": sum(e.action == "http" for e in events),
        },
        "alerts": [a.to_dict() for a in alerts],
        "categories": Counter(a.category for a in alerts).most_common(),
    }

    # Chronologie
    if events:
        t0, t1 = min(e.timestamp for e in events), max(e.timestamp for e in events)
        span = max((t1 - t0).total_seconds() / 60, 1)
        minutes, label = next(((m, l) for m, l in BUCKETS if span / m <= 96), BUCKETS[-1])
        start = t0.replace(second=0, microsecond=0)
        start -= timedelta(minutes=(start.hour * 60 + start.minute) % minutes)
        n = int((t1 - start).total_seconds() // (minutes * 60)) + 1
        series = {"Échecs de connexion": [0] * n, "Connexions réussies": [0] * n, "Erreurs HTTP 4xx/5xx": [0] * n}
        for e in events:
            i = int((e.timestamp - start).total_seconds() // (minutes * 60))
            if e.action == "login_failed":
                series["Échecs de connexion"][i] += 1
            elif e.action == "login_success":
                series["Connexions réussies"][i] += 1
            elif e.action == "http" and e.status and e.status >= 400:
                series["Erreurs HTTP 4xx/5xx"][i] += 1
        fmt = "%d/%m %H:%M" if minutes < 1440 else "%d/%m"
        data["timeline"] = {"bucket": label, "series": series,
                            "labels": [(start + timedelta(minutes=minutes * k)).strftime(fmt) for k in range(n)]}
    else:
        data["timeline"] = {"bucket": "", "series": {}, "labels": []}

    # IP les plus suspectes
    per_ip = defaultdict(lambda: {"alerts": 0, "worst": 9, "failed": 0, "errors": 0, "cats": set()})
    for a in alerts:
        if a.ip:
            p = per_ip[a.ip]
            p["alerts"] += 1
            p["worst"] = min(p["worst"], SEV_RANK[a.severity])
            p["cats"].add(a.category)
    for e in events:
        if e.ip in per_ip:
            per_ip[e.ip]["failed"] += e.action == "login_failed"
            per_ip[e.ip]["errors"] += bool(e.action == "http" and e.status and e.status >= 400)
    top = sorted(per_ip.items(), key=lambda kv: (kv[1]["worst"], -kv[1]["alerts"], -kv[1]["failed"] - kv[1]["errors"]))
    data["top_ips"] = [{"ip": ip, "alerts": p["alerts"], "severity": SEVERITIES[p["worst"]],
                        "activity": p["failed"] + p["errors"], "categories": sorted(p["cats"])}
                       for ip, p in top[:12]]
    return data


def write_dashboard(path: Path, data: dict) -> None:
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    path.write_text(TEMPLATE.replace("__DATA__", payload), encoding="utf-8")


TEMPLATE = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Analyse de logs</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --text:#1b1f24; --muted:#5f6b7a; --line:#e3e6ea; --hover:#f0f2f5;
  --crit:#c62828; --high:#e65100; --med:#b7860b; --low:#3d6fb4;
  --s1:#d64545; --s2:#2e9d6a; --s3:#7a5cc7;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#0f1216; --panel:#171b21; --text:#e6e9ee; --muted:#9aa5b4; --line:#2a313b; --hover:#1f252d;
         --crit:#ff6b6b; --high:#ff9b4a; --med:#e8c047; --low:#7aa7ec;
         --s1:#ef6b6b; --s2:#4cc38a; --s3:#a58cf0; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:20px 24px 8px;display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline}
h1{font-size:20px;margin:0}
h2{font-size:14px;margin:0 0 12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.muted{color:var(--muted)}
main{padding:8px 24px 40px;display:grid;gap:16px;grid-template-columns:repeat(12,1fr)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;min-width:0}
.kpis{grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.kpi .v{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--muted);font-size:12px}
.kpi.crit .v{color:var(--crit)} .kpi.high .v{color:var(--high)} .kpi.med .v{color:var(--med)}
.timeline{grid-column:1/-1}
.ips{grid-column:span 7} .cats{grid-column:span 5}
.table{grid-column:1/-1}
@media (max-width:900px){ .ips,.cats{grid-column:1/-1} main,header{padding-left:16px;padding-right:16px} }
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-bottom:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
svg text{fill:var(--muted);font-size:11px}
.bar-row{display:grid;grid-template-columns:minmax(110px,150px) 1fr auto;gap:10px;align-items:center;padding:4px 0}
.bar-row .track{height:8px;background:var(--hover);border-radius:4px;overflow:hidden}
.bar-row .fill{height:100%;border-radius:4px}
.ip{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}
.critique{background:var(--crit)} .haute{background:var(--high)} .moyenne{background:var(--med)} .basse{background:var(--low)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.filters input,.filters select{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:inherit}
.filters input{flex:1;min-width:180px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}
tbody tr.row{cursor:pointer} tbody tr.row:hover{background:var(--hover)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
tr.ev td{background:var(--hover)}
pre{margin:0;white-space:pre-wrap;word-break:break-all;font:12px/1.5 ui-monospace,Consolas,monospace}
.empty{padding:24px;text-align:center;color:var(--muted)}
</style>
</head>
<body>
<header>
  <h1>Analyse de logs de sécurité</h1>
  <span class="muted" id="meta"></span>
</header>
<main>
  <section class="kpis" id="kpis"></section>
  <section class="card timeline"><h2>Chronologie <span id="bucket" class="muted" style="text-transform:none"></span></h2>
    <div class="legend" id="legend"></div><div id="chart"></div></section>
  <section class="card ips"><h2>IP les plus suspectes</h2><div id="ips"></div></section>
  <section class="card cats"><h2>Alertes par catégorie</h2><div id="cats"></div></section>
  <section class="card table"><h2>Alertes</h2>
    <div class="filters">
      <input id="q" placeholder="Rechercher (IP, compte, texte…)">
      <select id="fsev"><option value="">Toutes sévérités</option></select>
      <select id="fcat"><option value="">Toutes catégories</option></select>
    </div>
    <div class="scroll"><table>
      <thead><tr><th>Sévérité</th><th>Catégorie</th><th>Description</th><th>Source</th><th>Début</th><th class="num">Évts</th></tr></thead>
      <tbody id="rows"></tbody>
    </table></div>
  </section>
</main>
<script type="application/json" id="data">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEV = ['critique','haute','moyenne','basse'];
const SEVVAR = {critique:'--crit', haute:'--high', moyenne:'--med', basse:'--low'};
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const fmt = n => n.toLocaleString('fr-FR');

document.getElementById('meta').textContent =
  `Généré le ${D.generated} · ${D.files.map(f => `${f.name} (${f.kind}, ${fmt(f.events)})`).join(' · ')}`;

// KPIs
const k = D.kpi;
document.getElementById('kpis').innerHTML = [
  ['Événements analysés', k.events, ''], ['Alertes', k.alerts, ''],
  ['Critiques', k.critique, 'crit'], ['Hautes', k.haute, 'high'], ['Moyennes', k.moyenne, 'med'],
  ['Échecs de connexion', k.failed, ''], ['Connexions réussies', k.success, ''], ['IP uniques', k.ips, ''],
].map(([l, v, c]) => `<div class="card kpi ${c}"><div class="v">${fmt(v)}</div><div class="l">${l}</div></div>`).join('');

// Chronologie (barres empilées SVG)
function drawTimeline(){
  const T = D.timeline, names = Object.keys(T.series), colors = ['--s1','--s2','--s3'].map(css);
  document.getElementById('bucket').textContent = T.bucket ? `· par tranche de ${T.bucket}` : '';
  document.getElementById('legend').innerHTML = names.map((n,i) => `<span><i style="background:${colors[i]}"></i>${n}</span>`).join('');
  const n = T.labels.length;
  if (!n){ document.getElementById('chart').innerHTML = '<div class="empty">Aucun événement</div>'; return; }
  const W = 1000, H = 220, L = 44, B = 24, TOP = 8;
  const tot = T.labels.map((_, i) => names.reduce((s, nm) => s + T.series[nm][i], 0));
  const max = Math.max(1, ...tot), bw = (W - L) / n;
  let g = '';
  [0, .5, 1].forEach(f => {
    const y = TOP + (H - TOP - B) * (1 - f), v = Math.round(max * f);
    g += `<line x1="${L}" x2="${W}" y1="${y}" y2="${y}" stroke="${css('--line')}"/><text x="${L-6}" y="${y+4}" text-anchor="end">${v}</text>`;
  });
  for (let i = 0; i < n; i++){
    let y = H - B;
    names.forEach((nm, s) => {
      const v = T.series[nm][i]; if (!v) return;
      const h = (H - TOP - B) * v / max; y -= h;
      g += `<rect x="${L + i*bw + bw*.12}" y="${y}" width="${Math.max(bw*.76,1)}" height="${h}" fill="${colors[s]}"><title>${esc(T.labels[i])} — ${esc(nm)} : ${v}</title></rect>`;
    });
  }
  const step = Math.ceil(n / 8);
  for (let i = 0; i < n; i += step)
    g += `<text x="${L + i*bw + bw/2}" y="${H-6}" text-anchor="middle">${esc(T.labels[i])}</text>`;
  document.getElementById('chart').innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Chronologie des événements">${g}</svg>`;
}

function bars(el, items){
  const max = Math.max(1, ...items.map(i => i.value));
  el.innerHTML = items.length ? items.map(i => `<div class="bar-row">
      <div>${i.label}</div>
      <div class="track"><div class="fill" style="width:${100*i.value/max}%;background:${i.color}"></div></div>
      <div class="muted">${i.note}</div></div>`).join('') : '<div class="empty">Rien à signaler</div>';
}
function drawSide(){
  bars(document.getElementById('ips'), D.top_ips.map(p => ({
    label: `<span class="ip">${esc(p.ip)}</span>`, value: p.alerts, color: css(SEVVAR[p.severity]),
    note: `${p.alerts} alerte${p.alerts>1?'s':''} · <span class="pill ${p.severity}">${p.severity}</span>`})));
  bars(document.getElementById('cats'), D.categories.map(([c, n]) => ({label: esc(c), value: n, color: css('--s3'), note: n})));
}

// Tableau filtrable
const fsev = document.getElementById('fsev'), fcat = document.getElementById('fcat'), q = document.getElementById('q');
SEV.forEach(s => fsev.add(new Option(s, s)));
D.categories.forEach(([c]) => fcat.add(new Option(c, c)));
function drawTable(){
  const term = q.value.toLowerCase();
  const list = D.alerts.filter(a => (!fsev.value || a.severity === fsev.value) && (!fcat.value || a.category === fcat.value)
    && (!term || [a.title, a.ip, a.user, a.category, a.source].join(' ').toLowerCase().includes(term)));
  const tb = document.getElementById('rows');
  tb.innerHTML = list.length ? list.map((a, i) => `<tr class="row" data-i="${i}">
      <td><span class="pill ${a.severity}">${a.severity}</span></td><td>${esc(a.category)}</td>
      <td>${esc(a.title)}</td><td class="muted">${esc(a.source)}</td>
      <td class="muted" style="white-space:nowrap">${esc(a.first_seen)}</td><td class="num">${fmt(a.count)}</td></tr>
      <tr class="ev" hidden><td colspan="6"><div class="muted" style="margin-bottom:6px">Du ${esc(a.first_seen)} au ${esc(a.last_seen)}${a.ip ? ' · IP ' + esc(a.ip) : ''}${a.user ? ' · compte ' + esc(a.user) : ''}</div><pre>${a.evidence.map(esc).join('\n')}</pre></td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">Aucune alerte</td></tr>';
}
document.getElementById('rows').addEventListener('click', e => {
  const tr = e.target.closest('tr.row'); if (tr) tr.nextElementSibling.hidden = !tr.nextElementSibling.hidden;
});
[q, fsev, fcat].forEach(el => el.addEventListener('input', drawTable));

function drawAll(){ drawTimeline(); drawSide(); }
drawAll(); drawTable();
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', drawAll);
</script>
</body>
</html>
"""

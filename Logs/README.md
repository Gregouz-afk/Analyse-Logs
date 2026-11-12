# Analyseur de logs de sécurité

Script Python (bibliothèque standard uniquement) qui analyse des logs **auth.log (SSH)**,
**Apache/Nginx** et **événements Windows**, détecte les attaques et génère un
**tableau de bord HTML** autonome (fonctionne hors ligne, thème clair/sombre).

## Démarrage rapide

```bash
python generate_samples.py                 # crée samples/ avec du trafic normal + des attaques
python analyze.py samples/ --open          # analyse et ouvre rapport.html
```

## Utilisation

```bash
python analyze.py /var/log/auth.log /var/log/apache2/access.log*.gz -o rapport.html
python analyze.py security.xml --config config.example.json --json alertes.json --csv alertes.csv
python analyze.py logs/ --min-severity haute
```

Le type de chaque fichier est détecté automatiquement (forçable avec `-t auth|apache|windows`).
Les fichiers `.gz` sont lus directement.

### Exporter les événements Windows

```powershell
# En administrateur — export XML des événements utiles
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=4740 or EventID=1102)]]" /f:xml > security.xml
```
Un fichier `.evtx` peut aussi être lu directement après `pip install python-evtx`.

## Détections

| Catégorie | Règle | Sévérité |
|---|---|---|
| Brute-force | ≥ 5 échecs depuis une IP en 10 min | moyenne / haute |
| Brute-force réussi | connexion réussie depuis une IP en plein brute-force | **critique** (IP publique) |
| Brute-force distribué | un compte attaqué depuis ≥ 5 IP | haute |
| Password spraying | une IP essaie ≥ 5 comptes différents | haute |
| Scan web | rafale de 404, outils (Nikto, sqlmap, gobuster…), recherche de `.env`, `.git`, backups | moyenne / haute |
| Fichier sensible exposé | `.env`, `.git/config`… servi avec un code 200 | **critique** |
| Attaque web | injection SQL, XSS, traversée de répertoires, injection de commande, Log4Shell | haute |
| Brute-force web | POST répétés sur une page de login / réponses 401 | haute |
| Connexion anormale | hors horaires, nouvelle IP pour un compte, root en SSH, RDP depuis Internet | basse → haute |
| Activité Windows | compte créé, ajout au groupe Administrateurs, verrouillage, journal effacé (1102) | moyenne → **critique** |

Tous les seuils sont réglables dans un fichier JSON (voir `config.example.json`).

## Structure

```
analyze.py              ligne de commande
generate_samples.py     logs d'exemple pour tester
loganalyzer/
  parsers.py            lecture des formats -> objets Event
  detectors.py          règles de détection -> objets Alert
  dashboard.py          tableau de bord HTML
```

Pour ajouter une règle : écrire une méthode dans `Detector` (`detectors.py`) qui appelle
`self.add(...)`, puis l'ajouter à la liste dans `run()`.

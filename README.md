# Inventaire réseau privé

Outil en ligne de commande pour inventorier, de façon limitée et non intrusive, les ports TCP d'adresses IPv4 privées que l'opérateur est autorisé à tester.

## Garanties et limites

- Accepte des CIDR RFC1918 (`10/8`, `172.16/12`, `192.168/16`) ou un fichier avec une IP par ligne. Les adresses IPv6 et publiques sont refusées.
- Le plafond est de 1 024 hôtes par exécution, même si `--max-hosts` est fourni. Les exclusions peuvent être des IP ou des CIDR.
- Affiche le nombre d'hôtes et les ports, puis demande une confirmation avant tout trafic. La concurrence, le débit TCP et les délais sont bornés.
- Exécute d'abord une passe de connexions TCP courtes, puis les sondes détaillées uniquement sur les ports ouverts. Il n'y a ni exploitation, ni authentification, ni contournement, ni parcours de liens.
- Les bannières ne sont relevées que si le service les émet spontanément. La version peut donc rester inconnue.
- Pour les ports web courants, le fichier intermédiaire contient au plus 1 Mo de la page d'accueil HTML. Les redirections ne sont pas suivies ; ce n'est pas une capture d'écran.
- Le reverse DNS est indicatif. Les certificats TLS ne sont inspectés que sur les ports 443 et 8443 ; un certificat non approuvé par le système peut ne pas fournir de métadonnées.
- Seuls les ports ouverts (et les erreurs de sonde) apparaissent dans le CSV. Les ports fermés sont mémorisés dans `scan_state.json` pour éviter de les rescanner. Les remplacements de fichiers tolèrent les verrouillages temporaires (par exemple pendant la synchronisation OneDrive). Les anciens états ambigus sont ignorés afin qu'ils ne puissent pas masquer des résultats absents du CSV.

## Utilisation

Depuis PowerShell, dans le dossier du projet :

```powershell
..\.venv\Scripts\python.exe scanner.py --cidr 192.168.1.0/28
```

Avec un fichier d'adresses, des exclusions et des destinations explicites :

```powershell
..\.venv\Scripts\python.exe scanner.py `
  --ip-file .\hosts.txt `
  --exclude 192.168.1.7 `
  --exclude 192.168.1.32/28 `
  --output .\results\inventory.csv `
  --work-dir .\results\intermediate
```

Options utiles : `--ports 22,80,443`, `--max-hosts 128`, `--workers 128`, `--rate 10` et `--timeout 1.5`. Par défaut, le scanner utilise jusqu'à 128 workers, mais limite le débit à 10 tentatives TCP par seconde. Un fichier CSV existant peut être repris après confirmation.

Format de fichier IP : une adresse IPv4 par ligne ; les lignes vides et commentaires commençant par `#` sont ignorés.

## Tests

Les tests sont hors ligne : les fonctions de sondage sont simulées.

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Toutes les dépendances utilisées par l'application proviennent de la bibliothèque standard Python.

## Comparaison de rapports de vulnérabilités Tenable

Le module `tenable_report.py` compare des exports CSV ou Excel (`.xlsx` et `.xlsm`)
Tenable successifs sans lancer de scan réseau. La configuration JSON précise les rapports dans l'ordre chronologique,
le nom des colonnes et les sévérités retenues. Une vulnérabilité est identifiée par
le quadruplet IP, port, Plugin ID et CVE ; chaque rapport est comparé au précédent.
Dans les tendances, le premier rapport sert de référence et ses éléments sont
comptabilisés comme nouveaux. Les métadonnées de site et de propriétaire provenant
des colonnes CSV prennent priorité sur celles déclarées pour chaque rapport.
Chaque version du rapport HTML détaille également, par niveau de risque, le nombre
de vulnérabilités actives, le nombre d'hôtes uniques touchés et le nombre de
nouvelles vulnérabilités par rapport au scan précédent.
Les tendances comprennent trois diagrammes empilés : vulnérabilités nouvelles et
persistantes, vulnérabilités actives par niveau de risque, et hôtes touchés.
Pour les hôtes, la pile distingue les hôtes concernés uniquement par des nouvelles
vulnérabilités, uniquement par des persistantes, et par les deux catégories, afin
que chaque adresse IP ne soit comptée qu'une seule fois dans le total.

Installer les dépendances graphiques et Excel, puis générer le rapport avec l'exemple inclus :

```powershell
..\.venv\Scripts\python.exe -m pip install -r requirements-report.txt
..\.venv\Scripts\python.exe tenable_report.py --config .\tests\data\config.json
```

Le script génère le rapport HTML et un classeur Excel `.xlsx` portant le même nom
de base. Le classeur contient les feuilles `Synthèse`, `Synthèse par risque` et
`Détails` (vulnérabilités nouvelles, persistantes et corrigées). Pour choisir son
emplacement, utiliser `--excel-output .\results\tenable_results.xlsx`. La page HTML
produite contient ses graphiques PNG en base64 et ne dépend d'aucun fichier image
ou script externe. Adapter la configuration et ses chemins relatifs pour analyser
vos propres exports. Pour un classeur contenant plusieurs feuilles,
ajouter `"sheet": "NomDeLaFeuille"` à l'entrée du rapport ; sans cette option,
la feuille active est utilisée. Les fichiers Excel `.xls` historiques ne sont pas
pris en charge. Les exemples fictifs et tests sont dans
`tests\data`; lancez les tests hors ligne avec :

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
# scrutinycheck

Outil en ligne de commande qui évalue la santé des disques à partir de
`smartctl --json`, avec les règles de [Scrutiny](https://github.com/AnalogJ/scrutiny)
(fork maintenu [Starosdev/scrutiny](https://github.com/Starosdev/scrutiny)),
sans serveur, base de données ni Docker.

Projet indépendant, non affilié à Scrutiny. Les tables et règles portées
viennent de Scrutiny (licence MIT), voir `THIRD_PARTY_NOTICES.md`.

## Prérequis

- [smartmontools](https://www.smartmontools.org/) 7.0 ou plus récent
  (`smartctl` dans le PATH, ou `--smartctl CHEMIN`).
- Droits administrateur (Windows) ou root (Linux/macOS) pour lire les disques.

## Utilisation

```
scrutinycheck                 # tous les disques trouvés par smartctl --scan-open
scrutinycheck /dev/sda        # un disque précis
scrutinycheck -d sat /dev/sdb # forcer le type smartctl (boîtiers USB…)
scrutinycheck -v              # détails : série, heures, température
scrutinycheck --strict        # verdict = pire alerte (voir « Verdict »)
scrutinycheck --json          # sortie machine
scrutinycheck -f sortie.json  # analyser une sortie `smartctl -x --json` enregistrée
```

Pour analyser un disque d'une autre machine :

```
smartctl -x --json /dev/sda > sda.json
scrutinycheck -f sda.json
```

## Codes de sortie

| Code | Signification |
| ---- | ------------- |
| 0 | tous les disques sont OK |
| 1 | erreur d'utilisation ou d'exécution |
| 2 | un disque n'a pas pu être lu, ou état inconnu (`--strict`) |
| 3 | au moins un disque en ATTENTION (seulement avec `--strict`) |
| 4 | au moins un disque DÉFAILLANT |

## Verdict : mode Scrutiny (défaut) et mode `--strict`

L'outil trouve toujours les **mêmes alertes** par attribut. Seule la façon de
les résumer en un verdict par disque change.

**Par défaut, le verdict est exactement celui de Scrutiny** (vérifié contre son
code Go, voir « Test différentiel »). Le disque est `DÉFAILLANT` si et
seulement si :

- son état SMART global n'est pas « réussi » (un état **absent** compte comme
  un échec, parce qu'un champ absent vaut `false` en Go), ou
- un attribut dépasse un seuil propre à Scrutiny (taux de panne Backblaze,
  seuils NVMe/SCSI).

Sinon il est `OK`, même s'il porte des alertes : la ligne affiche alors
`OK (n alerte(s))` et les alertes sont listées dessous.

**Avec `--strict`, le verdict est la pire alerte**, ce qui change trois cas
(exemples ci-dessous).

### Pourquoi une option

Le mode Scrutiny est la référence : c'est la logique que des milliers
d'utilisateurs font tourner, et ses choix se défendent. Un tableau de bord qui
surveille des disques en continu doit éviter les fausses alertes, sinon on
finit par les ignorer.

Mais `scrutinycheck` est souvent lancé **une seule fois**, pour décider s'il
faut garder un disque : achat d'occasion, disque récupéré, avant d'y mettre
des données importantes. Dans ce cas, on préfère être prévenu de tout, quitte
à vérifier soi-même. D'où le mode strict, en option.

### Exemple 1 : seuil constructeur franchi par le passé seulement

`tests/virtual/ata-warning-only.json` : l'attribut 1 (Read Error Rate) est
descendu une fois à 40, sous son seuil de 44, puis est revenu à 100.

```
$ scrutinycheck -f ata-warning-only.json
ata-warning-only.json OK (1 alerte)    WDC WD140EDFZ-11A0VA0   14.0 To  HDD
   └ [ATTENTION]    1 Read Error Rate brut=0 : seuil constructeur franchi par le passé (pire valeur 40, seuil 44)

$ scrutinycheck --strict -f ata-warning-only.json
ata-warning-only.json ATTENTION        WDC WD140EDFZ-11A0VA0   14.0 To  HDD     (code 3)
```

- Scrutiny : c'est de l'histoire ancienne, le disque va bien aujourd'hui.
- Strict : un épisode passé justifie de surveiller le disque.

### Exemple 2 : seuil constructeur franchi maintenant

`tests/virtual/ata-manufacturer-now.json` : même disque, mais l'attribut 1 est
**actuellement** à 40 pour un seuil de 44, alors que le disque se déclare
toujours globalement « réussi ».

```
$ scrutinycheck -f ata-manufacturer-now.json
ata-manufacturer-now.json OK (1 alerte)    WDC WD140EDFZ-11A0VA0   14.0 To  HDD
   └ [DÉFAILLANT]    1 Read Error Rate brut=0 : seuil constructeur franchi (valeur 40, seuil 44)

$ scrutinycheck --strict -f ata-manufacturer-now.json
ata-manufacturer-now.json DÉFAILLANT       WDC WD140EDFZ-11A0VA0   14.0 To  HDD     (code 4)
```

- Scrutiny : sur ce critère, seul le verdict global du disque compte. S'il dit
  « réussi », le disque reste OK.
- Strict : le fabricant considère lui-même cet attribut en panne, c'est un
  échec.

### Exemple 3 : état SMART global absent

`tests/fixtures/smart-sat.json` : sortie de `smartctl -A`, qui contient les
attributs mais pas le verdict global du disque.

```
$ scrutinycheck -f smart-sat.json
smart-sat.json DÉFAILLANT       ?    ?
   └ [DÉFAILLANT] smart_status État SMART global : état SMART global absent : compté comme un échec (logique Scrutiny)

$ scrutinycheck --strict -f smart-sat.json
smart-sat.json OK               ?    ?
```

- Scrutiny : pas de réponse = échec (par prudence, et c'est aussi la
  conséquence du décodage en Go).
- Strict : une réponse absente n'est pas une panne. On juge les attributs
  disponibles, et le disque est `INCONNU` s'il n'y en a aucun.

### Ce qui ne change pas

Un échec Scrutiny reste un échec dans les deux modes. Exemple réel,
`tests/fixtures/smart-ata-failed-scrutiny.json` :

```
smart-ata-failed-scrutiny.json DÉFAILLANT   Samsung SSD 840 Series   500 Go  SSD
   └ [DÉFAILLANT]  199 UltraDMA CRC Error Count brut=108 : risque de panne élevé (seuil 20 %) ; compteur cumulatif, peut dater d'un incident ancien (taux de panne annuel observé ≈ 22.3 %)
```

Ces 108 erreurs CRC viennent souvent d'un câble SATA défectueux. Dans un
Scrutiny qui tourne en continu, l'alerte disparaît quand le compteur arrête
d'augmenter. Un lancement unique ne peut pas le savoir, d'où la mention
« compteur cumulatif ».

## Couches d'évaluation (version minimale)

1. Verdict S.M.A.R.T. global du disque.
2. ATA : seuils fabricant, puis taux de panne observés (tranches dérivées des
   données Backblaze, reprises telles quelles de Scrutiny ; leur période
   source n'est pas documentée).
3. NVMe et SCSI : règles de Scrutiny.

Pas encore implémenté : profils de disques grand public, score de risque,
historique et tendances, recalcul reproductible des tables Backblaze.

## Développement

```
cargo test
```

Les tests utilisent de vraies sorties smartctl (`tests/fixtures/`, issues des
données de test de Scrutiny) : aucun disque physique n'est nécessaire.

### Test différentiel contre Scrutiny

`oracle/` compile le code Go **non modifié** du fork Scrutiny (commit figé dans
`oracle/build.sh`) avec un petit programme d'entrée (`oracle/main.go`), puis
`oracle/differential.py` génère des milliers de cas virtuels (bornes de tranches
±1, valeurs extrêmes, `when_failed`, chaînes brutes Seagate, champs NVMe/SCSI)
et compare les bits d'état attribut par attribut.

```
oracle/build.sh WORKDIR                       # nécessite Go et git
cargo build --release
python oracle/differential.py --oracle WORKDIR/scrutiny-oracle.exe \
  --rust target/release/scrutinycheck.exe --work WORKDIR/cases \
  --go-src WORKDIR/scrutiny-src/webapp/backend/pkg/thresholds/ata_attribute_metadata.go
```

En mode par défaut, les états des attributs **et** le verdict de chaque
disque concordent avec Scrutiny sur tous les cas générés.

## Licence

MIT, voir `LICENSE`. Les parties reprises de Scrutiny restent sous leur
licence MIT d'origine, voir `THIRD_PARTY_NOTICES.md`.

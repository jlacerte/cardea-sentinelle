<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Guide de test sur un poste Windows

Ce guide couvre tout le cycle sur une machine Windows : mettre à jour le dépôt,
compiler la variante de test, lancer les tests unitaires, démarrer le client de
test à côté de votre client Nextcloud habituel, et simuler des attaques
ransomware dans un dossier bac à sable.

Un script fait chaque étape avec vérification d'erreur et journal :
`admin\win\scripts\test-sentinel.ps1`. Les commandes manuelles équivalentes sont
données à chaque fois, pour comprendre ce qui se passe ou dépanner.

---

## 0. Les règles de sécurité, avant tout

1. **Utilisez un compte Nextcloud de test et un dossier de synchronisation de test.**
   Jamais votre compte principal.
2. **Compilez toujours la variante « Dev ».** Elle s'appelle `nextclouddev.exe`,
   a son propre dossier de configuration (`%APPDATA%\NextcloudDev`) et cohabite
   avec le client standard. La variante normale porte le même nom, le même
   dossier de configuration et le même verrou que le client officiel : lancée à
   sa place, elle reprendrait vos vrais comptes. Le script n'utilise que la
   variante Dev.
3. **Le simulateur d'attaque n'accepte qu'un dossier nommé `sentinel-sandbox`.**
   Il refuse tout autre chemin, la racine d'un disque et votre dossier
   personnel. Il garde une sauvegarde de ce qu'il a créé dans votre dossier
   temporaire.
4. **Vérifiez que les versions et la corbeille sont actives sur le serveur**
   (elles le sont par défaut). C'est la vraie protection de la copie serveur.

---

## 1. Installation unique des prérequis

À faire une seule fois. Comptez une à deux heures, surtout pour Qt et Craft.

| Outil | Installation | Vérification |
|---|---|---|
| Git | `winget install Git.Git` | `git --version` |
| CMake | `winget install Kitware.CMake` | `cmake --version` (≥ 3.16) |
| Ninja | `winget install Ninja-build.Ninja` | `ninja --version` |
| Inkscape (génération des icônes, exigé par CMake) | `winget install --id Inkscape.Inkscape -e` (demande une élévation) | `inkscape --version`, ou `C:\Program Files\Inkscape\bin\inkscape.exe` existe |
| Python 3 | `winget install Python.Python.3.12` | `py -3 --version` |
| Visual Studio 2022 Build Tools (C++) | voir `SENTINEL-BUILD-PLAN.md`, étape 2.1 | `cl` dans un « Developer PowerShell for VS 2022 » |
| KDE Craft : **Qt 6**, ECM, KF6 Archive/GuiAddons, QtKeychain, OpenSSL, SQLite, zlib | `admin\win\scripts\install-craft.ps1` | `admin\win\scripts\install-craft.ps1 -Verify` |

**Un seul Qt : celui de Craft.** N'installez pas Qt depuis l'installateur Qt
en plus. Deux Qt différents (un dans `C:\Qt`, un dans Craft) donnent des erreurs
de liaison ou un plantage immédiat de l'exécutable par incompatibilité de DLL.
Les scripts de compilation et de test utilisent en priorité le préfixe Craft
(`C:\CraftRoot\windows-msvc2022_64-cl`) et n'utilisent un Qt autonome que
s'il n'y a aucun préfixe Craft.

`install-craft.ps1` suit exactement la recette de la CI Windows (CraftMaster +
`craftmaster.ini` du dépôt, cache binaire Nextcloud). Il vérifie les
prérequis (VS 2022 C++, Python 3.9+ 64 bits, 30 Go libres, accès réseau), ne
pose aucune question, reprend là où il s'est arrêté si vous le relancez, et
termine par une vérification des fichiers CMake attendus. Comptez 20 à 60
minutes. Racine par défaut : `C:\CraftRoot` (évitez les chemins avec espaces) ;
pour une autre racine, passez `-CraftRoot D:\Craft` **et** définissez la
variable d'environnement utilisateur `SENTINEL_CRAFT_ROOT=D:\Craft` pour que
les autres scripts la trouvent.

Après chaque installation, **ouvrez une nouvelle fenêtre PowerShell** pour que
le `PATH` soit à jour. Le détail de chaque étape est dans
`SENTINEL-BUILD-PLAN.md` (phase 2).

---

## 2. Récupérer ou mettre à jour le dépôt

### Première fois : cloner

```powershell
cd D:\nextcloud            # ou le dossier de votre choix
git clone https://github.com/jlacerte/nextcloud-sentinel.git
cd nextcloud-sentinel
git checkout claude/hopeful-goldberg-7iu995
```

### Ensuite : mettre à jour avec le script

Ouvrez un **« Developer PowerShell for VS 2022 »** (menu Démarrer), puis :

```powershell
cd D:\nextcloud\nextcloud-sentinel
.\admin\win\scripts\test-sentinel.ps1 -Update
```

Ce que fait l'étape `Update` :

- refuse de continuer si vous avez des modifications locales non validées
  (elle les liste ; validez-les avec `git commit`, mettez-les de côté avec
  `git stash`, ou annulez-les avec `git checkout -- <fichier>`) ;
- `git fetch origin <branche>` avec trois tentatives en cas de panne réseau ;
- bascule sur la branche si vous n'y êtes pas ;
- avance en « fast-forward » seulement ; si votre branche locale a divergé, elle
  s'arrête et vous explique comment la réaligner (`git reset --hard
  origin/<branche>`, qui jette vos commits locaux : à vous de décider).

Équivalent manuel :

```powershell
git status                               # doit être propre
git fetch origin claude/hopeful-goldberg-7iu995
git checkout claude/hopeful-goldberg-7iu995
git merge --ff-only origin/claude/hopeful-goldberg-7iu995
git log -1 --oneline                     # le dernier commit attendu
```

Pour travailler sur une autre branche : `-Branch master` (ou n'importe quel nom).

---

## 3. Compiler la variante de test

Toujours depuis un « Developer PowerShell for VS 2022 » :

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Build
```

L'étape `Build` :

- refuse de compiler si `nextclouddev.exe` tourne (l'éditeur de liens ne peut
  pas remplacer un exécutable ouvert) : quittez-le via l'icône de la barre
  des tâches ;
- appelle `compile-sentinel.ps1 -Dev -Configure -Build` dans un processus
  séparé et vérifie son code de retour ;
- vérifie que `build-windows-Release-dev\bin\nextclouddev.exe` existe.

Première compilation : 15 à 30 minutes. Les suivantes ne recompilent que ce qui
a changé. `-Clean` efface le dossier de build avant (utile après une mise à jour de
Craft). `-BuildType Debug` compile en débogage. `-QtPath` ne sert que sans
Craft ; s'il y a un préfixe Craft, il est ignoré avec un avertissement.

Équivalent manuel :

```powershell
cd admin\win\scripts
.\compile-sentinel.ps1 -Dev -Configure -Build
```

### Si la compilation échoue

Les deux fichiers qui n'ont pas pu être compilés par Claude dans son
environnement (pas de Qt 6.8 ni de KF6) sont `src\gui\killswitch\sentinelcontroller.cpp`
et `src\gui\application.cpp`. Si l'erreur vient de là, copiez les lignes en rouge
et le fichier de journal (voir section 8) et renvoyez-les : c'est une correction
rapide.

---

## 4. Lancer les tests unitaires

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Test
```

L'étape `Test` ajoute les DLL de Qt et de Craft au `PATH`, puis lance
`ctest -R "KillSwitch|FormatSignature"` dans le dossier de build. Attendu :

| Suite | Tests | Contenu |
|---|---|---|
| `KillSwitchTest` | 128 | manager, chaque détecteur, faux positifs, renommages, concurrence |
| `FormatSignatureDetectorTest` | 38 | signatures de formats, chiffrement par blocs, leurres |
| `KillSwitchScenariosTest` | 26 | attaques complètes et usages normaux sur un bac à sable |

Le script échoue si un test échoue et liste les tests en cause. Comme les
exécutables QtTest peuvent ne rien afficher sur la console Windows, il relance
aussi chaque suite avec `-o fichier,txt`, affiche la ligne `Totals:` de chacune
et garde les rapports dans `logs\`. Pour tout lancer d'un coup : `-All`
(= `-Update -Build -Test`).

Équivalent manuel (depuis le dossier de build, avec `C:\Qt\6.8.x\msvc2022_64\bin`
et `%USERPROFILE%\CraftRoot\bin` dans le `PATH`) :

```powershell
cd build-windows-Release-dev
ctest -R "KillSwitch|FormatSignature|ThreatLogger" --output-on-failure -C Release
```

---

## 5. Démarrer le client de test

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Run
```

L'étape `Run` démarre `nextclouddev.exe` avec le bon `PATH` et vérifie qu'il
est toujours en vie trois secondes plus tard (un plantage immédiat signifie
presque toujours une DLL manquante). Votre client Nextcloud habituel peut
rester ouvert.

Au premier démarrage, l'assistant de connexion s'ouvre :

1. entrez l'adresse de votre serveur et **le compte de test** ;
2. choisissez **le dossier de test** comme dossier local (par exemple
   `D:\TestNextcloud`) ;
3. laissez la première synchronisation se terminer (icône verte).

Ouvrez ensuite **Paramètres > Kill Switch** : la protection doit être
« Enabled », statut vert. C'est aussi là que se trouve le bouton **Reset** qui
relance la synchronisation après un déclenchement.

---

## 6. Simuler une attaque

### 6.1 Préparer le bac à sable

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode seed -Sandbox "D:\TestNextcloud\sentinel-sandbox"
```

Le dossier est créé s'il n'existe pas, puis rempli d'environ 40 fichiers
réalistes (docx, xlsx, pdf, png, jpg, mp4, txt, csv, un `_canary.txt`). Le
chemin de la sauvegarde est affiché. **Attendez que le client de test ait tout
synchronisé** (icône verte) avant d'attaquer : la détection se fait au moment
de la synchronisation, elle doit voir des fichiers *modifiés*.

### 6.2 Attaquer

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode header -Sandbox "D:\TestNextcloud\sentinel-sandbox"
```

| `-Mode` | Ce que fait le simulateur | Ce que vous devriez voir | Détecteur attendu |
|---|---|---|---|
| `rename` | chiffre et renomme en `.XXXXXXXXX` (extension aléatoire) | pause après 2 ou 3 fichiers | PatternDetector |
| `inplace` | réécrit le contenu complet, même nom | pause dès le 1er fichier | FormatSignatureDetector |
| `header` | réécrit les 4 premiers Ko (LockBit 2/3) | pause dès le 1er fichier | FormatSignatureDetector |
| `chunked` | blocs de 1 Mo alternés (Play) | pause dès le 1er fichier | FormatSignatureDetector |
| `delete-recreate` | supprime l'original, crée `nom.ext.locked` | pause dès le 1er fichier | PatternDetector |
| `notes` | dépose des notes de rançon | pause immédiate | PatternDetector |
| `canary` | modifie `_canary.txt` | pause immédiate | CanaryDetector |
| `mass-delete` | supprime des fichiers en rafale | pause au 10e fichier | MassDeleteDetector |

Options : `-Count 5` limite le nombre de fichiers touchés. Le simulateur
travaille à 5 fichiers par seconde par défaut pour qu'une passe de
synchronisation puisse l'observer.

Dans le client de test, dans la minute qui suit (le délai dépend de la
détection des changements locaux) :

- le dialogue **« Kill Switch Triggered »** apparaît, avec la raison et les
  fichiers concernés ;
- le dossier passe en **pause** dans la fenêtre principale ;
- une notification apparaît dans la barre des tâches ;
- **Paramètres > Kill Switch** affiche « TRIGGERED - Sync Paused » et l'historique.

Résultat mesuré sur un vrai serveur (mode `header`, 10 fichiers) : déclenchement
0,6 s après le début de la synchronisation, **aucun** des 10 fichiers chiffrés
envoyé.

Test supplémentaire utile : fermez `nextclouddev.exe` pendant qu'il est
déclenché, relancez-le avec `-Run`. Il doit redémarrer **toujours en pause**,
avec le dialogue, et non reprendre l'envoi.

Vérifiez aussi côté serveur, dans l'interface web, que les fichiers du bac à
sable n'ont **pas** été remplacés par les versions chiffrées (ou seulement les
un ou deux premiers selon le mode).

### 6.3 Revenir à l'état initial

L'ordre compte. **Reset relance la synchronisation** : si les fichiers chiffrés
sont encore sur le disque, elle les revoit et le Kill Switch redéclenche dans
la seconde (le dialogue le dit : « Triggered again N seconds after the last
reset »). C'est le comportement voulu, rien n'est envoyé entre-temps, mais ça
ressemble à un bug si on ne s'y attend pas.

1. Restaurez d'abord les fichiers du bac à sable :

```powershell
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode reset -Sandbox "D:\TestNextcloud\sentinel-sandbox"
```

2. Ensuite seulement, dans le client : bouton **Reset** du dialogue, ou
   **Paramètres > Kill Switch > Reset**. La synchronisation reprend et revoit des
   fichiers sains.

Dans la vraie vie, l'étape 1 est « restaurer depuis le serveur » (interface
web, Versions ou Fichiers supprimés) ou supprimer les fichiers chiffrés.
Vous pouvez ensuite enchaîner un autre mode.

Équivalent manuel du simulateur :

```powershell
py -3 -I test\scripts\simulate-ransomware.py seed   "D:\TestNextcloud\sentinel-sandbox" --yes
py -3 -I test\scripts\simulate-ransomware.py attack --mode header "D:\TestNextcloud\sentinel-sandbox" --yes
py -3 -I test\scripts\simulate-ransomware.py reset  "D:\TestNextcloud\sentinel-sandbox" --yes
py -3 -I test\scripts\simulate-ransomware.py attack --help      # toutes les options, dont --dry-run
```

---

## 7. Usages normaux à vérifier aussi

Un bon test, c'est aussi ce qui ne doit **pas** déclencher. Dans le dossier de
test (hors bac à sable, ou dedans après un `reset`) :

- copier 20 à 30 photos ;
- créer une archive `.zip` et quelques PDF ;
- modifier des fichiers texte ;
- enregistrer une base KeePass (`.kdbx`) ;
- supprimer 5 fichiers ;
- renommer des fichiers, créer un `README.txt`.

Attendu : aucun déclenchement. Les niveaux Low et Medium peuvent apparaître
dans l'historique de la page Kill Switch, c'est normal. Si quelque chose
déclenche, notez le message exact du dialogue : il nomme le détecteur et la
règle.

---

## 8. Dépannage

Le script écrit un journal complet dans `logs\test-sentinel-<date>.log` (dossier
ignoré par git) et affiche un tableau récapitulatif à la fin. Ce journal, plus
les lignes en rouge, suffisent pour diagnostiquer à distance.

| Symptôme | Cause probable | Solution |
|---|---|---|
| `Refusing to update over local changes` | fichiers modifiés localement | `git stash` (ou commit), relancer |
| `has diverged from origin` | commits locaux absents du serveur | `git push`, ou `git reset --hard origin/<branche>` si vous les abandonnez |
| `git fetch` échoue trois fois | réseau, proxy, branche supprimée | vérifier l'accès à github.com |
| `No KDE Craft prefix and no Qt 6.8 found` | Craft pas installé, ou racine non standard | `install-craft.ps1`, ou `SENTINEL_CRAFT_ROOT` vers votre racine |
| `Could not find SVG_CONVERTER` à la configuration CMake | Inkscape absent | `winget install --id Inkscape.Inkscape -e`, nouvelle fenêtre PowerShell |
| ctest dit « Passed » mais la sortie des tests est vide | les exécutables QtTest n'écrivent pas sur la console Windows (cause en cours d'analyse) | `test-sentinel.ps1 -Test` relance chaque suite avec `-o fichier,txt` et affiche les totaux ; les rapports sont dans `logs\` |
| `Visual Studio 2022 with C++ workload not found` | Build Tools absents ou sans C++ | réinstaller avec le workload « Desktop development with C++ » |
| `The prefix is incomplete` (install-craft -Verify) | installation Craft interrompue | relancer `install-craft.ps1`, il reprend |
| erreurs de liaison Qt, ou DLL incompatible au lancement | deux Qt mélangés (C:\Qt et Craft) | `-Clean`, ne garder que Craft, vérifier qu'aucun `C:\Qt\...\bin` n'est dans le `PATH` |
| `nextclouddev.exe is running` au build | client de test ouvert | le quitter via l'icône de la barre des tâches |
| `nextclouddev.exe exited within 10 s` | DLL manquante, ou ressources Qt WebEngine introuvables (`%TEMP%\NextcloudDev-crash.log`) | lancer via `-Run` (qui règle `QTWEBENGINE_*` pour Craft) ; sinon lire le crash log affiché par le script |
| `No test matched` | build configuré sans tests | relancer `-Build` (le script active `BUILD_TESTING`) |
| `REFUSED: ... sentinel-sandbox` | mauvais chemin passé au simulateur | le dossier doit s'appeler `sentinel-sandbox` |
| Le client ne détecte rien | fichiers pas encore synchronisés avant l'attaque, ou Kill Switch désactivé | attendre l'icône verte après `seed` ; vérifier Paramètres > Kill Switch |
| Erreurs de compilation dans `sentinelcontroller.cpp` / `application.cpp` | fichiers non compilés par Claude | envoyer les lignes d'erreur |

---

## 9. Aide-mémoire

```powershell
# Developer PowerShell for VS 2022, dans le dossier du dépôt
.\admin\win\scripts\test-sentinel.ps1 -All                 # mise à jour + compilation + tests
.\admin\win\scripts\test-sentinel.ps1 -Update              # seulement git
.\admin\win\scripts\test-sentinel.ps1 -Build [-Clean]      # seulement compiler (variante Dev)
.\admin\win\scripts\test-sentinel.ps1 -Test                # seulement ctest
.\admin\win\scripts\test-sentinel.ps1 -Run                 # démarrer nextclouddev.exe
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode seed   -Sandbox "D:\TestNextcloud\sentinel-sandbox"
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode inplace -Sandbox "D:\TestNextcloud\sentinel-sandbox"
.\admin\win\scripts\test-sentinel.ps1 -Simulate -Mode reset  -Sandbox "D:\TestNextcloud\sentinel-sandbox"
```

Code de retour : `0` si tout a réussi, `1` si une étape a échoué (les
suivantes ne sont pas exécutées), `2` si aucune action n'a été demandée.

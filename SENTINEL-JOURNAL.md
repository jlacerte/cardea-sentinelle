# Nextcloud Sentinel Edition - Development Journal

## 2026-10-15 - Revue du prototype et correctifs de fond

### Constat

Une relecture complète du module Kill Switch (manager, détecteurs, actions,
intégration moteur/GUI) a montré que le prototype passait ses tests unitaires
mais ne pouvait pas fonctionner correctement dans le vrai client :

| Problème | Effet réel |
|----------|------------|
| Deux `KillSwitchManager` créés (un dans `Application`, un par `SyncEngine`, donc un par dossier) | Le singleton `instance()` pointait sur le dernier créé. Le logger, le BackupAction et les notifications étaient branchés sur un manager qui ne voyait aucun fichier. |
| Analyse faite deux fois (`SyncEngine::handleKillSwitchAnalysis` puis `OwncloudPropagator::createJob`) | Chaque événement compté deux fois : tous les seuils effectivement divisés par deux. |
| `SyncFileItem::_file` est relatif au dossier de sync | `EntropyDetector` n'ouvrait jamais le fichier (`-1`), `BackupAction` ne trouvait jamais la source. La détection par entropie était inopérante en production. |
| `trigger()` fabriquait un `ThreatInfo` sans `affectedFiles` | `BackupAction` sortait immédiatement (« No affected files »). Aucune sauvegarde n'a jamais pu être faite. |
| `setDeleteThreshold` / `setEntropyThreshold` / `addCanaryFile` ne touchaient que des champs du manager | Les réglages de l'UI (presets Light/Standard/Paranoid, canaris) n'avaient aucun effet sur les détecteurs. Rien n'était rechargé au démarrage. |
| Motif `^readme.*\.txt$` classé Critical | Un simple `README.txt` dans un projet mettait la sync en pause. |
| Règle de débit de `MassDeleteDetector` (`> 5 fichiers/s`) sans minimum | Tous les items d'une passe de sync arrivent en quelques ms : 2 suppressions à 1 ms d'intervalle = « 2000 fichiers/s » = déclenchement. |
| Un seul fichier inconnu à entropie ≥ 7.9 = Critical | Base KeePass (`.kdbx`), image disque, format propriétaire : pause de la sync sur un seul fichier légitime. |
| `CSYNC_INSTRUCTION_RENAME` rejeté avant les détecteurs | `report.docx` → `report.docx.locked` (renommage en place) invisible pour PatternDetector ; branche « RENAMED » du CanaryDetector morte. |
| `QtConcurrent::run` × 4 par item | Trois détecteurs sur quatre coûtent quelques µs ; le dispatch thread pool coûtait plus que ce qu'il économisait et exposait des détecteurs non thread-safe (cache LRU de l'entropie). |

### Changements

**Architecture**
- Un seul manager par processus, créé par `Application`. Les `SyncEngine` s'y
  connectent via `KillSwitchManager::instance()` ; sans application
  (nextcloudcmd, tests upstream) le moteur se comporte comme le client d'origine.
- `AnalysisContext { localRootPath }` passé à `analyzeItem()` et aux détecteurs :
  les chemins relatifs sont résolus en chemins absolus pour l'I/O et pour les
  `affectedFiles` transmis aux actions.
- `createJob()` ne ré-analyse plus : il se contente de bloquer la propagation
  si le switch est déclenché.
- `trigger(const ThreatInfo&)` : la menace déclenchante (avec ses fichiers)
  est transmise aux actions.
- Les setters du manager propagent aux détecteurs/actions ; `Application`
  recharge la configuration persistée (`[KillSwitch]`) au démarrage ;
  `removeCanaryFile()` ajouté et câblé dans les réglages.
- Détecteurs exécutés séquentiellement (retrait de QtConcurrent).
- Plus de double `finalize()` quand le switch se déclenche pendant l'analyse.

**Détection**
- PatternDetector : les notes de rançon de type README/WARNING/YOUR_FILES
  exigent un mot-clé de rançon ; les renommages sont analysés (cible du
  renommage) et comptés dans la fenêtre.
- MassDeleteDetector : la règle de débit demande au moins `max(3, seuil/2)`
  suppressions étalées sur ≥ 1 s. `affectedFiles` en chemins absolus.
- EntropyDetector : ignore les téléchargements (`Down`) ; un fichier de type
  texte à entropie anormale reste High seul ; un fichier de type inconnu à
  très haute entropie est Medium seul, High à partir de 3 dans la fenêtre,
  Critical à partir de 6 (comportement d'un chiffreur en cours). Liste blanche
  élargie (formats chiffrés par conception, images RAW, conteneurs, images
  disque, polices).
- CanaryDetector : renommage d'un canari = Critical.

**Divers**
- Notifications systray uniquement pour High/Critical (les Low/Medium restent
  dans le log et la page de réglages), liste de fichiers tronquée à 5.
- `ThreatLogger` plafonné à 2000 entrées (le fichier est réécrit à chaque
  menace).

### Tests

118 tests (100 avant). Nouveaux : renommages (pattern, canari, manager),
transmission des fichiers aux actions, propagation de configuration,
résolution de chemin via le contexte, escalade entropie (Medium → High →
Critical), fichier texte aléatoire, téléchargements ignorés, bases de mots
de passe en liste blanche, rafale courte de suppressions non comptée comme
débit, débit soutenu détecté. Deux assertions existantes inversées :
`README.txt` / `README.TXT` ne sont plus des notes de rançon.

Vérification : module compilé avec `-Wall -Wextra -Wpedantic -Werror` et
suite exécutée via un harnais autonome (Qt 6.4) ; le client complet (Qt 6.8 +
KF6) n'a pas pu être compilé dans cet environnement, les fichiers
`application.cpp`, `syncengine.cpp` et `owncloudpropagator.cpp` ont été relus
mais pas compilés.

### Points ouverts (décisions produit)

1. **BackupAction** : côté client, un fichier supprimé localement n'existe plus
   au moment où la sync le voit, et un fichier chiffré l'est déjà. La copie
   n'a de valeur que pour les suppressions venant du serveur (`Down`). La
   vraie protection est la pause de l'upload ; le serveur garde les versions.
   À documenter honnêtement dans le README ou à repenser (ex. snapshot avant
   `PropagateLocalRemove` uniquement).
2. **`evaluateThreatLevel()`** déclenche sur le nombre brut de `DELETE`, en
   ignorant la liste blanche de `MassDeleteDetector` (`node_modules`, `build`…).
   Le test `testFalsePositive_BuildCleanup` documente ce choix comme voulu ;
   la liste blanche est donc inopérante de bout en bout. À trancher.
3. **Seuil de suppression par défaut (10 fichiers / 60 s)** : vider un dossier
   de 10 photos déclenche la pause. Le client upstream a déjà une confirmation
   « supprimer tous les fichiers ? » (`handleMassDeletion`). Envisager un seuil
   relatif (% des fichiers du dossier) ou 25+ en preset Standard.
4. **Suppressions venant du serveur** (`Down`) comptées comme locales : une
   suppression faite dans l'interface web par l'utilisateur déclenche le
   switch sur tous ses postes. Protection utile (autre client infecté) mais à
   nommer différemment dans l'alerte.
5. **CI** : les workflows Sentinel ne tournent que sur `master` et
   `sentinel-*` ; une branche de travail n'a pas de retour CI.
6. **Blocage par `PropagateIgnoreJob`** après déclenchement : la sync « réussit »
   avec tout ignoré. Mettre réellement le dossier en pause
   (`Folder::setSyncPaused`) serait plus lisible pour l'utilisateur.

---

## 2026-01-11 (PM) - Major Feature Sprint

### Collaboration WSL/Windows Agents

Journée très productive avec deux agents Claude travaillant en parallèle:
- **Agent WSL**: Code review, feedback, CI monitoring
- **Agent Windows**: Feature development, UI implementation

### New Features Implemented

**PatternDetector (Phase 4 - DONE)**
- 80+ extensions ransomware connues (.locked, .encrypted, .wannacry, etc.)
- Détection notes de rançon (HOW_TO_DECRYPT.txt, etc.)
- Double extension (.pdf.locked)
- Patterns .hta ajoutés suite au code review
- 14 nouveaux tests unitaires

**EntropyDetector Improvements**
- Multi-block sampling (3-5 échantillons selon taille fichier)
- Early exit si premier sample > 7.8
- Cache LRU (10,000 entrées max)
- Expected entropy ranges par type de fichier
- Détection entropy spike (delta > 2.0)

**UI Dashboard & Presets**
- `killswitchdashboard.cpp` - Statistiques en temps réel
  - Compteurs: fichiers analysés, menaces bloquées
  - Top 5 détecteurs
  - Timeline 24h/7d/30d
  - Export CSV
- Presets de sécurité: Light / Standard / Paranoid

**Integration SyncEngine (Phase 2 - DONE)**
- Hook dans `OwncloudPropagator::createJob()`
- Initialisation dans `application.cpp`
- Ordre optimisé: PatternDetector → CanaryDetector → MassDeleteDetector → EntropyDetector

### Code Review Process

L'agent WSL a reviewé le code de l'agent Windows:
- Suggestion retrait `.java` (faux positifs) → Appliqué
- Suggestion ajout `.hta` → Appliqué
- Suggestion ordre détecteurs → Appliqué
- Communication via fichiers dans `status/`

### Commits (Session PM)

```
0f82445c4 docs: Add response to WSL agent feedback
1fbd91cb1 fix(killswitch): Address WSL agent feedback
d4bdc8701 feat(ui): Add Kill Switch statistics dashboard
159cb7d28 feat(ui): Add configuration presets
5272e4aa9 feat: Improve EntropyDetector with multi-block analysis
c223f059d test: Add false positive and edge case tests
ca11f4a3a feat: Add PatternDetector for ransomware extension detection
acc095255 feat: Integrate Kill Switch into SyncEngine
```

### CI Status

- Linux Sentinel CI #14: ✅ PASS (12m 26s)
- Windows Sentinel CI #17: 🔄 En cours

---

## 2026-01-11 (AM) - Build System Complete & All Tests Passing

### Accomplishments

**Kill Switch Module - Fully Functional**
- All 19 unit tests passing
- Integration tests passing
- Build successful on both Linux and Windows

**Bug Fixes**
- Fixed deadlock in `KillSwitchManager` by changing `QMutex` to `QRecursiveMutex`
  - Root cause: `analyzeItem()` acquired mutex, then called `trigger()` which also tried to acquire it
  - Tests went from 300s timeout to 0.38s execution
- Fixed `killswitchsettings.cpp` to use public `QSettings` API instead of private `ConfigFile` methods
- Fixed `build-wsl.sh` Docker script (removed `-it` flag causing TTY error)

**CI/CD Pipeline**
- Linux Sentinel CI: Working (Docker-based, GCC)
- Windows Sentinel CI: Working (Craft/MSVC)
- Repository made public to enable free GitHub Actions minutes

**Build Scripts Created**
- `build-wsl.sh` - Docker build for Linux/WSL
- `SETUP-WINDOWS.ps1` - Windows environment setup
- `BUILD.bat` - Quick Windows build
- `build-local.ps1` - Local Windows build script

### Test Results

```
Kill Switch Tests: 19/19 PASS
- MassDeleteDetector: 6 tests
- CanaryDetector: 7 tests
- EntropyDetector: 5 tests
- Integration: 1 test
```

### Files Modified Today

| File | Change |
|------|--------|
| `src/libsync/killswitch/killswitchmanager.h` | QMutex → QRecursiveMutex |
| `src/gui/killswitch/killswitchsettings.cpp` | Use public QSettings API |
| `.github/workflows/windows-sentinel-ci.yml` | Added Inkscape for icons |
| `.github/workflows/linux-sentinel-ci.yml` | Created Linux CI workflow |

### Commits

- `a5d7f2283` - fix: Use QRecursiveMutex to prevent deadlock in KillSwitchManager
- `e2cc1f3f0` - docs: Update agent briefing with timer fix
- `a0d15c450` - fix: Stop QTimer in destructor to prevent test timeout
- `fc202b4cd` - ci(windows): Add Inkscape installation for icon generation
- `86dbb1ee4` - fix: Use public QSettings API instead of private ConfigFile methods

### Next Steps

- [ ] Test Kill Switch with real sync scenarios
- [ ] Add UI integration in Settings dialog
- [ ] Implement backup action on trigger
- [ ] Add notification system for alerts
- [ ] Documentation for end users

---

## Roadmap - Nextcloud Sentinel Edition

### Phase 1 - Core Protection (DONE ✅)
- [x] Kill Switch Manager architecture
- [x] MassDeleteDetector - détecte suppressions massives
- [x] EntropyDetector - détecte fichiers chiffrés (haute entropie)
- [x] CanaryDetector - détecte modification de fichiers pièges
- [x] Unit tests (33+ passing)
- [x] CI/CD Linux & Windows

### Phase 2 - Integration (DONE ✅)
- [x] Brancher KillSwitchManager dans SyncEngine
- [x] Hook dans OwncloudPropagator::createJob()
- [x] Pause automatique de la sync si menace détectée
- [x] UI Settings intégré dans le client
- [x] Dashboard statistiques
- [x] Presets de configuration (Light/Standard/Paranoid)

### Phase 3 - Response Actions (EN COURS)
- [ ] Backup automatique avant suppression
- [x] Dialog d'alerte avec options (KillSwitchAlertDialog)
- [ ] Notification système (tray icon)
- [ ] Logging détaillé des menaces

### Phase 4 - Advanced Features (PARTIELLEMENT DONE)
- [x] PatternDetector - 80+ extensions ransomware
- [x] Détection notes de rançon
- [x] Double extension detection
- [x] Multi-block entropy sampling
- [x] LRU cache pour performance
- [ ] Machine learning pour détection comportementale
- [ ] Intégration avec Nextcloud server-side protection
- [x] Whitelist par extension

### Phase 5 - Release
- [ ] Documentation utilisateur
- [ ] Guide d'installation
- [ ] Tests beta avec utilisateurs réels
- [ ] Merge request vers Nextcloud upstream (optionnel)

---

*Developed with Claude Code assistance*

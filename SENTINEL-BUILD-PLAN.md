# Nextcloud Sentinel - Build Plan

Ce document décrit les étapes pour configurer l'environnement de build et compiler Nextcloud Sentinel Edition.

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                    NEXTCLOUD SENTINEL                            │
│                     Build Pipeline                               │
├─────────────────────────────────────────────────────────────────┤
│  Phase 1: GitHub & CI          │  Phase 2: Installation Windows │
│  ☐ Git & GitHub CLI            │  ☐ Visual Studio Build Tools   │
│  ☐ Créer repo GitHub           │  ☐ Qt 6.8 (MSVC 2022)          │
│  ☐ Pusher le code              │  ☐ KDE Craft + ECM             │
│  ☐ Vérifier workflows          │                                │
├─────────────────────────────────────────────────────────────────┤
│  Phase 3: Build Local          │  Phase 4: Résultats            │
│  ☐ Configurer CMake            │  ☐ Vérifier CI GitHub          │
│  ☐ Compiler le projet          │  ☐ Analyser tests locaux       │
│  ☐ Exécuter tests              │  ☐ Valider Kill Switch         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: GitHub & CI (5 min)

### Étape 1.1: Vérifier les prérequis

```powershell
# Vérifier Git
git --version
# Attendu: git version 2.x.x

# Vérifier GitHub CLI
gh --version
# Attendu: gh version 2.x.x

# Si GitHub CLI n'est pas installé:
winget install GitHub.cli
```

**Status:** ☐ Complété

### Étape 1.2: Authentifier GitHub CLI

```powershell
gh auth login
# Suivre les instructions (browser ou token)
```

**Status:** ☐ Complété

### Étape 1.3: Créer le repository GitHub

```powershell
cd D:\nextcloud\nextcloud-sentinel

# Créer un repo privé et pusher
gh repo create nextcloud-sentinel --private --source=. --push
```

**URL du repo:** _________________________

**Status:** ☐ Complété

### Étape 1.4: Vérifier les workflows CI

1. Ouvrir: `https://github.com/VOTRE_USER/nextcloud-sentinel/actions`
2. Vérifier que les workflows démarrent:
   - ☐ `Linux Sentinel CI`
   - ☐ `Windows Sentinel CI`

**Status:** ☐ Complété

---

## Phase 2: Installation Windows (30-60 min)

### Étape 2.1: Installer Visual Studio Build Tools 2022

```powershell
# Option A: Via winget (recommandé)
winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --passive"

# Option B: Téléchargement manuel
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
```

**Vérification:**
```powershell
# Devrait trouver cl.exe
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
```

**Status:** ☐ Complété

### Étape 2.2: Installer les outils de build

```powershell
# CMake
winget install Kitware.CMake

# Ninja (build rapide)
winget install Ninja-build.Ninja

# Python (pour KDE Craft)
winget install Python.Python.3.12
```

**Vérification:**
```powershell
cmake --version   # >= 3.16
ninja --version   # >= 1.10
python --version  # >= 3.10
```

**Status:** ☐ Complété

### Étape 2.3: Installer Qt 6.8 (uniquement SANS Craft)

> **Recommandé : sauter cette étape et passer à 2.4.** Avec KDE Craft, Qt est
> installé par Craft et c'est le seul Qt utilisé par les scripts de build. Un
> second Qt dans `C:\Qt` provoque des erreurs de liaison et des DLL
> incompatibles. Cette étape ne sert que pour une compilation sans Craft.

1. **Télécharger** Qt Online Installer:
   - https://www.qt.io/download-qt-installer

2. **Lancer** l'installateur et se connecter (compte gratuit)

3. **Sélectionner** Custom Installation:
   - ☐ Qt 6.8.x (ou plus récent)
   - ☐ MSVC 2022 64-bit
   - ☐ Qt 5 Compatibility Module
   - ☐ Qt Shader Tools
   - ☐ Additional Libraries > Qt WebEngine
   - ☐ Additional Libraries > Qt WebChannel

4. **Installer** dans `C:\Qt`

5. **Configurer** la variable d'environnement:
```powershell
[Environment]::SetEnvironmentVariable("Qt6_DIR", "C:\Qt\6.8.0\msvc2022_64", "User")
$env:Qt6_DIR = "C:\Qt\6.8.0\msvc2022_64"
```

**Chemin Qt installé:** _________________________

**Status:** ☐ Complété

### Étape 2.4: Installer KDE Craft (Qt, ECM, KF6, QtKeychain, OpenSSL, SQLite)

```powershell
cd D:\nextcloud\nextcloud-sentinel\admin\win\scripts
.\install-craft.ps1            # 20-60 min, reprend si interrompu
.\install-craft.ps1 -Verify    # contrôle final
```

Le script applique la recette de la CI Windows : CraftMaster, `craftmaster.ini`
du dépôt (version de Qt, blueprints Nextcloud, cache binaire), puis
`craft --install-deps nextcloud-client`. Résultat dans
`C:\CraftRoot\windows-msvc2022_64-cl` (racine modifiable avec `-CraftRoot`,
à reporter dans la variable d'environnement `SENTINEL_CRAFT_ROOT`).

Équivalent manuel (ce que fait le script) :
```powershell
$Root = "C:\CraftRoot"
git clone --depth=1 https://invent.kde.org/packaging/craftmaster.git $Root\CraftMaster
# fichier $Root\craftmaster-local.ini : [windows-msvc2022_64-cl] Paths/Python = <dossier de python.exe>
function craft { python $Root\CraftMaster\CraftMaster.py --config D:\nextcloud\nextcloud-sentinel\craftmaster.ini --config-override $Root\craftmaster-local.ini --variables Root=$Root --targets windows-msvc2022_64-cl -c @args }
craft --add-blueprint-repository "https://github.com/nextcloud/craft-blueprints-kde.git|stable-4.0|"
craft --add-blueprint-repository "https://github.com/nextcloud/desktop-client-blueprints.git|stable-4.0|"
craft craft
craft --install-deps nextcloud-client
```

**Chemin Craft:** C:\CraftRoot\windows-msvc2022_64-cl (ou _________________________)

**Status:** ☐ Complété

---

## Phase 3: Build Local (15-30 min)

### Étape 3.1: Ouvrir Developer PowerShell

```powershell
# Option A: Depuis le menu Démarrer
# Chercher "Developer PowerShell for VS 2022"

# Option B: Lancer manuellement
& "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64
```

**Status:** ☐ Complété

### Étape 3.2: Configurer CMake

```powershell
cd D:\nextcloud\nextcloud-sentinel\admin\win\scripts
.\compile-sentinel.ps1 -Configure
```

Ou manuellement:
```powershell
cd D:\nextcloud\nextcloud-sentinel
mkdir build-windows
cd build-windows

cmake .. -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_PREFIX_PATH="C:\CraftRoot\windows-msvc2022_64-cl" `
    -DNEXTCLOUD_DEV=ON `
    -DBUILD_TESTING=ON `
    -DBUILD_UPDATER=ON
```

**Résultat CMake:** ☐ Succès / ☐ Erreurs

**Status:** ☐ Complété

### Étape 3.3: Compiler le projet

```powershell
.\compile-sentinel.ps1 -Build
```

Ou manuellement:
```powershell
cd D:\nextcloud\nextcloud-sentinel\build-windows
cmake --build . --parallel
```

**Temps de compilation:** _________ minutes

**Résultat:** ☐ Succès / ☐ Erreurs

**Status:** ☐ Complété

### Étape 3.4: Exécuter les tests

```powershell
.\compile-sentinel.ps1 -Test
```

Ou manuellement:
```powershell
cd D:\nextcloud\nextcloud-sentinel\build-windows
ctest -R KillSwitch --output-on-failure
```

**Résultats des tests:**
- ☐ testManagerInitialization
- ☐ testManagerEnableDisable
- ☐ testManagerTrigger
- ☐ testMassDeleteDetector*
- ☐ testCanaryDetector*
- ☐ testEntropyCalculation*
- ☐ testFullIntegration*

**Status:** ☐ Complété

---

## Phase 4: Vérification des résultats

### Étape 4.1: Vérifier CI GitHub

1. Ouvrir: `https://github.com/VOTRE_USER/nextcloud-sentinel/actions`

2. Vérifier les jobs:

| Workflow | Job | Status |
|----------|-----|--------|
| Linux Sentinel CI | build-gcc | ☐ |
| Linux Sentinel CI | build-clang | ☐ |
| Linux Sentinel CI | static-analysis | ☐ |
| Linux Sentinel CI | coverage | ☐ |
| Windows Sentinel CI | build-and-test | ☐ |
| Windows Sentinel CI | static-analysis | ☐ |

**Status:** ☐ Complété

### Étape 4.2: Télécharger les artifacts

1. Aller dans le workflow run
2. Télécharger:
   - ☐ `test-results-linux-gcc`
   - ☐ `test-results-linux-clang`
   - ☐ `coverage-report-linux`
   - ☐ `test-results-windows`

**Status:** ☐ Complété

### Étape 4.3: Lancer le client (optionnel)

```powershell
cd D:\nextcloud\nextcloud-sentinel\build-windows\bin
.\nextcloud.exe
```

**Le client démarre:** ☐ Oui / ☐ Non

**Status:** ☐ Complété

---

## Résumé

| Phase | Étapes | Temps estimé | Status |
|-------|--------|--------------|--------|
| 1. GitHub & CI | 4 | 5 min | ☐ |
| 2. Installation | 4 | 30-60 min | ☐ |
| 3. Build Local | 4 | 15-30 min | ☐ |
| 4. Résultats | 3 | 5 min | ☐ |

**Temps total:** ~1-2 heures

---

## Dépannage

### CMake ne trouve pas Qt ou ECM
```powershell
.\admin\win\scripts\install-craft.ps1 -Verify      # le préfixe est-il complet ?
cmake .. -DCMAKE_PREFIX_PATH="C:\CraftRoot\windows-msvc2022_64-cl"
```
Si vous aviez aussi un Qt dans `C:\Qt`, retirez-le du `PATH` et de `Qt6_DIR` :
un seul Qt, celui de Craft.

### Erreur LNK2019 (unresolved external)
```powershell
# Réinstaller les dépendances Craft
craft --install-deps nextcloud-client
```

### Tests échouent avec "display not found"
```powershell
# Sur Windows, pas besoin de xvfb
# Vérifier que Qt platform plugin est trouvé
$env:QT_QPA_PLATFORM = "windows"
```

---

## Notes de développement

_Utiliser cette section pour noter les observations pendant le build:_

```
Date: ___________

Observations:
-
-
-

Problèmes rencontrés:
-
-

Solutions appliquées:
-
-
```

---

## Prochaines étapes après le build

1. ☐ Tester le Kill Switch manuellement dans l'UI
2. ☐ Configurer les seuils de détection
3. ☐ Tester avec des fichiers canary
4. ☐ Simuler une attaque ransomware (environnement contrôlé)
5. ☐ Documenter les résultats

---

*Document créé pour Nextcloud Sentinel Edition*
*Dernière mise à jour: Janvier 2026*

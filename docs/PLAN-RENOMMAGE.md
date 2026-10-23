<!--
SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Plan : régulariser le nom du projet

Statut : **proposé, phase 0 en attente de John** (2026-10-23).
Suivi : projet Archon « Sentinel », document « Plan de renommage » et tâches
« Renommage – phase N ».

## Pourquoi

Les [règles de marque de Nextcloud GmbH](https://nextcloud.com/trademarks/)
disent qu'on ne doit pas mettre « Nextcloud » dans le nom d'une application,
d'un produit ou d'un service, même non commercial, et qu'il faut leur
permission pour distribuer un client de bureau modifié qui porte leur nom et
leur logo. Un nom de fichier, de dossier ou de chemin reste permis, et on ne
doit pas laisser croire à une affiliation.

Aujourd'hui :

| Élément | Valeur actuelle | Problème |
|---|---|---|
| Dépôt GitHub | `jlacerte/nextcloud-sentinel` (public) | marque dans le nom |
| Nom du produit dans les docs | « Nextcloud Sentinel Edition » (≈ 45 fichiers), « Nextcloud Sentinel » (≈ 62 fichiers) | marque dans le nom |
| Titulaire SPDX des fichiers Sentinel | `Nextcloud Sentinel Project` (42 fichiers) ; `Nextcloud GmbH` sur 2 fichiers de tests écrits pour Sentinel | entité fictive qui ressemble à un projet Nextcloud ; attribution inexacte |
| Client compilé | `NextcloudDev` / `nextclouddev.exe`, icône Nextcloud, fabricant `Nextcloud GmbH` | marque et logo dans l'interface |

Rien n'a encore été distribué (aucune release GitHub) : on régularise avant.

Le code hérité de Nextcloud garde ses mentions de droit d'auteur
(`Nextcloud GmbH and Nextcloud contributors`) : on ne les retire jamais.

## Phase 0 : décisions de John (bloquante)

1. **Le nouveau nom.** Attention : « Sentinel » seul entre en collision avec
   deux produits de sécurité connus, SentinelOne (protection des postes et
   anti-rançongiciel) et Microsoft Sentinel. Dans le même domaine, c'est un
   risque de marque au moins aussi sérieux que « Nextcloud ». Choisir un nom
   distinctif, puis faire une recherche rapide dans les registres de marques :
   - Canada : <https://ised-isde.canada.ca/cipo/trademark-search/srch> (OPIC) ;
   - États-Unis : <https://tmsearch.uspto.gov/> ;
   - Europe : <https://euipo.europa.eu/eSearch/> ;
   - classe 9 (logiciels) et classe 42 (services informatiques) ;
   - plus une recherche GitHub et web du nom.
   Un dépôt renommé deux fois perd la redirection de son premier nom : on
   choisit une fois.
2. **Le titulaire SPDX** des fichiers créés pour le projet, par exemple
   `2026 <nom de John> and <Nouveau nom> contributors`. Le droit d'auteur
   appartient à l'auteur ; une entité fictive est moins solide.
3. **La stratégie de rebranding** : thème OEM (voir phase 3) si on continue de
   fusionner `upstream` (nextcloud/desktop), ce qui est le cas aujourd'hui.

## Phase 1 : renommer le dépôt GitHub

Possible à tout moment, même pendant la PR #26 : c'est une métadonnée.

- John renomme dans GitHub > Settings > General > Repository name, ou donne
  son accord explicite pour `gh repo rename`.
- GitHub redirige l'ancienne adresse web et git ; mettre quand même à jour le
  remote local : `git remote set-url origin https://github.com/jlacerte/<nouveau>.git`.
- Vérifications après le renommage :
  - [ ] CodeRabbit répond à un « Trigger review » (l'app est liée au dépôt par
        son identifiant, elle devrait suivre) ;
  - [ ] les deux CI Sentinel se lancent sur un push ;
  - [ ] la session Claude Code cloud retrouve le dépôt (sinon, la reconnecter) ;
  - [ ] Archon : mettre à jour le champ `github_repo` du projet.
- **Ne pas déplacer `D:\nextcloud\nextcloud-sentinel`** : le cache CMake du
  dossier de build contient des chemins absolus, et plusieurs docs et le
  `CLAUDE.md` de l'espace de travail utilisent ce chemin. Un nom de dossier
  local n'est pas un problème de marque. Déplacement possible plus tard, à
  part, avec une recompilation complète.

## Phase 2 : textes et en-têtes (PR séparée, après la fusion de #26)

Faire ce balayage dans sa propre branche, une fois #26 fusionnée, pour ne pas
créer de conflits dans la PR en revue.

- En-têtes SPDX : remplacer `Nextcloud Sentinel Project` par le titulaire
  choisi ; corriger `test/testkillswitchscenarios.cpp` et
  `test/testthreatlogger.cpp` (titulaire `Nextcloud GmbH` inexact).
- README, guides, THREAT-MODEL, SENTINEL-JOURNAL, `status/` : nouveau nom ;
  liens `github.com/jlacerte/nextcloud-sentinel` vers le nouveau dépôt
  (`test-sentinel.ps1`, README, GUIDE, THREAT-MODEL, scripts `SETUP-WINDOWS.ps1`,
  `TRIGGER-CI.bat`, etc.).
- README : une phrase claire, par exemple « Client anti-rançongiciel basé sur
  le client de bureau Nextcloud. Projet indépendant, non affilié à Nextcloud
  GmbH ni approuvé par elle. Nextcloud est une marque de Nextcloud GmbH. »
- `.coderabbit.yaml`, workflows : noms affichés.
- PR #26 : ajouter une réponse sous les cinq commentaires SPDX de CodeRabbit,
  qui disent aujourd'hui « on garde Nextcloud Sentinel Project ».

## Phase 3 : rebranding du client (avant toute distribution d'un exécutable)

Tant que le client ne quitte pas le poste de John, ce n'est pas urgent ; c'est
**obligatoire avant** de donner un exécutable à quelqu'un.

Approche recommandée : un thème OEM (mécanisme prévu par upstream,
`OEM_THEME_DIR`, voir les lignes commentées de `NEXTCLOUD.cmake`), pour que les
fusions depuis `upstream` restent simples. Sinon, modifier `NEXTCLOUD.cmake`
directement.

Variables qui portent la marque :

| Variable | Actuel | À faire |
|---|---|---|
| `APPLICATION_NAME`, `APPLICATION_SHORTNAME` | `NextcloudDev` / `Nextcloud` | nouveau nom |
| `APPLICATION_EXECUTABLE`, `APPLICATION_CONFIG_NAME` | `nextclouddev` / `nextcloud` | nouveau nom (change l'exe et le dossier de config) |
| `APPLICATION_VENDOR` | `Nextcloud GmbH` | titulaire choisi |
| `APPLICATION_DOMAIN`, `APPLICATION_REV_DOMAIN` | `nextcloud.com`, `com.nextcloud.desktopclient` | domaine du projet |
| `APPLICATION_UPDATE_URL` | `https://updates.nextcloud.org/client/` | **désactiver ou rediriger** : sinon le client peut proposer de se remplacer par le client officiel |
| `APPLICATION_ICON_NAME`, icônes `theme/` | logo Nextcloud | nouveau jeu d'icônes (pipeline Inkscape existant) |
| `APPLICATION_VIRTUALFILE_SUFFIX`, `LINUX_PACKAGE_SHORTNAME`, `THEME_CLASS` | `nextcloud`, `NextcloudTheme` | nouveau nom |
| `WIN_SHELLEXT_*_GUID`, `WIN_MSI_UPGRADE_CODE` | identiques au client officiel | **générer de nouveaux GUID** (le fichier le demande lui-même) : sinon conflit avec le client Nextcloud installé sur le même poste |

Conséquences à gérer :

- Le dossier `%APPDATA%\NextcloudDev`, le verrou et les entrées du trousseau
  changent : prévoir une migration (copier le dossier de config) ou refaire la
  connexion du compte de test (John tape lui-même le mot de passe).
- `test-sentinel.ps1`, `compile-sentinel.ps1`, le guide Windows et le plan de
  compilation citent `nextclouddev.exe` : tout mettre à jour dans le même lot.
- Les deux CI : noms d'exécutables et identité de build.
- Vérifier « À propos » et les textes de l'interface qui disent « Nextcloud »
  en dur (au-delà de `APPLICATION_NAME`).

## Hors périmètre, à noter

- `android-sentinel/` a le même problème de nom (application mobile : la règle
  de Nextcloud est encore plus explicite, « not the official client »). À
  planifier à part.
- En cas de diffusion large ou de doute, écrire à Nextcloud GmbH par
  <https://nextcloud.com/contact>.

## Ordre

1. Phase 0 (John) →
2. Phase 1 (dépôt) →
3. fusion de la PR #26 →
4. Phase 2 (PR séparée) →
5. Phase 3 (PR séparée, avant toute distribution).

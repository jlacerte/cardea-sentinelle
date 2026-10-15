<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
  - SPDX-FileCopyrightText: 2017 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Nextcloud Sentinel Edition

[![Status: Prototype](https://img.shields.io/badge/Status-Prototype-yellow.svg)](#project-status)
[![CI - Windows](https://github.com/jlacerte/nextcloud-sentinel/actions/workflows/windows-sentinel-ci.yml/badge.svg)](https://github.com/jlacerte/nextcloud-sentinel/actions/workflows/windows-sentinel-ci.yml)
[![CI - Linux](https://github.com/jlacerte/nextcloud-sentinel/actions/workflows/linux-sentinel-ci.yml/badge.svg)](https://github.com/jlacerte/nextcloud-sentinel/actions/workflows/linux-sentinel-ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![CodeRabbit](https://img.shields.io/badge/CodeRabbit-AI%20Review-orange)](https://coderabbit.ai)
[![Website](https://img.shields.io/badge/Website-nxtcloud.ca-blue)](https://nxtcloud.ca)

**Nextcloud desktop client with built-in Kill Switch anti-ransomware protection.**

> *"The fire crackles. Your files are protected."*

---

## Project Status

> **This project is currently in early development (prototype stage).**

We're building something new: a Nextcloud sync client that fights back against ransomware. This isn't a finished product yet - it's a working prototype that demonstrates our vision.

| Milestone | Status |
|-----------|--------|
| Core Kill Switch engine | ✅ Complete |
| Threat detectors (5 types) | ✅ Complete |
| Desktop UI (Settings + Alerts) | ✅ Complete |
| Test suite (192 tests, incl. end-to-end attack scenarios) | ✅ Complete |
| Windows build pipeline | ✅ Complete |
| Linux build pipeline | ✅ Complete |
| Android client | ⏳ Planned |
| macOS native build | ⏳ Planned |
| Production release | ⏳ Planned |

### What Works Today

- **Kill Switch detection** - Mass deletions, entropy analysis, pattern matching, canary files
- **Automatic sync pause** - Stops damage before it spreads
- **Threat dashboard** - Visual monitoring of security events
- **Configuration presets** - Light, Standard, Paranoid modes

### What's Coming

- Pre-built installers for Windows/macOS/Linux
- Android app with Kill Switch protection
- Cloud-based threat intelligence
- Enterprise management console

---

## The Vision

Ransomware doesn't care about your backups if it encrypts them before they sync.

Traditional sync clients are **dumb pipes** - they faithfully replicate whatever happens locally, including disasters. We believe sync clients should be **smart guardians** that recognize threats and protect your data.

**Sentinel is our answer:** a sync client that watches for suspicious patterns and hits the brakes before catastrophe strikes.

---

## Roadmap

```
Q1 2026  ██████████░░░░░░░░░░  Prototype (we are here)
         - Core engine complete
         - Desktop UI functional
         - CI/CD pipelines operational

Q2 2026  ░░░░░░░░░░░░░░░░░░░░  Alpha Release
         - Pre-built binaries
         - Installation documentation
         - Bug fixes from early testers

Q3 2026  ░░░░░░░░░░░░░░░░░░░░  Beta Release
         - Android client
         - Stability improvements
         - Performance optimization

Q4 2026  ░░░░░░░░░░░░░░░░░░░░  Production Release
         - v1.0 stable
         - Enterprise features
         - Support channels
```

---

## What is Sentinel?

Sentinel is a security-enhanced fork of the [Nextcloud Desktop Client](https://github.com/nextcloud/desktop) that adds **proactive ransomware protection** through an intelligent Kill Switch system.

When suspicious activity is detected (mass deletions, file encryption patterns, canary file tampering), Sentinel **automatically pauses sync** to prevent damage from spreading to your Nextcloud server.

---

## Key Features

### Kill Switch Protection

| Feature | Description |
|---------|-------------|
| **Pattern Detection** | 90+ known ransomware extensions, double extensions (`report.pdf.locked`), the random per-victim extensions of modern RaaS families (LockBit 3/4, BlackCat, Qilin, RansomHub: `invoice.pdf.HLJkNskOq`), and ransom notes |
| **Format Signature Check** | A `.jpg`, `.pdf`, `.docx`, `.zip`, `.mp4`... that no longer starts with its own signature, or whose structural tail (ZIP directory, PDF `%%EOF`, PNG `IEND`) is gone, has been encrypted in place |
| **Entropy Analysis** | Text-like files that became random, and bursts of random-looking files of unknown type |
| **Mass Delete Detection** | Too many deletions in a short time window |
| **Canary Files** | Honeypot files that must never change: any modification, rename or deletion trips the switch |
| **Sync Pause** | All sync folders are paused and an alert is raised; the pause survives a client restart until you reset it |
| **Backup Action** | Copies the files named by the triggering threat (useful for deletions coming from the server; local files that were already encrypted are recovered from the server's versions) |

### What a simulated attack looks like

Measured by `test/testkillswitchscenarios.cpp` with the five detectors and default settings ("files lost" = files handed to the sync before the switch tripped; the server copy of those files is still protected by Nextcloud's versioning):

| Attack (as real families do it) | Result |
|---|---|
| Rename with random extension (`.HLJkNskOq`) | Paused after 2 files (immediately if the original is deleted in the same run) |
| In-place full encryption, same names | Paused on the 1st file |
| In-place header-only (first 4 KB, LockBit 2/3 style) | Paused on the 1st file |
| Alternating 1 MB chunks, first chunk hit (Play style) | Paused on the 1st file |
| Tail-only encryption, header intact | Paused after 2 files |
| Delete + recreate as `.locked` | Paused on the 1st file |
| Ransom note dropped | Paused immediately |
| Canary file touched | Paused immediately |
| Mass deletion | Paused at the 10th file (default threshold) |

Benign workloads in the same suite (25 new photos, creating archives, editing text, saving a KeePass database, deleting a few files, legitimate renames, Nextcloud conflict copies, a new `README.txt`) never trip the switch.

**Known gaps:** chunked encryption that spares both the header and the structural tail of a file (e.g. only the middle megabyte), and tail-only damage on formats without a trailer (`.jpg`, `.mp4`), are not detected per file yet. Chunk-level sampling is the next step.

### Threat Dashboard

- Real-time threat level indicator
- History of detected threats with timestamps
- Configurable sensitivity presets (Light / Standard / Paranoid)
- One-click sync resume after false positives

---

## Why Sentinel?

| Scenario | Standard Client | Sentinel |
|----------|-----------------|----------|
| Ransomware encrypts 1000 files | All synced to server | **Blocked after ~10 files** |
| Accidental mass delete | Synced immediately | **Paused for confirmation** |
| Suspicious file patterns | No detection | **Alert + auto-pause** |
| Recovery options | Restore from server | **Local backup + server intact** |

---

## Try It Yourself

> **Note:** This is prototype software. Use at your own risk and always maintain separate backups.

### Build from Source

#### Windows (Quick Start)

Dependencies (Qt 6, ECM, KF6, QtKeychain, OpenSSL, SQLite) all come from KDE Craft, installed by `admin\win\scripts\install-craft.ps1`; do not install a second Qt. Then `admin\win\scripts\test-sentinel.ps1 -All` updates, builds the test variant and runs the tests. Full walkthrough: [GUIDE-TEST-WINDOWS.md](GUIDE-TEST-WINDOWS.md).


```bash
# Clone the repository
git clone https://github.com/jlacerte/nextcloud-sentinel.git
cd nextcloud-sentinel

# Run the setup script
.\CLICK-ME-FIRST.bat
```

#### Linux (Docker)

The Linux CI builds inside the upstream `continuous-integration-client-qt6` container; see `.github/workflows/linux-sentinel-ci.yml` for the exact CMake invocation (Qt 6.8, ECM, KF6).

#### Full Build Instructions

See [SENTINEL-BUILD-PLAN.md](SENTINEL-BUILD-PLAN.md) for detailed build instructions.

---

## Configuration

### Kill Switch Settings

Access via: **Settings > Kill Switch**

| Setting | Default | Description |
|---------|---------|-------------|
| Delete Threshold | 10 files | Max deletions before trigger |
| Time Window | 60 seconds | Monitoring window |
| Entropy Threshold | 7.5 | Shannon entropy limit (max 8.0) |
| Auto-Backup | Enabled | Backup before suspicious ops |

### Presets

- **Light**: Higher thresholds, fewer false positives
- **Standard**: Balanced protection (recommended)
- **Paranoid**: Maximum security, may have more alerts

---

## Architecture

```
src/libsync/killswitch/
├── killswitchmanager.cpp    # Main orchestrator
├── threatdetector.h         # Detector interface
├── threatlogger.cpp         # Threat history
├── detectors/
│   ├── patterndetector          # Extensions, random suffixes, ransom notes
│   ├── canarydetector           # Honeypot monitoring
│   ├── massdeletedetector       # Volume-based detection
│   ├── formatsignaturedetector  # Magic bytes + structural tail checks
│   └── entropydetector          # Entropy analysis
└── actions/
    ├── syncaction               # Action interface
    └── backupaction             # Copies of the threatened files

src/gui/killswitch/
├── sentinelcontroller       # Pauses/resumes folders, raises the alert, persists the trigger
├── killswitchsettings       # Settings page (presets, thresholds, canaries)
├── killswitchalertdialog    # Alert shown when the switch trips
└── killswitchdashboard      # Statistics
```

One `KillSwitchManager` per process: every sync folder feeds the same event stream, so an attack spread over several folders is still seen as one.

---

## Testing

```bash
# Run all Kill Switch tests (unit, format signatures, end-to-end scenarios)
cd build && ctest -R "KillSwitch|FormatSignature" --output-on-failure
```

**Test coverage:** 192 tests in three suites:
- `KillSwitchTest` (128): manager, each detector, false positives (README.txt, password databases, small deletion bursts), edge cases, renames, thread safety, real encrypted sample files (`test/data/encrypted/`)
- `FormatSignatureDetectorTest` (38): synthetic PNG/ZIP/PDF/JPEG/MP3/text files, chunked and tail-only corruption, decoys
- `KillSwitchScenariosTest` (26): full attack simulations and benign workloads against a sandbox of realistic files

On Windows, [GUIDE-TEST-WINDOWS.md](GUIDE-TEST-WINDOWS.md) walks through the whole loop (update, build, test, run, simulate) with `admin\win\scripts\test-sentinel.ps1`.

### Try an attack on the real client

`test/scripts/simulate-ransomware.py` (Python 3, no dependencies) only ever touches a folder named `sentinel-sandbox` and keeps a backup of what it seeded in your temp directory:

```bash
# 0. Build the "NextcloudDev" variant so it cannot see your real client's accounts and folders:
#    admin\win\scripts\compile-sentinel.ps1 -Dev -Configure -Build  ->  build-windows-Release-dev\bin\nextclouddev.exe
#    (it has its own config folder and runs next to the standard client; add a TEST account to it)
# 1. Create <the dev client's sync folder>/sentinel-sandbox and seed it, then let the client sync
py test/scripts/simulate-ransomware.py seed "C:\Users\you\Nextcloud\sentinel-sandbox" --yes

# 2. Attack it the way a real family would (rename, inplace, header, chunked, delete-recreate, notes, canary, mass-delete)
py test/scripts/simulate-ransomware.py attack --mode header "C:\Users\you\Nextcloud\sentinel-sandbox" --yes

# 3. Watch the client pause and alert; reset the Kill Switch in Settings > Kill Switch, then restore the sandbox
py test/scripts/simulate-ransomware.py reset "C:\Users\you\Nextcloud\sentinel-sandbox" --yes
```

Use a test account, or at least check that versioning and the trash bin are enabled on your server first. Never run the non-dev build while the standard Nextcloud client is installed: they share the executable name, the single-instance lock and the configuration folder, so it would either defer to the running client or take over your real accounts.

---

## Join the Journey

We're a small team with a big vision. If you believe sync clients should protect users, not just move bytes, we'd love your help.

### Ways to Contribute

- **Test the prototype** - Build it, break it, tell us what happened
- **Report bugs** - Every issue helps us improve
- **Suggest features** - What would make Sentinel essential for you?
- **Spread the word** - Star the repo, share with colleagues
- **Code contributions** - PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

### Development

```bash
# Create a feature branch
git checkout -b feature/my-feature

# Make changes and test (Windows: admin/win/scripts/compile-sentinel.ps1 -Build)
cd build && ctest -R "KillSwitch|FormatSignature"

# Submit a PR
```

All PRs are automatically reviewed by [CodeRabbit AI](https://coderabbit.ai) in French.

---

## Security

Found a security vulnerability? Please read [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

**Do NOT open a public issue for security vulnerabilities.**

---

## Upstream

Sentinel is based on [Nextcloud Desktop Client](https://github.com/nextcloud/desktop). We regularly sync with upstream to get the latest features and fixes.

---

## License

```
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

See [COPYING](COPYING) for the full license text.

---

## Developed By

**[nxtcloud.ca](https://nxtcloud.ca)** - A Canadian initiative building secure, privacy-focused cloud solutions.

We believe your data should be protected, not just stored. Sentinel is our answer to the growing ransomware threat.

---

## Acknowledgments

- [Nextcloud GmbH](https://nextcloud.com) - Original desktop client
- [CodeRabbit](https://coderabbit.ai) - AI code review
- All early testers and contributors

---

<p align="center">
  <b>Sentinel is prototype software under active development.</b><br>
  <i>The fire crackles. We're just getting started.</i>
</p>

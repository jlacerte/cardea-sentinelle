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
| Threat detectors (4 types) | ✅ Complete |
| Desktop UI (Settings + Alerts) | ✅ Complete |
| Test suite (81 tests) | ✅ Complete |
| Windows build pipeline | ✅ Complete |
| Linux build pipeline | ✅ Complete |
| Android client | ⏳ Planned |
| macOS native build | 🚧 CI build (unsigned) |
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
| **Mass Delete Detection** | Triggers when too many files are deleted in a short time window |
| **Entropy Analysis** | Detects encrypted/ransomware files by analyzing file entropy patterns |
| **Pattern Detection** | Recognizes 80+ known ransomware file extensions (.locked, .encrypted, .cry, etc.) |
| **Canary Files** | Monitors honeypot files - if they're touched, something's wrong |
| **Automatic Backup** | Creates safety snapshots before suspicious operations |

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

```bash
# Clone the repository
git clone https://github.com/jlacerte/nextcloud-sentinel.git
cd nextcloud-sentinel

# Run the setup script
.\CLICK-ME-FIRST.bat
```

#### Linux (Docker)

```bash
git clone https://github.com/jlacerte/nextcloud-sentinel.git
cd nextcloud-sentinel

# Build using Docker
./build-wsl.sh --docker
```

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
│   ├── massdeletedetector   # Volume-based detection
│   ├── entropydetector      # Entropy analysis
│   ├── patterndetector      # Extension matching
│   └── canarydetector       # Honeypot monitoring
└── actions/
    ├── syncaction           # Pause/resume sync
    └── backupaction         # Safety snapshots
```

---

## Testing

```bash
# Run Kill Switch tests
cd build && ctest -R KillSwitch --output-on-failure
```

**Test coverage:** 81 tests covering:
- False positive scenarios
- Edge cases (empty files, long paths, unicode)
- Thread safety
- Cache and timing

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

# Make changes and test
./build-wsl.sh --docker
cd build-docker && ctest -R KillSwitch

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

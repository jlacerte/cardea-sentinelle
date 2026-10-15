<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Sentinel threat model

Status: prototype. This describes what the Kill Switch does **as implemented
on this branch**, which attacks it stops, which it does not, and what the
user must do anyway. Claims are tied to the code (file names given) or to
the measured results in `SENTINEL-JOURNAL.md` (2026-10-15 entries);
anything unverified is marked. Written for issue #16.

## 1. What Sentinel is, and is not

Sentinel is the upstream Nextcloud desktop client plus a **sync-time
detector**. After each discovery run and before anything is propagated,
`SyncEngine::handleKillSwitchAnalysis()` (`src/libsync/syncengine.cpp`)
hands every discovered item to the one `KillSwitchManager` of the process.
Five detectors (`src/libsync/killswitch/detectors/`) score each item; a
finding at level High or Critical calls `KillSwitchManager::trigger()`
(`killswitchmanager.cpp`), which aborts the run. From then on the
propagator turns every item into a `PropagateIgnoreJob`
(`owncloudpropagator.cpp`); `SentinelController` (`src/gui/killswitch/`)
pauses every sync folder the user had not paused, terminates running syncs,
raises an alert and writes `triggered=true` to the client configuration so
that a restart re-arms the switch instead of resuming the upload.

What this protects is the **server copy**: damaged files are not uploaded
over the healthy copies on the server, and deletions are not propagated.
Sentinel is therefore:

- **not an antivirus**: it does not inspect processes, block the
  ransomware or prevent the local encryption; local files are lost until
  restored from the server.
- **not a backup**: `BackupAction` (`actions/backupaction.cpp`) copies the
  files named by the triggering threat to
  `<AppData>/sentinel-backups/<timestamp>` (500 MB, 7 days). At trigger
  time a locally encrypted file is already encrypted and a deleted file is
  gone, so the copy only helps for deletions coming *from* the server.
- **not privileged**: it runs as the user, in the same session as the
  ransomware, with the same rights over its own configuration and process.
- **client-side only**: the server is unaware of it (#17).

## 2. Assets and trust boundaries

| Asset | Where | Who can write to it |
|---|---|---|
| Local sync folders | user's disk | the user and every process running as the user, ransomware included |
| Client process and configuration: `[KillSwitch]` group of `nextcloud.cfg` (`enabled`, thresholds, `canaryFiles`, `autoBackup`, `triggered`, `triggerReason`, `triggerTime`, `pausedFolders`) and each folder's `paused` flag | `%APPDATA%\Nextcloud` on Windows (`%APPDATA%\NextcloudDev` for the Dev build), `~/.config/Nextcloud` on Linux | same: plain INI read with `QSettings` (`ConfigFile::settingsWithGroup`), no integrity check |
| Account credentials (app password) | system keychain via QtKeychain | any process of the user's session, subject to the platform keychain policy (not verified per platform) |
| Threat log `sentinel-threats.json`, `sentinel-backups/` | application data directory | same as the configuration |
| Server copy, versions, trash bin | Nextcloud server | anyone holding the credentials, from any client; versions are capped at 50 % of the user's free space and purged under quota pressure (research notes in the journal) |
| Other clients of the same account (web, mobile, standard desktop) | elsewhere | they bypass Sentinel entirely and receive whatever reaches the server |

The only boundary Sentinel relies on is the one between the machine and
the server: the server runs no local code and versions every file it
overwrites. Everything local, Sentinel included, is within reach of an
attacker running as the user.

## 3. Attacker model A: commodity ransomware (the design target)

Model A does not know Sentinel exists and behaves like the surveyed
families: fast, usually renaming with a fixed or per-victim random
extension, dropping notes, encrypting whole files, headers or chunks. The
rules, from the detector headers:

- **Immediate High/Critical on one file**: an existing file whose magic
  number is gone and whose header is random (`FormatSignatureDetector`), a
  text file whose content is random (`EntropyDetector`), a known double
  extension such as `.pdf.locked` or a ransom note (`PatternDetector`), any
  change to a canary (`CanaryDetector`).
- **Counted inside the window** (default 60 s, `timeWindow`): random
  per-victim extensions without a corroborating delete (Medium, High at 3),
  new files whose content does not match their extension and tail-only
  damage (Medium, High at 3), unknown-type files at ciphertext entropy
  (Medium, High at 3, Critical at 6), deletions (trigger at the threshold,
  default 10).

Measured by `test/testkillswitchscenarios.cpp` (five detectors, default
settings; "files damaged" = files already encrypted when the switch tripped):

| Attack, as the family does it | Trips | Files damaged before the trip |
|---|---|---|
| Rename with random extension (LockBit 3/4, BlackCat, Qilin) | yes | 2 (0 when the original is deleted in the same run) |
| In-place full encryption, same names (Medusa, Clop) | yes | 0 |
| Header-only, first 4 KB (LockBit 2/3, Black Basta) | yes | 0 |
| Alternating 1 MB chunks, first chunk hit (Play, RansomHub) | yes | 0 |
| Tail-only, header intact (docx/pdf/png) | yes | 2 |
| Delete and recreate as `.locked` | yes | 0 |
| Ransom note dropped | yes, Critical | immediate |
| Canary touched | yes, Critical | immediate |
| Mass deletion (default threshold) | yes | 10th deletion trips |
| Chunks sparing header and tail (probe 4b) | **no** | all (#7) |
| Tail-only on jpg/mp4 (probe 5b) | **no** | all (#8) |

Benign workloads in the same suite (25 new photos, archives, text edits, a
`.kdbx` save, 5 deletions, legitimate renames, conflict copies, a new
`README.txt`, PDFs replaced by valid PDFs) never trip.

**Time window.** The file watcher schedules a sync 2 s after a local change
(`Folder::scheduleThisFolderSoon`, `SyncEngine::minimumFileAgeForUpload`);
the remote poll is 30 s by default. Within a run every item is analysed
*before* propagation, and a trip aborts the whole run: nothing from it
reaches the server. A damaged file is uploaded only when a run holds too
few hits for a counted rule (two renamed files, below the threshold of 3),
completes, and the next run sees the rest. That is the "2" in the table:
the worst measured case uploads at most two damaged files, and only if the
attack straddles two runs. A run already propagating when encryption starts
uploads files discovered earlier; upstream aborts an upload whose file
changed since discovery, but this was not re-verified here.

**What is lost.** Locally: everything the ransomware reaches. On the server:
at most the few files uploaded before the trip, each with its previous
version kept (versions are written on every WebDAV overwrite; whether they
follow a renamed file was not verified). Recovery is from the server's
versions and trash bin once the machine is clean, then a reset in
Settings > Kill Switch; resetting while damaged files are still on disk
trips the switch again within seconds, by design.

## 4. Attacker model B: a Nextcloud-aware attacker

Model B has read this code and runs with the user's privileges. Likelihood
is judged for today's ecosystem (no family is known to target Sentinel);
impact is on the server copy.

| Bypass | Mechanism in this code base | Likelihood | Impact | Mitigation status |
|---|---|---|---|---|
| Disable the switch in the configuration | Write `enabled=false` under `[KillSwitch]` in `nextcloud.cfg` (or `mode=audit`, the audit mode from #15, which detects but never pauses), kill and relaunch the client. `Application::setupAccountsAndFolders` reads the key only at startup and `handleKillSwitchAnalysis()` then returns at once. No warning. | low today, trivial once targeted | total: everything is uploaded | not implemented; #16 proposes signing the state and confirming an `enabled` flip |
| Erase the persisted trigger | Delete `triggered`/`pausedFolders` from `[KillSwitch]`, clear the folders' `paused` flags, relaunch: `restorePersistedState()` re-arms only when `triggered` is true. Useful after a trip; before one, the row above is simpler. | low | total, after a trip | not implemented; #16 (signed state) |
| Kill the client | While the client is dead nothing is uploaded, so the server copy is safe. On relaunch without edits a persisted trip re-arms, and an undetected attack is seen in full on the first run and trips with nothing uploaded. | high (families routinely kill backup and sync agents) | none for the server copy by itself; matters only combined with the edits above | by design: fail closed (`SentinelController` constructor) |
| Pause the folders | Set `paused=true` on the folder definitions or drive the UI. Equivalent to killing the client: no upload, nothing gained; unpausing lets the next run trip. | low | none for the server copy | not needed |
| Avoid the canaries | Canary *names* sit in `canaryFiles` in the same file; defaults (`_canary.txt`, `.canary`, `zzz_canary.txt`, `DO_NOT_DELETE.sentinel`, `.killswitch_canary`) are in `canarydetector.cpp`; Sentinel does not create the files. An attacker skips those names. Deleting or renaming them does *not* help: REMOVE or RENAME on a canary is Critical. | medium for a targeted tool, nil for commodity families | the canary signal is silenced; four detectors remain | not planned; one signal among five |
| Chunks sparing header and structural tail | `FormatSignatureDetector::checkFile` reads only the first 4 KB and the tail; `EntropyDetector::isNormallyHighEntropy` skips compressed formats by extension. Probe 4b: not detected per file. | medium: Play/RansomHub-style chunking exists, but the surveyed implementations start at offset 0 and are caught | high: all such files uploaded; server versions hold the originals until purged | #7 open (1 MB-boundary sampling with structural validation) |
| Tail-only damage on trailer-less formats | `.jpg`, `.mp4`, `.mp3` have no mandatory trailer and are entropy-whitelisted. Probe 5b: not detected per file. | low: no surveyed family does this | high for those formats | #8 open |
| Slow encryption below the thresholds | `KillSwitchManager::onWindowTimeout` drops events older than `timeWindow` every second, as do the detectors' own 60 s windows: two counted hits a minute never reach High. The single-file rules are unaffected, so the slow attacker is confined to signature-less files (`.bin`, `.dat`, `.tar`...), new files with a wrong signature, tail-only and middle-chunk damage, and renames that keep the original intact. | low: commodity families optimise for speed | partial, those file classes only | not planned; `timeWindow` is configurable at the price of false positives |
| Encrypt from another device or the web (direction Down) | `FormatSignatureDetector` and `EntropyDetector` return None for `SyncFileItem::Down`; the three name-based detectors ignore direction. Same-name ciphertext from the server is downloaded unchecked over the local clean copy; a `.locked` name, a note or a mass deletion coming down still trips, which preserves this machine's copies. | medium: any infected device on the account | the server copy is damaged before Sentinel sees anything; what survives is the server's versions and, if the trip comes first, this machine's files | partial; #13 (direction-aware events, Down-only backup), #17 |
| Exhaust the versions quota first | Versions never exceed 50 % of free space and in-place encryption roughly doubles the stored size: filling the quota beforehand makes the server purge the clean versions when the ciphertext lands. Matters only with a bypass of the upload block. | low: needs Nextcloud-specific tooling | high: defeats the server-side recovery path | not addressable client-side; #17 phase 2 (named versions are never purged) |
| Upload through a client that is not Sentinel | Read the app password from the keychain (reachable by the user's processes; platform specifics not verified) or reuse a browser session, then PUT the ciphertext over WebDAV. Sentinel never sees it. | low today | total for the server copy; the server still writes versions | out of client scope; #17 (server-held account lock) |

In every row, anything the user can do in the UI (toggle, reset, remove
canaries) the attacker can do with synthetic input or by editing the same
file, and a process with user privileges can patch or replace the client
binary itself (install-directory permissions were not verified).

## 5. Residual risk and what the user must do anyway

Sentinel narrows model A to a handful of files and does not resist model
B. The user remains responsible for:

1. **3-2-1 backups** with one copy offline or immutable, outside the
   account. Server versions are the recovery path for model A, not a
   backup: same credentials, expiry, quota purge.
2. **Server-side retention**: keep versions and trash bin enabled
   (default), set a minimum `versions_retention_obligation`, keep enough
   free quota that versions survive a doubling of the data set.
3. **A test account** for every experiment (`GUIDE-TEST-WINDOWS.md`,
   section 0; `test/scripts/simulate-ransomware.py`): the switch is easy to
   trip on purpose, and a reset uploads whatever is on disk.
4. **No unprotected client on a protected account**: every standard
   desktop, mobile or web session is an upload path Sentinel cannot see.
5. **Administrator alerts** (#17): until the server is told about a trip,
   only the local user knows.
6. **Expect false positives** (#12, #15): a tripped switch is investigated,
   not reflexively reset.

## 6. Hardening options evaluated (from #16)

| Option | What it buys against model B | What it does not |
|---|---|---|
| **Sign the persisted state** (`enabled`, `triggered`, `pausedFolders`) with an HMAC keyed by a keychain secret; a missing or invalid signature counts as triggered (fail closed) | Defeats a blind edit of `nextcloud.cfg`, the cheapest row of section 4; raises the bar from "write an INI file" to "read the keychain and recompute the MAC". Low cost: QtKeychain is already linked in `src/gui`. | A process of the same user can usually read the same keychain entry, so a Sentinel-aware tool recomputes it. Nothing against killing the process or another upload path. |
| **Confirmation when `enabled` flips** (at startup, when the previous run was enabled or triggered and the file now says disabled) | Makes the disable visible instead of silent. | The "previous run" marker lives in the same writable file unless signed; a modal dialog is dismissed with synthetic input. |
| **Server-held pause** (#17): the client reports a trip, the server sets the account read-only until an admin or a second factor clears it, and names the affected versions | The decision leaves the infected machine: erasing local state, killing the client or uploading via another client no longer resumes the damage; named versions resist quota purge; admins are alerted. | Needs a companion server app. Useless if Sentinel is disabled *before* the first damaged file (nothing is reported) and against the undetected classes (#7, #8). |
| **Audit mode** (#15) | Not a hardening; lowers the false-positive cost that drives users to disable protection, the realistic path to the first row of section 4. | Detects, does not pause; one more value an attacker can write. |

None of these stop an attacker with user privileges from killing the
process, and that is acceptable: a dead client uploads nothing. What
matters is a client that uploads damaged files *silently* (disabled before
encrypting) or is bypassed (another upload path); only the server-held
pause addresses the second.

## 7. Assumptions

- The ransomware runs as the user, not as an administrator, and does not
  target Sentinel (model A). Model B is documented, not defended against.
- Versioning and the trash bin are enabled on the server and the account
  has quota headroom.
- The Sentinel client is the only client writing to the account during an
  attack.
- Local encryption runs at the speed of the surveyed families, so the
  first damaged files are discovered within one or two sync runs.
- The user reads the alert and does not reset before the machine is clean.
- The measured table comes from the scenario suite; the full client could
  not be built where the tests ran (`SENTINEL-JOURNAL.md`), so the GUI path
  (`SentinelController`, `application.cpp`) was reviewed, not executed.

## Changelog

- 2026-10-15: first version, for issue #16; reflects the detectors, manager
  and controller as of the 2026-10-15 journal entries.

## References

- [SENTINEL-JOURNAL.md](../SENTINEL-JOURNAL.md): review findings, measured results, known gaps
- [GUIDE-TEST-WINDOWS.md](../GUIDE-TEST-WINDOWS.md): safety rules for testing (section 0)
- Issues: [#7](https://github.com/jlacerte/nextcloud-sentinel/issues/7) chunk sampling,
  [#8](https://github.com/jlacerte/nextcloud-sentinel/issues/8) tail-only on trailer-less formats,
  [#12](https://github.com/jlacerte/nextcloud-sentinel/issues/12) deletion threshold,
  [#13](https://github.com/jlacerte/nextcloud-sentinel/issues/13) server-side (Down) events,
  [#15](https://github.com/jlacerte/nextcloud-sentinel/issues/15) audit mode,
  [#16](https://github.com/jlacerte/nextcloud-sentinel/issues/16) this threat model and hardening,
  [#17](https://github.com/jlacerte/nextcloud-sentinel/issues/17) server integration

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: GPL-2.0-or-later
"""
simulate-ransomware.py - manual validation tool for the Sentinel Kill Switch
============================================================================

This is a QA harness for the Nextcloud Sentinel desktop client. It reproduces,
on disk, the file-change patterns that ransomware produces, so that the Kill
Switch of a REAL running client can be exercised end to end. It never encrypts
anything and has no payload: "damaged" files are simply overwritten with random
bytes, which is what ciphertext looks like to the content detectors. The script
does not talk to the client or the server; the client notices the changes on
its next sync pass, exactly as it would in a real incident.

It only ever writes inside a folder named ``sentinel-sandbox`` that you create
yourself, and it keeps a pristine copy so you can restore everything.

WORKFLOW
--------
1. Create a sub-folder called exactly ``sentinel-sandbox`` inside your local
   Nextcloud sync folder, e.g. ``~/Nextcloud/sentinel-sandbox``.
2. Seed it:
       python3 -I simulate-ransomware.py seed ~/Nextcloud/sentinel-sandbox --yes
   ~40 realistic files are written (docx, xlsx, pdf, png, jpg, mp4, txt, csv,
   md, kdbx; 20 KB - 3 MB) plus a ``_canary.txt``. A backup copy is stored in
   the system temp directory and its path is printed; ``reset`` restores from it.
3. Let the client upload everything and go green. The detectors judge CHANGES
   to files the client already knows about, so this step is essential.
4. Run one attack:
       python3 -I simulate-ransomware.py attack --mode inplace ~/Nextcloud/sentinel-sandbox --yes
   Files are changed at ``--rate`` files per second (default 5) so a sync pass
   can observe the stream rather than one atomic batch.
5. Watch the client: the Kill Switch should pause sync, raise a tray alert and
   list the threat on its settings page. Note how many files it took.
6. Reset the Kill Switch in the client, then restore the sandbox:
       python3 -I simulate-ransomware.py reset ~/Nextcloud/sentinel-sandbox --yes

EXPECTATION PER MODE (which detector should fire)
-------------------------------------------------
rename           LockBit 3.0 / BlackCat / Qilin: content replaced, random
                 9-char extension appended (report.docx -> report.docx.HLJkNskOq).
                 -> PatternDetector (random/double extension).
inplace          Medusa / Clop: whole content replaced, name unchanged.
                 -> FormatSignatureDetector on the first file (header no longer
                    matches the extension and content is random).
header           LockBit 2.0: only the first 4 KB replaced.
                 -> FormatSignatureDetector on the first file.
chunked          Play / RansomHub: alternating 1 MB chunks, first chunk hit;
                 files under 1 MB are replaced whole.
                 -> FormatSignatureDetector on the first file (header hit).
delete-recreate  Content written to name.ext.locked, original deleted.
                 -> PatternDetector (double extension, original deleted).
notes            Drops <ID>.README.txt and RECOVER-<ext>-FILES.txt in each
                 folder; no data file is touched.
                 -> PatternDetector, Critical on the first note.
canary           Overwrites _canary.txt.
                 -> CanaryDetector, Critical immediately.
mass-delete      Deletes --count files (default 15).
                 -> MassDeleteDetector / manager at the 10th delete
                    (default threshold: 10 deletions in 60 s).

SAFETY
------
* The resolved target path must contain a directory component named
  ``sentinel-sandbox`` (override: ``--i-understand-this-destroys-files``).
* The home directory itself and any drive / filesystem root are always refused.
* The plan is printed first; actually writing requires ``--yes`` or typing
  "yes" at the prompt.
* ``--dry-run`` prints the plan and changes nothing.

Only the Python 3 standard library is used (os, random, time, argparse,
zipfile, struct, zlib, shutil, pathlib). Runs on Windows, Linux and macOS.
Run it with ``python3 -I`` so nothing is imported from the sandbox directory.
"""

import argparse
import os
import random
import shutil
import struct
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

KB = 1024
MB = 1024 * KB
SANDBOX_NAME = "sentinel-sandbox"
BACKUP_PREFIX = "sentinel-sandbox-seed-backup"
CANARY_NAME = "_canary.txt"
# Extensions this tool treats as encryptable user data (the canary is handled separately).
DATA_SUFFIXES = (".docx", ".xlsx", ".pdf", ".png", ".jpg", ".mp4", ".txt", ".csv", ".md", ".kdbx")
MODES = ["rename", "inplace", "header", "chunked", "delete-recreate", "notes", "canary", "mass-delete"]


# --------------------------------------------------------------------------- byte / file builders

def random_bytes(size):
    return random.randbytes(size)


def random_extension(length=9):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def build_office(path, payload_size):
    """A minimal but structurally valid OOXML (ZIP) container, like a .docx/.xlsx."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="xml" ContentType="application/xml"/>'
                    '</Types>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        # A chunk of real text so the document is not trivially compressible, plus padding.
        body = ("<document><body>"
                + ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 64)
                + "</body></document>").encode("utf-8")
        zf.writestr("word/document.xml", body)
        zf.writestr("docProps/padding.bin", random_bytes(max(0, payload_size)))


def build_pdf(path, stream_size):
    """A minimal PDF: %PDF- header, one FlateDecode stream, xref and %%EOF trailer."""
    stream = zlib.compress(random_bytes(stream_size))
    parts = []
    parts.append(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    parts.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    parts.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    parts.append(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n")
    parts.append(b"4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream))
    parts.append(stream)
    parts.append(b"\nendstream\nendobj\n")
    body = b"".join(parts)
    xref_pos = len(body)
    body += b"xref\n0 5\n0000000000 65535 f \n"
    body += b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
    body += b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
    path.write_bytes(body)


def _png_chunk(chunk_type, data):
    return (struct.pack(">I", len(data)) + chunk_type + data
            + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF))


def build_png(path, idat_size):
    """A minimal PNG: signature, IHDR, one IDAT and IEND."""
    ihdr = struct.pack(">IIBBBBB", 640, 480, 8, 2, 0, 0, 0)  # 640x480, 8-bit truecolour
    data = (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(random_bytes(idat_size)))
            + _png_chunk(b"IEND", b""))
    path.write_bytes(data)


def build_jpeg(path, scan_size):
    """A minimal JFIF JPEG: SOI, APP0, DQT, SOF0, SOS, scan data, EOI."""
    out = bytearray()
    out += bytes.fromhex("FFD8")
    out += bytes.fromhex("FFE0" "0010" "4A46494600" "0101" "00" "0001" "0001" "0000")  # APP0/JFIF
    out += bytes.fromhex("FFDB" "0043" "00") + bytes([0x10] * 64)                        # DQT
    out += bytes.fromhex("FFC0" "000B" "08" "0001" "0001" "01" "01" "11" "00")           # SOF0
    out += bytes.fromhex("FFDA" "0008" "01" "01" "00" "00" "3F" "00")                    # SOS
    out += random_bytes(scan_size)
    out += bytes.fromhex("FFD9")                                                         # EOI
    path.write_bytes(bytes(out))


def build_mp4(path, mdat_size):
    """A minimal ISO-BMFF file: ftyp box + mdat box."""
    ftyp = struct.pack(">I", 32) + b"ftyp" + b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41"
    mdat = struct.pack(">I", 8 + mdat_size) + b"mdat" + random_bytes(mdat_size)
    path.write_bytes(ftyp + mdat)


def build_kdbx(path, size):
    """A KeePass 2 (KDBX4) file: signature + version, then an encrypted-looking payload."""
    header = bytes.fromhex("03D9A29A67FB4BB5") + struct.pack("<I", 0x00040000)
    path.write_bytes(header + random_bytes(size))


def build_text(path, approx_size, topic=None):
    if topic is None:
        topic = path.stem.replace("-", " ").replace("_", " ").title()
    lines = [
        "Agenda for the weekly planning meeting and the follow-up actions.",
        "The quarterly figures were discussed; the revenue forecast was adjusted.",
        "Bitte die Unterlagen bis Freitag an die Buchhaltung weiterleiten.",
        "Reminder: the backup rotation moves to the new NAS on the 15th.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod.",
    ]
    text = "# %s\n\n" % topic
    i = 0
    while len(text.encode("utf-8")) < approx_size:
        text += "%d. %s\n" % (i + 1, lines[i % len(lines)])
        i += 1
    path.write_bytes(text.encode("utf-8"))


def build_csv(path, approx_size):
    text = "date,account,description,amount,currency\n"
    row = 0
    while len(text.encode("utf-8")) < approx_size:
        text += "2026-%02d-%02d,ACC-%04d,Office supplies line %d,%d.%02d,EUR\n" % (
            1 + row % 12, 1 + row % 28, 1000 + row % 500, row, (row * 7919) % 100000, row % 100)
        row += 1
    path.write_bytes(text.encode("utf-8"))


# A seed plan: (relative path, builder, approx payload size). Mirrors the C++ test sandbox.
def seed_plan():
    plan = [
        ("Documents/report-q1.docx", build_office, 120 * KB),
        ("Documents/report-q2.docx", build_office, 120 * KB),
        ("Documents/proposal.docx", build_office, 200 * KB),
        ("Documents/minutes.docx", build_office, 40 * KB),
        ("Documents/handbook.pdf", build_pdf, 200 * KB),
        ("Documents/contract.pdf", build_pdf, 120 * KB),
        ("Documents/invoice-2026-03.pdf", build_pdf, 50 * KB),
        ("Documents/thesis.pdf", build_pdf, 280 * KB),
        ("Finance/budget.xlsx", build_office, 80 * KB),
        ("Finance/forecast.xlsx", build_office, 80 * KB),
        ("Finance/ledger.xlsx", build_office, 200 * KB),
        ("Finance/expenses.csv", build_csv, 40 * KB),
        ("Finance/accounts.csv", build_csv, 40 * KB),
        ("Photos/diagram.png", build_png, 120 * KB),
        ("Photos/logo.png", build_png, 40 * KB),
        ("Photos/screenshot.png", build_png, 220 * KB),
        ("Media/holiday.mp4", build_mp4, 250 * KB),
        ("Media/demo.mp4", build_mp4, 180 * KB),
        ("Notes/todo.txt", build_text, 30 * KB),
        ("Notes/meeting.txt", build_text, 40 * KB),
        ("Notes/ideas.md", build_text, 30 * KB),
        ("Notes/README.md", build_text, 25 * KB),
        ("Notes/changelog.txt", build_text, 30 * KB),
        ("Vault/passwords.kdbx", build_kdbx, 50 * KB),
        # A few larger files (~3 MB) for the chunked mode.
        ("Large/archive.docx", build_office, 3 * MB),
        ("Large/scan.pdf", build_pdf, 3 * MB),
        ("Large/video.mp4", build_mp4, 3 * MB),
        ("Large/poster.png", build_png, 3 * MB),
    ]
    for i in range(1, 7):
        plan.append(("Photos/IMG_%04d.jpg" % i, build_jpeg, 150 * KB))
    return plan


# --------------------------------------------------------------------------- safety

class RefusedError(Exception):
    pass


def resolve_sandbox(raw_path, override):
    """Resolve and validate the target. Returns an absolute Path or raises RefusedError."""
    target = Path(raw_path).expanduser().resolve()
    parts_lower = [p.lower() for p in target.parts]

    # Never a filesystem / drive root (e.g. "/", "C:\\").
    if target.parent == target or len(target.parts) <= 1:
        raise RefusedError("refusing to operate on a filesystem root: %s" % target)

    # Never the user's home directory itself.
    try:
        if target == Path.home().resolve():
            raise RefusedError("refusing to operate on the home directory itself: %s" % target)
    except (RuntimeError, OSError):
        pass

    if not override and SANDBOX_NAME.lower() not in parts_lower:
        raise RefusedError(
            "target path has no '%s' directory component: %s\n"
            "Create a folder named '%s' inside your sync folder and point me at it,\n"
            "or pass --i-understand-this-destroys-files to override."
            % (SANDBOX_NAME, target, SANDBOX_NAME))
    return target


def backup_dir_for(target):
    """A stable backup location in the system temp dir, keyed to the target path."""
    key = str(target).encode("utf-8")
    digest = "%08x" % (zlib.crc32(key) & 0xFFFFFFFF)
    return Path(tempfile.gettempdir()) / ("%s-%s" % (BACKUP_PREFIX, digest))


def iter_files(root):
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def data_files(root):
    """Seeded user-data files (not the canary), as relative POSIX paths, sorted."""
    result = []
    for path in iter_files(root):
        rel = path.relative_to(root)
        if rel.name == CANARY_NAME:
            continue
        if path.suffix.lower() in DATA_SUFFIXES:
            result.append(rel)
    return result


# --------------------------------------------------------------------------- mutation primitives

def overwrite_whole(path, trailer=b""):
    size = path.stat().st_size
    path.write_bytes(random_bytes(size) + trailer)


def overwrite_range(path, offset, length):
    size = path.stat().st_size
    end = min(size, offset + length)
    if offset >= end:
        return
    with open(path, "r+b") as handle:
        handle.seek(offset)
        handle.write(random_bytes(end - offset))


def throttle(rate):
    if rate and rate > 0:
        time.sleep(1.0 / rate)


# --------------------------------------------------------------------------- commands

def cmd_seed(target, args):
    plan = seed_plan()
    backup = backup_dir_for(target)
    print("Plan: seed %d files into %s" % (len(plan), target))
    print("      keep a pristine backup in %s" % backup)
    if args.dry_run:
        for rel, _builder, size in plan:
            print("  would write %-40s ~%d KB" % (rel, size // KB))
        return 0
    if not confirm(args):
        return 1

    target.mkdir(parents=True, exist_ok=True)
    for rel, builder, size in plan:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        builder(dest, size)
        print("  wrote %s (%d KB)" % (rel, dest.stat().st_size // KB))

    build_text(target / CANARY_NAME, 2 * KB, "Canary file - do not modify or delete")
    print("  wrote %s" % CANARY_NAME)

    if backup.exists():
        shutil.rmtree(backup)
    shutil.copytree(target, backup)
    print("Seeded %d files. Backup kept at: %s" % (len(plan) + 1, backup))
    print("Let the client sync to green, then run an attack.")
    return 0


def cmd_reset(target, args):
    backup = backup_dir_for(target)
    if not backup.exists():
        print("No backup found at %s - cannot reset. Re-run 'seed' first." % backup)
        return 1
    print("Plan: delete the current contents of %s" % target)
    print("      and restore the pristine seed from %s" % backup)
    if args.dry_run:
        print("  (dry run - nothing changed)")
        return 0
    if not confirm(args):
        return 1
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(backup, target)
    print("Restored %d files from the backup." % sum(1 for _ in iter_files(target)))
    print("Remember to reset the Kill Switch in the client if it tripped.")
    return 0


def _select_targets(target, mode, count):
    files = data_files(target)
    if mode == "chunked":
        large = [rel for rel in files if rel.parts and rel.parts[0] == "Large"]
        files = large if large else files
    else:
        files = [rel for rel in files if not (rel.parts and rel.parts[0] == "Large")]
    if count and count > 0:
        files = files[:count]
    return files


def cmd_attack(target, args):
    mode = args.mode
    ext = args.extension or random_extension(9)
    rate = args.rate

    if mode == "canary":
        canary = target / CANARY_NAME
        print("Plan: overwrite the canary %s with random bytes" % CANARY_NAME)
        if args.dry_run:
            return 0
        if not confirm(args):
            return 1
        if not canary.exists():
            print("  canary missing - run 'seed' first")
            return 1
        overwrite_whole(canary)
        print("  overwrote %s" % CANARY_NAME)
        print("Expectation: CanaryDetector raises Critical immediately.")
        return 0

    if mode == "notes":
        folders = sorted({(target / rel).parent for rel in data_files(target)} | {target})
        notes = []
        for folder in folders:
            notes.append(folder / ("%s.README.txt" % ext))
            notes.append(folder / ("RECOVER-%s-FILES.txt" % ext))
        print("Plan: drop %d ransom notes across %d folders (no data files touched)"
              % (len(notes), len(folders)))
        if args.dry_run:
            for note in notes:
                print("  would write %s" % note.relative_to(target))
            return 0
        if not confirm(args):
            return 1
        for note in notes:
            build_text(note, 2 * KB, "YOUR FILES HAVE BEEN ENCRYPTED")
            print("  wrote %s" % note.relative_to(target))
            throttle(rate)
        print("Expectation: PatternDetector raises Critical on the first note.")
        return 0

    if mode == "mass-delete":
        count = args.count if args.count is not None else 15
        victims = _select_targets(target, "inplace", count)
        print("Plan: delete %d files at %.1f/s" % (len(victims), rate))
        if args.dry_run:
            for rel in victims:
                print("  would delete %s" % rel)
            return 0
        if not confirm(args):
            return 1
        for rel in victims:
            (target / rel).unlink()
            print("  deleted %s" % rel)
            throttle(rate)
        print("Expectation: MassDeleteDetector / manager trips at the 10th deletion (default).")
        return 0

    # Content-mutation modes
    count = args.count
    if count is None:
        count = 4 if mode == "chunked" else 10
    victims = _select_targets(target, mode, count)
    print("Plan: mode=%s, %d files, %.1f/s, extension=.%s" % (mode, len(victims), rate, ext))
    if args.dry_run:
        for rel in victims:
            print("  would hit %s" % rel)
        return 0
    if not victims:
        print("  no seeded data files found - run 'seed' first")
        return 1
    if not confirm(args):
        return 1

    for rel in victims:
        path = target / rel
        if mode == "inplace":
            overwrite_whole(path, trailer=b"Clop^_-")
            print("  overwrote (whole) %s" % rel)
        elif mode == "header":
            overwrite_range(path, 0, 4 * KB)
            print("  overwrote (first 4 KB) %s" % rel)
        elif mode == "chunked":
            size = path.stat().st_size
            if size <= MB:
                overwrite_whole(path)
            else:
                offset = 0
                while offset < size:
                    overwrite_range(path, offset, MB)
                    offset += 2 * MB
            print("  overwrote (1 MB chunks) %s" % rel)
        elif mode == "rename":
            overwrite_whole(path)
            new_path = path.with_name(path.name + "." + ext)
            path.rename(new_path)
            print("  encrypted + renamed %s -> %s" % (rel, new_path.name))
        elif mode == "delete-recreate":
            new_path = path.with_name(path.name + ".locked")
            new_path.write_bytes(random_bytes(path.stat().st_size))
            path.unlink()
            print("  wrote %s and deleted %s" % (new_path.relative_to(target), rel))
        throttle(rate)

    expectation = {
        "inplace": "FormatSignatureDetector flags the first file (header no longer matches, random content).",
        "header": "FormatSignatureDetector flags the first file (first 4 KB random).",
        "chunked": "FormatSignatureDetector flags the first file (first chunk hits the header).",
        "rename": "PatternDetector flags the random/double extension within a few files.",
        "delete-recreate": "PatternDetector flags the .locked double extension on the first file.",
    }[mode]
    print("Expectation: %s" % expectation)
    return 0


def confirm(args):
    if args.yes:
        return True
    try:
        answer = input("Type 'yes' to proceed: ").strip().lower()
    except EOFError:
        answer = ""
    if answer == "yes":
        return True
    print("Aborted.")
    return False


# --------------------------------------------------------------------------- CLI

def build_parser():
    parser = argparse.ArgumentParser(
        prog="simulate-ransomware.py",
        description="Manual validation tool for the Nextcloud Sentinel Kill Switch. "
                    "Reproduces ransomware file-change patterns inside a 'sentinel-sandbox' folder.",
        epilog="See the module docstring for the full seed -> sync -> attack -> observe -> reset workflow.")
    parser.add_argument("--i-understand-this-destroys-files", dest="override", action="store_true",
                        help="skip the 'sentinel-sandbox' path check (dangerous)")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("path", help="the sentinel-sandbox folder inside your sync folder")
        sp.add_argument("--yes", action="store_true", help="proceed without the interactive prompt")
        sp.add_argument("--dry-run", action="store_true", help="print the plan and change nothing")

    sp_seed = sub.add_parser("seed", help="create ~40 realistic files + a backup copy")
    add_common(sp_seed)

    sp_attack = sub.add_parser("attack", help="reproduce a ransomware behaviour")
    add_common(sp_attack)
    sp_attack.add_argument("--mode", required=True, choices=MODES, help="which behaviour to reproduce")
    sp_attack.add_argument("--count", type=int, default=None, help="how many files to affect")
    sp_attack.add_argument("--rate", type=float, default=5.0, help="files per second (default 5)")
    sp_attack.add_argument("--extension", default=None,
                           help="extension for rename/notes modes (default: random 9 chars)")

    sp_reset = sub.add_parser("reset", help="restore the sandbox from the seed backup")
    add_common(sp_reset)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = resolve_sandbox(args.path, args.override)
    except RefusedError as error:
        print("REFUSED: %s" % error)
        return 2

    if args.command == "seed":
        return cmd_seed(target, args)
    if args.command == "attack":
        return cmd_attack(target, args)
    if args.command == "reset":
        return cmd_reset(target, args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

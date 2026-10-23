/*
 * Nextcloud Sentinel Edition - Pattern Detector
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../threatdetector.h"
#include <QRegularExpression>
#include <QSet>

namespace OCC {

/**
 * @brief Detects ransomware file patterns via extension and name matching
 *
 * This detector identifies files with known ransomware characteristics:
 * - File extensions commonly used by ransomware (.locked, .encrypted, etc.)
 * - Ransom note patterns (HOW_TO_DECRYPT, <ID>.README.txt, RECOVER-<ext>-FILES.txt, ...)
 * - Double extensions with a known ransomware suffix (.pdf.encrypted, .docx.locked)
 * - Double extensions with a RANDOM per-victim suffix, as appended by modern
 *   RaaS families that no static list can contain: LockBit 3.0/4.0
 *   (invoice.pdf.HLJkNskOq), BlackCat/ALPHV ([a-z0-9]{7}), Qilin/Agenda
 *   (photo.jpg.9_bJ6s6BxF), Black Basta, RansomHub (see looksLikeRandomExtension)
 *
 * Detection criteria:
 * - Single file with a known ransomware extension: Low threat (could be false positive)
 * - Single file with a known double extension: High threat (strong indicator)
 * - Single file with a random-looking extension after a normal one: Medium threat
 *   (less certain than the fixed list; the manager only triggers at High)
 * - >= threshold suspicious files in the window (any of the above, new, modified
 *   or renamed): High threat; >= 2 * threshold: Critical
 * - Ransom note file detected: Critical threat (immediate trigger)
 * - Corroboration: a new/renamed "X.ext.SUFFIX" while the recent events contain a
 *   DELETE of "X.ext" in the same directory is the encrypt-to-new-file-then-delete-
 *   original pattern and escalates the finding by one level
 *
 * New, modified and renamed files are inspected (for a rename, the target
 * name is what matters: "report.docx" -> "report.docx.locked"). A rename that
 * merely appends a random or known ransomware extension to the original name
 * is suspicious even when the original extension is not a "normal" one
 * ("Makefile" -> "Makefile.HLJkNskOq").
 *
 * Ransom note patterns deliberately require a ransom-specific keyword or an
 * exact family-specific name: a plain README.txt or warning.txt exists in
 * countless legitimate folders and must never pause the sync on its own.
 */
class OWNCLOUDSYNC_EXPORT PatternDetector : public ThreatDetector
{
public:
    PatternDetector();

    QString name() const override { return QStringLiteral("PatternDetector"); }

    using ThreatDetector::analyze;
    ThreatInfo analyze(const SyncFileItem &item,
                       const QVector<struct KillSwitchManager::Event> &recentEvents,
                       const AnalysisContext &context) override;

    // Configuration
    void setThreshold(int count) { m_threshold = count; }
    void addCustomExtension(const QString &extension);
    void addCustomPattern(const QString &pattern);

    /**
     * @brief Check if a file has a ransomware extension
     */
    bool hasRansomwareExtension(const QString &filePath) const;

    /**
     * @brief Check if a file matches a ransom note pattern
     */
    bool isRansomNote(const QString &fileName) const;

    /**
     * @brief Check if a file has a suspicious double extension
     * (e.g., document.pdf.encrypted)
     */
    bool hasDoubleExtension(const QString &fileName) const;

    /**
     * @brief Check if an extension (without the leading dot) looks like a
     * random per-victim ransomware extension
     *
     * True when: 6-16 characters of [A-Za-z0-9_-], at least two letters, not a
     * known real extension (allowlist, compared lowercase, plus the
     * "lowercase word + up to 4 digits" shape of versioned formats such as
     * sqlite3, sha256, tax2024), containing no letter at all is never random,
     * and the extension either contains a digit or mixes upper and lower case
     * letters beyond a leading capital. Purely lowercase words (.backup,
     * .torrent) and capitalised words (.Backup) are therefore never random.
     */
    bool looksLikeRandomExtension(const QString &ext) const;

    /**
     * @brief Check for a normal extension followed by a random-looking one
     * (e.g., invoice.pdf.HLJkNskOq, photo.jpg.9_bJ6s6BxF)
     *
     * Hidden files (leading dot) are ignored: rsync and similar tools write
     * ".name.ext.XXXXXX" temporaries with exactly this shape.
     */
    bool hasRandomExtensionAfterNormal(const QString &fileName) const;

private:
    /**
     * @brief Initialize the default ransomware patterns database
     */
    void initializePatterns();

    /**
     * @brief Count suspicious files in recent events
     */
    int countSuspiciousFiles(const QVector<struct KillSwitchManager::Event> &recentEvents) const;

    /**
     * @brief Check if an event path (CREATE/MODIFY/RENAME target) is suspicious
     * by any of the name-based rules (fixed extension, double extension,
     * random extension after a normal one, ransom note)
     */
    bool isSuspiciousPath(const QString &path) const;

    /**
     * @brief For a rename, check whether the target is the original name plus
     * one appended random-looking or known ransomware extension
     * @return the appended extension (without dot) or an empty string
     */
    QString renameAppendedSuspiciousExtension(const QString &from, const QString &to) const;

    /**
     * @brief Check whether the recent events contain a DELETE of the same
     * path without its last extension ("X.ext" for "X.ext.SUFFIX")
     */
    static bool originalWasDeleted(const QString &relativePath,
                                   const QVector<struct KillSwitchManager::Event> &recentEvents);

    int m_threshold = 3; // Number of suspicious files to trigger alert

    // Known ransomware extensions (lowercase for comparison)
    QSet<QString> m_ransomwareExtensions;

    // Ransom note filename patterns
    QVector<QRegularExpression> m_ransomNotePatterns;

    // LockBit 3.0 "<random ID>.README.txt"; the captured ID must look random
    QRegularExpression m_lockBitNotePattern;

    // Normal file extensions that can appear before ransomware extension
    QSet<QString> m_normalExtensions;

    // Real-world extensions (lowercase, no dot) that would otherwise look random
    QSet<QString> m_knownExtensionAllowlist;
};

} // namespace OCC

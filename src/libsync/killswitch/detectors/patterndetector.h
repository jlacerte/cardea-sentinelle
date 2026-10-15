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
 * - Ransom note patterns (HOW_TO_DECRYPT, README_DECRYPT, etc.)
 * - Double extensions (.pdf.encrypted, .docx.locked)
 *
 * Detection criteria:
 * - Single file with ransomware extension: Low threat (could be false positive)
 * - Multiple files with ransomware extensions: High threat
 * - Ransom note file detected: Critical threat (immediate trigger)
 * - Double extension pattern: Medium/High threat depending on count
 *
 * New, modified and renamed files are inspected (for a rename, the target
 * name is what matters: "report.docx" -> "report.docx.locked").
 *
 * Ransom note patterns deliberately require a ransom-specific keyword:
 * a plain README.txt or warning.txt exists in countless legitimate folders
 * and must never pause the sync on its own.
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

private:
    /**
     * @brief Initialize the default ransomware patterns database
     */
    void initializePatterns();

    /**
     * @brief Count suspicious files in recent events
     */
    int countSuspiciousFiles(const QVector<struct KillSwitchManager::Event> &recentEvents) const;

    int m_threshold = 3; // Number of suspicious files to trigger alert

    // Known ransomware extensions (lowercase for comparison)
    QSet<QString> m_ransomwareExtensions;

    // Ransom note filename patterns
    QVector<QRegularExpression> m_ransomNotePatterns;

    // Normal file extensions that can appear before ransomware extension
    QSet<QString> m_normalExtensions;
};

} // namespace OCC

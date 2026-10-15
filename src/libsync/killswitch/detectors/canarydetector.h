/*
 * Nextcloud Sentinel Edition - Canary File Detector
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../threatdetector.h"

namespace OCC {

/**
 * @brief Detects modifications to canary/honeypot files
 *
 * Canary files are decoy files placed in the sync folder that should
 * never be modified by normal user activity. Any modification to these
 * files indicates unauthorized access or malware activity.
 *
 * Detection criteria:
 * - Any modification, deletion, or rename of canary files
 * - Immediate critical alert on any canary file change
 */
class OWNCLOUDSYNC_EXPORT CanaryDetector : public ThreatDetector
{
public:
    CanaryDetector();

    QString name() const override { return QStringLiteral("CanaryDetector"); }

    using ThreatDetector::analyze;
    ThreatInfo analyze(const SyncFileItem &item,
                       const QVector<struct KillSwitchManager::Event> &recentEvents,
                       const AnalysisContext &context) override;

    /**
     * @brief Add a canary file pattern
     * @param pattern Filename or pattern to match (e.g., "_canary.txt", "*.canary")
     */
    void addCanaryPattern(const QString &pattern);

    /**
     * @brief Remove a canary file pattern
     */
    void removeCanaryPattern(const QString &pattern);

    /**
     * @brief Get list of canary patterns
     */
    QStringList canaryPatterns() const { return m_patterns; }

    /**
     * @brief Check if a file matches any canary pattern
     */
    bool isCanaryFile(const QString &filePath) const;

private:
    QStringList m_patterns;
};

} // namespace OCC

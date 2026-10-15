/*
 * Nextcloud Sentinel Edition - Threat Logger
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "killswitchmanager.h"
#include <QObject>
#include <QFile>
#include <QJsonArray>

namespace OCC {

/**
 * @brief ThreatLogger - Logs detected threats to a JSON file
 *
 * This class maintains a persistent log of all threats detected by the
 * Kill Switch system. The log can be used for:
 * - Post-incident analysis
 * - Trend detection
 * - User reporting
 * - Debugging false positives
 *
 * Log format (JSON):
 * {
 *   "threats": [
 *     {
 *       "timestamp": "2026-01-11T15:30:00",
 *       "level": "Critical",
 *       "detector": "PatternDetector",
 *       "description": "Ransom note detected: HOW_TO_DECRYPT.txt",
 *       "files": ["path/to/file1", "path/to/file2"],
 *       "action_taken": "sync_paused"
 *     }
 *   ]
 * }
 */
class OWNCLOUDSYNC_EXPORT ThreatLogger : public QObject
{
    Q_OBJECT

public:
    explicit ThreatLogger(QObject *parent = nullptr);
    ~ThreatLogger() override;

    /**
     * @brief Get the singleton instance
     */
    static ThreatLogger *instance();

    /**
     * @brief Log a detected threat
     */
    void logThreat(const ThreatInfo &threat, const QString &actionTaken = QString());

    /**
     * @brief Get the path to the log file
     */
    QString logFilePath() const;

    /**
     * @brief Get all logged threats
     */
    QVector<ThreatInfo> loadThreats() const;

    /**
     * @brief Get threats from the last N days
     */
    QVector<ThreatInfo> threatsFromLastDays(int days) const;

    /**
     * @brief Clear the threat log
     */
    void clearLog();

    /**
     * @brief Export log to CSV
     */
    bool exportToCsv(const QString &filePath) const;

    /**
     * @brief Get statistics
     */
    struct Statistics {
        int totalThreats = 0;
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        QMap<QString, int> byDetector;
    };
    Statistics getStatistics() const;

private:
    void ensureLogFileExists();
    QJsonArray readLogEntries() const;
    void writeLogEntries(const QJsonArray &entries);
    QString threatLevelToString(ThreatLevel level) const;

    static ThreatLogger *s_instance;
    QString m_logFilePath;

    // The whole file is rewritten on every entry. Keep it bounded: an
    // encryptor touching thousands of files would otherwise turn each log
    // call into a multi-megabyte rewrite.
    static constexpr int MAX_LOG_ENTRIES = 2000;
};

} // namespace OCC

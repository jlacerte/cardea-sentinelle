/*
 * Nextcloud Sentinel Edition - Threat Logger
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "killswitchmanager.h"
#include <QObject>
#include <QJsonObject>
#include <QMap>
#include <QVector>

#include <functional>

namespace OCC {

/**
 * @brief ThreatLogger - Logs detected threats to an append-only JSON Lines file
 *
 * This class maintains a persistent log of all threats detected by the
 * Kill Switch system. The log can be used for:
 * - Post-incident analysis
 * - Trend detection
 * - User reporting
 * - Debugging false positives
 *
 * Log format (JSON Lines, `sentinel-threats.jsonl`): one JSON object per
 * line, appended in O(1) without ever re-reading the file:
 *
 *   {"timestamp":"2026-01-11T15:30:00.000","level":"Critical",
 *    "detector":"PatternDetector","description":"Ransom note detected: HOW_TO_DECRYPT.txt",
 *    "files":["path/to/file1","path/to/file2"],"action_taken":"sync_paused"}
 *
 * Rotation: before an append, if the current file is larger than
 * rotationSizeBytes() (5 MB by default) it is renamed to
 * `sentinel-threats.1.jsonl`, replacing any older rotated file. Readers
 * walk the rotated file first and the current file second, so the history
 * stays continuous across a rotation.
 *
 * Migration: a legacy `sentinel-threats.json` ({"threats":[...]}) found on
 * construction is converted into the JSON Lines file once and renamed to
 * `sentinel-threats.json.migrated`.
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
     * @brief Log a detected threat (one appended line, O(1))
     */
    void logThreat(const ThreatInfo &threat, const QString &actionTaken = QString());

    /**
     * @brief Get the path to the current log file
     */
    QString logFilePath() const;

    /**
     * @brief Get the path of the rotated (previous generation) log file
     */
    QString rotatedLogFilePath() const;

    /**
     * @brief Get the path of the legacy single-document JSON log
     */
    QString legacyLogFilePath() const;

    /**
     * @brief Get all logged threats, oldest first (at most the last MAX_LOADED_ENTRIES)
     */
    QVector<ThreatInfo> loadThreats() const;

    /**
     * @brief Get threats from the last N days
     */
    QVector<ThreatInfo> threatsFromLastDays(int days) const;

    /**
     * @brief Clear the threat log (current and rotated file)
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

    /**
     * @brief Size (bytes) above which the current file is rotated before the next append
     */
    void setRotationSizeBytes(qint64 bytes);
    qint64 rotationSizeBytes() const { return m_rotationSizeBytes; }

    /// Default rotation threshold: 5 MB
    static constexpr qint64 DEFAULT_ROTATION_SIZE_BYTES = 5LL * 1024 * 1024;

    /// loadThreats() never returns more than this many (most recent) entries
    static constexpr int MAX_LOADED_ENTRIES = 10000;

private:
    void ensureLogFileExists();
    void migrateLegacyLog();
    void rotateIfNeeded();
    bool appendLine(const QByteArray &line);

    QJsonObject entryFromThreat(const ThreatInfo &threat, const QString &actionTaken) const;
    static bool threatFromEntry(const QJsonObject &entry, ThreatInfo &threat);

    /**
     * @brief Walk every valid entry of the rotated file then the current file, oldest first
     *
     * Malformed lines are skipped with a warning.
     */
    void forEachEntry(const std::function<void(const QJsonObject &)> &visitor) const;
    void forEachEntryInFile(const QString &path, const std::function<void(const QJsonObject &)> &visitor) const;

    QString threatLevelToString(ThreatLevel level) const;
    static ThreatLevel threatLevelFromString(const QString &level);

    static ThreatLogger *s_instance;
    QString m_logFilePath;
    QString m_rotatedLogFilePath;
    QString m_legacyLogFilePath;
    qint64 m_rotationSizeBytes = DEFAULT_ROTATION_SIZE_BYTES;
};

} // namespace OCC

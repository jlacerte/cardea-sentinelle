/*
 * Nextcloud Sentinel Edition - Kill Switch Manager
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "owncloudlib.h"

#include <QObject>
#include <QVector>
#include <QTimer>
#include <QDateTime>
#include <QRecursiveMutex>
#include <memory>

namespace OCC {

class SyncFileItem;
class ThreatDetector;
class SyncAction;

/**
 * @brief Threat level enumeration
 */
enum class ThreatLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @brief Operating mode of the kill switch
 *
 * Protect: a High/Critical finding trips the switch, the registered actions
 *          run, syncPaused() is emitted and every item is blocked until the
 *          user resets.
 * Audit:   detectors run and log exactly as in Protect mode, but a finding
 *          that would have tripped the switch is only recorded (see
 *          auditTriggers()) and announced through auditTriggered(). Nothing
 *          is paused or blocked and no action is executed. This is meant for
 *          calibrating thresholds on real users without inflicting
 *          false-positive pauses.
 */
enum class KillSwitchMode {
    Protect = 0,
    Audit = 1
};

/**
 * @brief Structure describing a detected threat
 */
struct OWNCLOUDSYNC_EXPORT ThreatInfo {
    ThreatLevel level = ThreatLevel::None;
    QString detectorName;
    QString description;
    QStringList affectedFiles;
    QDateTime timestamp;
};

/**
 * @brief Per-call context handed to the detectors
 *
 * SyncFileItem::_file is relative to the sync folder root. Detectors that
 * need to read the file from disk (entropy analysis) or to hand a usable
 * path to the response actions (backup) resolve it through this context.
 */
struct OWNCLOUDSYNC_EXPORT AnalysisContext {
    /// Absolute path of the sync folder root (with or without trailing slash). May be empty in unit tests.
    QString localRootPath;

    /// Resolve a sync-relative path to an absolute local path. Returns the input unchanged when no root is known.
    QString localPath(const QString &relativePath) const
    {
        if (localRootPath.isEmpty() || relativePath.isEmpty()) {
            return relativePath;
        }
        if (localRootPath.endsWith(QLatin1Char('/')) || relativePath.startsWith(QLatin1Char('/'))) {
            return localRootPath + relativePath;
        }
        return localRootPath + QLatin1Char('/') + relativePath;
    }
};

/**
 * @brief Kill Switch Manager - Central threat detection and response coordinator
 *
 * This class coordinates multiple threat detectors and manages the response
 * to potential ransomware or mass deletion attacks. It can pause synchronization,
 * create backups, and alert the user.
 *
 * There is exactly one manager per process (see instance()). All sync engines
 * feed their items into it, so an attack spread across several sync folders
 * is still seen as one event stream.
 *
 * Architecture:
 *   KillSwitchManager
 *     ├── ThreatDetector[] (analyzers)
 *     │   ├── MassDeleteDetector
 *     │   ├── EntropyDetector
 *     │   ├── CanaryDetector
 *     │   └── PatternDetector
 *     └── SyncAction[] (responses)
 *         ├── BackupAction
 *         └── (sync pause / alerts are driven through signals)
 */
class OWNCLOUDSYNC_EXPORT KillSwitchManager : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool enabled READ isEnabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(bool triggered READ isTriggered NOTIFY triggeredChanged)
    Q_PROPERTY(ThreatLevel currentThreatLevel READ currentThreatLevel NOTIFY threatLevelChanged)

public:
    /**
     * @brief Event structure for tracking file operations
     *
     * type is one of "DELETE", "CREATE", "MODIFY", "RENAME".
     * path is the sync-relative path (for renames: the rename target).
     */
    struct Event {
        QDateTime timestamp;
        QString type;
        QString path;
    };

    explicit KillSwitchManager(QObject *parent = nullptr);
    ~KillSwitchManager() override;

    /**
     * @brief Get the singleton instance (nullptr if none was created)
     */
    static KillSwitchManager *instance();

    /**
     * @brief Check if kill switch protection is enabled
     */
    bool isEnabled() const;

    /**
     * @brief Enable or disable kill switch protection
     */
    void setEnabled(bool enabled);

    /**
     * @brief Check if the kill switch has been triggered
     *
     * Never becomes true through analysis while in Audit mode. A trigger that
     * happened in Protect mode survives a switch to Audit mode until reset().
     */
    bool isTriggered() const;

    /**
     * @brief Current operating mode (default: Protect)
     */
    KillSwitchMode mode() const;

    /**
     * @brief Switch between Protect and Audit mode
     *
     * Switching from Audit to Protect never trips the switch retroactively,
     * even if a would-be trigger was recorded a moment ago. Switching from
     * Protect to Audit while triggered keeps the triggered state (the sync
     * stays paused) until the user calls reset().
     */
    void setMode(KillSwitchMode mode);

    /**
     * @brief Number of would-be triggers recorded in Audit mode
     *
     * Counts every would-be trigger since the last clearAuditTriggers(),
     * even those no longer held by auditTriggers().
     */
    int auditTriggerCount() const;

    /**
     * @brief The most recent would-be triggers recorded in Audit mode (at most 1000)
     */
    QVector<ThreatInfo> auditTriggers() const;

    /**
     * @brief Forget the would-be triggers recorded in Audit mode
     */
    void clearAuditTriggers();

    /**
     * @brief Persisted setting value for a mode ("protect" / "audit")
     */
    static QString modeToString(KillSwitchMode mode);

    /**
     * @brief Parse a persisted mode value; anything unknown maps to Protect
     */
    static KillSwitchMode modeFromString(const QString &value);

    /**
     * @brief Get the current threat level
     */
    ThreatLevel currentThreatLevel() const;

    /**
     * @brief Register a threat detector
     *
     * A detector keeps whatever it was configured with; the manager's own
     * setters (setDeleteThreshold, setEntropyThreshold, addCanaryFile, ...)
     * propagate to the registered detectors when they are called.
     */
    void registerDetector(std::shared_ptr<ThreatDetector> detector);

    /**
     * @brief Register a sync action to execute on threat detection
     */
    void registerAction(std::shared_ptr<SyncAction> action);

    /**
     * @brief Analyze a sync item for threats
     * @param item The sync file item to analyze
     * @param context Where the item lives on disk (sync folder root)
     * @return true if the item should be blocked (never in Audit mode, unless
     *         the switch was already tripped in Protect mode)
     */
    bool analyzeItem(const SyncFileItem &item, const AnalysisContext &context = AnalysisContext());

    /**
     * @brief Analyze a batch of sync items
     * @param items Vector of sync items to analyze
     * @param context Where the items live on disk (sync folder root)
     * @return true if sync should be paused
     */
    bool analyzeBatch(const QVector<SyncFileItem> &items, const AnalysisContext &context = AnalysisContext());

    /**
     * @brief Manually trigger the kill switch
     * @param reason The reason for triggering
     */
    void trigger(const QString &reason);

    /**
     * @brief Trigger the kill switch for a detected threat.
     *
     * The threat (including its affected files) is handed to the registered
     * actions, so e.g. the backup action knows what to back up.
     *
     * In Audit mode this only records the would-be trigger and emits
     * auditTriggered(); the switch is not tripped and no action runs.
     */
    void trigger(const ThreatInfo &threat);

    /**
     * @brief Reset the kill switch after user confirmation
     */
    void reset();

    /**
     * @brief Get the list of detected threats
     */
    QVector<ThreatInfo> threats() const;

    // Configuration (propagated to the matching detectors/actions)
    void setDeleteThreshold(int count, int windowSeconds);
    int deleteThreshold() const { return m_deleteThreshold; }
    int windowSeconds() const { return m_windowSeconds; }
    void setEntropyThreshold(double threshold);
    double entropyThreshold() const { return m_entropyThreshold; }
    void addCanaryFile(const QString &filename);
    void removeCanaryFile(const QString &filename);
    QStringList canaryFiles() const { return m_canaryFiles; }
    void setAutoBackup(bool enabled);
    bool autoBackup() const { return m_autoBackup; }

signals:
    void enabledChanged(bool enabled);
    void modeChanged(KillSwitchMode mode);
    void triggeredChanged(bool triggered);
    void threatLevelChanged(ThreatLevel level);
    void threatDetected(const ThreatInfo &threat);
    void syncPaused(const QString &reason);
    void syncResumed();
    void backupCreated(const QString &path);

    /**
     * @brief Emitted in Audit mode for every finding that would have tripped the switch
     */
    void auditTriggered(const ThreatInfo &threat);

private slots:
    void onWindowTimeout();
    void evaluateThreatLevel();

private:
    void executeActions(const ThreatInfo &threat);
    void recordAuditTrigger(const ThreatInfo &threat);
    void recordEvent(const QString &eventType, const QString &path);

    static KillSwitchManager *s_instance;

    bool m_enabled = true;
    bool m_triggered = false;
    KillSwitchMode m_mode = KillSwitchMode::Protect;
    ThreatLevel m_threatLevel = ThreatLevel::None;

    // Audit mode bookkeeping
    static constexpr int MaxAuditTriggers = 1000;
    QVector<ThreatInfo> m_auditTriggers;
    int m_auditTriggerCount = 0;

    QVector<std::shared_ptr<ThreatDetector>> m_detectors;
    QVector<std::shared_ptr<SyncAction>> m_actions;
    QVector<ThreatInfo> m_threats;

    // Event tracking
    QVector<Event> m_recentEvents;
    QTimer m_windowTimer;
    mutable QRecursiveMutex m_mutex;

    // Configuration
    int m_deleteThreshold = 10;
    int m_windowSeconds = 60;
    double m_entropyThreshold = 7.5;
    QStringList m_canaryFiles;
    bool m_autoBackup = true;
};

} // namespace OCC

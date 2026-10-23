/*
 * Nextcloud Sentinel Edition - Kill Switch Manager Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "killswitchmanager.h"
#include "threatdetector.h"
#include "actions/syncaction.h"
#include "actions/backupaction.h"
#include "detectors/canarydetector.h"
#include "detectors/entropydetector.h"
#include "detectors/massdeletedetector.h"
#include "syncfileitem.h"

#include <QLoggingCategory>
#include <QMutexLocker>
#include <algorithm>
#include <utility>

namespace OCC {

Q_LOGGING_CATEGORY(lcKillSwitch, "nextcloud.sync.killswitch", QtInfoMsg)

KillSwitchManager *KillSwitchManager::s_instance = nullptr;

KillSwitchManager::KillSwitchManager(QObject *parent)
    : QObject(parent)
{
    if (s_instance && s_instance != this) {
        // A second manager silently stealing the singleton slot means the
        // GUI, the logger and the sync engines no longer talk to the same
        // object. Only unit tests should ever get here.
        qCWarning(lcKillSwitch) << "A KillSwitchManager already exists - replacing the global instance";
    }
    s_instance = this;

    // Setup window timer for event expiration
    m_windowTimer.setInterval(1000); // Check every second
    connect(&m_windowTimer, &QTimer::timeout, this, &KillSwitchManager::onWindowTimeout);
    m_windowTimer.start();

    qCInfo(lcKillSwitch) << "Kill Switch Manager initialized";
}

KillSwitchManager::~KillSwitchManager()
{
    // Stop the window timer to prevent callbacks on destroyed object
    m_windowTimer.stop();

    if (s_instance == this) {
        s_instance = nullptr;
    }
}

KillSwitchManager *KillSwitchManager::instance()
{
    return s_instance;
}

bool KillSwitchManager::isEnabled() const
{
    return m_enabled;
}

void KillSwitchManager::setEnabled(bool enabled)
{
    if (m_enabled != enabled) {
        m_enabled = enabled;
        qCInfo(lcKillSwitch) << "Kill Switch" << (enabled ? "enabled" : "disabled");
        emit enabledChanged(enabled);
    }
}

bool KillSwitchManager::isTriggered() const
{
    QMutexLocker locker(&m_mutex);
    return m_triggered;
}

ThreatLevel KillSwitchManager::currentThreatLevel() const
{
    QMutexLocker locker(&m_mutex);
    return m_threatLevel;
}

KillSwitchMode KillSwitchManager::mode() const
{
    QMutexLocker locker(&m_mutex);
    return m_mode;
}

void KillSwitchManager::setMode(KillSwitchMode mode)
{
    QMutexLocker locker(&m_mutex);
    if (m_mode == mode) {
        return;
    }
    m_mode = mode;

    // Deliberately nothing else: switching back to Protect must not trip the
    // switch for a would-be trigger that was recorded in Audit mode, and
    // switching to Audit while triggered keeps the sync paused until the
    // user has looked at the alert and reset.
    if (mode == KillSwitchMode::Audit) {
        qCWarning(lcKillSwitch) << "Kill Switch switched to AUDIT mode: threats are logged, sync is never paused";
        if (m_triggered) {
            qCWarning(lcKillSwitch) << "Kill Switch is currently triggered; it stays triggered until reset";
        }
    } else {
        qCInfo(lcKillSwitch) << "Kill Switch switched to PROTECT mode";
    }
    emit modeChanged(mode);
}

int KillSwitchManager::auditTriggerCount() const
{
    QMutexLocker locker(&m_mutex);
    return m_auditTriggerCount;
}

QVector<ThreatInfo> KillSwitchManager::auditTriggers() const
{
    QMutexLocker locker(&m_mutex);
    return m_auditTriggers;
}

void KillSwitchManager::clearAuditTriggers()
{
    QMutexLocker locker(&m_mutex);
    if (m_auditTriggerCount == 0 && m_auditTriggers.isEmpty()) {
        return;
    }
    qCInfo(lcKillSwitch) << "Cleared" << m_auditTriggerCount << "audit would-be trigger(s)";
    m_auditTriggers.clear();
    m_auditTriggerCount = 0;
}

QString KillSwitchManager::modeToString(KillSwitchMode mode)
{
    return mode == KillSwitchMode::Audit ? QStringLiteral("audit") : QStringLiteral("protect");
}

KillSwitchMode KillSwitchManager::modeFromString(const QString &value)
{
    return value.trimmed().compare(QStringLiteral("audit"), Qt::CaseInsensitive) == 0
        ? KillSwitchMode::Audit
        : KillSwitchMode::Protect;
}

void KillSwitchManager::registerDetector(std::shared_ptr<ThreatDetector> detector)
{
    if (!detector) {
        return;
    }
    QMutexLocker locker(&m_mutex);
    m_detectors.append(detector);
    qCInfo(lcKillSwitch) << "Registered detector:" << detector->name();
}

void KillSwitchManager::registerAction(std::shared_ptr<SyncAction> action)
{
    if (!action) {
        return;
    }
    QMutexLocker locker(&m_mutex);
    m_actions.append(action);
    qCInfo(lcKillSwitch) << "Registered action:" << action->name();
}

bool KillSwitchManager::analyzeItem(const SyncFileItem &item, const AnalysisContext &context)
{
    if (!m_enabled) {
        return false;
    }

    QMutexLocker locker(&m_mutex);

    if (m_triggered) {
        return true; // Block everything until the user resets
    }

    // Record the event
    QString eventType;
    QString eventPath = item._file;
    switch (item._instruction) {
    case CSYNC_INSTRUCTION_REMOVE:
        eventType = QStringLiteral("DELETE");
        break;
    case CSYNC_INSTRUCTION_NEW:
        eventType = QStringLiteral("CREATE");
        break;
    case CSYNC_INSTRUCTION_SYNC:
    case CSYNC_INSTRUCTION_CONFLICT:
        eventType = QStringLiteral("MODIFY");
        break;
    case CSYNC_INSTRUCTION_RENAME:
        // Ransomware commonly renames "report.docx" to "report.docx.locked".
        // The interesting name is the rename target.
        eventType = QStringLiteral("RENAME");
        if (!item._renameTarget.isEmpty()) {
            eventPath = item._renameTarget;
        }
        break;
    default:
        return false; // No threat from other operations
    }

    recordEvent(eventType, eventPath);

    // Detectors run sequentially on purpose: three of the four are a few
    // microseconds of string matching, only the entropy detector does I/O,
    // and the caller has to wait for all of them anyway. Dispatching four
    // thread-pool tasks per sync item costs far more than it saves and the
    // detectors are not written to be used from several threads at once.
    const QVector<Event> events = m_recentEvents;

    ThreatInfo highestThreat;

    for (const auto &detector : std::as_const(m_detectors)) {
        ThreatInfo threat = detector->analyze(item, events, context);
        if (threat.level == ThreatLevel::None) {
            continue;
        }

        threat.timestamp = QDateTime::currentDateTime();
        m_threats.append(threat);

        qCWarning(lcKillSwitch) << "Threat detected by" << threat.detectorName
                                << "- Level:" << static_cast<int>(threat.level)
                                << "- " << threat.description;

        emit threatDetected(threat);

        // Track highest threat level found
        if (threat.level > highestThreat.level) {
            highestThreat = threat;
        }
    }

    // Trigger on highest threat if High or Critical
    if (highestThreat.level >= ThreatLevel::High) {
        trigger(highestThreat);
        if (m_mode == KillSwitchMode::Protect) {
            return true; // Block this item
        }
        // Audit mode: trigger() only recorded the would-be trigger. Nothing
        // is blocked; fall through so the threat level keeps being updated.
    }

    evaluateThreatLevel();
    return false;
}

bool KillSwitchManager::analyzeBatch(const QVector<SyncFileItem> &items, const AnalysisContext &context)
{
    if (!m_enabled) {
        return false;
    }

    // Count deletions in this batch
    int deleteCount = 0;
    for (const auto &item : items) {
        if (item._instruction == CSYNC_INSTRUCTION_REMOVE) {
            deleteCount++;
        }
    }

    // Immediate trigger on massive batch deletion
    if (deleteCount > m_deleteThreshold * 2) {
        trigger(QStringLiteral("Massive batch deletion detected: %1 files").arg(deleteCount));
        if (mode() == KillSwitchMode::Protect) {
            return true;
        }
        // Audit mode: recorded only, still run the per-item detectors so
        // their findings are logged as usual.
    }

    // Analyze each item
    for (const auto &item : items) {
        if (analyzeItem(item, context)) {
            return true;
        }
    }

    return isTriggered();
}

void KillSwitchManager::trigger(const QString &reason)
{
    ThreatInfo threat;
    threat.level = ThreatLevel::Critical;
    threat.detectorName = QStringLiteral("KillSwitchManager");
    threat.description = reason;
    threat.timestamp = QDateTime::currentDateTime();
    trigger(threat);
}

void KillSwitchManager::trigger(const ThreatInfo &threat)
{
    QMutexLocker locker(&m_mutex);

    if (m_triggered) {
        return; // Already triggered
    }

    ThreatInfo triggerInfo = threat;
    triggerInfo.level = ThreatLevel::Critical;
    if (!triggerInfo.timestamp.isValid()) {
        triggerInfo.timestamp = QDateTime::currentDateTime();
    }

    if (m_mode == KillSwitchMode::Audit) {
        // Detect and tell, but never pause: record what would have happened.
        recordAuditTrigger(triggerInfo);
        return;
    }

    m_triggered = true;
    m_threatLevel = ThreatLevel::Critical;

    qCCritical(lcKillSwitch) << "!!! KILL SWITCH TRIGGERED !!!";
    qCCritical(lcKillSwitch) << "Reason:" << threat.description
                             << "- Detector:" << threat.detectorName
                             << "- Files:" << threat.affectedFiles.size();

    // Execute all registered actions
    executeActions(triggerInfo);

    emit triggeredChanged(true);
    emit threatLevelChanged(m_threatLevel);
    emit syncPaused(triggerInfo.description);
}

void KillSwitchManager::reset()
{
    QMutexLocker locker(&m_mutex);

    m_triggered = false;
    m_threatLevel = ThreatLevel::None;
    m_threats.clear();
    m_recentEvents.clear();
    for (const auto &detector : std::as_const(m_detectors)) {
        detector->reset();
    }

    qCInfo(lcKillSwitch) << "Kill Switch reset by user";

    emit triggeredChanged(false);
    emit threatLevelChanged(m_threatLevel);
    emit syncResumed();
}

QVector<ThreatInfo> KillSwitchManager::threats() const
{
    QMutexLocker locker(&m_mutex);
    return m_threats;
}

void KillSwitchManager::setDeleteThreshold(int count, int windowSeconds)
{
    QMutexLocker locker(&m_mutex);
    m_deleteThreshold = qMax(1, count);
    m_windowSeconds = qMax(1, windowSeconds);
    for (const auto &detector : std::as_const(m_detectors)) {
        if (auto *massDelete = dynamic_cast<MassDeleteDetector *>(detector.get())) {
            massDelete->setThreshold(m_deleteThreshold);
        }
    }
    qCInfo(lcKillSwitch) << "Delete threshold set to" << m_deleteThreshold << "files in" << m_windowSeconds << "seconds";
}

void KillSwitchManager::setEntropyThreshold(double threshold)
{
    QMutexLocker locker(&m_mutex);
    m_entropyThreshold = threshold;
    for (const auto &detector : std::as_const(m_detectors)) {
        if (auto *entropy = dynamic_cast<EntropyDetector *>(detector.get())) {
            entropy->setSuspiciousEntropyThreshold(threshold);
        }
    }
    qCInfo(lcKillSwitch) << "Entropy threshold set to" << threshold;
}

void KillSwitchManager::addCanaryFile(const QString &filename)
{
    if (filename.trimmed().isEmpty()) {
        return;
    }
    QMutexLocker locker(&m_mutex);
    if (!m_canaryFiles.contains(filename)) {
        m_canaryFiles.append(filename);
        qCInfo(lcKillSwitch) << "Added canary file:" << filename;
    }
    for (const auto &detector : std::as_const(m_detectors)) {
        if (auto *canary = dynamic_cast<CanaryDetector *>(detector.get())) {
            canary->addCanaryPattern(filename);
        }
    }
}

void KillSwitchManager::removeCanaryFile(const QString &filename)
{
    QMutexLocker locker(&m_mutex);
    m_canaryFiles.removeAll(filename);
    for (const auto &detector : std::as_const(m_detectors)) {
        if (auto *canary = dynamic_cast<CanaryDetector *>(detector.get())) {
            canary->removeCanaryPattern(filename);
        }
    }
    qCInfo(lcKillSwitch) << "Removed canary file:" << filename;
}

void KillSwitchManager::setAutoBackup(bool enabled)
{
    QMutexLocker locker(&m_mutex);
    m_autoBackup = enabled;
    for (const auto &action : std::as_const(m_actions)) {
        if (auto *backup = dynamic_cast<BackupAction *>(action.get())) {
            backup->setEnabled(enabled);
        }
    }
    qCInfo(lcKillSwitch) << "Auto-backup" << (enabled ? "enabled" : "disabled");
}

void KillSwitchManager::onWindowTimeout()
{
    QMutexLocker locker(&m_mutex);

    // Remove events older than the window
    QDateTime cutoff = QDateTime::currentDateTime().addSecs(-m_windowSeconds);
    m_recentEvents.erase(
        std::remove_if(m_recentEvents.begin(), m_recentEvents.end(),
                       [&cutoff](const Event &e) { return e.timestamp < cutoff; }),
        m_recentEvents.end());
}

void KillSwitchManager::evaluateThreatLevel()
{
    // Count recent deletions
    int deleteCount = 0;
    for (const auto &event : std::as_const(m_recentEvents)) {
        if (event.type == QStringLiteral("DELETE")) {
            deleteCount++;
        }
    }

    ThreatLevel newLevel = ThreatLevel::None;

    if (deleteCount >= m_deleteThreshold) {
        newLevel = ThreatLevel::Critical;
    } else if (deleteCount >= m_deleteThreshold * 0.7) {
        newLevel = ThreatLevel::High;
    } else if (deleteCount >= m_deleteThreshold * 0.5) {
        newLevel = ThreatLevel::Medium;
    } else if (deleteCount >= m_deleteThreshold * 0.3) {
        newLevel = ThreatLevel::Low;
    }

    if (newLevel != m_threatLevel) {
        m_threatLevel = newLevel;
        emit threatLevelChanged(newLevel);

        if (newLevel >= ThreatLevel::Critical && !m_triggered) {
            trigger(QStringLiteral("Deletion threshold exceeded: %1 files in %2 seconds")
                        .arg(deleteCount)
                        .arg(m_windowSeconds));
        }
    }
}

void KillSwitchManager::executeActions(const ThreatInfo &threat)
{
    for (const auto &action : std::as_const(m_actions)) {
        if (!action->isEnabled()) {
            continue;
        }
        qCInfo(lcKillSwitch) << "Executing action:" << action->name();
        action->execute(threat);
    }
}

void KillSwitchManager::recordAuditTrigger(const ThreatInfo &threat)
{
    // Caller holds m_mutex.
    if (m_auditTriggers.size() >= MaxAuditTriggers) {
        m_auditTriggers.removeFirst(); // Keep the most recent ones
    }
    m_auditTriggers.append(threat);
    ++m_auditTriggerCount;

    qCWarning(lcKillSwitch) << "AUDIT: would have triggered the Kill Switch (#" << m_auditTriggerCount << ")"
                            << "- Reason:" << threat.description
                            << "- Detector:" << threat.detectorName
                            << "- Files:" << threat.affectedFiles.size();

    emit auditTriggered(threat);
}

void KillSwitchManager::recordEvent(const QString &eventType, const QString &path)
{
    Event event;
    event.timestamp = QDateTime::currentDateTime();
    event.type = eventType;
    event.path = path;
    m_recentEvents.append(event);
}

} // namespace OCC

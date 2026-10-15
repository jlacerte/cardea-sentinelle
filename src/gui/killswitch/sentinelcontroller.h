/*
 * Nextcloud Sentinel Edition - Kill Switch GUI Controller
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "folder.h"

#include <QDateTime>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QStringList>

namespace OCC {

class KillSwitchManager;
class KillSwitchAlertDialog;

/**
 * @brief Translates Kill Switch decisions into user-facing client behaviour
 *
 * KillSwitchManager lives in libsync and only knows how to emit signals.
 * This controller is the GUI side of the kill switch:
 *
 * - on KillSwitchManager::syncPaused() every sync folder that is not already
 *   paused by the user is paused (Folder::setSyncPaused(true)), a running
 *   sync is terminated, and the KillSwitchAlertDialog is raised without
 *   blocking the caller (the signal is emitted from inside the sync engine).
 * - folders added while the kill switch is triggered are paused as well.
 * - on KillSwitchManager::syncResumed() only the folders paused by this
 *   controller are resumed; folders the user paused stay paused.
 * - on KillSwitchManager::auditTriggered() (Audit mode, see KillSwitchMode)
 *   the controller deliberately does nothing but log: audit mode exists to
 *   calibrate thresholds on real users without nagging them, so no folder
 *   is paused and no dialog is raised. The would-be trigger counter on the
 *   Kill Switch settings page and the log are the user-facing side of it.
 */
class SentinelController : public QObject
{
    Q_OBJECT

public:
    explicit SentinelController(KillSwitchManager *manager, QObject *parent = nullptr);
    ~SentinelController() override;

    /** Aliases of the folders currently paused by the controller (not by the user). */
    [[nodiscard]] QStringList pausedFolderAliases() const;

private slots:
    void slotSyncPaused(const QString &reason);
    void slotSyncResumed();
    void slotFolderListChanged(const OCC::Folder::Map &folderMap);

private:
    void pauseFolder(Folder *folder);
    void pauseAllFolders();
    void terminateRunningSyncs();
    void showAlertDialog(const QString &reason);
    void closeAlertDialog();

    /**
     * The triggered state is persisted so that killing and restarting the
     * client (which a ransomware operator, or a panicking user, may do)
     * does not silently resume the upload: on startup a persisted trigger
     * re-trips the manager and the dialog comes back.
     */
    void persistTriggeredState(const QString &reason);
    void clearPersistedState();
    void restorePersistedState();

    QPointer<KillSwitchManager> _manager;
    QPointer<KillSwitchAlertDialog> _alertDialog;
    QSet<QString> _pausedByController;
    QDateTime _lastReset;
};

} // namespace OCC

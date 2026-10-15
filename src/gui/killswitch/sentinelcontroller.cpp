/*
 * Nextcloud Sentinel Edition - Kill Switch GUI Controller Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sentinelcontroller.h"
#include "killswitchalertdialog.h"

#include "configfile.h"
#include "folder.h"
#include "folderman.h"
#include "owncloudgui.h"
#include "libsync/killswitch/killswitchmanager.h"

#include <QDateTime>
#include <QLoggingCategory>
#include <QTimer>

namespace OCC {

Q_LOGGING_CATEGORY(lcSentinelController, "nextcloud.gui.killswitch.controller", QtInfoMsg)

SentinelController::SentinelController(KillSwitchManager *manager, QObject *parent)
    : QObject(parent)
    , _manager(manager)
{
    if (!_manager) {
        qCWarning(lcSentinelController) << "No Kill Switch manager, controller is inactive";
        return;
    }

    connect(_manager.data(), &KillSwitchManager::syncPaused,
            this, &SentinelController::slotSyncPaused);
    connect(_manager.data(), &KillSwitchManager::syncResumed,
            this, &SentinelController::slotSyncResumed);

    if (auto *folderMan = FolderMan::instance()) {
        connect(folderMan, &FolderMan::folderListChanged,
                this, &SentinelController::slotFolderListChanged);
    } else {
        qCWarning(lcSentinelController) << "FolderMan not available, folders added later will not be paused";
    }

    // Startup consistency: the manager may already be triggered, or it was
    // triggered when the client last ran and nobody reset it.
    if (_manager->isTriggered()) {
        qCWarning(lcSentinelController) << "Kill Switch already triggered on startup, pausing folders";
        pauseAllFolders();
    } else {
        restorePersistedState();
    }
}

SentinelController::~SentinelController()
{
    // No event loop left to service WA_DeleteOnClose at this point.
    delete _alertDialog.data();
}

QStringList SentinelController::pausedFolderAliases() const
{
    return _pausedByController.values();
}

void SentinelController::slotSyncPaused(const QString &reason)
{
    qCCritical(lcSentinelController) << "Kill Switch triggered, pausing all sync folders. Reason:" << reason;

    // Pausing only flips the folder state; it is safe to do right away even
    // though the signal is emitted from inside the sync engine.
    pauseAllFolders();
    persistTriggeredState(reason);

    // Everything that may re-enter the sync machinery (terminating runs) or
    // spin a nested event loop (the dialog) is deferred to the event loop.
    QTimer::singleShot(0, this, [this, reason] {
        terminateRunningSyncs();
        showAlertDialog(reason);
    });
}

void SentinelController::slotSyncResumed()
{
    qCInfo(lcSentinelController) << "Kill Switch reset, resuming" << _pausedByController.size() << "folder(s)";

    closeAlertDialog();
    clearPersistedState();

    auto *folderMan = FolderMan::instance();
    if (!folderMan) {
        _pausedByController.clear();
        return;
    }

    const auto folders = folderMan->map().values();
    for (auto *folder : folders) {
        if (!folder || !_pausedByController.contains(folder->alias())) {
            continue;
        }
        qCInfo(lcSentinelController) << "Resuming folder" << folder->alias();
        folder->setSyncPaused(false);
    }
    _pausedByController.clear();

    folderMan->scheduleAllFolders();
}

void SentinelController::slotFolderListChanged(const OCC::Folder::Map &folderMap)
{
    // Drop aliases of folders that no longer exist so they cannot match a
    // folder re-added under the same alias after the kill switch was reset.
    for (auto it = _pausedByController.begin(); it != _pausedByController.end();) {
        if (folderMap.contains(*it)) {
            ++it;
        } else {
            qCInfo(lcSentinelController) << "Folder" << *it << "was removed while paused by the Kill Switch";
            it = _pausedByController.erase(it);
        }
    }

    if (!_manager || !_manager->isTriggered()) {
        return;
    }

    const auto folders = folderMap.values();
    for (auto *folder : folders) {
        pauseFolder(folder);
    }
}

void SentinelController::pauseFolder(Folder *folder)
{
    if (!folder) {
        return;
    }

    if (folder->syncPaused()) {
        if (!_pausedByController.contains(folder->alias())) {
            qCInfo(lcSentinelController) << "Folder" << folder->alias() << "is already paused by the user, leaving it alone";
        }
        return;
    }

    qCWarning(lcSentinelController) << "Pausing folder" << folder->alias();
    _pausedByController.insert(folder->alias());
    folder->setSyncPaused(true);

    if (_manager && _manager->isTriggered()) {
        // Keep the persisted list in step with folders paused later on.
        auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));
        settings->setValue(QStringLiteral("pausedFolders"), _pausedByController.values());
    }
}

void SentinelController::pauseAllFolders()
{
    auto *folderMan = FolderMan::instance();
    if (!folderMan) {
        qCWarning(lcSentinelController) << "FolderMan not available, cannot pause folders";
        return;
    }

    const auto folders = folderMan->map().values();
    for (auto *folder : folders) {
        pauseFolder(folder);
    }
}

void SentinelController::terminateRunningSyncs()
{
    auto *folderMan = FolderMan::instance();
    if (!folderMan) {
        return;
    }

    // The sync engines abort themselves on KillSwitchManager::syncPaused;
    // this covers anything that is still running once we are back in the
    // event loop.
    const auto folders = folderMan->map().values();
    for (auto *folder : folders) {
        if (folder && folder->isSyncRunning() && _pausedByController.contains(folder->alias())) {
            qCWarning(lcSentinelController) << "Terminating running sync of folder" << folder->alias();
            folder->slotTerminateSync();
        }
    }
}

void SentinelController::showAlertDialog(const QString &reason)
{
    if (!_manager || !_manager->isTriggered()) {
        // Reset in the meantime (e.g. from the settings page), nothing to show.
        return;
    }

    if (_alertDialog) {
        ownCloudGui::raiseDialog(_alertDialog.data());
        return;
    }

    // Parent-less and heap allocated on purpose: the caller must not block,
    // and the dialog has to outlive whatever raised it.
    auto *dialog = new KillSwitchAlertDialog(reason, _manager->threats());
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    _alertDialog = dialog;

    dialog->show();
    ownCloudGui::raiseDialog(dialog);
}

void SentinelController::closeAlertDialog()
{
    if (_alertDialog) {
        // WA_DeleteOnClose takes care of deleting it.
        _alertDialog->close();
    }
}

void SentinelController::persistTriggeredState(const QString &reason)
{
    auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));
    settings->setValue(QStringLiteral("triggered"), true);
    settings->setValue(QStringLiteral("triggerReason"), reason);
    settings->setValue(QStringLiteral("triggerTime"), QDateTime::currentDateTime().toString(Qt::ISODate));
    settings->setValue(QStringLiteral("pausedFolders"), _pausedByController.values());
    settings->sync();
}

void SentinelController::clearPersistedState()
{
    auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));
    settings->remove(QStringLiteral("triggered"));
    settings->remove(QStringLiteral("triggerReason"));
    settings->remove(QStringLiteral("triggerTime"));
    settings->remove(QStringLiteral("pausedFolders"));
    settings->sync();
}

void SentinelController::restorePersistedState()
{
    auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));
    if (!settings->value(QStringLiteral("triggered"), false).toBool()) {
        return;
    }

    const QString previousReason = settings->value(QStringLiteral("triggerReason")).toString();
    const QString previousTime = settings->value(QStringLiteral("triggerTime")).toString();
    const QStringList pausedFolders = settings->value(QStringLiteral("pausedFolders")).toStringList();

    // Folder::setSyncPaused() is persisted by the Folder itself, so these
    // folders come back paused on their own; remembering their aliases is
    // what lets a reset resume exactly them and not the user's own pauses.
    for (const QString &alias : pausedFolders) {
        _pausedByController.insert(alias);
    }

    qCCritical(lcSentinelController) << "Kill Switch was triggered when the client last ran"
                                      << "(" << previousTime << ":" << previousReason << ")"
                                      << "- re-arming it";

    // Re-trip the manager: it emits syncPaused(), which brings the dialog
    // back and pauses any folder that is not paused yet.
    _manager->trigger(tr("Kill Switch was active when the client was last closed (%1): %2")
                          .arg(previousTime, previousReason));
}

} // namespace OCC

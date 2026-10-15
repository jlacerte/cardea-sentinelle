/*
 * Nextcloud Sentinel Edition - Kill Switch Alert Dialog Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "killswitchalertdialog.h"
#include "ui_killswitchalertdialog.h"

#include "libsync/killswitch/killswitchmanager.h"

#include <QStyle>
#include <QApplication>
#include <QListWidget>
#include <QListWidgetItem>

namespace OCC {

KillSwitchAlertDialog::KillSwitchAlertDialog(const QString &reason,
                                               const QVector<ThreatInfo> &threats,
                                               QWidget *parent)
    : QDialog(parent)
    , _ui(new Ui::KillSwitchAlertDialog)
{
    _ui->setupUi(this);

    setWindowTitle(tr("Kill Switch Triggered"));
    setWindowIcon(QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical));

    // Set the reason text
    _ui->reasonLabel->setText(reason);

    // Tell the user what happened to the sync folders and how to get out
    // of it. "Keep Protection Active" only closes this dialog; the folders
    // stay paused until the kill switch is reset from the settings page.
    _ui->subtitleLabel->setText(tr("All sync folders have been paused to protect your data"));
    _ui->warningLabel->setText(
        tr("Only reset the Kill Switch if you are certain this was a false positive. "
           "If you are unsure, keep protection active and investigate the detected threats. "
           "Your sync folders stay paused until the Kill Switch is reset here or in "
           "Settings > Kill Switch."));

    // Populate threat details
    populateThreats(threats);

    // Connect buttons
    connect(_ui->resetButton, &QPushButton::clicked,
            this, &KillSwitchAlertDialog::slotResetClicked);
    connect(_ui->keepProtectionButton, &QPushButton::clicked,
            this, &KillSwitchAlertDialog::slotKeepProtectionClicked);

    // Make dialog modal and always on top
    setModal(true);
    setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
}

KillSwitchAlertDialog::~KillSwitchAlertDialog()
{
    delete _ui;
}

bool KillSwitchAlertDialog::showAlert(const QString &reason,
                                       const QVector<ThreatInfo> &threats,
                                       QWidget *parent)
{
    KillSwitchAlertDialog dialog(reason, threats, parent);
    dialog.exec();
    return dialog._resetRequested;
}

void KillSwitchAlertDialog::slotResetClicked()
{
    _resetRequested = true;

    // Reset the kill switch
    if (auto *manager = KillSwitchManager::instance()) {
        manager->reset();
    }

    accept();
}

void KillSwitchAlertDialog::slotKeepProtectionClicked()
{
    _resetRequested = false;
    reject();
}

void KillSwitchAlertDialog::populateThreats(const QVector<ThreatInfo> &threats)
{
    _ui->threatList->clear();

    for (const auto &threat : threats) {
        QString levelStr;
        QString icon;

        switch (threat.level) {
        case ThreatLevel::Low:
            levelStr = tr("LOW");
            break;
        case ThreatLevel::Medium:
            levelStr = tr("MEDIUM");
            break;
        case ThreatLevel::High:
            levelStr = tr("HIGH");
            break;
        case ThreatLevel::Critical:
            levelStr = tr("CRITICAL");
            break;
        default:
            levelStr = tr("UNKNOWN");
            break;
        }

        QString entry = QStringLiteral("[%1] %2\n  Detector: %3\n  %4")
                            .arg(levelStr)
                            .arg(threat.description)
                            .arg(threat.detectorName)
                            .arg(threat.affectedFiles.join(", "));

        auto *item = new QListWidgetItem(entry);

        // Color based on threat level
        if (threat.level >= ThreatLevel::Critical) {
            item->setForeground(Qt::red);
        } else if (threat.level >= ThreatLevel::High) {
            item->setForeground(QColor("#FF4500"));
        } else if (threat.level >= ThreatLevel::Medium) {
            item->setForeground(QColor("#FFA500"));
        }

        _ui->threatList->addItem(item);
    }

    // Show affected files count
    int totalFiles = 0;
    for (const auto &threat : threats) {
        totalFiles += threat.affectedFiles.size();
    }

    _ui->affectedFilesLabel->setText(
        tr("%1 threat(s) detected, %2 file(s) affected")
            .arg(threats.size())
            .arg(totalFiles));
}

} // namespace OCC

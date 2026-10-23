/*
 * Nextcloud Sentinel Edition - Kill Switch Settings Widget Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "killswitchsettings.h"
#include "threathistorydialog.h"
#include "ui_killswitchsettings.h"

#include "libsync/killswitch/killswitchmanager.h"
#include "libsync/configfile.h"
#include "theme.h"

#include <QCheckBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QPushButton>
#include <QComboBox>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QInputDialog>
#include <QDateTime>
#include <QLoggingCategory>

namespace OCC {

Q_LOGGING_CATEGORY(lcKillSwitchSettings, "nextcloud.gui.killswitch", QtInfoMsg)

KillSwitchSettings::KillSwitchSettings(QWidget *parent)
    : QWidget(parent)
    , _ui(new Ui::KillSwitchSettings)
{
    _ui->setupUi(this);

    setupConnections();
    loadSettings();
    updateStatusIndicator();

    qCInfo(lcKillSwitchSettings) << "Kill Switch settings widget initialized";
}

KillSwitchSettings::~KillSwitchSettings()
{
    delete _ui;
}

QSize KillSwitchSettings::sizeHint() const
{
    return {500, 600};
}

void KillSwitchSettings::setupConnections()
{
    // Enable/disable toggle
    connect(_ui->enableKillSwitch, &QCheckBox::toggled,
            this, &KillSwitchSettings::slotEnableToggled);

    // Protect / Audit mode
    connect(_ui->modeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &KillSwitchSettings::slotModeChanged);

    // Preset selection
    connect(_ui->presetComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &KillSwitchSettings::slotPresetChanged);

    // Threshold settings
    connect(_ui->deleteThresholdSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &KillSwitchSettings::slotDeleteThresholdChanged);
    connect(_ui->timeWindowSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &KillSwitchSettings::slotTimeWindowChanged);
    connect(_ui->entropyThresholdSpinBox, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &KillSwitchSettings::slotEntropyThresholdChanged);

    // Canary file management
    connect(_ui->addCanaryButton, &QPushButton::clicked,
            this, &KillSwitchSettings::slotAddCanaryFile);
    connect(_ui->removeCanaryButton, &QPushButton::clicked,
            this, &KillSwitchSettings::slotRemoveCanaryFile);

    // Actions
    connect(_ui->resetButton, &QPushButton::clicked,
            this, &KillSwitchSettings::slotResetKillSwitch);
    connect(_ui->viewHistoryButton, &QPushButton::clicked,
            this, &KillSwitchSettings::slotViewThreatHistory);
    connect(_ui->clearHistoryButton, &QPushButton::clicked,
            this, &KillSwitchSettings::slotClearThreatHistory);

    // Connect to KillSwitchManager if available
    if (auto *manager = KillSwitchManager::instance()) {
        connect(manager, &KillSwitchManager::threatDetected,
                this, &KillSwitchSettings::slotThreatDetected);
        connect(manager, &KillSwitchManager::threatLevelChanged,
                this, [this](ThreatLevel level) {
                    slotThreatLevelChanged(static_cast<int>(level));
                });
        connect(manager, &KillSwitchManager::triggeredChanged,
                this, &KillSwitchSettings::slotTriggeredChanged);
        connect(manager, &KillSwitchManager::auditTriggered,
                this, &KillSwitchSettings::slotAuditTriggered);
    }
}

void KillSwitchSettings::loadSettings()
{
    _loading = true;

    // Use QSettings directly via ConfigFile's settingsWithGroup
    auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));

    // Load settings from config
    _ui->enableKillSwitch->setChecked(settings->value(QStringLiteral("enabled"), true).toBool());
    const KillSwitchMode mode = KillSwitchManager::modeFromString(
        settings->value(QStringLiteral("mode"), QStringLiteral("protect")).toString());
    _ui->modeComboBox->setCurrentIndex(mode == KillSwitchMode::Audit ? ModeAudit : ModeProtect);
    _ui->deleteThresholdSpinBox->setValue(settings->value(QStringLiteral("deleteThreshold"), 10).toInt());
    _ui->timeWindowSpinBox->setValue(settings->value(QStringLiteral("timeWindow"), 60).toInt());
    _ui->entropyThresholdSpinBox->setValue(settings->value(QStringLiteral("entropyThreshold"), 7.5).toDouble());

    // Load canary files
    _ui->canaryListWidget->clear();
    QStringList defaultCanaryFiles = {QStringLiteral("_canary.txt"), QStringLiteral(".canary"), QStringLiteral("zzz_canary.txt")};
    QStringList canaryFiles = settings->value(QStringLiteral("canaryFiles"), defaultCanaryFiles).toStringList();
    for (const QString &file : canaryFiles) {
        _ui->canaryListWidget->addItem(file);
    }

    // Detect current preset based on values
    updatePresetComboBox();

    _loading = false;

    updateThreatDisplay();
    updateStatusIndicator();
}

void KillSwitchSettings::saveSettings()
{
    if (_loading) return;

    // Use QSettings directly via ConfigFile's settingsWithGroup
    auto settings = ConfigFile::settingsWithGroup(QStringLiteral("KillSwitch"));

    settings->setValue(QStringLiteral("enabled"), _ui->enableKillSwitch->isChecked());
    settings->setValue(QStringLiteral("mode"),
                       KillSwitchManager::modeToString(_ui->modeComboBox->currentIndex() == ModeAudit
                                                           ? KillSwitchMode::Audit
                                                           : KillSwitchMode::Protect));
    settings->setValue(QStringLiteral("deleteThreshold"), _ui->deleteThresholdSpinBox->value());
    settings->setValue(QStringLiteral("timeWindow"), _ui->timeWindowSpinBox->value());
    settings->setValue(QStringLiteral("entropyThreshold"), _ui->entropyThresholdSpinBox->value());

    // Save canary files
    QStringList canaryFiles;
    for (int i = 0; i < _ui->canaryListWidget->count(); ++i) {
        canaryFiles << _ui->canaryListWidget->item(i)->text();
    }
    settings->setValue(QStringLiteral("canaryFiles"), canaryFiles);

    qCInfo(lcKillSwitchSettings) << "Kill Switch settings saved";
}

void KillSwitchSettings::slotEnableToggled(bool enabled)
{
    if (auto *manager = KillSwitchManager::instance()) {
        manager->setEnabled(enabled);
    }

    _ui->modeLabel->setEnabled(enabled);
    _ui->modeComboBox->setEnabled(enabled);
    _ui->settingsGroup->setEnabled(enabled);
    _ui->canaryGroup->setEnabled(enabled);

    saveSettings();
    updateStatusIndicator();

    qCInfo(lcKillSwitchSettings) << "Kill Switch" << (enabled ? "enabled" : "disabled");
}

void KillSwitchSettings::slotModeChanged(int index)
{
    const KillSwitchMode mode = index == ModeAudit ? KillSwitchMode::Audit : KillSwitchMode::Protect;

    if (auto *manager = KillSwitchManager::instance()) {
        manager->setMode(mode);
    }

    saveSettings();
    updateStatusIndicator();

    qCInfo(lcKillSwitchSettings) << "Kill Switch mode set to" << KillSwitchManager::modeToString(mode);
}

void KillSwitchSettings::slotPresetChanged(int index)
{
    if (_loading) return;

    // Don't apply if already applying a preset (prevents recursion)
    if (_applyingPreset) return;

    // Only apply if user selected a non-custom preset
    if (index != PresetCustom) {
        applyPreset(index);
        qCInfo(lcKillSwitchSettings) << "Preset changed to:" << index;
    }
}

void KillSwitchSettings::applyPreset(int index)
{
    _applyingPreset = true;

    switch (index) {
    case PresetLight:
        // Light: Fewer alerts, higher thresholds
        _ui->deleteThresholdSpinBox->setValue(20);
        _ui->timeWindowSpinBox->setValue(90);
        _ui->entropyThresholdSpinBox->setValue(7.9);
        break;

    case PresetStandard:
        // Standard: Balanced protection (default)
        _ui->deleteThresholdSpinBox->setValue(10);
        _ui->timeWindowSpinBox->setValue(60);
        _ui->entropyThresholdSpinBox->setValue(7.5);
        break;

    case PresetParanoid:
        // Paranoid: Maximum detection, lower thresholds
        _ui->deleteThresholdSpinBox->setValue(5);
        _ui->timeWindowSpinBox->setValue(30);
        _ui->entropyThresholdSpinBox->setValue(7.2);
        break;

    default:
        break;
    }

    _applyingPreset = false;
    saveSettings();
}

void KillSwitchSettings::updatePresetComboBox()
{
    int deleteThreshold = _ui->deleteThresholdSpinBox->value();
    int timeWindow = _ui->timeWindowSpinBox->value();
    double entropyThreshold = _ui->entropyThresholdSpinBox->value();

    int detectedPreset = PresetCustom;

    // Check if current values match any preset
    if (deleteThreshold == 20 && timeWindow == 90 &&
        qFuzzyCompare(entropyThreshold, 7.9)) {
        detectedPreset = PresetLight;
    } else if (deleteThreshold == 10 && timeWindow == 60 &&
               qFuzzyCompare(entropyThreshold, 7.5)) {
        detectedPreset = PresetStandard;
    } else if (deleteThreshold == 5 && timeWindow == 30 &&
               qFuzzyCompare(entropyThreshold, 7.2)) {
        detectedPreset = PresetParanoid;
    }

    // Update combobox without triggering signal
    _ui->presetComboBox->blockSignals(true);
    _ui->presetComboBox->setCurrentIndex(detectedPreset);
    _ui->presetComboBox->blockSignals(false);
}

void KillSwitchSettings::slotDeleteThresholdChanged(int value)
{
    if (auto *manager = KillSwitchManager::instance()) {
        manager->setDeleteThreshold(value, _ui->timeWindowSpinBox->value());
    }
    saveSettings();

    // Update preset indicator if not applying a preset
    if (!_applyingPreset && !_loading) {
        updatePresetComboBox();
    }
}

void KillSwitchSettings::slotTimeWindowChanged(int value)
{
    if (auto *manager = KillSwitchManager::instance()) {
        manager->setDeleteThreshold(_ui->deleteThresholdSpinBox->value(), value);
    }
    saveSettings();

    // Update preset indicator if not applying a preset
    if (!_applyingPreset && !_loading) {
        updatePresetComboBox();
    }
}

void KillSwitchSettings::slotEntropyThresholdChanged(double value)
{
    if (auto *manager = KillSwitchManager::instance()) {
        manager->setEntropyThreshold(value);
    }
    saveSettings();

    // Update preset indicator if not applying a preset
    if (!_applyingPreset && !_loading) {
        updatePresetComboBox();
    }
}

void KillSwitchSettings::slotAddCanaryFile()
{
    bool ok;
    QString filename = QInputDialog::getText(this,
                                             tr("Add Canary File"),
                                             tr("Enter canary filename pattern:"),
                                             QLineEdit::Normal,
                                             "_canary.txt",
                                             &ok);
    if (ok && !filename.isEmpty()) {
        _ui->canaryListWidget->addItem(filename);

        if (auto *manager = KillSwitchManager::instance()) {
            manager->addCanaryFile(filename);
        }

        saveSettings();
        qCInfo(lcKillSwitchSettings) << "Added canary file:" << filename;
    }
}

void KillSwitchSettings::slotRemoveCanaryFile()
{
    auto *item = _ui->canaryListWidget->currentItem();
    if (item) {
        QString filename = item->text();
        delete _ui->canaryListWidget->takeItem(_ui->canaryListWidget->row(item));

        if (auto *manager = KillSwitchManager::instance()) {
            manager->removeCanaryFile(filename);
        }

        saveSettings();
        qCInfo(lcKillSwitchSettings) << "Removed canary file:" << filename;
    }
}

void KillSwitchSettings::slotResetKillSwitch()
{
    auto *manager = KillSwitchManager::instance();
    if (!manager) {
        return;
    }

    if (!manager->isTriggered()) {
        // Audit mode: the button only clears the would-be trigger counter.
        // Nothing is paused, so there is nothing to confirm.
        if (manager->auditTriggerCount() > 0) {
            manager->clearAuditTriggers();
            updateStatusIndicator();
            qCInfo(lcKillSwitchSettings) << "Audit would-be triggers cleared by user";
        }
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(
        this,
        tr("Reset Kill Switch"),
        tr("Are you sure you want to reset the Kill Switch?\n\n"
           "This will resume synchronization. Only do this if you have "
           "verified that the detected threat was a false positive."),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        manager->reset();
        manager->clearAuditTriggers();
        updateStatusIndicator();
        qCInfo(lcKillSwitchSettings) << "Kill Switch reset by user";
    }
}

void KillSwitchSettings::slotClearThreatHistory()
{
    _ui->threatListWidget->clear();
    qCInfo(lcKillSwitchSettings) << "Threat history cleared";
}

void KillSwitchSettings::slotThreatDetected(const ThreatInfo &threat)
{
    QString levelStr;
    QString color;

    switch (threat.level) {
    case ThreatLevel::Low:
        levelStr = tr("LOW");
        color = "#FFD700"; // Yellow
        break;
    case ThreatLevel::Medium:
        levelStr = tr("MEDIUM");
        color = "#FFA500"; // Orange
        break;
    case ThreatLevel::High:
        levelStr = tr("HIGH");
        color = "#FF4500"; // Red-Orange
        break;
    case ThreatLevel::Critical:
        levelStr = tr("CRITICAL");
        color = "#FF0000"; // Red
        break;
    default:
        return;
    }

    QString entry = QStringLiteral("[%1] %2 - %3: %4")
                        .arg(threat.timestamp.toString("hh:mm:ss"))
                        .arg(levelStr)
                        .arg(threat.detectorName)
                        .arg(threat.description);

    auto *item = new QListWidgetItem(entry);
    item->setForeground(QColor(color));
    _ui->threatListWidget->insertItem(0, item);

    // Limit history to 100 items
    while (_ui->threatListWidget->count() > 100) {
        delete _ui->threatListWidget->takeItem(_ui->threatListWidget->count() - 1);
    }

    updateStatusIndicator();
}

void KillSwitchSettings::slotThreatLevelChanged(int /*level*/)
{
    updateStatusIndicator();
}

void KillSwitchSettings::slotTriggeredChanged(bool /*triggered*/)
{
    // updateStatusIndicator() derives the label, the indicator and the
    // reset button from the manager state (triggered, mode, threat level).
    updateStatusIndicator();
}

void KillSwitchSettings::slotAuditTriggered(const ThreatInfo &threat)
{
    qCWarning(lcKillSwitchSettings) << "Audit mode: Kill Switch would have triggered -" << threat.description;
    updateStatusIndicator();
}

void KillSwitchSettings::updateThreatDisplay()
{
    auto *manager = KillSwitchManager::instance();
    if (!manager) return;

    // Display existing threats
    _ui->threatListWidget->clear();
    for (const auto &threat : manager->threats()) {
        slotThreatDetected(threat);
    }
}

void KillSwitchSettings::updateStatusIndicator()
{
    auto *manager = KillSwitchManager::instance();

    if (!manager || !manager->isEnabled()) {
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #808080; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("Protection Disabled"));
        _ui->statusLabel->setStyleSheet("");
        return;
    }

    if (manager->isTriggered()) {
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FF0000; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("TRIGGERED - Sync Paused"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FF0000; font-weight: bold; }");
        _ui->resetButton->setText(tr("Reset Kill Switch"));
        _ui->resetButton->setEnabled(true);
        return;
    }

    if (manager->mode() == KillSwitchMode::Audit) {
        const int count = manager->auditTriggerCount();
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FFA500; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("AUDIT MODE - detections are logged, sync is never paused (%n would-be trigger(s))",
                                     "", count));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FFA500; font-weight: bold; }");
        // In audit mode the button clears the would-be trigger counter (slotResetKillSwitch).
        _ui->resetButton->setText(tr("Clear Would-be Triggers"));
        _ui->resetButton->setEnabled(count > 0);
        return;
    }

    _ui->resetButton->setText(tr("Reset Kill Switch"));
    _ui->resetButton->setEnabled(false);

    switch (manager->currentThreatLevel()) {
    case ThreatLevel::None:
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #00FF00; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("Protected - No Threats"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #00AA00; }");
        break;
    case ThreatLevel::Low:
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FFD700; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("Low Activity Detected"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FFD700; }");
        break;
    case ThreatLevel::Medium:
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FFA500; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("Moderate Activity Detected"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FFA500; }");
        break;
    case ThreatLevel::High:
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FF4500; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("High Risk Activity!"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FF4500; font-weight: bold; }");
        break;
    case ThreatLevel::Critical:
        _ui->statusIndicator->setStyleSheet(
            "QLabel { background-color: #FF0000; border-radius: 10px; min-width: 20px; min-height: 20px; }");
        _ui->statusLabel->setText(tr("CRITICAL THREAT!"));
        _ui->statusLabel->setStyleSheet("QLabel { color: #FF0000; font-weight: bold; }");
        break;
    }
}

void KillSwitchSettings::slotStyleChanged()
{
    customizeStyle();
}

void KillSwitchSettings::customizeStyle()
{
    // Apply theme-specific styling if needed
}


void KillSwitchSettings::slotViewThreatHistory()
{
    ThreatHistoryDialog dialog(this);
    dialog.exec();
}

} // namespace OCC

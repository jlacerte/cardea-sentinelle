/*
 * Nextcloud Sentinel Edition - Threat Logger Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "threatlogger.h"

#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QTextStream>
#include <QLoggingCategory>

namespace OCC {

Q_LOGGING_CATEGORY(lcThreatLogger, "nextcloud.sync.killswitch.logger", QtInfoMsg)

ThreatLogger *ThreatLogger::s_instance = nullptr;

ThreatLogger::ThreatLogger(QObject *parent)
    : QObject(parent)
{
    // Store log in app data directory
    QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(dataPath);
    if (!dir.exists()) {
        dir.mkpath(dataPath);
    }
    m_logFilePath = dir.filePath(QStringLiteral("sentinel-threats.json"));

    ensureLogFileExists();

    s_instance = this;
    qCInfo(lcThreatLogger) << "ThreatLogger initialized, log file:" << m_logFilePath;
}

ThreatLogger::~ThreatLogger()
{
    if (s_instance == this) {
        s_instance = nullptr;
    }
}

ThreatLogger *ThreatLogger::instance()
{
    return s_instance;
}

void ThreatLogger::ensureLogFileExists()
{
    QFile file(m_logFilePath);
    if (!file.exists()) {
        if (file.open(QIODevice::WriteOnly)) {
            QJsonObject root;
            root[QStringLiteral("version")] = 1;
            root[QStringLiteral("threats")] = QJsonArray();
            file.write(QJsonDocument(root).toJson());
            file.close();
        }
    }
}

QString ThreatLogger::threatLevelToString(ThreatLevel level) const
{
    switch (level) {
    case ThreatLevel::None:
        return QStringLiteral("None");
    case ThreatLevel::Low:
        return QStringLiteral("Low");
    case ThreatLevel::Medium:
        return QStringLiteral("Medium");
    case ThreatLevel::High:
        return QStringLiteral("High");
    case ThreatLevel::Critical:
        return QStringLiteral("Critical");
    }
    return QStringLiteral("Unknown");
}

QJsonArray ThreatLogger::readLogEntries() const
{
    QFile file(m_logFilePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qCWarning(lcThreatLogger) << "Could not open log file for reading:" << m_logFilePath;
        return QJsonArray();
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();

    if (!doc.isObject()) {
        return QJsonArray();
    }

    return doc.object()[QStringLiteral("threats")].toArray();
}

void ThreatLogger::writeLogEntries(const QJsonArray &entries)
{
    QFile file(m_logFilePath);
    if (!file.open(QIODevice::WriteOnly)) {
        qCWarning(lcThreatLogger) << "Could not open log file for writing:" << m_logFilePath;
        return;
    }

    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("threats")] = entries;

    file.write(QJsonDocument(root).toJson());
    file.close();
}

void ThreatLogger::logThreat(const ThreatInfo &threat, const QString &actionTaken)
{
    QJsonArray entries = readLogEntries();

    QJsonObject entry;
    entry[QStringLiteral("timestamp")] = threat.timestamp.toString(Qt::ISODate);
    entry[QStringLiteral("level")] = threatLevelToString(threat.level);
    entry[QStringLiteral("detector")] = threat.detectorName;
    entry[QStringLiteral("description")] = threat.description;

    QJsonArray files;
    for (const QString &f : threat.affectedFiles) {
        files.append(f);
    }
    entry[QStringLiteral("files")] = files;

    if (!actionTaken.isEmpty()) {
        entry[QStringLiteral("action_taken")] = actionTaken;
    }

    entries.append(entry);
    while (entries.size() > MAX_LOG_ENTRIES) {
        entries.removeFirst();
    }
    writeLogEntries(entries);

    qCInfo(lcThreatLogger) << "Logged threat:" << threat.description
                           << "Level:" << threatLevelToString(threat.level)
                           << "Detector:" << threat.detectorName;
}

QString ThreatLogger::logFilePath() const
{
    return m_logFilePath;
}

QVector<ThreatInfo> ThreatLogger::loadThreats() const
{
    QVector<ThreatInfo> result;
    QJsonArray entries = readLogEntries();

    for (const QJsonValue &val : entries) {
        QJsonObject obj = val.toObject();
        ThreatInfo threat;
        threat.timestamp = QDateTime::fromString(obj[QStringLiteral("timestamp")].toString(), Qt::ISODate);
        threat.detectorName = obj[QStringLiteral("detector")].toString();
        threat.description = obj[QStringLiteral("description")].toString();

        QString levelStr = obj[QStringLiteral("level")].toString();
        if (levelStr == QStringLiteral("Critical")) {
            threat.level = ThreatLevel::Critical;
        } else if (levelStr == QStringLiteral("High")) {
            threat.level = ThreatLevel::High;
        } else if (levelStr == QStringLiteral("Medium")) {
            threat.level = ThreatLevel::Medium;
        } else if (levelStr == QStringLiteral("Low")) {
            threat.level = ThreatLevel::Low;
        } else {
            threat.level = ThreatLevel::None;
        }

        QJsonArray files = obj[QStringLiteral("files")].toArray();
        for (const QJsonValue &f : files) {
            threat.affectedFiles.append(f.toString());
        }

        result.append(threat);
    }

    return result;
}

QVector<ThreatInfo> ThreatLogger::threatsFromLastDays(int days) const
{
    QVector<ThreatInfo> all = loadThreats();
    QVector<ThreatInfo> result;
    QDateTime cutoff = QDateTime::currentDateTime().addDays(-days);

    for (const ThreatInfo &threat : all) {
        if (threat.timestamp >= cutoff) {
            result.append(threat);
        }
    }

    return result;
}

void ThreatLogger::clearLog()
{
    writeLogEntries(QJsonArray());
    qCInfo(lcThreatLogger) << "Threat log cleared";
}

bool ThreatLogger::exportToCsv(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qCWarning(lcThreatLogger) << "Could not open CSV file for writing:" << filePath;
        return false;
    }

    QTextStream out(&file);
    out << "Timestamp,Level,Detector,Description,Files\n";

    QVector<ThreatInfo> threats = loadThreats();
    for (const ThreatInfo &threat : threats) {
        QString files = threat.affectedFiles.join(QStringLiteral(";"));
        // Escape quotes in description
        QString desc = threat.description;
        desc.replace(QStringLiteral("\""), QStringLiteral("\"\""));

        out << threat.timestamp.toString(Qt::ISODate) << ","
            << threatLevelToString(threat.level) << ","
            << threat.detectorName << ","
            << "\"" << desc << "\","
            << "\"" << files << "\"\n";
    }

    file.close();
    qCInfo(lcThreatLogger) << "Exported" << threats.size() << "threats to CSV:" << filePath;
    return true;
}

ThreatLogger::Statistics ThreatLogger::getStatistics() const
{
    Statistics stats;
    QVector<ThreatInfo> threats = loadThreats();

    stats.totalThreats = threats.size();

    for (const ThreatInfo &threat : threats) {
        switch (threat.level) {
        case ThreatLevel::Critical:
            stats.criticalCount++;
            break;
        case ThreatLevel::High:
            stats.highCount++;
            break;
        case ThreatLevel::Medium:
            stats.mediumCount++;
            break;
        case ThreatLevel::Low:
            stats.lowCount++;
            break;
        default:
            break;
        }

        stats.byDetector[threat.detectorName]++;
    }

    return stats;
}

} // namespace OCC

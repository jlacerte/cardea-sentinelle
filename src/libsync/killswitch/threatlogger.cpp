/*
 * Nextcloud Sentinel Edition - Threat Logger Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "threatlogger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
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
    m_logFilePath = dir.filePath(QStringLiteral("sentinel-threats.jsonl"));
    m_rotatedLogFilePath = dir.filePath(QStringLiteral("sentinel-threats.1.jsonl"));
    m_legacyLogFilePath = dir.filePath(QStringLiteral("sentinel-threats.json"));

    migrateLegacyLog();
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

void ThreatLogger::setRotationSizeBytes(qint64 bytes)
{
    m_rotationSizeBytes = qMax<qint64>(1, bytes);
}

void ThreatLogger::ensureLogFileExists()
{
    QFile file(m_logFilePath);
    if (!file.exists()) {
        if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
            qCWarning(lcThreatLogger) << "Could not create log file:" << m_logFilePath << file.errorString();
        }
    }
}

void ThreatLogger::migrateLegacyLog()
{
    QFile legacy(m_legacyLogFilePath);
    if (!legacy.exists()) {
        return;
    }
    if (!legacy.open(QIODevice::ReadOnly)) {
        qCWarning(lcThreatLogger) << "Could not open legacy log for migration:" << m_legacyLogFilePath
                                  << legacy.errorString();
        return;
    }

    QJsonParseError parseError{};
    const QJsonDocument doc = QJsonDocument::fromJson(legacy.readAll(), &parseError);
    legacy.close();

    int migrated = 0;
    if (doc.isObject()) {
        const QJsonArray threats = doc.object().value(QStringLiteral("threats")).toArray();
        for (const QJsonValue &val : threats) {
            if (!val.isObject()) {
                continue;
            }
            if (appendLine(QJsonDocument(val.toObject()).toJson(QJsonDocument::Compact))) {
                ++migrated;
            }
        }
    } else {
        qCWarning(lcThreatLogger) << "Legacy log is not a JSON object, nothing migrated:"
                                  << parseError.errorString();
    }

    const QString migratedPath = m_legacyLogFilePath + QStringLiteral(".migrated");
    QFile::remove(migratedPath);
    if (!QFile::rename(m_legacyLogFilePath, migratedPath)) {
        qCWarning(lcThreatLogger) << "Could not rename legacy log to" << migratedPath;
    }
    qCInfo(lcThreatLogger) << "Migrated" << migrated << "entries from legacy log" << m_legacyLogFilePath;
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

ThreatLevel ThreatLogger::threatLevelFromString(const QString &level)
{
    if (level == QStringLiteral("Critical")) {
        return ThreatLevel::Critical;
    }
    if (level == QStringLiteral("High")) {
        return ThreatLevel::High;
    }
    if (level == QStringLiteral("Medium")) {
        return ThreatLevel::Medium;
    }
    if (level == QStringLiteral("Low")) {
        return ThreatLevel::Low;
    }
    return ThreatLevel::None;
}

QJsonObject ThreatLogger::entryFromThreat(const ThreatInfo &threat, const QString &actionTaken) const
{
    QJsonObject entry;
    entry[QStringLiteral("timestamp")] = threat.timestamp.toString(Qt::ISODateWithMs);
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
    return entry;
}

bool ThreatLogger::threatFromEntry(const QJsonObject &entry, ThreatInfo &threat)
{
    if (!entry.contains(QStringLiteral("timestamp")) || !entry.contains(QStringLiteral("level"))) {
        return false;
    }
    threat.timestamp = QDateTime::fromString(entry.value(QStringLiteral("timestamp")).toString(), Qt::ISODateWithMs);
    threat.level = threatLevelFromString(entry.value(QStringLiteral("level")).toString());
    threat.detectorName = entry.value(QStringLiteral("detector")).toString();
    threat.description = entry.value(QStringLiteral("description")).toString();

    threat.affectedFiles.clear();
    const QJsonArray files = entry.value(QStringLiteral("files")).toArray();
    for (const QJsonValue &f : files) {
        threat.affectedFiles.append(f.toString());
    }
    return true;
}

void ThreatLogger::rotateIfNeeded()
{
    const QFileInfo info(m_logFilePath);
    if (!info.exists() || info.size() < m_rotationSizeBytes) {
        return;
    }

    QFile::remove(m_rotatedLogFilePath);
    if (!QFile::rename(m_logFilePath, m_rotatedLogFilePath)) {
        qCWarning(lcThreatLogger) << "Could not rotate log file" << m_logFilePath << "to" << m_rotatedLogFilePath;
        return;
    }
    qCInfo(lcThreatLogger) << "Rotated threat log (" << info.size() << "bytes) to" << m_rotatedLogFilePath;
}

bool ThreatLogger::appendLine(const QByteArray &line)
{
    QFile file(m_logFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        qCWarning(lcThreatLogger) << "Could not open log file for appending:" << m_logFilePath << file.errorString();
        return false;
    }

    QByteArray data = line;
    data.append('\n');
    const bool ok = file.write(data) == data.size();
    file.flush();
    file.close();
    if (!ok) {
        qCWarning(lcThreatLogger) << "Short write to log file:" << m_logFilePath << file.errorString();
    }
    return ok;
}

void ThreatLogger::logThreat(const ThreatInfo &threat, const QString &actionTaken)
{
    rotateIfNeeded();
    appendLine(QJsonDocument(entryFromThreat(threat, actionTaken)).toJson(QJsonDocument::Compact));

    qCInfo(lcThreatLogger) << "Logged threat:" << threat.description
                           << "Level:" << threatLevelToString(threat.level)
                           << "Detector:" << threat.detectorName;
}

QString ThreatLogger::logFilePath() const
{
    return m_logFilePath;
}

QString ThreatLogger::rotatedLogFilePath() const
{
    return m_rotatedLogFilePath;
}

QString ThreatLogger::legacyLogFilePath() const
{
    return m_legacyLogFilePath;
}

void ThreatLogger::forEachEntryInFile(const QString &path,
                                      const std::function<void(const QJsonObject &)> &visitor) const
{
    QFile file(path);
    if (!file.exists()) {
        return;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        qCWarning(lcThreatLogger) << "Could not open log file for reading:" << path << file.errorString();
        return;
    }

    qint64 lineNumber = 0;
    int skipped = 0;
    while (!file.atEnd()) {
        ++lineNumber;
        const QByteArray line = file.readLine().trimmed();
        if (line.isEmpty()) {
            continue;
        }

        QJsonParseError parseError{};
        const QJsonDocument doc = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            if (skipped < 5) {
                const QString reason = parseError.error != QJsonParseError::NoError
                    ? parseError.errorString()
                    : QStringLiteral("not a JSON object");
                qCWarning(lcThreatLogger) << "Skipping malformed log line" << lineNumber << "in" << path << ":"
                                          << reason;
            }
            ++skipped;
            continue;
        }
        visitor(doc.object());
    }
    file.close();

    if (skipped > 0) {
        qCWarning(lcThreatLogger) << "Skipped" << skipped << "malformed line(s) in" << path;
    }
}

void ThreatLogger::forEachEntry(const std::function<void(const QJsonObject &)> &visitor) const
{
    forEachEntryInFile(m_rotatedLogFilePath, visitor);
    forEachEntryInFile(m_logFilePath, visitor);
}

QVector<ThreatInfo> ThreatLogger::loadThreats() const
{
    QVector<ThreatInfo> result;
    forEachEntry([&result](const QJsonObject &entry) {
        ThreatInfo threat;
        if (threatFromEntry(entry, threat)) {
            result.append(threat);
        }
    });

    if (result.size() > MAX_LOADED_ENTRIES) {
        result.remove(0, result.size() - MAX_LOADED_ENTRIES);
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
    QFile::remove(m_rotatedLogFilePath);

    QFile file(m_logFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qCWarning(lcThreatLogger) << "Could not truncate log file:" << m_logFilePath << file.errorString();
        return;
    }
    file.close();
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

    // The explicit QString return type matters: with QT_USE_QSTRINGBUILDER the
    // concatenation below is a QStringBuilder that references `value`, which
    // dies when the lambda returns (issue #25: a garbled first character).
    const auto quote = [](QString value) -> QString {
        value.replace(QStringLiteral("\""), QStringLiteral("\"\""));
        return QStringLiteral("\"") + value + QStringLiteral("\"");
    };

    QVector<ThreatInfo> threats = loadThreats();
    for (const ThreatInfo &threat : threats) {
        out << threat.timestamp.toString(Qt::ISODate) << ","
            << threatLevelToString(threat.level) << ","
            << quote(threat.detectorName) << ","
            << quote(threat.description) << ","
            << quote(threat.affectedFiles.join(QStringLiteral(";"))) << "\n";
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

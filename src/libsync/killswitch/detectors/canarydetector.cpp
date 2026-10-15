/*
 * Nextcloud Sentinel Edition - Canary File Detector Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "canarydetector.h"
#include "syncfileitem.h"

#include <QFileInfo>
#include <QRegularExpression>

namespace OCC {

CanaryDetector::CanaryDetector()
{
    // Default canary patterns
    m_patterns << QStringLiteral("_canary.txt")
               << QStringLiteral(".canary")
               << QStringLiteral("zzz_canary.txt")
               << QStringLiteral("DO_NOT_DELETE.sentinel")
               << QStringLiteral(".killswitch_canary");
}

void CanaryDetector::addCanaryPattern(const QString &pattern)
{
    if (!m_patterns.contains(pattern)) {
        m_patterns.append(pattern);
    }
}

void CanaryDetector::removeCanaryPattern(const QString &pattern)
{
    m_patterns.removeAll(pattern);
}

bool CanaryDetector::isCanaryFile(const QString &filePath) const
{
    QFileInfo fileInfo(filePath);
    QString filename = fileInfo.fileName().toLower();

    for (const QString &pattern : m_patterns) {
        QString lowerPattern = pattern.toLower();

        // Check for wildcard patterns
        if (lowerPattern.contains(QChar('*')) || lowerPattern.contains(QChar('?'))) {
            QRegularExpression regex(
                QRegularExpression::wildcardToRegularExpression(lowerPattern),
                QRegularExpression::CaseInsensitiveOption);
            if (regex.match(filename).hasMatch()) {
                return true;
            }
        } else {
            // Exact match
            if (filename == lowerPattern) {
                return true;
            }
        }
    }

    return false;
}

ThreatInfo CanaryDetector::analyze(const SyncFileItem &item,
                                    const QVector<struct KillSwitchManager::Event> &recentEvents,
                                    const AnalysisContext &context)
{
    Q_UNUSED(recentEvents)
    Q_UNUSED(context)

    ThreatInfo result;
    result.level = ThreatLevel::None;
    result.detectorName = name();

    if (!m_enabled) {
        return result;
    }

    // Check if this is a canary file. For a rename, both the source and the
    // target name matter: renaming "_canary.txt" to "_canary.txt.locked" is
    // exactly what we are here for.
    const bool sourceIsCanary = isCanaryFile(item._file);
    const bool targetIsCanary = !item._renameTarget.isEmpty() && isCanaryFile(item._renameTarget);
    if (!sourceIsCanary && !targetIsCanary) {
        return result;
    }

    // Any operation on a canary file is critical
    QString operation;
    switch (item._instruction) {
    case CSYNC_INSTRUCTION_REMOVE:
        operation = QStringLiteral("DELETED");
        break;
    case CSYNC_INSTRUCTION_SYNC:
        operation = QStringLiteral("MODIFIED");
        break;
    case CSYNC_INSTRUCTION_RENAME:
        operation = QStringLiteral("RENAMED");
        break;
    case CSYNC_INSTRUCTION_NEW:
        // New canary file is OK (might be initial setup)
        return result;
    default:
        operation = QStringLiteral("TOUCHED");
        break;
    }

    result.level = ThreatLevel::Critical;
    result.description = QStringLiteral("CANARY FILE %1: %2")
                             .arg(operation)
                             .arg(item._file);
    result.affectedFiles.append(item._file);

    return result;
}

} // namespace OCC

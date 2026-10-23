/*
 * Nextcloud Sentinel Edition - Mass Delete Detector Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "massdeletedetector.h"
#include "syncfileitem.h"

#include <QFileInfo>
#include <QLoggingCategory>

namespace OCC {

Q_LOGGING_CATEGORY(lcMassDeleteDetector, "nextcloud.sync.killswitch.massdelete", QtInfoMsg)

MassDeleteDetector::MassDeleteDetector()
{
    initializeWhitelist();
}

void MassDeleteDetector::initializeWhitelist()
{
    // Common directories that are safely bulk-deleted during development
    m_whitelistedDirs = {
        // JavaScript/Node.js
        QStringLiteral("node_modules"),
        QStringLiteral(".npm"),
        QStringLiteral(".yarn"),
        QStringLiteral(".pnpm-store"),

        // Build outputs
        QStringLiteral("build"),
        QStringLiteral("dist"),
        QStringLiteral("out"),
        QStringLiteral("target"),
        QStringLiteral("bin"),
        QStringLiteral("obj"),

        // Version control
        QStringLiteral(".git"),
        QStringLiteral(".svn"),
        QStringLiteral(".hg"),

        // Python
        QStringLiteral("__pycache__"),
        QStringLiteral(".pytest_cache"),
        QStringLiteral(".mypy_cache"),
        QStringLiteral(".tox"),
        QStringLiteral("venv"),
        QStringLiteral(".venv"),
        QStringLiteral("env"),

        // IDE/Editor
        QStringLiteral(".idea"),
        QStringLiteral(".vscode"),
        QStringLiteral(".vs"),

        // Package managers
        QStringLiteral("vendor"),
        QStringLiteral("packages"),

        // Caches
        QStringLiteral(".cache"),
        QStringLiteral(".gradle"),
        QStringLiteral(".m2"),

        // Temp
        QStringLiteral("tmp"),
        QStringLiteral("temp"),
    };

    qCInfo(lcMassDeleteDetector) << "Initialized with" << m_whitelistedDirs.size()
                                  << "whitelisted directories";
}

void MassDeleteDetector::addWhitelistedDirectory(const QString &pattern)
{
    m_whitelistedDirs.insert(pattern.toLower());
    qCInfo(lcMassDeleteDetector) << "Added whitelisted directory:" << pattern;
}

bool MassDeleteDetector::isWhitelisted(const QString &path) const
{
    // Split path into components and check each directory
    const QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);

    for (const QString &part : parts) {
        if (m_whitelistedDirs.contains(part.toLower())) {
            return true;
        }
    }

    return false;
}

QString MassDeleteDetector::detectTreeDeletion(const QStringList &paths) const
{
    if (paths.isEmpty()) {
        return QString();
    }

    // Find common prefix (directory) for all paths
    QString commonPrefix = paths.first();
    int lastSlash = commonPrefix.lastIndexOf(QLatin1Char('/'));
    if (lastSlash > 0) {
        commonPrefix = commonPrefix.left(lastSlash);
    }

    for (const QString &path : paths) {
        while (!path.startsWith(commonPrefix + QLatin1Char('/')) &&
               !path.startsWith(commonPrefix) &&
               !commonPrefix.isEmpty()) {
            lastSlash = commonPrefix.lastIndexOf(QLatin1Char('/'));
            if (lastSlash > 0) {
                commonPrefix = commonPrefix.left(lastSlash);
            } else {
                commonPrefix.clear();
                break;
            }
        }
    }

    // Check if common prefix is non-trivial (at least one directory deep)
    if (commonPrefix.isEmpty() || commonPrefix.count(QLatin1Char('/')) < 1) {
        return QString();
    }

    // Check if the directory itself is being deleted (not just contents)
    bool dirBeingDeleted = false;
    for (const QString &path : paths) {
        if (path == commonPrefix || path.endsWith(QLatin1Char('/'))) {
            dirBeingDeleted = true;
            break;
        }
    }

    // If we have many files under same directory, it's likely a tree deletion
    if (paths.size() >= 5) {
        return commonPrefix;
    }

    return dirBeingDeleted ? commonPrefix : QString();
}

ThreatInfo MassDeleteDetector::analyze(const SyncFileItem &item,
                                        const QVector<struct KillSwitchManager::Event> &recentEvents,
                                        const AnalysisContext &context)
{
    ThreatInfo result;
    result.level = ThreatLevel::None;
    result.detectorName = name();

    if (!m_enabled) {
        return result;
    }

    // Only interested in deletions
    if (item._instruction != CSYNC_INSTRUCTION_REMOVE) {
        return result;
    }

    // Count recent deletions (excluding whitelisted directories)
    int deleteCount = 0;
    int whitelistedCount = 0;
    QDateTime oldestDelete;
    QDateTime newestDelete;
    QStringList deletedPaths;

    for (const auto &event : recentEvents) {
        if (event.type == QStringLiteral("DELETE")) {
            if (isWhitelisted(event.path)) {
                whitelistedCount++;
                continue; // Don't count whitelisted paths
            }

            deleteCount++;
            deletedPaths.append(event.path);

            if (!oldestDelete.isValid() || event.timestamp < oldestDelete) {
                oldestDelete = event.timestamp;
            }
            if (!newestDelete.isValid() || event.timestamp > newestDelete) {
                newestDelete = event.timestamp;
            }
            result.affectedFiles.append(context.localPath(event.path));
        }
    }

    // Log whitelisted skips for debugging
    if (whitelistedCount > 0) {
        qCDebug(lcMassDeleteDetector) << "Skipped" << whitelistedCount
                                       << "deletions in whitelisted directories";
    }

    // Check for tree deletion pattern
    QString treeRoot = detectTreeDeletion(deletedPaths);
    if (!treeRoot.isEmpty()) {
        qCInfo(lcMassDeleteDetector) << "Detected tree deletion:" << treeRoot;
    }

    // Calculate deletion rate. Only meaningful once we have seen a minimum
    // number of deletions spread over at least MIN_RATE_WINDOW_MS: all items
    // of one sync run are analyzed within milliseconds of each other, which
    // would otherwise turn any two deletions into a "high deletion rate".
    double rate = 0.0;
    const int minDeletesForRate = qMax(3, m_threshold / 2);
    if (deleteCount >= minDeletesForRate && oldestDelete.isValid() && newestDelete.isValid()) {
        qint64 msElapsed = oldestDelete.msecsTo(newestDelete);
        if (msElapsed >= MIN_RATE_WINDOW_MS) {
            rate = (deleteCount * 1000.0) / msElapsed; // files per second
        }
    }

    // Evaluate threat level
    if (deleteCount >= m_threshold * 2) {
        result.level = ThreatLevel::Critical;
        if (!treeRoot.isEmpty()) {
            result.description = QStringLiteral("Critical: Tree deletion of '%1' (%2 files)")
                                     .arg(treeRoot)
                                     .arg(deleteCount);
        } else {
            result.description = QStringLiteral("Critical: %1 files deleted (threshold: %2)")
                                     .arg(deleteCount)
                                     .arg(m_threshold);
        }
    } else if (deleteCount >= m_threshold) {
        result.level = ThreatLevel::High;
        result.description = QStringLiteral("High: %1 files deleted, approaching critical threshold")
                                 .arg(deleteCount);
    } else if (rate > m_rateLimit) {
        result.level = ThreatLevel::High;
        result.description = QStringLiteral("High deletion rate: %.1f files/sec (limit: %.1f)")
                                 .arg(rate)
                                 .arg(m_rateLimit);
    } else if (deleteCount >= m_threshold * 0.5) {
        result.level = ThreatLevel::Medium;
        result.description = QStringLiteral("Medium: %1 files deleted in short window")
                                 .arg(deleteCount);
    }

    return result;
}

} // namespace OCC

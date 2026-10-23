/*
 * Nextcloud Sentinel Edition - Threat Logger Unit Tests
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QtTest>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QTemporaryDir>

#include "libsync/killswitch/threatlogger.h"

using namespace OCC;

class TestThreatLogger : public QObject
{
    Q_OBJECT

private:
    static QString dataDir()
    {
        return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    }

    static void removeLogFiles()
    {
        QDir dir(dataDir());
        if (!dir.exists()) {
            return;
        }
        const QStringList names = dir.entryList({QStringLiteral("sentinel-threats*")}, QDir::Files);
        for (const QString &name : names) {
            QVERIFY(dir.remove(name));
        }
    }

    static ThreatInfo makeThreat(int i, ThreatLevel level = ThreatLevel::High,
                                 const QString &detector = QStringLiteral("PatternDetector"))
    {
        ThreatInfo info;
        info.level = level;
        info.detectorName = detector;
        info.description = QStringLiteral("Threat number %1").arg(i);
        info.affectedFiles = {QStringLiteral("Documents/file_%1.docx.locked").arg(i),
                              QStringLiteral("Documents/HOW_TO_DECRYPT.txt")};
        // Deterministic, strictly increasing timestamps so order can be asserted
        info.timestamp = QDateTime(QDate(2026, 1, 11), QTime(15, 30, 0)).addSecs(i);
        return info;
    }

    static int countLines(const QString &path)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            return -1;
        }
        int lines = 0;
        while (!file.atEnd()) {
            file.readLine();
            ++lines;
        }
        return lines;
    }

    static void appendRaw(const QString &path, const QByteArray &data)
    {
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Append));
        QCOMPARE(file.write(data), static_cast<qint64>(data.size()));
        file.close();
    }

private slots:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
    }

    void init()
    {
        removeLogFiles();
    }

    void cleanupTestCase()
    {
        removeLogFiles();
    }

    void testAppendLoadRoundTrip()
    {
        ThreatLogger logger;
        QVERIFY(logger.logFilePath().endsWith(QStringLiteral("sentinel-threats.jsonl")));
        QVERIFY(QFileInfo::exists(logger.logFilePath()));
        QCOMPARE(logger.loadThreats().size(), 0);

        ThreatInfo threat = makeThreat(7, ThreatLevel::Critical, QStringLiteral("CanaryDetector"));
        threat.description = QStringLiteral("Canary \"modified\": héllo, wörld");
        logger.logThreat(threat, QStringLiteral("sync_paused"));

        // Exactly one line, which is a self-contained JSON object
        QCOMPARE(countLines(logger.logFilePath()), 1);
        QFile file(logger.logFilePath());
        QVERIFY(file.open(QIODevice::ReadOnly));
        const QByteArray line = file.readLine().trimmed();
        file.close();
        const QJsonDocument doc = QJsonDocument::fromJson(line);
        QVERIFY(doc.isObject());
        const QJsonObject obj = doc.object();
        QCOMPARE(obj.value(QStringLiteral("level")).toString(), QStringLiteral("Critical"));
        QCOMPARE(obj.value(QStringLiteral("detector")).toString(), QStringLiteral("CanaryDetector"));
        QCOMPARE(obj.value(QStringLiteral("description")).toString(), threat.description);
        QCOMPARE(obj.value(QStringLiteral("action_taken")).toString(), QStringLiteral("sync_paused"));
        QCOMPARE(obj.value(QStringLiteral("files")).toArray().size(), 2);
        QCOMPARE(obj.value(QStringLiteral("timestamp")).toString(), threat.timestamp.toString(Qt::ISODateWithMs));

        const QVector<ThreatInfo> loaded = logger.loadThreats();
        QCOMPARE(loaded.size(), 1);
        QCOMPARE(loaded[0].level, ThreatLevel::Critical);
        QCOMPARE(loaded[0].detectorName, QStringLiteral("CanaryDetector"));
        QCOMPARE(loaded[0].description, threat.description);
        QCOMPARE(loaded[0].affectedFiles, threat.affectedFiles);
        QCOMPARE(loaded[0].timestamp, threat.timestamp);

        // A second logger instance (restart) sees the same history
        ThreatLogger again;
        QCOMPARE(again.loadThreats().size(), 1);
    }

    void testManyEntriesKeptInOrder()
    {
        ThreatLogger logger;
        const int count = 2500;
        for (int i = 0; i < count; ++i) {
            logger.logThreat(makeThreat(i));
        }

        const QVector<ThreatInfo> loaded = logger.loadThreats();
        QCOMPARE(loaded.size(), count);
        for (int i = 0; i < count; ++i) {
            QCOMPARE(loaded[i].description, QStringLiteral("Threat number %1").arg(i));
            if (i > 0) {
                QVERIFY(loaded[i].timestamp > loaded[i - 1].timestamp);
            }
        }
    }

    void testRotationAndContinuity()
    {
        ThreatLogger logger;
        logger.setRotationSizeBytes(4096);
        QCOMPARE(logger.rotationSizeBytes(), static_cast<qint64>(4096));

        const int count = 200; // each line is ~170 bytes: several rotations
        for (int i = 0; i < count; ++i) {
            logger.logThreat(makeThreat(i));
        }

        QVERIFY(QFileInfo::exists(logger.rotatedLogFilePath()));
        QVERIFY(QFileInfo(logger.rotatedLogFilePath()).size() >= 4096);
        QVERIFY(QFileInfo(logger.logFilePath()).size() < 4096 + 400);

        const int inRotated = countLines(logger.rotatedLogFilePath());
        const int inCurrent = countLines(logger.logFilePath());
        QVERIFY(inRotated > 0);
        QVERIFY(inCurrent > 0);

        // History is continuous across the rotated and the current file:
        // the last (inRotated + inCurrent) entries, in order, nothing duplicated.
        const QVector<ThreatInfo> loaded = logger.loadThreats();
        QCOMPARE(loaded.size(), inRotated + inCurrent);
        const int first = count - loaded.size();
        for (int i = 0; i < loaded.size(); ++i) {
            QCOMPARE(loaded[i].description, QStringLiteral("Threat number %1").arg(first + i));
        }
        QCOMPARE(loaded.last().description, QStringLiteral("Threat number %1").arg(count - 1));

        // Older generations are discarded: only one rotated file exists
        QDir dir(dataDir());
        const QStringList names = dir.entryList({QStringLiteral("sentinel-threats*")}, QDir::Files);
        QCOMPARE(names.size(), 2);
    }

    void testMigrationFromLegacyJson()
    {
        const QString legacyPath = QDir(dataDir()).filePath(QStringLiteral("sentinel-threats.json"));
        QDir().mkpath(dataDir());

        QJsonArray threats;
        for (int i = 0; i < 3; ++i) {
            QJsonObject entry;
            entry[QStringLiteral("timestamp")] = QStringLiteral("2026-01-1%1T15:30:00").arg(i + 1);
            entry[QStringLiteral("level")] = i == 0 ? QStringLiteral("Critical") : QStringLiteral("Low");
            entry[QStringLiteral("detector")] = QStringLiteral("MassDeleteDetector");
            entry[QStringLiteral("description")] = QStringLiteral("Legacy entry %1").arg(i);
            entry[QStringLiteral("files")] = QJsonArray{QStringLiteral("a/%1").arg(i)};
            entry[QStringLiteral("action_taken")] = QStringLiteral("sync_paused");
            threats.append(entry);
        }
        QJsonObject root;
        root[QStringLiteral("version")] = 1;
        root[QStringLiteral("threats")] = threats;
        {
            QFile legacy(legacyPath);
            QVERIFY(legacy.open(QIODevice::WriteOnly));
            legacy.write(QJsonDocument(root).toJson());
            legacy.close();
        }

        {
            ThreatLogger logger;
            QCOMPARE(logger.legacyLogFilePath(), legacyPath);
            QVERIFY(!QFileInfo::exists(legacyPath));
            QVERIFY(QFileInfo::exists(legacyPath + QStringLiteral(".migrated")));
            QCOMPARE(countLines(logger.logFilePath()), 3);

            const QVector<ThreatInfo> loaded = logger.loadThreats();
            QCOMPARE(loaded.size(), 3);
            QCOMPARE(loaded[0].level, ThreatLevel::Critical);
            QCOMPARE(loaded[0].description, QStringLiteral("Legacy entry 0"));
            QCOMPARE(loaded[0].timestamp, QDateTime(QDate(2026, 1, 11), QTime(15, 30, 0)));
            QCOMPARE(loaded[2].affectedFiles, QStringList{QStringLiteral("a/2")});

            // New entries go after the migrated ones
            logger.logThreat(makeThreat(99));
            QCOMPARE(logger.loadThreats().size(), 4);
            QCOMPARE(logger.loadThreats().last().description, QStringLiteral("Threat number 99"));
        }

        // Migration happens once: a second construction does not re-import
        ThreatLogger again;
        QCOMPARE(again.loadThreats().size(), 4);
    }

    void testMalformedLineSkipped()
    {
        ThreatLogger logger;
        logger.logThreat(makeThreat(0));
        appendRaw(logger.logFilePath(), "{\"timestamp\":\"2026-01-11T15:30:05\",\"level\":\"Hi");
        appendRaw(logger.logFilePath(), "\n\n[1,2,3]\nnot json at all\n");
        logger.logThreat(makeThreat(1));

        const QVector<ThreatInfo> loaded = logger.loadThreats();
        QCOMPARE(loaded.size(), 2);
        QCOMPARE(loaded[0].description, QStringLiteral("Threat number 0"));
        QCOMPARE(loaded[1].description, QStringLiteral("Threat number 1"));
        QCOMPARE(logger.getStatistics().totalThreats, 2);
    }

    void testCsvExportNeutralizesFormulas()
    {
        // File names come from the synced folder; a value starting with = + - @
        // must not run as a formula when the export is opened in a spreadsheet.
        ThreatLogger logger;
        ThreatInfo threat = makeThreat(0, ThreatLevel::High, QStringLiteral("@Detector"));
        threat.description = QStringLiteral("-2+3");
        threat.affectedFiles = {QStringLiteral("=HYPERLINK(\"http://x\",\"a\").docx")};
        logger.logThreat(threat);

        ThreatInfo plain = makeThreat(1, ThreatLevel::High, QStringLiteral("PatternDetector"));
        plain.description = QStringLiteral("a-b");
        plain.affectedFiles = {QStringLiteral("x+y.docx")};
        logger.logThreat(plain);

        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        const QString csvPath = tmp.filePath(QStringLiteral("export.csv"));
        QVERIFY(logger.exportToCsv(csvPath));

        QFile csv(csvPath);
        QVERIFY(csv.open(QIODevice::ReadOnly));
        const QStringList lines = QString::fromUtf8(csv.readAll()).remove(QLatin1Char('\r')).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        QCOMPARE(lines.size(), 3);
        QCOMPARE(lines[1],
                 QStringLiteral("%1,High,\"'@Detector\",\"'-2+3\",\"'=HYPERLINK(\"\"http://x\"\",\"\"a\"\").docx\"")
                     .arg(threat.timestamp.toString(Qt::ISODate)));
        // Those characters further inside a value change nothing
        QCOMPARE(lines[2],
                 QStringLiteral("%1,High,\"PatternDetector\",\"a-b\",\"x+y.docx\"")
                     .arg(plain.timestamp.toString(Qt::ISODate)));
    }

    void testCsvExportQuoting()
    {
        ThreatLogger logger;
        ThreatInfo threat = makeThreat(0, ThreatLevel::Medium, QStringLiteral("EntropyDetector"));
        threat.description = QStringLiteral("Entropy \"spike\", 7.98 bits/byte");
        threat.affectedFiles = {QStringLiteral("dir with, comma/a.bin"), QStringLiteral("b\"q.bin")};
        logger.logThreat(threat);

        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());
        const QString csvPath = tmp.filePath(QStringLiteral("export.csv"));
        QVERIFY(logger.exportToCsv(csvPath));

        QFile csv(csvPath);
        QVERIFY(csv.open(QIODevice::ReadOnly | QIODevice::Text));
        const QStringList lines = QString::fromUtf8(csv.readAll()).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        csv.close();

        QCOMPARE(lines.size(), 2);
        QCOMPARE(lines[0], QStringLiteral("Timestamp,Level,Detector,Description,Files"));
        QCOMPARE(lines[1],
                 QStringLiteral("%1,Medium,\"EntropyDetector\",\"Entropy \"\"spike\"\", 7.98 bits/byte\","
                                "\"dir with, comma/a.bin;b\"\"q.bin\"")
                     .arg(threat.timestamp.toString(Qt::ISODate)));

        // Export fails cleanly on an unwritable path
        QVERIFY(!logger.exportToCsv(tmp.filePath(QStringLiteral("missing/dir/export.csv"))));
    }

    void testStatistics()
    {
        ThreatLogger logger;
        logger.logThreat(makeThreat(0, ThreatLevel::Critical, QStringLiteral("PatternDetector")));
        logger.logThreat(makeThreat(1, ThreatLevel::Critical, QStringLiteral("CanaryDetector")));
        logger.logThreat(makeThreat(2, ThreatLevel::High, QStringLiteral("PatternDetector")));
        logger.logThreat(makeThreat(3, ThreatLevel::Medium, QStringLiteral("EntropyDetector")));
        logger.logThreat(makeThreat(4, ThreatLevel::Medium, QStringLiteral("EntropyDetector")));
        logger.logThreat(makeThreat(5, ThreatLevel::Medium, QStringLiteral("EntropyDetector")));
        logger.logThreat(makeThreat(6, ThreatLevel::Low, QStringLiteral("MassDeleteDetector")));

        const ThreatLogger::Statistics stats = logger.getStatistics();
        QCOMPARE(stats.totalThreats, 7);
        QCOMPARE(stats.criticalCount, 2);
        QCOMPARE(stats.highCount, 1);
        QCOMPARE(stats.mediumCount, 3);
        QCOMPARE(stats.lowCount, 1);
        QCOMPARE(stats.byDetector.size(), 4);
        QCOMPARE(stats.byDetector.value(QStringLiteral("PatternDetector")), 2);
        QCOMPARE(stats.byDetector.value(QStringLiteral("EntropyDetector")), 3);
        QCOMPARE(stats.byDetector.value(QStringLiteral("CanaryDetector")), 1);
        QCOMPARE(stats.byDetector.value(QStringLiteral("MassDeleteDetector")), 1);
    }

    void testThreatsFromLastDays()
    {
        ThreatLogger logger;
        ThreatInfo old = makeThreat(0);
        old.timestamp = QDateTime::currentDateTime().addDays(-10);
        ThreatInfo recent = makeThreat(1);
        recent.timestamp = QDateTime::currentDateTime().addSecs(-60);
        logger.logThreat(old);
        logger.logThreat(recent);

        QCOMPARE(logger.loadThreats().size(), 2);
        const QVector<ThreatInfo> lastWeek = logger.threatsFromLastDays(7);
        QCOMPARE(lastWeek.size(), 1);
        QCOMPARE(lastWeek[0].description, QStringLiteral("Threat number 1"));
        QCOMPARE(logger.threatsFromLastDays(30).size(), 2);
    }

    void testClearLog()
    {
        ThreatLogger logger;
        logger.setRotationSizeBytes(1024);
        for (int i = 0; i < 50; ++i) {
            logger.logThreat(makeThreat(i));
        }
        QVERIFY(QFileInfo::exists(logger.rotatedLogFilePath()));
        QVERIFY(logger.loadThreats().size() > 0);

        logger.clearLog();

        QVERIFY(!QFileInfo::exists(logger.rotatedLogFilePath()));
        QVERIFY(QFileInfo::exists(logger.logFilePath()));
        QCOMPARE(QFileInfo(logger.logFilePath()).size(), static_cast<qint64>(0));
        QCOMPARE(logger.loadThreats().size(), 0);
        QCOMPARE(logger.getStatistics().totalThreats, 0);

        // Logging still works after a clear
        logger.logThreat(makeThreat(0));
        QCOMPARE(logger.loadThreats().size(), 1);
    }

    void testLoadCapsAtMaxEntries()
    {
        ThreatLogger logger;
        // Raise the rotation limit so the whole history stays in the files
        logger.setRotationSizeBytes(64LL * 1024 * 1024);
        const int count = ThreatLogger::MAX_LOADED_ENTRIES + 25;
        for (int i = 0; i < count; ++i) {
            logger.logThreat(makeThreat(i));
        }
        const QVector<ThreatInfo> loaded = logger.loadThreats();
        QCOMPARE(loaded.size(), ThreatLogger::MAX_LOADED_ENTRIES);
        QCOMPARE(loaded.first().description, QStringLiteral("Threat number 25"));
        QCOMPARE(loaded.last().description, QStringLiteral("Threat number %1").arg(count - 1));
    }

    void benchmarkAppendIsLinear()
    {
        ThreatLogger logger;
        QElapsedTimer timer;
        timer.start();
        for (int i = 0; i < 2000; ++i) {
            logger.logThreat(makeThreat(i), QStringLiteral("sync_paused"));
        }
        const qint64 elapsedMs = timer.elapsed();
        qInfo() << "2000 logThreat() calls took" << elapsedMs << "ms";
        // The previous implementation rewrote the whole file on each call
        // (quadratic, ~11 s on this machine for 2000 entries).
        QVERIFY2(elapsedMs < 2000, qPrintable(QStringLiteral("logging 2000 threats took %1 ms").arg(elapsedMs)));
        QCOMPARE(logger.loadThreats().size(), 2000);
    }
};

QTEST_GUILESS_MAIN(TestThreatLogger)
#include "testthreatlogger.moc"

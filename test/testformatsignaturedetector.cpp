/*
 * Nextcloud Sentinel Edition - Format Signature Detector Unit Tests
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QtTest>
#include <QRandomGenerator>
#include <QTemporaryDir>

#include "libsync/killswitch/killswitchmanager.h"
#include "libsync/killswitch/detectors/formatsignaturedetector.h"
#include "libsync/syncfileitem.h"

using namespace OCC;

using Verdict = FormatSignatureDetector::Verdict;

#define EXPECT_VERDICT(expr, expected) \
    do { \
        const FormatSignatureDetector::Result verdictResult = (expr); \
        QVERIFY2(verdictResult.verdict == Verdict::expected, \
                 qPrintable(QStringLiteral("expected " #expected ", got reason: ") + verdictResult.reason)); \
    } while (false)

class TestFormatSignatureDetector : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir _dir;

    // ---------- byte helpers ----------

    static QByteArray randomBytes(int size)
    {
        QByteArray data(size, Qt::Uninitialized);
        for (int i = 0; i < size; i++) {
            data[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
        }
        return data;
    }

    static QByteArray u32be(quint32 v)
    {
        QByteArray out;
        out.append(static_cast<char>(v >> 24));
        out.append(static_cast<char>(v >> 16));
        out.append(static_cast<char>(v >> 8));
        out.append(static_cast<char>(v));
        return out;
    }

    static QByteArray u16le(quint16 v)
    {
        QByteArray out;
        out.append(static_cast<char>(v));
        out.append(static_cast<char>(v >> 8));
        return out;
    }

    static QByteArray u32le(quint32 v)
    {
        return u16le(static_cast<quint16>(v)) + u16le(static_cast<quint16>(v >> 16));
    }

    static QByteArray pngChunk(const QByteArray &type, const QByteArray &data)
    {
        return u32be(static_cast<quint32>(data.size())) + type + data
            + u32be(FormatSignatureDetector::crc32(type + data));
    }

    static QByteArray minimalPng()
    {
        QByteArray ihdr = u32be(1) + u32be(1); // 1x1
        ihdr.append('\x08'); // bit depth
        ihdr.append('\x02'); // truecolor
        ihdr.append('\0');
        ihdr.append('\0');
        ihdr.append('\0');
        return QByteArray::fromHex("89504E470D0A1A0A")
            + pngChunk("IHDR", ihdr)
            + pngChunk("IDAT", randomBytes(40))
            + pngChunk("IEND", QByteArray());
    }

    static QByteArray zipEocd(const QByteArray &comment)
    {
        QByteArray eocd = QByteArray::fromHex("504B0506");
        eocd += QByteArray(16, '\0'); // disk numbers, entry counts, cd size, cd offset
        eocd += u16le(static_cast<quint16>(comment.size()));
        eocd += comment;
        return eocd;
    }

    static QByteArray emptyZip()
    {
        return zipEocd(QByteArray("this comment makes the empty archive larger than the minimum size"));
    }

    static QByteArray zipWithEntry(const QByteArray &content)
    {
        const QByteArray name("[Content_Types].xml");
        QByteArray local = QByteArray::fromHex("504B0304");
        local += u16le(20);                                    // version needed
        local += u16le(0);                                     // flags
        local += u16le(0);                                     // stored
        local += u16le(0) + u16le(0);                          // time, date
        local += u32le(FormatSignatureDetector::crc32(content)); // crc
        local += u32le(static_cast<quint32>(content.size()));
        local += u32le(static_cast<quint32>(content.size()));
        local += u16le(static_cast<quint16>(name.size()));
        local += u16le(0);
        local += name;
        local += content;
        return local + zipEocd(QByteArray());
    }

    static QByteArray minimalPdf()
    {
        return QByteArray("%PDF-1.4\n"
                          "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                          "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
                          "trailer\n<< /Root 1 0 R >>\n"
                          "startxref\n0\n"
                          "%%EOF\n");
    }

    static QByteArray minimalJpeg(int scanBytes = 4000)
    {
        QByteArray jpeg = QByteArray::fromHex("FFD8");
        // APP0 / JFIF, length 16
        jpeg += QByteArray::fromHex("FFE0" "0010" "4A46494600" "0101" "00" "0001" "0001" "0000");
        // DQT, length 67
        jpeg += QByteArray::fromHex("FFDB" "0043" "00") + QByteArray(64, '\x10');
        // SOF0, length 11: 8 bit, 1x1, one component
        jpeg += QByteArray::fromHex("FFC0" "000B" "08" "0001" "0001" "01" "01" "11" "00");
        // SOS, length 8
        jpeg += QByteArray::fromHex("FFDA" "0008" "01" "01" "00" "00" "3F" "00");
        jpeg += randomBytes(scanBytes);
        jpeg += QByteArray::fromHex("FFD9");
        return jpeg;
    }

    static QByteArray id3Mp3()
    {
        return QByteArray("ID3") + QByteArray::fromHex("03000000000A00") + randomBytes(4000);
    }

    static QByteArray plainText()
    {
        QByteArray text;
        for (int i = 0; i < 40; i++) {
            text += "The quick brown fox jumps over the lazy dog. Zeile ";
            text += QByteArray::number(i);
            text += " \xC3\xA4\xC3\xB6\xC3\xBC \xE2\x82\xAC\n";
        }
        return text;
    }

    // ---------- file helpers ----------

    QString write(const QString &name, const QByteArray &data)
    {
        const QString path = _dir.filePath(name);
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            return QString();
        }
        file.write(data);
        file.close();
        return path;
    }

    FormatSignatureDetector::Result check(const QString &name, const QByteArray &data)
    {
        FormatSignatureDetector detector;
        return detector.checkFile(write(name, data), name);
    }

    static SyncFileItem makeItem(const QString &relativeName,
                                 SyncInstructions instruction = CSYNC_INSTRUCTION_NEW,
                                 SyncFileItem::Direction direction = SyncFileItem::Up)
    {
        SyncFileItem item;
        item._file = relativeName;
        item._instruction = instruction;
        item._type = ItemTypeFile;
        item._direction = direction;
        return item;
    }

    AnalysisContext context() const
    {
        AnalysisContext ctx;
        ctx.localRootPath = _dir.path();
        return ctx;
    }

private slots:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
        QVERIFY(_dir.isValid());
    }

    // ==================== Static helpers ====================

    void testSignatureTable()
    {
        QVERIFY(FormatSignatureDetector::hasKnownSignature("photo.jpg"));
        QVERIFY(FormatSignatureDetector::hasKnownSignature("Docs/Report.DOCX"));
        QVERIFY(FormatSignatureDetector::hasKnownSignature("a.pdf"));
        QVERIFY(FormatSignatureDetector::hasKnownSignature("a.mp4"));
        QVERIFY(FormatSignatureDetector::hasKnownSignature("a.kdbx"));
        QVERIFY(FormatSignatureDetector::hasKnownSignature("notes.txt"));
        QVERIFY(!FormatSignatureDetector::hasKnownSignature("dump.bin"));
        QVERIFY(!FormatSignatureDetector::hasKnownSignature("backup.tar"));
        QVERIFY(!FormatSignatureDetector::hasKnownSignature("secret.gpg"));
        QVERIFY(!FormatSignatureDetector::hasKnownSignature("noextension"));
        QVERIFY(!FormatSignatureDetector::hasKnownSignature(".hidden"));

        QVERIFY(FormatSignatureDetector::isTextExtension("notes.txt"));
        QVERIFY(FormatSignatureDetector::isTextExtension("data.JSON"));
        QVERIFY(FormatSignatureDetector::isTextExtension("main.cpp"));
        QVERIFY(!FormatSignatureDetector::isTextExtension("photo.jpg"));
        QVERIFY(!FormatSignatureDetector::isTextExtension("dump.bin"));
    }

    void testCrc32KnownVector()
    {
        QCOMPARE(FormatSignatureDetector::crc32("123456789"), 0xCBF43926u);
        QCOMPARE(FormatSignatureDetector::crc32(QByteArray()), 0u);
    }

    void testHeaderEntropy()
    {
        QVERIFY(FormatSignatureDetector::headerEntropy(randomBytes(4096)) >= 7.0);
        QVERIFY(FormatSignatureDetector::headerEntropy(plainText()) < 6.0);
        QCOMPARE(FormatSignatureDetector::headerEntropy(QByteArray()), 0.0);
    }

    // ==================== Valid files match ====================

    void testValidPngMatches()
    {
        const auto result = check("valid.png", minimalPng());
        EXPECT_VERDICT(result, Match);
        QVERIFY(!result.tailCorrupted);
        QCOMPARE(result.expectedFormat, QStringLiteral("PNG image"));
    }

    void testValidZipMatches()
    {
        EXPECT_VERDICT(check("empty.zip", emptyZip()), Match);
        EXPECT_VERDICT(check("archive.zip", zipWithEntry(randomBytes(5000))), Match);
        EXPECT_VERDICT(check("big.zip", zipWithEntry(randomBytes(200000))), Match);
    }

    void testValidDocxMatches()
    {
        const auto result = check("report.docx", zipWithEntry(plainText()));
        EXPECT_VERDICT(result, Match);
        QVERIFY(!result.headerLooksRandom);
    }

    void testValidPdfMatches()
    {
        EXPECT_VERDICT(check("paper.pdf", minimalPdf()), Match);
        // Junk before the header (within 1 KB) and trailing newlines are tolerated
        EXPECT_VERDICT(check("junk.pdf", QByteArray(200, '\n') + minimalPdf() + "\r\n\r\n"), Match);
    }

    void testValidJpegMatches()
    {
        const auto result = check("photo.jpg", minimalJpeg());
        EXPECT_VERDICT(result, Match);
        // Trailing data after EOI (motion photos) must not be flagged
        EXPECT_VERDICT(check("motion.jpeg", minimalJpeg() + randomBytes(3000)), Match);
    }

    void testValidMp3Matches()
    {
        EXPECT_VERDICT(check("song.mp3", id3Mp3()), Match);
        // Headerless stream: MPEG1 layer III 128 kbit/s 44.1 kHz frames (417 bytes)
        QByteArray frames;
        for (int i = 0; i < 4; i++) {
            frames += QByteArray::fromHex("FFFB9000") + randomBytes(413);
        }
        EXPECT_VERDICT(check("raw.mp3", frames), Match);
    }

    void testValidTextMatches()
    {
        EXPECT_VERDICT(check("notes.txt", plainText()), Match);
        EXPECT_VERDICT(check("bom.md", QByteArray("\xEF\xBB\xBF") + plainText()), Match);
        EXPECT_VERDICT(check("utf16.csv", QByteArray("\xFF\xFE") + QByteArray("a\0,\0b\0\n\0", 8).repeated(20)), Match);
        // Multi-byte character cut by the 4 KB sample boundary is not an error
        const QByteArray longText = QByteArray(4095, 'a') + QByteArray("\xE2\x82\xAC") + plainText();
        EXPECT_VERDICT(check("long.txt", longText), Match);
    }

    void testOtherFormatsMatch()
    {
        EXPECT_VERDICT(check("a.gif", QByteArray("GIF89a") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.gz", QByteArray::fromHex("1F8B08") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.7z", QByteArray::fromHex("377ABCAF271C") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.doc", QByteArray::fromHex("D0CF11E0A1B11AE1") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.sqlite", QByteArray("SQLite format 3\0", 16) + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.mp4", QByteArray::fromHex("00000018") + "ftypisom" + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.heic", QByteArray::fromHex("00000018") + "ftypheic" + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.mov", QByteArray::fromHex("00001000") + "mdat" + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.webp", QByteArray("RIFF") + randomBytes(4) + "WEBPVP8 " + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.bz2", QByteArray("BZh9") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.bmp", QByteArray("BM") + randomBytes(12) + u32le(40) + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.pem", QByteArray("-----BEGIN CERTIFICATE-----\nMIIB") + QByteArray(60, 'A')), Match);
        EXPECT_VERDICT(check("a.crt", QByteArray("-----BEGIN CERTIFICATE-----\nMIIB") + QByteArray(60, 'A')), Match);
        // DER: SEQUENCE with a length that matches the file size
        const QByteArray derBody = randomBytes(300);
        EXPECT_VERDICT(check("a.der", QByteArray::fromHex("3082012C") + derBody), Match);
        EXPECT_VERDICT(check("a.rtf", QByteArray("{\\rtf1\\ansi ") + QByteArray(80, 'x')), Match);
        EXPECT_VERDICT(check("a.mkv", QByteArray::fromHex("1A45DFA3") + randomBytes(100)), Match);
        EXPECT_VERDICT(check("a.exe", QByteArray("MZ") + randomBytes(100)), Match);
    }

    // ==================== Encrypted files mismatch ====================

    void testFullyRandomPngMismatch()
    {
        const auto result = check("random.png", randomBytes(5000));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
        QVERIFY(result.reason.contains("signature"));
    }

    void testFullyRandomDocxAndZipMismatch()
    {
        auto result = check("random.docx", randomBytes(5000));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
        result = check("random.zip", randomBytes(100000));
        EXPECT_VERDICT(result, Mismatch);
    }

    void testFullyRandomPdfMismatch()
    {
        const auto result = check("random.pdf", randomBytes(5000));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
    }

    void testFullyRandomJpegMismatch()
    {
        const auto result = check("random.jpg", randomBytes(5000));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
    }

    void testFullyRandomMp3AndMp4Mismatch()
    {
        EXPECT_VERDICT(check("random.mp3", randomBytes(5000)), Mismatch);
        EXPECT_VERDICT(check("random.mp4", randomBytes(5000)), Mismatch);
        EXPECT_VERDICT(check("random.m4a", randomBytes(5000)), Mismatch);
    }

    void testJpegHeaderWithRandomBodyMismatch()
    {
        // Intact SOI + APP0 marker, then ciphertext where the next segment should start
        const QByteArray decoy = QByteArray::fromHex("FFD8FFE00010") + "JFIF" + randomBytes(5120);
        const auto result = check("decoy.jpg", decoy);
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
        QVERIFY(result.reason.contains("segment"));
    }

    void testPngHeaderWithRandomBodyMismatch()
    {
        const auto result = check("decoy.png", QByteArray::fromHex("89504E470D0A1A0A") + randomBytes(5120));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.reason.contains("IHDR"));
    }

    void testDocxChunkedEncryptionSparingHeaderMismatch()
    {
        // 100 KB of document, then the last 64 KB overwritten: header intact, EOCD gone
        QByteArray docx = zipWithEntry(randomBytes(100000));
        const QByteArray tail = randomBytes(65536);
        docx.replace(docx.size() - tail.size(), tail.size(), tail);

        const auto result = check("chunked.docx", docx);
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.tailCorrupted);
        QVERIFY(result.reason.contains("truncated/corrupted tail"));
    }

    void testPdfWithoutEofMismatch()
    {
        QByteArray pdf = minimalPdf();
        pdf.replace("%%EOF", "");
        pdf += randomBytes(3000);
        const auto result = check("noeof.pdf", pdf);
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.tailCorrupted);
        QVERIFY(result.reason.contains("truncated/corrupted tail"));
    }

    void testPngWithoutIendMismatch()
    {
        const auto result = check("noiend.png", minimalPng() + randomBytes(2000));
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.tailCorrupted);
    }

    void testTextWithNulBytesMismatch()
    {
        QByteArray data = randomBytes(2000);
        data[10] = '\0';
        const auto result = check("notes.txt", data);
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.headerLooksRandom);
        QVERIFY(result.reason.contains("NUL"));
    }

    void testTextInvalidUtf8Mismatch()
    {
        // No NUL anywhere, but bytes that cannot form UTF-8 sequences
        const auto result = check("latin.json", QByteArray("{\"name\": \"") + QByteArray(100, '\xFF') + "\"}");
        EXPECT_VERDICT(result, Mismatch);
        QVERIFY(result.reason.contains("UTF-8"));
        QVERIFY(!result.headerLooksRandom);
    }

    void testTinyAndMissingFilesAreUnknown()
    {
        EXPECT_VERDICT(check("tiny.jpg", randomBytes(63)), Unknown);
        EXPECT_VERDICT(check("tiny.zip", zipEocd(QByteArray())), Unknown); // 22 bytes
        EXPECT_VERDICT(check("empty.txt", QByteArray()), Unknown);
        FormatSignatureDetector detector;
        EXPECT_VERDICT(detector.checkFile(_dir.filePath("does-not-exist.pdf"), "does-not-exist.pdf"), Unknown);
    }

    void testUnknownExtensionsAreUnknown()
    {
        EXPECT_VERDICT(check("random.bin", randomBytes(5000)), Unknown);
        EXPECT_VERDICT(check("random.dat", randomBytes(5000)), Unknown);
        EXPECT_VERDICT(check("secret.gpg", randomBytes(5000)), Unknown);
        EXPECT_VERDICT(check("secret.pgp", randomBytes(5000)), Unknown);
        EXPECT_VERDICT(check("noext", randomBytes(5000)), Unknown);
    }

    // ==================== analyze() ====================

    void testAnalyzeValidFilesAreNone()
    {
        write("ok.png", minimalPng());
        write("ok.docx", zipWithEntry(plainText()));
        write("ok.txt", plainText());
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;
        for (const char *name : {"ok.png", "ok.docx", "ok.txt"}) {
            const ThreatInfo info = detector.analyze(makeItem(QString::fromLatin1(name), CSYNC_INSTRUCTION_SYNC), events, context());
            QCOMPARE(info.level, ThreatLevel::None);
        }
    }

    void testAnalyzeTextNamedJpgIsLowOnly()
    {
        write("misnamed.jpg", plainText());
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;

        for (int i = 0; i < 5; i++) {
            const ThreatInfo info = detector.analyze(makeItem("misnamed.jpg", CSYNC_INSTRUCTION_SYNC), events, context());
            QCOMPARE(info.level, ThreatLevel::Low);
            QCOMPARE(info.detectorName, QStringLiteral("FormatSignatureDetector"));
            QVERIFY(info.description.contains("not random"));
        }
        // Low hits do not count towards the window
        write("fresh.pdf", randomBytes(5000));
        const ThreatInfo info = detector.analyze(makeItem("fresh.pdf"), events, context());
        QCOMPARE(info.level, ThreatLevel::Medium);
    }

    void testAnalyzeUnknownExtensionIsNone()
    {
        write("random.bin", randomBytes(5000));
        write("random.dat", randomBytes(5000));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;
        QCOMPARE(detector.analyze(makeItem("random.bin", CSYNC_INSTRUCTION_SYNC), events, context()).level, ThreatLevel::None);
        QCOMPARE(detector.analyze(makeItem("random.dat"), events, context()).level, ThreatLevel::None);
    }

    void testAnalyzeDirectionDownIsNone()
    {
        write("down.jpg", randomBytes(5000));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;
        const ThreatInfo info = detector.analyze(makeItem("down.jpg", CSYNC_INSTRUCTION_SYNC, SyncFileItem::Down), events, context());
        QCOMPARE(info.level, ThreatLevel::None);
    }

    void testAnalyzeSkipsDirectoriesOtherInstructionsAndDisabled()
    {
        write("skip.jpg", randomBytes(5000));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;

        SyncFileItem dirItem = makeItem("skip.jpg", CSYNC_INSTRUCTION_SYNC);
        dirItem._type = ItemTypeDirectory;
        QCOMPARE(detector.analyze(dirItem, events, context()).level, ThreatLevel::None);

        QCOMPARE(detector.analyze(makeItem("skip.jpg", CSYNC_INSTRUCTION_REMOVE), events, context()).level, ThreatLevel::None);
        QCOMPARE(detector.analyze(makeItem("skip.jpg", CSYNC_INSTRUCTION_NONE), events, context()).level, ThreatLevel::None);

        detector.setEnabled(false);
        QCOMPARE(detector.analyze(makeItem("skip.jpg", CSYNC_INSTRUCTION_SYNC), events, context()).level, ThreatLevel::None);
        detector.setEnabled(true);
        QCOMPARE(detector.analyze(makeItem("skip.jpg", CSYNC_INSTRUCTION_SYNC), events, context()).level, ThreatLevel::High);
    }

    void testAnalyzeNewMismatchEscalatesWithinWindow()
    {
        FormatSignatureDetector detector;
        detector.setThreshold(3);
        detector.setWindowSeconds(60);
        QVector<KillSwitchManager::Event> events;

        const ThreatLevel expected[] = {
            ThreatLevel::Medium, ThreatLevel::Medium, ThreatLevel::High,
            ThreatLevel::High, ThreatLevel::High, ThreatLevel::Critical,
        };
        for (int i = 0; i < 6; i++) {
            const QString name = QStringLiteral("new%1.jpg").arg(i);
            write(name, randomBytes(5000));
            const ThreatInfo info = detector.analyze(makeItem(name), events, context());
            QCOMPARE(info.level, expected[i]);
            QCOMPARE(info.affectedFiles, QStringList{_dir.filePath(name)});
            QVERIFY(info.description.contains("JPEG image"));
            QVERIFY(info.description.contains(name));
        }
    }

    void testAnalyzeSyncMismatchIsHighImmediately()
    {
        write("existing.pdf", randomBytes(5000));
        write("conflict.docx", randomBytes(5000));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;

        const ThreatInfo sync = detector.analyze(makeItem("existing.pdf", CSYNC_INSTRUCTION_SYNC), events, context());
        QCOMPARE(sync.level, ThreatLevel::High);
        QCOMPARE(sync.affectedFiles, QStringList{_dir.filePath("existing.pdf")});
        QVERIFY(sync.description.contains("PDF document"));
        QVERIFY(sync.description.contains("Modified file"));

        const ThreatInfo conflict = detector.analyze(makeItem("conflict.docx", CSYNC_INSTRUCTION_CONFLICT), events, context());
        QCOMPARE(conflict.level, ThreatLevel::High);
    }

    void testAnalyzeChunkedEncryptionEscalatesWithCount()
    {
        // Header intact, tail encrypted (chunked encryption that skipped the
        // first block). One such file also looks like an archive still being
        // written, so a single hit is Medium; a burst of them is High.
        FormatSignatureDetector detector;
        detector.setThreshold(3);
        QVector<KillSwitchManager::Event> events;

        QVector<ThreatLevel> levels;
        for (int i = 0; i < 3; i++) {
            QByteArray docx = zipWithEntry(randomBytes(100000));
            const QByteArray tail = randomBytes(65536);
            docx.replace(docx.size() - tail.size(), tail.size(), tail);
            const QString name = QStringLiteral("chunked%1.docx").arg(i);
            write(name, docx);

            const ThreatInfo info = detector.analyze(makeItem(name, CSYNC_INSTRUCTION_SYNC), events, context());
            QVERIFY(info.description.contains("truncated/corrupted tail"));
            levels.append(info.level);
        }

        QCOMPARE(levels[0], ThreatLevel::Medium);
        QCOMPARE(levels[1], ThreatLevel::Medium);
        QCOMPARE(levels[2], ThreatLevel::High);
    }

    void testAnalyzeTinyFileIsNone()
    {
        write("tiny.jpg", randomBytes(40));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;
        QCOMPARE(detector.analyze(makeItem("tiny.jpg", CSYNC_INSTRUCTION_SYNC), events, context()).level, ThreatLevel::None);
    }

    void testAnalyzeWithoutContextUsesRelativePath()
    {
        // Without a sync root the relative path cannot be opened: nothing to say
        write("blind.jpg", randomBytes(5000));
        FormatSignatureDetector detector;
        QVector<KillSwitchManager::Event> events;
        QCOMPARE(detector.analyze(makeItem("blind.jpg", CSYNC_INSTRUCTION_SYNC), events).level, ThreatLevel::None);
    }

    // ==================== Real samples ====================

    void testRealEncryptedSamples()
    {
        const QString fakeJpg = QFINDTESTDATA("data/encrypted/fake-image.jpg");
        if (fakeJpg.isEmpty()) {
            QSKIP("Test data not found - run generate-test-files.sh first");
        }
        const QString dataDir = QFileInfo(fakeJpg).absolutePath();
        FormatSignatureDetector detector;

        // Valid headers glued onto random data: the decoys of an in-place encryptor
        for (const char *fake : {"fake-image.jpg", "fake-image.png", "fake-archive.zip"}) {
            const QString name = QString::fromLatin1(fake);
            const auto result = detector.checkFile(dataDir + QLatin1Char('/') + name, name);
            QVERIFY2(result.verdict == Verdict::Mismatch, qPrintable(name + ": " + result.reason));
            QVERIFY2(result.headerLooksRandom, qPrintable(name));
        }

        // Genuine content
        for (const char *good : {"normal.txt", "config.json", "source.cpp", "RESTORE_FILES.html"}) {
            const QString name = QString::fromLatin1(good);
            const auto result = detector.checkFile(dataDir + QLatin1Char('/') + name, name);
            QVERIFY2(result.verdict != Verdict::Mismatch, qPrintable(name + ": " + result.reason));
        }

        // Renamed ciphertext is the PatternDetector's job; here it is simply unknown
        EXPECT_VERDICT(detector.checkFile(dataDir + "/random.bin", "random.bin"), Unknown);
        EXPECT_VERDICT(detector.checkFile(dataDir + "/document.pdf.locked", "document.pdf.locked"), Unknown);
        EXPECT_VERDICT(detector.checkFile(dataDir + "/aes256.txt.enc", "aes256.txt.enc"), Unknown);
    }
};

QTEST_GUILESS_MAIN(TestFormatSignatureDetector)
#include "testformatsignaturedetector.moc"

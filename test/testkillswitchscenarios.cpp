/*
 * Nextcloud Sentinel Edition - Kill Switch end-to-end attack scenarios
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * These tests drive the complete Kill Switch (manager + the five detectors
 * registered in the same order as src/gui/application.cpp) against a small
 * on-disk "sandbox" of realistic files. Every attack scenario mutates the
 * files exactly as a real ransomware family would (see the research notes
 * on LockBit 3, BlackCat, Play, Black Basta, RansomHub, ...) and then feeds
 * the items the sync discovery would produce, in a plausible order. The
 * index at which the manager trips is the number of files that were
 * already damaged ("lost") before sync was paused.
 *
 * Benign scenarios assert that normal user activity does not trip the
 * switch and report the highest threat level that was raised.
 *
 * A summary table is printed with qInfo() at the end of the run.
 */

#include <QtTest>
#include <QRandomGenerator>
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <memory>

#include "libsync/killswitch/killswitchmanager.h"
#include "libsync/killswitch/detectors/patterndetector.h"
#include "libsync/killswitch/detectors/canarydetector.h"
#include "libsync/killswitch/detectors/massdeletedetector.h"
#include "libsync/killswitch/detectors/formatsignaturedetector.h"
#include "libsync/killswitch/detectors/entropydetector.h"
#include "libsync/syncfileitem.h"

using namespace OCC;

namespace {

constexpr int KB = 1024;
constexpr int MB = 1024 * KB;

QString levelName(ThreatLevel level)
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
    return QStringLiteral("?");
}

// ---------- byte helpers ----------

QByteArray randomBytes(int size)
{
    QByteArray data(size, Qt::Uninitialized);
    const int words = size / 4;
    if (words > 0) {
        QRandomGenerator::global()->fillRange(reinterpret_cast<quint32 *>(data.data()), words);
    }
    for (int i = words * 4; i < size; ++i) {
        data[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
    }
    return data;
}

QByteArray u32be(quint32 v)
{
    QByteArray out;
    out.append(static_cast<char>(v >> 24));
    out.append(static_cast<char>(v >> 16));
    out.append(static_cast<char>(v >> 8));
    out.append(static_cast<char>(v));
    return out;
}

QByteArray u16le(quint16 v)
{
    QByteArray out;
    out.append(static_cast<char>(v));
    out.append(static_cast<char>(v >> 8));
    return out;
}

QByteArray u32le(quint32 v)
{
    return u16le(static_cast<quint16>(v)) + u16le(static_cast<quint16>(v >> 16));
}

struct ZipEntry {
    QByteArray name;
    QByteArray content;
};

QByteArray zipLocalHeader(const ZipEntry &entry)
{
    QByteArray local = QByteArray::fromHex("504B0304");
    local += u16le(20) + u16le(0) + u16le(0) + u16le(0) + u16le(0);     // version, flags, stored, time, date
    local += u32le(FormatSignatureDetector::crc32(entry.content));
    local += u32le(static_cast<quint32>(entry.content.size()));
    local += u32le(static_cast<quint32>(entry.content.size()));
    local += u16le(static_cast<quint16>(entry.name.size())) + u16le(0);
    return local + entry.name;
}

QByteArray zipCentralHeader(const ZipEntry &entry, quint32 localOffset)
{
    QByteArray central = QByteArray::fromHex("504B0102");
    central += u16le(20) + u16le(20) + u16le(0) + u16le(0) + u16le(0) + u16le(0);
    central += u32le(FormatSignatureDetector::crc32(entry.content));
    central += u32le(static_cast<quint32>(entry.content.size()));
    central += u32le(static_cast<quint32>(entry.content.size()));
    central += u16le(static_cast<quint16>(entry.name.size())) + u16le(0) + u16le(0);
    central += u16le(0) + u16le(0) + u32le(0);
    central += u32le(localOffset);
    return central + entry.name;
}

/// A proper ZIP archive: local headers + data, central directory, EOCD
QByteArray zipArchive(const QVector<ZipEntry> &entries)
{
    QByteArray data;
    QByteArray central;
    for (const ZipEntry &entry : entries) {
        central += zipCentralHeader(entry, static_cast<quint32>(data.size()));
        data += zipLocalHeader(entry) + entry.content;
    }
    QByteArray eocd = QByteArray::fromHex("504B0506");
    eocd += u16le(0) + u16le(0);
    eocd += u16le(static_cast<quint16>(entries.size())) + u16le(static_cast<quint16>(entries.size()));
    eocd += u32le(static_cast<quint32>(central.size())) + u32le(static_cast<quint32>(data.size())) + u16le(0);
    return data + central + eocd;
}

// Office documents are ZIP containers: the XML parts plus (deflated-looking)
// random media entries of at most 128 KB each, like the images of a real file
QByteArray officeDocument(int payloadSize)
{
    QVector<ZipEntry> entries;
    entries.append({"[Content_Types].xml", QByteArray("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types/>")});
    const int documentSize = qMin(payloadSize, 32 * KB);
    entries.append({"word/document.xml", randomBytes(documentSize)});
    int remaining = payloadSize - documentSize;
    for (int image = 1; remaining > 0; ++image) {
        const int size = qMin(remaining, 128 * KB);
        entries.append({"word/media/image" + QByteArray::number(image) + ".jpeg", randomBytes(size)});
        remaining -= size;
    }
    return zipArchive(entries);
}

// A PDF with a classic cross-reference table: the content is split into
// stream objects of at most 128 KB (one image per page, like a scan)
QByteArray pdfDocument(int streamSize)
{
    QByteArray pdf("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    QVector<int> offsets;
    auto addObject = [&pdf, &offsets](const QByteArray &body) {
        offsets.append(pdf.size());
        pdf += QByteArray::number(offsets.size()) + " 0 obj\n" + body + "\nendobj\n";
    };
    const int pages = qMax(1, (streamSize + 128 * KB - 1) / (128 * KB));
    addObject("<< /Type /Catalog /Pages 2 0 R >>");
    QByteArray kids;
    for (int i = 0; i < pages; ++i) {
        kids += QByteArray::number(3 + i) + " 0 R ";
    }
    addObject("<< /Type /Pages /Kids [" + kids + "] /Count " + QByteArray::number(pages) + " >>");
    int remaining = streamSize;
    for (int i = 0; i < pages; ++i) {
        const int size = qMin(remaining, 128 * KB);
        remaining -= size;
        addObject("<< /Type /Page /Parent 2 0 R /Length " + QByteArray::number(size) + " /Filter /FlateDecode >>\nstream\n"
                  + randomBytes(size) + "\nendstream");
    }
    const int xrefOffset = pdf.size();
    pdf += "xref\n0 " + QByteArray::number(offsets.size() + 1) + "\n0000000000 65535 f \n";
    for (int offset : offsets) {
        pdf += QByteArray::number(offset).rightJustified(10, '0') + " 00000 n \n";
    }
    pdf += "trailer\n<< /Size " + QByteArray::number(offsets.size() + 1) + " /Root 1 0 R >>\n"
           "startxref\n" + QByteArray::number(xrefOffset) + "\n%%EOF\n";
    return pdf;
}

QByteArray pngChunk(const QByteArray &type, const QByteArray &data)
{
    return u32be(static_cast<quint32>(data.size())) + type + data
        + u32be(FormatSignatureDetector::crc32(type + data));
}

QByteArray pngImage(int idatSize)
{
    QByteArray ihdr = u32be(640) + u32be(480);
    ihdr.append('\x08'); // bit depth
    ihdr.append('\x02'); // truecolor
    ihdr.append('\0');
    ihdr.append('\0');
    ihdr.append('\0');
    return QByteArray::fromHex("89504E470D0A1A0A")
        + pngChunk("IHDR", ihdr)
        + pngChunk("IDAT", randomBytes(idatSize))
        + pngChunk("IEND", QByteArray());
}

// Entropy-coded data as a real encoder writes it: every FF is stuffed with a
// 00 and a restart marker follows every 8 KB
QByteArray jpegScanData(int size)
{
    QByteArray scan = randomBytes(size);
    for (int i = 0; i < scan.size(); ++i) {
        if (static_cast<quint8>(scan.at(i)) == 0xFF) {
            if (i + 1 < scan.size()) {
                scan[i + 1] = '\0';
            }
            ++i;
        }
    }
    for (int i = 8 * KB; i + 1 < scan.size(); i += 8 * KB) {
        scan[i] = '\xFF';
        scan[i + 1] = static_cast<char>(0xD0 + (i / (8 * KB)) % 8);
    }
    if (!scan.isEmpty() && static_cast<quint8>(scan.at(scan.size() - 1)) == 0xFF) {
        scan[scan.size() - 1] = '\x7F';
    }
    return scan;
}

QByteArray jpegImage(int scanBytes)
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
    jpeg += jpegScanData(scanBytes);
    jpeg += QByteArray::fromHex("FFD9");
    return jpeg;
}

QByteArray mp4Atom(const QByteArray &type, const QByteArray &payload)
{
    return u32be(static_cast<quint32>(8 + payload.size())) + type + payload;
}

// Phone-style recording: ftyp, one big mdat, moov written last
QByteArray mp4Video(int mdatSize)
{
    const QByteArray ftyp = mp4Atom("ftyp", "isom" + u32be(512) + "isomiso2avc1mp41");
    const QByteArray moov = mp4Atom("moov", mp4Atom("mvhd", QByteArray(100, '\x01')) + mp4Atom("trak", randomBytes(6 * KB)));
    return ftyp + mp4Atom("mdat", randomBytes(mdatSize)) + moov;
}

// Streaming/meeting-style recording: ftyp, moov, then moof + mdat fragments of 256 KB
QByteArray fragmentedMp4Video(int approxSize)
{
    QByteArray file = mp4Atom("ftyp", "iso5" + u32be(512) + "iso5dash") + mp4Atom("moov", mp4Atom("mvhd", QByteArray(100, '\x01')));
    for (int fragment = 1; file.size() < approxSize; ++fragment) {
        file += mp4Atom("moof", mp4Atom("mfhd", u32be(0) + u32be(static_cast<quint32>(fragment))));
        file += mp4Atom("mdat", randomBytes(256 * KB));
    }
    return file;
}

// MPEG1 layer III 128 kbit/s 44.1 kHz frames (417 bytes) behind a small ID3v2 tag
QByteArray mp3Audio(int approxSize)
{
    QByteArray mp3 = QByteArray("ID3") + QByteArray::fromHex("0300" "00" "00000A00") + QByteArray(1280, '\0');
    while (mp3.size() < approxSize) {
        mp3 += QByteArray::fromHex("FFFB9000") + randomBytes(413);
    }
    return mp3;
}

QByteArray keepassDatabase(int size)
{
    // KDBX 4 signature + version, then the encrypted payload
    return QByteArray::fromHex("03D9A29A67FB4BB5" "00000400") + randomBytes(size);
}

QByteArray textDocument(int approxSize, const QString &topic)
{
    static const char *const sentences[] = {
        "Agenda for the weekly planning meeting and the follow-up actions.",
        "The quarterly figures were discussed; the revenue forecast was adjusted.",
        "Bitte die Unterlagen bis Freitag an die Buchhaltung weiterleiten.",
        // Split so "\xA9b" is not read as one hex escape; parenthesized for -Wstring-concatenation
        ("Le rapport annuel sera publi\xC3\xA9 au d\xC3\xA9" "but du mois prochain."),
        "Reminder: the backup rotation moves to the new NAS on the 15th.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod.",
    };
    QByteArray text = "# " + topic.toUtf8() + "\n\n";
    int line = 1;
    while (text.size() < approxSize) {
        text += QByteArray::number(line) + ". " + sentences[line % 6] + "\n";
        ++line;
    }
    return text;
}

QByteArray csvDocument(int approxSize)
{
    QByteArray text("date,account,description,amount,currency\n");
    int row = 0;
    while (text.size() < approxSize) {
        text += "2026-0" + QByteArray::number(1 + row % 9) + "-" + QByteArray::number(10 + row % 19)
            + ",ACC-" + QByteArray::number(1000 + row % 37)
            + ",Office supplies and travel expenses line " + QByteArray::number(row)
            + "," + QByteArray::number((row * 7919) % 100000) + "." + QByteArray::number(row % 100)
            + ",EUR\n";
        ++row;
    }
    return text;
}

int sizeBetween(int min, int max)
{
    return min + QRandomGenerator::global()->bounded(max - min + 1);
}

QString randomExtension(int length)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    QString ext;
    for (int i = 0; i < length; ++i) {
        ext += QLatin1Char(alphabet[QRandomGenerator::global()->bounded(static_cast<int>(sizeof(alphabet) - 1))]);
    }
    return ext;
}

// ---------- sync item builders (what the discovery phase would produce) ----------

SyncFileItem fileItem(const QString &relativePath, SyncInstructions instruction)
{
    SyncFileItem item;
    item._file = relativePath;
    item._instruction = instruction;
    item._type = ItemTypeFile;
    item._direction = SyncFileItem::Up;
    return item;
}

SyncFileItem modifiedItem(const QString &relativePath)
{
    return fileItem(relativePath, CSYNC_INSTRUCTION_SYNC);
}

SyncFileItem newItem(const QString &relativePath)
{
    return fileItem(relativePath, CSYNC_INSTRUCTION_NEW);
}

SyncFileItem removedItem(const QString &relativePath)
{
    return fileItem(relativePath, CSYNC_INSTRUCTION_REMOVE);
}

SyncFileItem renamedItem(const QString &from, const QString &to)
{
    SyncFileItem item = fileItem(from, CSYNC_INSTRUCTION_RENAME);
    item._renameTarget = to;
    return item;
}

// ---------- the sandbox: a sync folder seeded with realistic files ----------

class Sandbox
{
public:
    Sandbox()
    {
        if (!_dir.isValid()) {
            return;
        }
        // Folders in the order the discovery lists them (alphabetical)
        // Documents
        write(QStringLiteral("Documents/report-q1.docx"), officeDocument(sizeBetween(40 * KB, 200 * KB)));
        write(QStringLiteral("Documents/report-q2.docx"), officeDocument(sizeBetween(40 * KB, 200 * KB)));
        write(QStringLiteral("Documents/proposal.docx"), officeDocument(sizeBetween(80 * KB, 300 * KB)));
        write(QStringLiteral("Documents/minutes.docx"), officeDocument(sizeBetween(20 * KB, 60 * KB)));
        write(QStringLiteral("Documents/handbook.pdf"), pdfDocument(sizeBetween(100 * KB, 300 * KB)));
        write(QStringLiteral("Documents/contract.pdf"), pdfDocument(sizeBetween(60 * KB, 200 * KB)));
        write(QStringLiteral("Documents/invoice-2026-03.pdf"), pdfDocument(sizeBetween(20 * KB, 80 * KB)));
        write(QStringLiteral("Documents/thesis.pdf"), pdfDocument(sizeBetween(200 * KB, 300 * KB)));
        // Finance
        write(QStringLiteral("Finance/budget.xlsx"), officeDocument(sizeBetween(30 * KB, 120 * KB)));
        write(QStringLiteral("Finance/forecast.xlsx"), officeDocument(sizeBetween(30 * KB, 120 * KB)));
        write(QStringLiteral("Finance/ledger.xlsx"), officeDocument(sizeBetween(100 * KB, 300 * KB)));
        write(QStringLiteral("Finance/expenses.csv"), csvDocument(sizeBetween(20 * KB, 60 * KB)));
        write(QStringLiteral("Finance/accounts.csv"), csvDocument(sizeBetween(20 * KB, 60 * KB)));
        // Media
        write(QStringLiteral("Media/holiday.mp4"), mp4Video(sizeBetween(200 * KB, 300 * KB)));
        write(QStringLiteral("Media/demo.mp4"), mp4Video(sizeBetween(100 * KB, 300 * KB)));
        // Notes
        write(QStringLiteral("Notes/todo.txt"), textDocument(sizeBetween(20 * KB, 40 * KB), QStringLiteral("Todo")));
        write(QStringLiteral("Notes/meeting.txt"), textDocument(sizeBetween(20 * KB, 60 * KB), QStringLiteral("Meeting")));
        write(QStringLiteral("Notes/ideas.md"), textDocument(sizeBetween(20 * KB, 40 * KB), QStringLiteral("Ideas")));
        write(QStringLiteral("Notes/README.md"), textDocument(sizeBetween(20 * KB, 30 * KB), QStringLiteral("Readme")));
        write(QStringLiteral("Notes/changelog.txt"), textDocument(sizeBetween(20 * KB, 40 * KB), QStringLiteral("Changelog")));
        // Photos
        for (int i = 1; i <= 6; ++i) {
            write(QStringLiteral("Photos/IMG_%1.jpg").arg(i, 4, 10, QLatin1Char('0')),
                  jpegImage(sizeBetween(80 * KB, 300 * KB)));
        }
        write(QStringLiteral("Photos/diagram.png"), pngImage(sizeBetween(40 * KB, 200 * KB)));
        write(QStringLiteral("Photos/logo.png"), pngImage(sizeBetween(20 * KB, 60 * KB)));
        write(QStringLiteral("Photos/screenshot.png"), pngImage(sizeBetween(100 * KB, 300 * KB)));
        // Password manager
        write(QStringLiteral("Vault/passwords.kdbx"), keepassDatabase(sizeBetween(20 * KB, 80 * KB)));
        // Canary placed by the client
        write(QStringLiteral("_canary.txt"), textDocument(2 * KB, QStringLiteral("Canary - do not modify")));
        // Larger files for the chunked-encryption scenarios (3-4 MB). The
        // first three carry structure all over the file (ZIP local headers,
        // PDF objects, MP4 fragment headers); the phone video and the PNG
        // are one compressed blob with a header and a trailer.
        write(QStringLiteral("Large/archive.docx"), officeDocument(sizeBetween(3 * MB, 4 * MB)));
        write(QStringLiteral("Large/scan.pdf"), pdfDocument(sizeBetween(3 * MB, 4 * MB)));
        write(QStringLiteral("Large/recording.mp4"), fragmentedMp4Video(sizeBetween(3 * MB, 4 * MB) + 8 * KB));
        write(QStringLiteral("Large/photo.jpg"), jpegImage(sizeBetween(3 * MB, 4 * MB)));
        write(QStringLiteral("Large/podcast.mp3"), mp3Audio(sizeBetween(3 * MB, 4 * MB)));
        write(QStringLiteral("Large/video.mp4"), mp4Video(sizeBetween(3 * MB, 4 * MB)));
        write(QStringLiteral("Large/poster.png"), pngImage(sizeBetween(3 * MB, 4 * MB)));
    }

    bool isValid() const { return _dir.isValid(); }
    QString root() const { return _dir.path(); }
    QString absolute(const QString &relative) const { return _dir.filePath(relative); }
    const QStringList &files() const { return _files; }

    /// Files a ransomware would encrypt: everything except the canary and the large files
    QStringList victims() const
    {
        QStringList result;
        for (const QString &file : _files) {
            if (file == QLatin1String("_canary.txt") || file.startsWith(QLatin1String("Large/"))) {
                continue;
            }
            result.append(file);
        }
        return result;
    }

    QStringList largeFiles() const
    {
        return _files.filter(QRegularExpression(QStringLiteral("^Large/")));
    }

    QStringList withSuffix(const QStringList &suffixes) const
    {
        QStringList result;
        for (const QString &file : _files) {
            if (suffixes.contains(QFileInfo(file).suffix().toLower())) {
                result.append(file);
            }
        }
        return result;
    }

    bool write(const QString &relative, const QByteArray &data)
    {
        const QString path = absolute(relative);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            return false;
        }
        const bool ok = file.write(data) == data.size();
        file.close();
        if (ok && !_files.contains(relative)) {
            _files.append(relative);
        }
        return ok;
    }

    qint64 size(const QString &relative) const
    {
        return QFileInfo(absolute(relative)).size();
    }

    /// Overwrite [offset, offset + length) with random bytes, in place (what an in-place encryptor does)
    bool encryptRange(const QString &relative, qint64 offset, qint64 length)
    {
        QFile file(absolute(relative));
        if (!file.open(QIODevice::ReadWrite)) {
            return false;
        }
        const qint64 end = qMin(file.size(), offset + length);
        if (offset >= end || !file.seek(offset)) {
            return false;
        }
        const QByteArray noise = randomBytes(static_cast<int>(end - offset));
        return file.write(noise) == noise.size();
    }

    /// Replace the whole content with random bytes of the same size (+ optional trailer)
    bool encryptWhole(const QString &relative, const QByteArray &trailer = QByteArray())
    {
        const qint64 oldSize = size(relative);
        return write(relative, randomBytes(static_cast<int>(oldSize)) + trailer);
    }

    /// Encrypt the whole file into a new name and remove the original
    bool encryptToNewName(const QString &from, const QString &to)
    {
        const qint64 oldSize = size(from);
        if (!write(to, randomBytes(static_cast<int>(oldSize)))) {
            return false;
        }
        return remove(from);
    }

    bool rename(const QString &from, const QString &to)
    {
        if (!QFile::rename(absolute(from), absolute(to))) {
            return false;
        }
        _files.removeAll(from);
        _files.append(to);
        return true;
    }

    bool remove(const QString &relative)
    {
        _files.removeAll(relative);
        return QFile::remove(absolute(relative));
    }

private:
    QTemporaryDir _dir;
    QStringList _files;
};

// ---------- the engine under test, wired like src/gui/application.cpp ----------

struct Harness
{
    explicit Harness(const QString &root)
        : manager(std::make_unique<KillSwitchManager>())
    {
        // Same order as Application::setupKillSwitch()
        manager->registerDetector(std::make_shared<PatternDetector>());
        manager->registerDetector(std::make_shared<CanaryDetector>());
        manager->registerDetector(std::make_shared<MassDeleteDetector>());
        manager->registerDetector(std::make_shared<FormatSignatureDetector>());
        manager->registerDetector(std::make_shared<EntropyDetector>());
        // Config defaults as applied by the application
        manager->setDeleteThreshold(10, 60);
        manager->setEntropyThreshold(7.5);

        context.localRootPath = root;

        QObject::connect(manager.get(), &KillSwitchManager::threatDetected, manager.get(),
                         [this](const ThreatInfo &threat) {
                             if (threat.level > highestLevel) {
                                 highestLevel = threat.level;
                                 highestDetector = threat.detectorName;
                                 highestDescription = threat.description;
                             }
                             ++threatCount;
                         });
        QObject::connect(manager.get(), &KillSwitchManager::syncPaused, manager.get(),
                         [this](const QString &reason) { pauseReason = reason; });
    }

    /// Feed the items in order; returns the index of the item at which the kill switch tripped, or -1
    int feed(const QVector<SyncFileItem> &items)
    {
        for (int i = 0; i < items.size(); ++i) {
            manager->analyzeItem(items.at(i), context);
            // The manager's own deletion-count evaluation trips the switch
            // without analyzeItem() returning true, so look at the state.
            if (manager->isTriggered()) {
                return i;
            }
            const ThreatLevel managerLevel = manager->currentThreatLevel();
            if (managerLevel > highestLevel) {
                highestLevel = managerLevel;
                highestDetector = QStringLiteral("KillSwitchManager");
                highestDescription = QStringLiteral("manager threat level");
            }
        }
        return -1;
    }

    std::unique_ptr<KillSwitchManager> manager;
    AnalysisContext context;
    ThreatLevel highestLevel = ThreatLevel::None;
    QString highestDetector;
    QString highestDescription;
    QString pauseReason;
    int threatCount = 0;
};

} // namespace

class TestKillSwitchScenarios : public QObject
{
    Q_OBJECT

private:
    struct SummaryRow {
        QString scenario;
        QString outcome;
        QString detail;
    };
    QVector<SummaryRow> _summary;

    /// Record an attack result. filesPerItem: how many items the discovery emits per victim file.
    void recordAttack(const QString &name, int triggerIndex, int itemCount, int itemsPerFile,
                      const Harness &harness)
    {
        SummaryRow row;
        row.scenario = name;
        if (triggerIndex < 0) {
            row.outcome = QStringLiteral("NOT TRIGGERED after %1 items (highest: %2)")
                              .arg(itemCount)
                              .arg(levelName(harness.highestLevel));
        } else {
            const int filesLost = triggerIndex / qMax(1, itemsPerFile);
            row.outcome = QStringLiteral("triggered at item %1/%2, files lost: %3")
                              .arg(triggerIndex + 1)
                              .arg(itemCount)
                              .arg(filesLost);
        }
        row.detail = harness.pauseReason.isEmpty()
            ? QStringLiteral("%1: %2").arg(harness.highestDetector, harness.highestDescription)
            : harness.pauseReason;
        _summary.append(row);
        qInfo().noquote() << "[scenario]" << name << "->" << row.outcome << "|" << row.detail.left(140);
    }

    void recordBenign(const QString &name, int triggerIndex, int itemCount, const Harness &harness,
                      bool probe = false)
    {
        SummaryRow row;
        row.scenario = name;
        if (triggerIndex < 0) {
            row.outcome = QStringLiteral("not triggered (%1 items), highest level: %2")
                              .arg(itemCount)
                              .arg(levelName(harness.highestLevel));
        } else {
            row.outcome = QStringLiteral("%1triggered at item %2/%3")
                              .arg(probe ? QStringLiteral("") : QStringLiteral("FALSE POSITIVE: "))
                              .arg(triggerIndex + 1)
                              .arg(itemCount);
        }
        row.detail = harness.pauseReason.isEmpty()
            ? (harness.highestLevel == ThreatLevel::None
                   ? QString()
                   : QStringLiteral("%1: %2").arg(harness.highestDetector, harness.highestDescription))
            : harness.pauseReason;
        _summary.append(row);
        qInfo().noquote() << "[scenario]" << name << "->" << row.outcome << "|" << row.detail.left(140);
    }

    static QVector<SyncFileItem> modifiedItems(const QStringList &paths)
    {
        QVector<SyncFileItem> items;
        for (const QString &path : paths) {
            items.append(modifiedItem(path));
        }
        return items;
    }

private slots:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
        Sandbox probe;
        QVERIFY(probe.isValid());
        QVERIFY2(probe.files().size() >= 30, qPrintable(QString::number(probe.files().size())));
        // Every seeded file must pass the format check, otherwise the benign
        // scenarios would be measuring our builders and not the detector.
        FormatSignatureDetector detector;
        for (const QString &file : probe.files()) {
            const auto result = detector.checkFile(probe.absolute(file), file);
            QVERIFY2(result.verdict != FormatSignatureDetector::Verdict::Mismatch,
                     qPrintable(file + QStringLiteral(": ") + result.reason));
        }
    }

    void cleanupTestCase()
    {
        qInfo().noquote() << "";
        qInfo().noquote() << "=== Kill Switch scenario summary ===";
        qInfo().noquote() << QStringLiteral("| %1 | %2 | %3 |")
                                 .arg(QStringLiteral("Scenario"), -58)
                                 .arg(QStringLiteral("Outcome"), -58)
                                 .arg(QStringLiteral("Reason / highest finding"));
        qInfo().noquote() << QStringLiteral("|%1|%2|%3|")
                                 .arg(QString(60, QLatin1Char('-')), QString(60, QLatin1Char('-')),
                                      QString(40, QLatin1Char('-')));
        for (const SummaryRow &row : std::as_const(_summary)) {
            qInfo().noquote() << QStringLiteral("| %1 | %2 | %3 |")
                                     .arg(row.scenario, -58)
                                     .arg(row.outcome, -58)
                                     .arg(row.detail.left(110));
        }
    }

    // ==================== Attack scenarios ====================

    // 1a. LockBit 3.0 style: encrypt in place and append a random 9-char extension.
    //     Clients that detect the move report a RENAME (old -> new).
    void attackRenameRandomExtension_renameItems()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());
        const QString ext = QStringLiteral("HLJkNskOq");

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            const QString target = victim + QLatin1Char('.') + ext;
            QVERIFY(box.encryptWhole(victim));
            QVERIFY(box.rename(victim, target));
            items.append(renamedItem(victim, target));
        }

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("1a rename + random ext .%1 (RENAME items)").arg(ext), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "LockBit-style rename with random extension was not detected");
        QVERIFY2(index <= 2, qPrintable(QStringLiteral("expected trigger by the 3rd file, got %1").arg(index + 1)));
    }

    // 1b. Same attack, but the discovery sees NEW (encrypted copy) + REMOVE (original).
    void attackRenameRandomExtension_newAndRemoveItems()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());
        const QString ext = randomExtension(9);

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            const QString target = victim + QLatin1Char('.') + ext;
            QVERIFY(box.encryptToNewName(victim, target));
            // Discovery lists the directory alphabetically: "a.docx" (gone) sorts before "a.docx.XYZ" (new)
            items.append(removedItem(victim));
            items.append(newItem(target));
        }

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("1b rename + random ext .%1 (REMOVE+NEW items)").arg(ext), index, items.size(), 2, harness);
        QVERIFY2(index >= 0, "LockBit-style rename (NEW+REMOVE) was not detected");
        QVERIFY2(index <= 5, qPrintable(QStringLiteral("expected trigger by the 3rd file, got item %1").arg(index + 1)));
    }

    // 1c. Same, NEW listed before REMOVE (no corroboration from a prior delete)
    void attackRenameRandomExtension_newBeforeRemove()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());
        const QString ext = randomExtension(7).toLower() + QStringLiteral("7"); // BlackCat-like [a-z0-9]{7+}

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            const QString target = victim + QLatin1Char('.') + ext;
            QVERIFY(box.encryptToNewName(victim, target));
            items.append(newItem(target));
            items.append(removedItem(victim));
        }

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("1c rename + random ext .%1 (NEW+REMOVE items)").arg(ext), index, items.size(), 2, harness);
        QVERIFY2(index >= 0, "BlackCat-style rename (NEW then REMOVE) was not detected");
        QVERIFY2(index <= 5, qPrintable(QStringLiteral("expected trigger by the 3rd file, got item %1").arg(index + 1)));
    }

    // 2. In-place full encryption, names unchanged (Medusa/Clop style, with a trailer marker)
    void attackInPlaceFull()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            QVERIFY(box.encryptWhole(victim, QByteArray("Clop^_-")));
        }
        const QVector<SyncFileItem> items = modifiedItems(victims);

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("2 in-place full encryption, same names (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "In-place full encryption was not detected");
        QVERIFY2(index == 0, qPrintable(QStringLiteral("expected trigger on the 1st file, got %1").arg(index + 1)));
    }

    // 3. LockBit 2.0 style: only the first 4 KB of each file are encrypted
    void attackInPlaceHeaderOnly()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            QVERIFY(box.encryptRange(victim, 0, 4 * KB));
        }
        const QVector<SyncFileItem> items = modifiedItems(victims);

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("3 in-place header-only 4 KB (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Header-only encryption was not detected");
        QVERIFY2(index == 0, qPrintable(QStringLiteral("expected trigger on the 1st file, got %1").arg(index + 1)));
    }

    // 4a. Play style: alternating 1 MB chunks, starting at offset 0
    void attackAlternatingChunksFromStart()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        const QStringList victims = box.largeFiles();
        QVERIFY(victims.size() >= 4);
        for (const QString &victim : victims) {
            const qint64 size = box.size(victim);
            for (qint64 offset = 0; offset < size; offset += 2 * MB) {
                QVERIFY(box.encryptRange(victim, offset, MB));
            }
        }
        const QVector<SyncFileItem> items = modifiedItems(victims);

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("4a alternating 1 MB chunks, first chunk encrypted (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Alternating-chunk encryption starting at offset 0 was not detected");
        QVERIFY2(index == 0, qPrintable(QStringLiteral("expected trigger on the 1st file, got %1").arg(index + 1)));
    }

    // 4b. Play/RansomHub/Conti style chunk that spares both the header and the
    //     tail: encrypt [1 MB, 2 MB) only. The FormatSignatureDetector's body
    //     walk sees the missing ZIP local headers, PDF objects and MP4 fragment
    //     headers, the JPEG marker grammar and the MP3 frame chain; a single
    //     mdat or IDAT blob (phone video, PNG) is a documented blind spot.
    void attackAlternatingChunksHeaderAndTailIntact()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        const QStringList victims = box.largeFiles();
        QVERIFY(victims.size() >= 7);
        for (const QString &victim : victims) {
            const qint64 size = box.size(victim);
            // encrypt [1 MB, 2 MB) only; header and the last >1 MB stay intact
            QVERIFY(size > 3 * MB);
            QVERIFY(box.encryptRange(victim, MB, MB));
        }

        // Per-file view before the engine runs: which formats see the chunk
        FormatSignatureDetector detector;
        QStringList seen;
        for (const QString &victim : victims) {
            const auto result = detector.checkFile(box.absolute(victim), victim);
            if (result.verdict == FormatSignatureDetector::Verdict::Mismatch) {
                QVERIFY2(result.bodyCorrupted, qPrintable(victim + ": " + result.reason));
                seen.append(QFileInfo(victim).suffix());
            }
        }
        qInfo().noquote() << "[4b] chunk at 1 MB seen in:" << seen.join(QLatin1Char(' '));
        for (const char *suffix : {"docx", "pdf", "mp3"}) {
            QVERIFY2(seen.contains(QLatin1String(suffix)), suffix);
        }
        QVERIFY2(seen.count(QStringLiteral("mp4")) >= 1, "fragmented mp4 not seen");

        const QVector<SyncFileItem> items = modifiedItems(victims);
        const int index = harness.feed(items);
        recordAttack(QStringLiteral("4b 1 MB chunk at offset 1 MB, header+tail intact (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Chunk encryption sparing header and tail was not detected");
        QVERIFY2(index <= 2, qPrintable(QStringLiteral("expected trigger by the 3rd file, got %1").arg(index + 1)));
    }

    // 5. Tail-only: header intact, tail random, across docx/xlsx/pdf/png. The last
    //    bytes carry the structure these formats are validated by (ZIP EOCD, PDF
    //    %%EOF, PNG IEND), so overwriting the tail clobbers it while the first 4 KB
    //    header stays valid. The tail is sized relative to the file so even the
    //    smallest seeded documents (~20 KB) keep an intact header.
    void attackTailOnly()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QStringList victims;
        for (const QString &file : box.withSuffix({QStringLiteral("docx"), QStringLiteral("xlsx"),
                                                   QStringLiteral("pdf"), QStringLiteral("png")})) {
            if (!file.startsWith(QLatin1String("Large/")) && box.size(file) > 16 * KB) {
                victims.append(file);
            }
        }
        QVERIFY2(victims.size() >= 3, qPrintable(QString::number(victims.size())));
        for (const QString &victim : victims) {
            const qint64 size = box.size(victim);
            const qint64 length = qMin<qint64>(96 * KB, size - 8 * KB); // keep the first 8 KB intact
            QVERIFY(box.encryptRange(victim, size - length, length));
        }
        const QVector<SyncFileItem> items = modifiedItems(victims);

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("5 tail-only 96 KB, header intact, docx/xlsx/pdf/png (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Tail-only encryption of docx/pdf/png was not detected");
        QVERIFY2(index <= 2, qPrintable(QStringLiteral("expected trigger by the 3rd file, got %1").arg(index + 1)));
    }

    // 5b. Tail-only on formats without a trailer structure (jpg, mp4, txt, csv):
    //     the last 4 KB window must still obey the format (JPEG marker grammar,
    //     the MP4 atom chain reaching the trailing moov, text without NUL bytes).
    void attackTailOnlyOnFormatsWithoutTrailer()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QStringList victims;
        for (const QString &file : box.withSuffix({QStringLiteral("jpg"), QStringLiteral("mp4"),
                                                   QStringLiteral("txt"), QStringLiteral("csv")})) {
            if (!file.startsWith(QLatin1String("Large/")) && file != QLatin1String("_canary.txt") && box.size(file) > 16 * KB) {
                victims.append(file);
            }
        }
        QVERIFY(victims.size() >= 5);
        for (const QString &victim : victims) {
            const qint64 size = box.size(victim);
            const qint64 length = qMin<qint64>(96 * KB, size - 8 * KB);
            QVERIFY(box.encryptRange(victim, size - length, length));
        }

        // Every format is covered per file; ciphertext that happens to start
        // with an FFD9 passes a JPEG as a motion photo (~0.5 %), so one miss
        // in the batch is tolerated.
        FormatSignatureDetector detector;
        int missed = 0;
        for (const QString &victim : victims) {
            const auto result = detector.checkFile(box.absolute(victim), victim);
            if (result.verdict != FormatSignatureDetector::Verdict::Mismatch) {
                qInfo().noquote() << "[5b] not seen:" << victim << result.reason;
                ++missed;
            } else {
                QVERIFY2(result.bodyCorrupted, qPrintable(victim + ": " + result.reason));
            }
        }
        QVERIFY2(missed <= 1, qPrintable(QStringLiteral("%1 of %2 tail-damaged files not seen").arg(missed).arg(victims.size())));

        const QVector<SyncFileItem> items = modifiedItems(victims);
        const int index = harness.feed(items);
        recordAttack(QStringLiteral("5b tail-only on jpg/mp4/txt/csv, header intact (SYNC)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Tail-only encryption of jpg/mp4/txt/csv was not detected");
        QVERIFY2(index <= 2, qPrintable(QStringLiteral("expected trigger by the 3rd file, got %1").arg(index + 1)));
    }

    // 6. Encrypt to a new file with a fixed known extension and delete the original
    void attackDeleteAndRecreateLocked()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims();
        for (const QString &victim : victims) {
            const QString target = victim + QStringLiteral(".locked");
            QVERIFY(box.encryptToNewName(victim, target));
            items.append(removedItem(victim));
            items.append(newItem(target));
        }

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("6 delete + recreate as .locked (REMOVE+NEW items)"), index, items.size(), 2, harness);
        QVERIFY2(index >= 0, ".locked recreate was not detected");
        QVERIFY2(index <= 1, qPrintable(QStringLiteral("expected trigger on the 1st file, got item %1").arg(index + 1)));
    }

    // 7a. LockBit 3.0 ransom note after two renamed files
    void attackRansomNoteLockBit()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());
        const QString ext = QStringLiteral("HLJkNskOq");

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims().mid(0, 2);
        for (const QString &victim : victims) {
            const QString target = victim + QLatin1Char('.') + ext;
            QVERIFY(box.encryptWhole(victim));
            QVERIFY(box.rename(victim, target));
            items.append(renamedItem(victim, target));
        }
        const QString note = QStringLiteral("Documents/%1.README.txt").arg(ext);
        QVERIFY(box.write(note, textDocument(2 * KB, QStringLiteral("Your files are encrypted"))));
        items.append(newItem(note));

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("7a ransom note %1.README.txt after 2 renames").arg(ext), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "LockBit ransom note was not detected");
        QVERIFY2(index == 2, qPrintable(QStringLiteral("expected trigger on the note (item 3), got %1").arg(index + 1)));
    }

    // 7b. BlackCat/ALPHV ransom note after two files encrypted to a new name
    void attackRansomNoteBlackCat()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());
        const QString ext = QStringLiteral("abc1234");

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims().mid(0, 2);
        for (const QString &victim : victims) {
            const QString target = victim + QLatin1Char('.') + ext;
            QVERIFY(box.encryptToNewName(victim, target));
            items.append(newItem(target));
            items.append(removedItem(victim));
        }
        const QString note = QStringLiteral("Documents/RECOVER-%1-FILES.txt").arg(ext);
        QVERIFY(box.write(note, textDocument(2 * KB, QStringLiteral("Recover your files"))));
        items.append(newItem(note));

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("7b ransom note RECOVER-%1-FILES.txt after 2 files").arg(ext), index, items.size(), 2, harness);
        QVERIFY2(index >= 0, "BlackCat ransom note was not detected");
        QVERIFY2(index <= 4, qPrintable(QStringLiteral("expected trigger by the note (item 5), got %1").arg(index + 1)));
    }

    // 8. The canary file is overwritten
    void attackCanaryModified()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVERIFY(box.encryptWhole(QStringLiteral("_canary.txt")));
        const QVector<SyncFileItem> items = {modifiedItem(QStringLiteral("_canary.txt"))};

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("8 canary _canary.txt overwritten (SYNC)"), index, items.size(), 1, harness);
        QCOMPARE(index, 0);
    }

    // 9. Mass deletion of 15 files
    void attackMassDeletion()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims().mid(0, 15);
        QCOMPARE(victims.size(), 15);
        for (const QString &victim : victims) {
            QVERIFY(box.remove(victim));
            items.append(removedItem(victim));
        }

        const int index = harness.feed(items);
        recordAttack(QStringLiteral("9 mass deletion of 15 files (REMOVE)"), index, items.size(), 1, harness);
        QVERIFY2(index >= 0, "Mass deletion was not detected");
        QVERIFY2(index <= 9, qPrintable(QStringLiteral("expected trigger by the 10th delete, got %1").arg(index + 1)));
    }

    // ==================== Benign scenarios ====================

    // a. Import of 25 new photos
    void benignPhotoImport()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        for (int i = 1; i <= 25; ++i) {
            const QString path = QStringLiteral("Photos/2026-10 Import/DSC_%1.jpg").arg(i, 4, 10, QLatin1Char('0'));
            QVERIFY(box.write(path, jpegImage(sizeBetween(100 * KB, 300 * KB))));
            items.append(newItem(path));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("a import of 25 new jpg photos (NEW)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // b. New zip archive and 3 new pdfs
    void benignNewArchiveAndPdfs()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        QVERIFY(box.write(QStringLiteral("Documents/2025-backup.zip"), officeDocument(sizeBetween(200 * KB, 300 * KB))));
        items.append(newItem(QStringLiteral("Documents/2025-backup.zip")));
        for (int i = 1; i <= 3; ++i) {
            const QString path = QStringLiteral("Documents/scan-%1.pdf").arg(i);
            QVERIFY(box.write(path, pdfDocument(sizeBetween(50 * KB, 300 * KB))));
            items.append(newItem(path));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("b new zip archive + 3 new pdfs (NEW)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // c. Editing 10 text files
    void benignTextEdits()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        QStringList texts = box.withSuffix({QStringLiteral("txt"), QStringLiteral("md"), QStringLiteral("csv")});
        texts.removeAll(QStringLiteral("_canary.txt"));
        for (int i = 1; texts.size() < 10; ++i) {
            const QString path = QStringLiteral("Notes/draft-%1.txt").arg(i);
            QVERIFY(box.write(path, textDocument(sizeBetween(20 * KB, 40 * KB), QStringLiteral("Draft"))));
            texts.append(path);
        }
        for (const QString &path : std::as_const(texts)) {
            const QByteArray edited = (path.endsWith(QLatin1String(".csv")) ? csvDocument(sizeBetween(20 * KB, 60 * KB))
                                                                            : textDocument(sizeBetween(20 * KB, 60 * KB), QStringLiteral("Edited")))
                + "\nEdited on 2026-10-15 - added a paragraph with some \xC3\xBC" "ml\xC3\xA4" "uts.\n";
            QVERIFY(box.write(path, edited));
            items.append(modifiedItem(path));
        }
        QCOMPARE(items.size(), 10);

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("c editing 10 text files (SYNC)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // d. KeePass saves the database: signature kept, encrypted payload entirely new
    void benignKeepassSave()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVERIFY(box.write(QStringLiteral("Vault/passwords.kdbx"), keepassDatabase(sizeBetween(20 * KB, 80 * KB))));
        const QVector<SyncFileItem> items = {modifiedItem(QStringLiteral("Vault/passwords.kdbx"))};

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("d saving .kdbx with new random payload (SYNC)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // d2. Info only: a .kdbx rewritten without its KeePass signature (pure random bytes)
    void probeKeepassWithoutSignature()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVERIFY(box.encryptWhole(QStringLiteral("Vault/passwords.kdbx")));
        const QVector<SyncFileItem> items = {modifiedItem(QStringLiteral("Vault/passwords.kdbx"))};

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("d2 (probe) .kdbx rewritten as pure random bytes, no signature"), index, items.size(), harness, true);
        // Not asserted: the KeePass signature is part of the format table on purpose.
    }

    // e. Deleting 5 files
    void benignDeleteFive()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        const QStringList victims = box.victims().mid(0, 5);
        for (const QString &victim : victims) {
            QVERIFY(box.remove(victim));
            items.append(removedItem(victim));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("e deleting 5 files (REMOVE)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // f. Legitimate renames and a Nextcloud conflict copy
    void benignRenamesAndConflictCopy()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        const QVector<QPair<QString, QString>> renames = {
            {QStringLiteral("Notes/todo.txt"), QStringLiteral("Notes/todo.md")},
            {QStringLiteral("Photos/IMG_0001.jpg"), QStringLiteral("Photos/IMG_0001.jpeg")},
            {QStringLiteral("Documents/report-q1.docx"), QStringLiteral("Documents/report-q1-final.docx")},
            {QStringLiteral("Finance/expenses.csv"), QStringLiteral("Finance/expenses.csv.bak")},
            {QStringLiteral("Media/demo.mp4"), QStringLiteral("Media/demo-2026.mp4")},
        };
        QVector<SyncFileItem> items;
        for (const auto &pair : renames) {
            QVERIFY(box.rename(pair.first, pair.second));
            items.append(renamedItem(pair.first, pair.second));
        }
        const QString conflict = QStringLiteral("Documents/Report (conflicted copy 2026-10-15 120000).docx");
        QVERIFY(box.write(conflict, officeDocument(sizeBetween(40 * KB, 200 * KB))));
        items.append(newItem(conflict));

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("f 5 legitimate renames + conflict copy (RENAME/NEW)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // g. New README.txt and notes.txt
    void benignReadmeAndNotes()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        for (const QString &path : {QStringLiteral("README.txt"), QStringLiteral("Notes/notes.txt")}) {
            QVERIFY(box.write(path, textDocument(sizeBetween(4 * KB, 20 * KB), QStringLiteral("Project notes"))));
            items.append(newItem(path));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("g new README.txt and notes.txt (NEW)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // h. Overwriting 3 pdfs with other valid pdfs
    void benignPdfOverwrite()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        const QStringList pdfs = box.withSuffix({QStringLiteral("pdf")}).mid(0, 3);
        QCOMPARE(pdfs.size(), 3);
        for (const QString &path : pdfs) {
            QVERIFY(box.write(path, pdfDocument(sizeBetween(50 * KB, 300 * KB))));
            items.append(modifiedItem(path));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("h overwriting 3 pdfs with other valid pdfs (SYNC)"), index, items.size(), harness);
        QVERIFY2(index < 0, qPrintable(QStringLiteral("false positive: ") + harness.pauseReason));
    }

    // i. rm -rf node_modules: 12 deletions under a whitelisted directory.
    //    The MassDeleteDetector ignores them, but KillSwitchManager::evaluateThreatLevel()
    //    counts raw DELETE events and trips at the configured threshold regardless of the
    //    whitelist. This is a documented product decision; the outcome is recorded, not asserted.
    void benignNodeModulesDeletion()
    {
        Sandbox box;
        QVERIFY(box.isValid());
        Harness harness(box.root());

        QVector<SyncFileItem> items;
        for (int i = 1; i <= 12; ++i) {
            const QString path = QStringLiteral("webapp/node_modules/pkg-%1/index.js").arg(i);
            QVERIFY(box.write(path, textDocument(sizeBetween(2 * KB, 8 * KB), QStringLiteral("module"))));
        }
        for (int i = 1; i <= 12; ++i) {
            const QString path = QStringLiteral("webapp/node_modules/pkg-%1/index.js").arg(i);
            QVERIFY(box.remove(path));
            items.append(removedItem(path));
        }

        const int index = harness.feed(items);
        recordBenign(QStringLiteral("i rm -rf node_modules, 12 deletions (REMOVE)"), index, items.size(), harness, true);
        qInfo().noquote() << "[note] node_modules deletion:"
                          << (index < 0 ? QStringLiteral("not triggered")
                                        : QStringLiteral("triggered at item %1 by the manager's raw DELETE count").arg(index + 1))
                          << "- product decision, see KillSwitchManager::evaluateThreatLevel()";
    }
};

QTEST_GUILESS_MAIN(TestKillSwitchScenarios)
#include "testkillswitchscenarios.moc"

/*
 * Nextcloud Sentinel Edition - Format Signature Detector Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "formatsignaturedetector.h"
#include "entropydetector.h"
#include "syncfileitem.h"

#include <QFile>
#include <QHash>
#include <QList>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <functional>
#include <limits>

namespace OCC {

namespace {

// How the content of an extension is validated
enum class Family {
    Generic,    // magic-number table only
    Text,       // textness heuristic (NUL bytes, UTF-8)
    Jpeg,       // FF D8 FF + marker segment walk
    Png,        // signature + IHDR CRC + IEND trailer
    Zip,        // PK header + EOCD in the tail
    Pdf,        // %PDF- in the first 1 KB + %%EOF in the last 2 KB
    IsoBmff,    // "ftyp" box (or another top-level box) at offset 4
    Mp3,        // ID3 tag or validated MPEG audio frame
    Aac,        // ID3 tag, ADIF header or ADTS frame sync
    Bmp,        // "BM" + plausible DIB header size
    Asn1,       // DER SEQUENCE whose length matches the file size
    PemOrAsn1,  // PEM text or DER
    Pem,        // "-----BEGIN "
    Skip,       // encrypted by design: never judged
};

// One alternative of a magic number: bytes with per-byte mask at an offset
struct Pattern {
    int offset = 0;
    QByteArray bytes;
    QByteArray mask;
};

struct Spec {
    Family family;
    QString format;
    QVector<Pattern> patterns;
};

// Patterns: hex bytes separated by spaces, "??" (or a "?" nibble) is a
// wildcard, "@N" sets the offset, "|" separates alternatives.
struct RawEntry {
    const char *extensions;
    Family family;
    const char *format;
    const char *patterns;
};

const RawEntry s_rawTable[] = {
    // Images
    {"jpg jpeg jpe", Family::Jpeg, "JPEG image", "FF D8 FF"},
    {"png", Family::Png, "PNG image", "89 50 4E 47 0D 0A 1A 0A"},
    {"gif", Family::Generic, "GIF image", "47 49 46 38 37 61|47 49 46 38 39 61"},
    {"bmp dib", Family::Bmp, "BMP image", "42 4D"},
    {"webp", Family::Generic, "WebP image", "52 49 46 46 ?? ?? ?? ?? 57 45 42 50"},
    {"tif tiff nef arw dng srw pef", Family::Generic, "TIFF image",
     "49 49 2A 00|4D 4D 00 2A|49 49 2B 00|4D 4D 00 2B"},
    {"heic heif hif avif", Family::IsoBmff, "HEIF/AVIF image", ""},
    {"psd psb", Family::Generic, "Photoshop document", "38 42 50 53"},
    {"cr2", Family::Generic, "Canon CR2 raw image", "49 49 2A 00 10 00 00 00 43 52"},
    {"orf", Family::Generic, "Olympus raw image", "49 49 52 4F|49 49 52 53|4D 4D 4F 52"},
    {"rw2 rwl", Family::Generic, "Panasonic raw image", "49 49 55 00"},
    // Documents
    {"pdf", Family::Pdf, "PDF document", ""},
    {"ai", Family::Generic, "Adobe Illustrator document",
     "25 50 44 46|25 21 50 53 2D 41 64 6F 62 65|C5 D0 D3 C6"},
    {"doc xls ppt msg msi vsd", Family::Generic, "OLE2 compound document", "D0 CF 11 E0 A1 B1 1A E1"},
    {"docx xlsx pptx docm xlsm pptm vsdx odt ods odp odg epub jar war apk ipa whl nupkg xpi kmz zip",
     Family::Zip, "ZIP archive", "50 4B 03 04|50 4B 05 06|50 4B 07 08"},
    {"rtf", Family::Generic, "RTF document", "7B 5C 72 74 66 31"},
    // Databases
    {"sqlite sqlite3", Family::Generic, "SQLite database",
     "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"},
    {"kdbx", Family::Generic, "KeePass database", "03 D9 A2 9A 67 FB 4B B5|03 D9 A2 9A 66 FB 4B B5"},
    {"kdb", Family::Generic, "KeePass 1.x database", "03 D9 A2 9A 65 FB 4B B5"},
    // Archives and packages
    {"gz tgz", Family::Generic, "gzip archive", "1F 8B 08"},
    {"bz2 tbz2", Family::Generic, "bzip2 archive", "42 5A 68 3?"},
    {"xz txz", Family::Generic, "xz archive", "FD 37 7A 58 5A 00"},
    {"zst", Family::Generic, "Zstandard archive", "28 B5 2F FD|5? 2A 4D 18"},
    {"7z", Family::Generic, "7-Zip archive", "37 7A BC AF 27 1C"},
    {"rar", Family::Generic, "RAR archive", "52 61 72 21 1A 07 00|52 61 72 21 1A 07 01 00"},
    {"deb", Family::Generic, "Debian package", "21 3C 61 72 63 68 3E 0A"},
    {"rpm", Family::Generic, "RPM package", "ED AB EE DB"},
    {"cab", Family::Generic, "Cabinet archive", "4D 53 43 46"},
    // Executables
    {"exe dll sys scr ocx cpl drv", Family::Generic, "Windows executable", "4D 5A"},
    // Audio
    {"mp3", Family::Mp3, "MP3 audio", ""},
    {"aac", Family::Aac, "AAC audio", ""},
    {"wav", Family::Generic, "WAV audio",
     "52 49 46 46 ?? ?? ?? ?? 57 41 56 45|52 46 36 34 ?? ?? ?? ?? 57 41 56 45"},
    {"flac", Family::Generic, "FLAC audio", "66 4C 61 43|49 44 33"},
    {"ogg oga ogv opus spx", Family::Generic, "Ogg container", "4F 67 67 53"},
    {"wma wmv asf", Family::Generic, "ASF media", "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C"},
    // Video
    {"m4a m4b m4p m4r mp4 m4v mov 3gp 3g2", Family::IsoBmff, "MPEG-4/QuickTime media", ""},
    {"avi", Family::Generic, "AVI video", "52 49 46 46 ?? ?? ?? ?? 41 56 49 20"},
    {"mkv mka mks mk3d webm", Family::Generic, "Matroska/WebM container", "1A 45 DF A3"},
    // Fonts
    {"ttf ttc", Family::Generic, "TrueType font", "00 01 00 00|74 72 75 65|74 74 63 66"},
    {"otf", Family::Generic, "OpenType font", "4F 54 54 4F|00 01 00 00"},
    {"woff", Family::Generic, "WOFF font", "77 4F 46 46"},
    {"woff2", Family::Generic, "WOFF2 font", "77 4F 46 32"},
    // Disk images with a strong header
    {"qcow2 qcow", Family::Generic, "QCOW disk image", "51 46 49 FB"},
    {"vhdx", Family::Generic, "VHDX disk image", "76 68 64 78 66 69 6C 65"},
    {"vdi", Family::Generic, "VirtualBox disk image", "@64 7F 10 DA BE"},
    // Certificates and keys
    {"p12 pfx der p7b p7s", Family::Asn1, "DER-encoded ASN.1 object", ""},
    {"crt cer", Family::PemOrAsn1, "X.509 certificate", ""},
    {"pem", Family::Pem, "PEM-encoded object", ""},
    // Encrypted by design: random content is expected
    {"gpg pgp asc", Family::Skip, "", ""},
    // Text
    {"txt md csv tsv json xml html htm yaml yml ini log js ts css py cpp h c java sh conf cfg toml tex srt vtt svg",
     Family::Text, "text file", ""},
};

int hexNibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

QVector<Pattern> parsePatterns(const char *spec)
{
    QVector<Pattern> result;
    const QByteArray all(spec);
    if (all.isEmpty()) {
        return result;
    }
    const QList<QByteArray> alternatives = all.split('|');
    for (const QByteArray &alternative : alternatives) {
        Pattern pattern;
        const QList<QByteArray> tokens = alternative.simplified().split(' ');
        for (const QByteArray &token : tokens) {
            if (token.isEmpty()) {
                continue;
            }
            if (token.startsWith('@')) {
                pattern.offset = token.mid(1).toInt();
                continue;
            }
            if (token.size() != 2) {
                continue;
            }
            int value = 0;
            int mask = 0;
            for (int k = 0; k < 2; ++k) {
                const int shift = (k == 0) ? 4 : 0;
                const int nibble = hexNibble(token.at(k));
                if (nibble >= 0) {
                    value |= nibble << shift;
                    mask |= 0xF << shift;
                }
            }
            pattern.bytes.append(static_cast<char>(value));
            pattern.mask.append(static_cast<char>(mask));
        }
        if (!pattern.bytes.isEmpty()) {
            result.append(pattern);
        }
    }
    return result;
}

const QHash<QString, Spec> &specTable()
{
    static const QHash<QString, Spec> table = [] {
        QHash<QString, Spec> t;
        for (const RawEntry &entry : s_rawTable) {
            Spec spec;
            spec.family = entry.family;
            spec.format = QString::fromLatin1(entry.format);
            spec.patterns = parsePatterns(entry.patterns);
            const QStringList extensions = QString::fromLatin1(entry.extensions)
                                               .split(QLatin1Char(' '), Qt::SkipEmptyParts);
            for (const QString &extension : extensions) {
                t.insert(extension, spec);
            }
        }
        return t;
    }();
    return table;
}

QString extensionOf(const QString &fileName)
{
    const int slash = fileName.lastIndexOf(QLatin1Char('/'));
    const QString base = (slash >= 0) ? fileName.mid(slash + 1) : fileName;
    const int dot = base.lastIndexOf(QLatin1Char('.'));
    if (dot <= 0 || dot == base.size() - 1) {
        return QString();
    }
    return base.mid(dot + 1).toLower();
}

const Spec *specFor(const QString &fileName)
{
    const QString extension = extensionOf(fileName);
    if (extension.isEmpty()) {
        return nullptr;
    }
    const auto it = specTable().constFind(extension);
    return (it == specTable().constEnd()) ? nullptr : &it.value();
}

bool matchesAny(const QByteArray &head, const QVector<Pattern> &patterns)
{
    for (const Pattern &pattern : patterns) {
        if (pattern.offset + pattern.bytes.size() > head.size()) {
            continue;
        }
        bool ok = true;
        for (int i = 0; i < pattern.bytes.size() && ok; ++i) {
            const char actual = head.at(pattern.offset + i);
            ok = (actual & pattern.mask.at(i)) == (pattern.bytes.at(i) & pattern.mask.at(i));
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

quint8 byteAt(const QByteArray &data, int index)
{
    return static_cast<quint8>(data.at(index));
}

quint32 u32be(const QByteArray &data, int index)
{
    return (static_cast<quint32>(byteAt(data, index)) << 24)
        | (static_cast<quint32>(byteAt(data, index + 1)) << 16)
        | (static_cast<quint32>(byteAt(data, index + 2)) << 8)
        | static_cast<quint32>(byteAt(data, index + 3));
}

quint32 u32le(const QByteArray &data, int index)
{
    return (static_cast<quint32>(byteAt(data, index + 3)) << 24)
        | (static_cast<quint32>(byteAt(data, index + 2)) << 16)
        | (static_cast<quint32>(byteAt(data, index + 1)) << 8)
        | static_cast<quint32>(byteAt(data, index));
}

// ---- JPEG: walk the marker segments that precede the entropy-coded data ----

bool jpegSegmentsLookValid(const QByteArray &head)
{
    const int size = head.size();
    int pos = 2; // after SOI
    while (pos < size) {
        if (byteAt(head, pos) != 0xFF) {
            return false; // a segment must start with a marker
        }
        while (pos < size && byteAt(head, pos) == 0xFF) {
            ++pos; // fill bytes are allowed before the marker code
        }
        if (pos >= size) {
            return true; // buffer ended mid-marker; intact so far
        }
        const quint8 marker = byteAt(head, pos);
        ++pos;
        if (marker == 0x00) {
            return false; // stuffed byte outside the scan data
        }
        if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            continue; // standalone markers without a length
        }
        if (marker == 0xD9 || marker == 0xDA) {
            return true; // EOI, or SOS: entropy-coded data follows
        }
        if (pos + 2 > size) {
            return true; // buffer ended before the length field
        }
        const int length = (byteAt(head, pos) << 8) | byteAt(head, pos + 1);
        if (length < 2) {
            return false;
        }
        pos += length;
    }
    return true;
}

// ---- MP3: MPEG audio frame header validation ----

struct Mp3Frame {
    bool valid = false;
    int length = 0;
};

Mp3Frame parseMp3Frame(const QByteArray &data, int pos)
{
    Mp3Frame frame;
    if (pos + 4 > data.size()) {
        return frame;
    }
    const quint8 b0 = byteAt(data, pos);
    const quint8 b1 = byteAt(data, pos + 1);
    const quint8 b2 = byteAt(data, pos + 2);
    if (b0 != 0xFF || (b1 & 0xE0) != 0xE0) {
        return frame;
    }
    const int version = (b1 >> 3) & 0x03; // 0 = 2.5, 1 = reserved, 2 = 2, 3 = 1
    const int layer = (b1 >> 1) & 0x03;   // 1 = III, 2 = II, 3 = I
    const int bitrateIndex = b2 >> 4;
    const int sampleRateIndex = (b2 >> 2) & 0x03;
    const int padding = (b2 >> 1) & 0x01;
    if (version == 1 || layer == 0 || bitrateIndex == 0 || bitrateIndex == 15 || sampleRateIndex == 3) {
        return frame;
    }

    static const int bitrates[2][3][16] = {
        // MPEG 1: layer I, II, III
        {{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
         {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
         {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0}},
        // MPEG 2 / 2.5
        {{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
         {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
         {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}},
    };
    static const int sampleRates[4][3] = {
        {11025, 12000, 8000},  // 2.5
        {0, 0, 0},             // reserved
        {22050, 24000, 16000}, // 2
        {44100, 48000, 32000}, // 1
    };

    const bool mpeg1 = (version == 3);
    const int bitrate = bitrates[mpeg1 ? 0 : 1][3 - layer][bitrateIndex] * 1000;
    const int sampleRate = sampleRates[version][sampleRateIndex];
    if (bitrate == 0 || sampleRate == 0) {
        return frame;
    }

    if (layer == 3) { // layer I
        frame.length = (12 * bitrate / sampleRate + padding) * 4;
    } else if (layer == 2 || mpeg1) { // layer II, or MPEG 1 layer III
        frame.length = 144 * bitrate / sampleRate + padding;
    } else { // MPEG 2 / 2.5 layer III
        frame.length = 72 * bitrate / sampleRate + padding;
    }
    frame.valid = frame.length >= 4;
    return frame;
}

bool mp3LooksValid(const QByteArray &head)
{
    if (head.startsWith("ID3")) {
        return true;
    }
    // A frame is trusted when the next frame starts where it says it ends
    // (or when it is at the very start of the file and runs past the sample).
    for (int pos = 0; pos + 4 <= head.size(); ++pos) {
        const Mp3Frame frame = parseMp3Frame(head, pos);
        if (!frame.valid) {
            continue;
        }
        const int next = pos + frame.length;
        if (next + 4 > head.size()) {
            if (pos == 0) {
                return true;
            }
            continue;
        }
        if (parseMp3Frame(head, next).valid) {
            return true;
        }
    }
    return false;
}

bool aacLooksValid(const QByteArray &head)
{
    if (head.startsWith("ID3") || head.startsWith("ADIF")) {
        return true;
    }
    return head.size() >= 2 && byteAt(head, 0) == 0xFF && (byteAt(head, 1) & 0xF6) == 0xF0;
}

bool isoBmffLooksValid(const QByteArray &head)
{
    if (head.size() < 12) {
        return false;
    }
    const QByteArray type = head.mid(4, 4);
    if (type == "ftyp") {
        const QByteArray brand = head.mid(8, 4);
        for (char c : brand) {
            const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && c != ' ') {
                return false;
            }
        }
        return true;
    }
    static const char *const topLevelBoxes[] = {"moov", "mdat", "free", "skip", "wide", "pnot"};
    for (const char *box : topLevelBoxes) {
        if (type == box) {
            const quint32 boxSize = u32be(head, 0);
            return boxSize >= 8 || boxSize == 1 || boxSize == 0;
        }
    }
    return false;
}

bool bmpLooksValid(const QByteArray &head)
{
    if (!head.startsWith("BM") || head.size() < 18) {
        return false;
    }
    const quint32 dibHeaderSize = u32le(head, 14);
    static const quint32 knownSizes[] = {12, 40, 52, 56, 64, 108, 124};
    return std::find(std::begin(knownSizes), std::end(knownSizes), dibHeaderSize) != std::end(knownSizes);
}

bool derLooksValid(const QByteArray &head, qint64 fileSize)
{
    if (head.size() < 2 || byteAt(head, 0) != 0x30) {
        return false;
    }
    const quint8 lengthByte = byteAt(head, 1);
    if (lengthByte == 0x80) {
        return true; // indefinite length (BER)
    }
    qint64 length = 0;
    int headerSize = 2;
    if (lengthByte < 0x80) {
        length = lengthByte;
    } else {
        const int lengthBytes = lengthByte & 0x7F;
        if (lengthBytes < 1 || lengthBytes > 4 || head.size() < 2 + lengthBytes) {
            return false;
        }
        for (int i = 0; i < lengthBytes; ++i) {
            length = (length << 8) | byteAt(head, 2 + i);
        }
        headerSize = 2 + lengthBytes;
    }
    return headerSize + length == fileSize;
}

bool pemLooksValid(const QByteArray &head)
{
    return head.startsWith("-----BEGIN ");
}

enum class Utf8Status { Valid, Invalid, TruncatedAtEnd };

Utf8Status utf8Status(const QByteArray &data)
{
    const int size = data.size();
    int i = 0;
    while (i < size) {
        const quint8 c = byteAt(data, i);
        if (c < 0x80) {
            ++i;
            continue;
        }
        int sequenceLength = 0;
        if (c >= 0xC2 && c <= 0xDF) {
            sequenceLength = 2;
        } else if (c >= 0xE0 && c <= 0xEF) {
            sequenceLength = 3;
        } else if (c >= 0xF0 && c <= 0xF4) {
            sequenceLength = 4;
        } else {
            return Utf8Status::Invalid;
        }
        if (i + sequenceLength > size) {
            // Check whatever continuation bytes are present before giving the
            // sample the benefit of the doubt.
            for (int k = i + 1; k < size; ++k) {
                if ((byteAt(data, k) & 0xC0) != 0x80) {
                    return Utf8Status::Invalid;
                }
            }
            return Utf8Status::TruncatedAtEnd;
        }
        const quint8 c1 = byteAt(data, i + 1);
        if ((c == 0xE0 && c1 < 0xA0) || (c == 0xED && c1 > 0x9F)
            || (c == 0xF0 && c1 < 0x90) || (c == 0xF4 && c1 > 0x8F)) {
            return Utf8Status::Invalid; // overlong encodings and surrogates
        }
        for (int k = 1; k < sequenceLength; ++k) {
            if ((byteAt(data, i + k) & 0xC0) != 0x80) {
                return Utf8Status::Invalid;
            }
        }
        i += sequenceLength;
    }
    return Utf8Status::Valid;
}

// ---------------------------------------------------------------------------
// Body checks: sampled 4 KB windows and cheap per-format structure walks.
//
// Everything below runs only after the header (and, where the format has
// one, the tail) matched. A body check returns "corrupted" only on evidence
// that is deterministic for the format (a structure that must be there is
// not, and random bytes sit in its place). Anything it cannot judge is
// silently fine: these checks are meant to add coverage for chunked
// encryption, never to turn a legitimate but unusual file into an alarm.
// ---------------------------------------------------------------------------

struct BodyVerdict {
    bool corrupted = false;
    QString reason;
};

BodyVerdict bodyFailure(const QString &reason)
{
    BodyVerdict verdict;
    verdict.corrupted = true;
    verdict.reason = reason;
    return verdict;
}

constexpr int WINDOW = FormatSignatureDetector::BODY_WINDOW_SIZE;

// All reads of the body checks go through one of these; it keeps the file
// open, clamps every read to the file and caps the number of reads so that
// no walk can degenerate into reading a whole file.
class BodyProbe
{
public:
    BodyProbe(QFile &file, qint64 fileSize)
        : m_file(file)
        , m_fileSize(fileSize)
    {
    }

    qint64 fileSize() const { return m_fileSize; }

    QByteArray readAt(qint64 offset, qint64 length)
    {
        if (offset < 0 || offset >= m_fileSize || length <= 0 || m_reads >= MAX_READS) {
            return QByteArray();
        }
        ++m_reads;
        if (!m_file.seek(offset)) {
            return QByteArray();
        }
        return m_file.read(std::min<qint64>(length, m_fileSize - offset));
    }

    QByteArray window(qint64 offset) { return readAt(offset, WINDOW); }

    /// Offsets of the sampled windows after the head: every step (+ skew) and the tail
    QVector<qint64> windowOffsets() const
    {
        QVector<qint64> offsets;
        const qint64 tail = m_fileSize - WINDOW;
        qint64 step = std::max<qint64>(FormatSignatureDetector::BODY_WINDOW_STEP,
                                       m_fileSize / (FormatSignatureDetector::BODY_MAX_WINDOWS - 2));
        step = (step + WINDOW - 1) / WINDOW * WINDOW;
        for (qint64 offset = step + FormatSignatureDetector::BODY_WINDOW_SKEW;
             offset + WINDOW <= tail && offsets.size() < FormatSignatureDetector::BODY_MAX_WINDOWS - 2;
             offset += step) {
            offsets.append(offset);
        }
        offsets.append(tail);
        return offsets;
    }

    // 16 windows + 12 bisection windows + 64 atom headers is the worst case
    static constexpr int MAX_READS = 96;

private:
    QFile &m_file;
    qint64 m_fileSize;
    int m_reads = 0;
};

bool looksRandom(const QByteArray &data)
{
    if (data.size() < 256) {
        return false;
    }
    const double bar = std::min(FormatSignatureDetector::RANDOM_HEADER_ENTROPY,
                                0.85 * std::log2(static_cast<double>(data.size())));
    return EntropyDetector::calculateEntropy(data) >= bar;
}

quint64 u64be(const QByteArray &data, int index)
{
    return (static_cast<quint64>(u32be(data, index)) << 32) | u32be(data, index + 4);
}

quint16 u16le(const QByteArray &data, int index)
{
    return static_cast<quint16>(byteAt(data, index) | (byteAt(data, index + 1) << 8));
}

// ---- JPEG: marker grammar of the entropy-coded data ----

// Inside the scan data an FF byte may only be followed by 00 (stuffing),
// FF (fill), D0-D7 (restart) or a real marker. A marker with a length
// (DHT/DQT/DRI between scans) is skipped and must be followed by another
// marker; SOS is followed by more scan data. Counting goes on after an EOI
// so that a window is judged by all of its bytes; the EOI position is kept
// so the caller can tell a legitimate trailer from damage.
struct JpegWindowScan {
    int violations = 0;      // in the whole window
    int firstViolation = -1; // position of the first violating byte
    int eoiPosition = -1;    // position of the first FFD9 (-1: none)
    bool junk() const { return violations >= 2; }
    bool eoiBeforeDamage() const { return eoiPosition >= 0 && (firstViolation < 0 || eoiPosition < firstViolation); }
};

// Segments between scans are tables of at most ~2 KB and an SOS header is
// at most 14 bytes (6 + 2 components x 4); a "marker" that claims more is
// random data.
constexpr int JPEG_MAX_INTERSCAN_SEGMENT = 2048;
constexpr int JPEG_MAX_SOS_SEGMENT = 16;

JpegWindowScan jpegScanWindow(const QByteArray &window, int from)
{
    JpegWindowScan scan;
    const int size = window.size();
    int pos = std::max(0, from);
    auto violation = [&scan](int at) {
        if (scan.firstViolation < 0) {
            scan.firstViolation = at;
        }
        ++scan.violations;
    };
    while (pos + 1 < size) {
        if (byteAt(window, pos) != 0xFF) {
            ++pos;
            continue;
        }
        const quint8 marker = byteAt(window, pos + 1);
        if (marker == 0xFF) {
            ++pos; // fill byte
            continue;
        }
        if (marker == 0x00 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) {
            pos += 2;
            continue;
        }
        if (marker == 0xD9) {
            if (scan.eoiPosition < 0) {
                scan.eoiPosition = pos;
            }
            pos += 2;
            continue;
        }
        if (marker < 0xC0 || marker == 0xD8) {
            violation(pos);
            pos += 2;
            continue;
        }
        // A marker with a length field
        if (pos + 4 > size) {
            break;
        }
        const int length = (byteAt(window, pos + 2) << 8) | byteAt(window, pos + 3);
        if (length < 2 || length > (marker == 0xDA ? JPEG_MAX_SOS_SEGMENT : JPEG_MAX_INTERSCAN_SEGMENT)) {
            violation(pos);
            pos += 2;
            continue;
        }
        pos += 2 + length;
        if (marker == 0xDA) {
            continue; // SOS: entropy-coded data follows
        }
        if (pos < size && byteAt(window, pos) != 0xFF) {
            violation(pos); // a segment must be followed by the next marker
        }
    }
    return scan;
}

// Walk the marker segments from SOI to SOS and return the offset where the
// entropy-coded data starts, or -1 when it cannot be found within 64 hops
// (the segments before the first scan are all length-prefixed, so this is a
// handful of tiny reads even for a file with megabytes of APP segments).
qint64 jpegScanStart(BodyProbe &probe, const QByteArray &head)
{
    qint64 pos = 2;
    for (int hop = 0; hop < 64; ++hop) {
        QByteArray bytes;
        if (pos + 4 <= head.size()) {
            bytes = head.mid(static_cast<int>(pos), 4);
        } else {
            bytes = probe.readAt(pos, 4);
        }
        if (bytes.size() < 4 || byteAt(bytes, 0) != 0xFF) {
            return -1;
        }
        const quint8 marker = byteAt(bytes, 1);
        if (marker == 0xFF) {
            ++pos;
            continue;
        }
        if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            pos += 2;
            continue;
        }
        if (marker < 0xC0 || marker == 0xD9) {
            return -1;
        }
        const int length = (byteAt(bytes, 2) << 8) | byteAt(bytes, 3);
        if (length < 2) {
            return -1;
        }
        if (marker == 0xDA) {
            return pos + 2 + length;
        }
        pos += 2 + length;
    }
    return -1;
}

BodyVerdict jpegBody(BodyProbe &probe, const QByteArray &head)
{
    const qint64 scanStart = jpegScanStart(probe, head);
    if (scanStart < 0 || scanStart >= probe.fileSize()) {
        return BodyVerdict(); // cannot tell where the scan data begins
    }

    // An FFD9 is believed to be the end of the image (after which motion
    // photos, MPF images and other trailers are none of our business) when
    // the 4 KB before it are spotless scan data. Random bytes before it mean
    // the FFD9 is itself part of the random data. Blind spot: ciphertext
    // whose first few hundred bytes happen to contain FFD9 (about 0.5 % of
    // damaged files) passes as a trailer.
    auto isImageEnd = [&probe, scanStart](qint64 eoi) {
        const qint64 from = std::max(scanStart, eoi - WINDOW);
        if (eoi - from < 512) {
            return true; // a tiny image: nothing to verify
        }
        const QByteArray before = probe.readAt(from, eoi - from);
        return !before.isEmpty() && jpegScanWindow(before, 0).violations == 0;
    };
    // Classify a window; returns true when the image ends in it (no further
    // checking), false otherwise.
    auto endsImage = [&isImageEnd](qint64 offset, const JpegWindowScan &scan) {
        return scan.eoiBeforeDamage() && isImageEnd(offset + scan.eoiPosition);
    };

    struct Window {
        qint64 offset = 0;
        int from = 0;
        QByteArray data;
    };
    QVector<Window> windows;
    if (scanStart + 64 < head.size()) {
        windows.append({0, static_cast<int>(scanStart), head});
    }
    for (const qint64 offset : probe.windowOffsets()) {
        if (offset >= scanStart) {
            windows.append({offset, 0, QByteArray()});
        }
    }

    // "lo" is the highest point known to be valid (a clean window start or
    // the scan start itself); the first junk window becomes "hi" and the
    // boundary between them is bisected to see whether an EOI precedes it.
    qint64 lo = scanStart;
    for (Window &window : windows) {
        if (window.data.isEmpty()) {
            window.data = probe.window(window.offset);
            if (window.data.isEmpty()) {
                return BodyVerdict();
            }
        }
        const JpegWindowScan scan = jpegScanWindow(window.data, window.from);
        if (endsImage(window.offset, scan)) {
            return BodyVerdict();
        }
        if (!scan.junk()) {
            lo = window.offset;
            continue;
        }
        qint64 hi = window.offset;
        int hiFirstViolation = scan.firstViolation;
        for (int step = 0; step < 12 && hi - lo > WINDOW; ++step) {
            const qint64 mid = lo + (hi - lo) / 2;
            const QByteArray midWindow = probe.window(mid);
            if (midWindow.isEmpty()) {
                return BodyVerdict();
            }
            const JpegWindowScan midScan = jpegScanWindow(midWindow, 0);
            if (endsImage(mid, midScan)) {
                return BodyVerdict();
            }
            if (midScan.junk()) {
                hi = mid;
                hiFirstViolation = midScan.firstViolation;
            } else {
                lo = mid;
            }
        }
        if (hi - lo > WINDOW) {
            return BodyVerdict(); // unresolved: give the file the benefit of the doubt
        }
        return bodyFailure(QStringLiteral("JPEG marker grammar violated at offset %1 (%2 violations in the 4 KB window, "
                                          "no EOI marker before it)")
                               .arg(hi + hiFirstViolation)
                               .arg(scan.violations));
    }
    return BodyVerdict();
}

// ---- PNG: chunk chain of the first 64 KB ----

BodyVerdict pngBody(BodyProbe &probe, const QByteArray &head)
{
    QByteArray front = head;
    if (probe.fileSize() > head.size()) {
        front += probe.readAt(head.size(), FormatSignatureDetector::PNG_FRONT_SIZE - head.size());
    }
    int pos = 8;
    while (pos + 8 <= front.size()) {
        const quint32 length = u32be(front, pos);
        const QByteArray type = front.mid(pos + 4, 4);
        bool typeOk = true;
        for (char c : type) {
            typeOk = typeOk && ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
        }
        if (!typeOk || length > 0x7FFFFFFFu) {
            return bodyFailure(QStringLiteral("PNG chunk chain broken at offset %1").arg(pos));
        }
        const qint64 end = static_cast<qint64>(pos) + 12 + length;
        if (end > front.size()) {
            break; // chunk extends past the verified region
        }
        if (u32be(front, static_cast<int>(end) - 4) != FormatSignatureDetector::crc32(front.mid(pos + 4, 4 + static_cast<int>(length)))) {
            return bodyFailure(QStringLiteral("PNG chunk %1 at offset %2 has a wrong CRC").arg(QString::fromLatin1(type)).arg(pos));
        }
        if (type == "IEND") {
            break;
        }
        pos = static_cast<int>(end);
    }
    return BodyVerdict();
}

// ---- ZIP: local file headers named by the central directory ----

BodyVerdict zipBody(BodyProbe &probe, const QByteArray &tail, qint64 tailOffset)
{
    const int eocdInTail = tail.lastIndexOf("PK\x05\x06");
    if (eocdInTail < 0 || eocdInTail + 22 > tail.size()) {
        return BodyVerdict();
    }
    const qint64 eocdPos = tailOffset + eocdInTail;
    const quint16 entries = u16le(tail, eocdInTail + 10);
    const quint32 cdSize = u32le(tail, eocdInTail + 12);
    const quint32 cdOffset = u32le(tail, eocdInTail + 16);
    if (entries == 0 || entries == 0xFFFF || cdSize == 0 || cdSize == 0xFFFFFFFFu || cdOffset == 0xFFFFFFFFu) {
        return BodyVerdict(); // empty archive or ZIP64: not handled
    }
    const qint64 cdPos = eocdPos - cdSize;
    const qint64 prefix = cdPos - cdOffset; // self-extracting stubs shift every offset
    if (cdPos < 0 || prefix < 0) {
        return BodyVerdict();
    }

    const qint64 cdWanted = std::min<qint64>(cdSize, 16384);
    QByteArray cd;
    if (cdPos >= tailOffset) {
        cd = tail.mid(static_cast<int>(cdPos - tailOffset), static_cast<int>(cdWanted));
    } else {
        cd = probe.readAt(cdPos, cdWanted);
    }
    if (cd.size() < 46) {
        return BodyVerdict();
    }
    if (!cd.startsWith("PK\x01\x02")) {
        if (looksRandom(cd.left(WINDOW))) {
            return bodyFailure(QStringLiteral("ZIP central directory missing at offset %1 (random data)").arg(cdPos));
        }
        return BodyVerdict();
    }

    struct Entry {
        qint64 localOffset;
        QByteArray name;
    };
    QVector<Entry> parsed;
    int pos = 0;
    while (pos + 46 <= cd.size() && parsed.size() < 64) {
        if (cd.mid(pos, 4) != "PK\x01\x02") {
            break;
        }
        const int nameLength = u16le(cd, pos + 28);
        const int extraLength = u16le(cd, pos + 30);
        const int commentLength = u16le(cd, pos + 32);
        const qint64 localOffset = u32le(cd, pos + 42);
        if (pos + 46 + nameLength > cd.size()) {
            break;
        }
        parsed.append({prefix + localOffset, cd.mid(pos + 46, nameLength)});
        pos += 46 + nameLength + extraLength + commentLength;
    }
    if (parsed.isEmpty()) {
        return BodyVerdict();
    }

    // Up to 8 entries spread over the file: the ones a chunk is likely to hit
    std::sort(parsed.begin(), parsed.end(), [](const Entry &a, const Entry &b) { return a.localOffset < b.localOffset; });
    QVector<Entry> samples;
    const int wanted = std::min<int>(8, static_cast<int>(parsed.size()));
    for (int i = 0; i < wanted; ++i) {
        const int index = (wanted == 1) ? 0 : static_cast<int>(static_cast<qint64>(i) * (parsed.size() - 1) / (wanted - 1));
        if (samples.isEmpty() || samples.last().localOffset != parsed.at(index).localOffset) {
            samples.append(parsed.at(index));
        }
    }

    for (const Entry &entry : samples) {
        if (entry.localOffset + 30 > probe.fileSize()) {
            return bodyFailure(QStringLiteral("ZIP local header offset %1 lies beyond the end of the file").arg(entry.localOffset));
        }
        const QByteArray local = probe.readAt(entry.localOffset, 30 + entry.name.size());
        if (local.size() < 30) {
            return BodyVerdict();
        }
        if (!local.startsWith("PK\x03\x04")) {
            return bodyFailure(QStringLiteral("ZIP local header missing at offset %1 (entry \"%2\")")
                                   .arg(entry.localOffset)
                                   .arg(QString::fromUtf8(entry.name)));
        }
        const int localNameLength = u16le(local, 26);
        if (localNameLength != entry.name.size() || local.mid(30, localNameLength) != entry.name) {
            return bodyFailure(QStringLiteral("ZIP local header at offset %1 does not name \"%2\"")
                                   .arg(entry.localOffset)
                                   .arg(QString::fromUtf8(entry.name)));
        }
    }
    return BodyVerdict();
}

// ---- PDF: objects named by the classic cross-reference table ----

bool isPdfWhitespace(char c)
{
    return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == '\0';
}

bool isDigit(char c)
{
    return c >= '0' && c <= '9';
}

// Parse an unsigned integer at pos (after optional whitespace); returns -1 on failure
qint64 pdfInteger(const QByteArray &data, int &pos)
{
    while (pos < data.size() && isPdfWhitespace(data.at(pos))) {
        ++pos;
    }
    qint64 value = -1;
    while (pos < data.size() && isDigit(data.at(pos))) {
        value = (value < 0 ? 0 : value) * 10 + (data.at(pos) - '0');
        if (value > 0xFFFFFFFFFFLL) {
            return -1;
        }
        ++pos;
    }
    return value;
}

// "N G obj" within the first 48 bytes (offsets are often off by a byte or two)
bool pdfObjectHeaderNear(const QByteArray &window)
{
    const int limit = std::min<int>(static_cast<int>(window.size()), 48);
    int pos = 0;
    while (pos < limit) {
        int p = pos;
        if (pdfInteger(window, p) >= 0 && p < window.size() && isPdfWhitespace(window.at(p))
            && pdfInteger(window, p) >= 0 && p < window.size() && isPdfWhitespace(window.at(p))) {
            while (p < window.size() && isPdfWhitespace(window.at(p))) {
                ++p;
            }
            if (window.mid(p, 3) == "obj") {
                return true;
            }
        }
        ++pos;
    }
    return false;
}

struct PdfXrefEntry {
    qint64 offset;
    qint64 object;
};

// Parse "xref" subsections from data at pos into entries; returns the position after the table
int pdfParseXrefTable(const QByteArray &data, int pos, QVector<PdfXrefEntry> &entries, qint64 fileSize)
{
    while (pos < data.size() && entries.size() < 512) {
        int p = pos;
        const qint64 start = pdfInteger(data, p);
        if (start < 0) {
            break; // "trailer" or garbage
        }
        const qint64 count = pdfInteger(data, p);
        if (count < 0) {
            break;
        }
        pos = p;
        for (qint64 i = 0; i < count && entries.size() < 512; ++i) {
            int q = pos;
            const qint64 offset = pdfInteger(data, q);
            const qint64 generation = pdfInteger(data, q);
            while (q < data.size() && isPdfWhitespace(data.at(q))) {
                ++q;
            }
            if (offset < 0 || generation < 0 || q >= data.size()) {
                return pos;
            }
            const char type = data.at(q);
            if (type != 'n' && type != 'f') {
                return pos;
            }
            pos = q + 1;
            if (type == 'n' && offset > 0 && offset + 16 < fileSize) {
                entries.append({offset, start + i});
            }
        }
    }
    return pos;
}

BodyVerdict pdfBody(BodyProbe &probe, const QByteArray &tail)
{
    const int startxref = tail.lastIndexOf("startxref");
    if (startxref < 0) {
        return BodyVerdict();
    }
    int pos = startxref + 9;
    qint64 xrefPos = pdfInteger(tail, pos);
    QVector<PdfXrefEntry> entries;
    for (int hop = 0; hop < 2 && xrefPos > 0 && xrefPos < probe.fileSize(); ++hop) {
        const QByteArray table = probe.readAt(xrefPos, 16384);
        int p = 0;
        while (p < table.size() && isPdfWhitespace(table.at(p))) {
            ++p;
        }
        if (table.mid(p, 4) != "xref") {
            // A cross-reference stream (compressed) or a sloppy offset: nothing cheap to verify
            break;
        }
        p = pdfParseXrefTable(table, p + 4, entries, probe.fileSize());
        // Linearized files: the first-page table points at the main one via /Prev
        const int prev = table.indexOf("/Prev", p);
        if (prev < 0) {
            break;
        }
        int q = prev + 5;
        xrefPos = pdfInteger(table, q);
    }
    if (entries.isEmpty()) {
        return BodyVerdict();
    }

    std::sort(entries.begin(), entries.end(), [](const PdfXrefEntry &a, const PdfXrefEntry &b) { return a.offset < b.offset; });
    QVector<PdfXrefEntry> samples;
    const int wanted = std::min<int>(12, static_cast<int>(entries.size()));
    for (int i = 0; i < wanted; ++i) {
        const int index = (wanted == 1) ? 0 : static_cast<int>(static_cast<qint64>(i) * (entries.size() - 1) / (wanted - 1));
        if (samples.isEmpty() || samples.last().offset != entries.at(index).offset) {
            samples.append(entries.at(index));
        }
    }

    // Damage is only believed when an object later in the file is intact:
    // encryption of a chunk leaves the rest consistent, whereas a shifted
    // table (CRLF conversion, sloppy writer) breaks every later offset.
    qint64 firstBadOffset = -1;
    qint64 firstBadObject = -1;
    bool intactAfterBad = false;
    for (const PdfXrefEntry &entry : samples) {
        const QByteArray window = probe.window(entry.offset);
        if (window.isEmpty()) {
            return BodyVerdict();
        }
        if (pdfObjectHeaderNear(window)) {
            if (firstBadOffset >= 0) {
                intactAfterBad = true;
            }
        } else if (firstBadOffset < 0 && looksRandom(window)) {
            firstBadOffset = entry.offset;
            firstBadObject = entry.object;
        }
    }
    if (firstBadOffset >= 0 && intactAfterBad) {
        return bodyFailure(QStringLiteral("PDF object %1 missing at offset %2 (random data there, later objects intact)")
                               .arg(firstBadObject)
                               .arg(firstBadOffset));
    }
    return BodyVerdict();
}

// ---- ISO BMFF (MP4/MOV/M4A/HEIC): top-level atom chain ----

BodyVerdict isoBmffBody(BodyProbe &probe, const QByteArray &head)
{
    const qint64 fileSize = probe.fileSize();
    qint64 pos = 0;
    for (int atom = 0; atom < 64 && pos < fileSize; ++atom) {
        QByteArray header;
        if (pos + 16 <= head.size()) {
            header = head.mid(static_cast<int>(pos), 16);
        } else {
            header = probe.readAt(pos, 16);
        }
        if (header.size() < 8) {
            return BodyVerdict(); // a few stray bytes at the end: not a chunk's work
        }
        qint64 size = u32be(header, 0);
        int headerLength = 8;
        if (size == 1) {
            if (header.size() < 16) {
                return BodyVerdict();
            }
            const quint64 large = u64be(header, 8);
            size = (large > static_cast<quint64>(std::numeric_limits<qint64>::max())) ? -1 : static_cast<qint64>(large);
            headerLength = 16;
        }
        bool typeOk = true;
        for (int i = 4; i < 8; ++i) {
            const quint8 c = byteAt(header, i);
            typeOk = typeOk && c >= 0x20 && c <= 0x7E;
        }
        if (!typeOk || (size != 0 && size < headerLength)) {
            // Not an atom header. Random bytes here are a chunk that landed on
            // the header; anything else (a half-written file) is not our call.
            const QByteArray window = (pos + WINDOW <= head.size()) ? head.mid(static_cast<int>(pos), WINDOW) : probe.window(pos);
            if (looksRandom(window)) {
                return bodyFailure(QStringLiteral("MP4 atom chain broken at offset %1 (random data where an atom header is expected)").arg(pos));
            }
            return BodyVerdict();
        }
        if (size == 0) {
            return BodyVerdict(); // last atom extends to the end of the file
        }
        const qint64 atomPos = pos;
        pos += size;
        if (pos > fileSize) {
            // A known atom whose size overshoots the file is a truncated or
            // still growing file. Any other printable type with a size that
            // does not fit is random bytes that happened to be printable.
            static const char *const topLevel[] = {"ftyp", "moov", "mdat", "free", "skip", "wide", "pnot", "uuid", "meta",
                                                   "moof", "mfra", "sidx", "styp", "ssix", "prft", "emsg", "junk", "pdin",
                                                   "meco", "PICT", "idat", "iloc", "iinf", "iprp", "iref", "ipco"};
            const QByteArray type = header.mid(4, 4);
            for (const char *known : topLevel) {
                if (type == known) {
                    return BodyVerdict();
                }
            }
            const QByteArray window = (atomPos + WINDOW <= head.size()) ? head.mid(static_cast<int>(atomPos), WINDOW) : probe.window(atomPos);
            if (looksRandom(window)) {
                return bodyFailure(QStringLiteral("MP4 atom chain broken at offset %1 (random data where an atom header is expected)").arg(atomPos));
            }
            return BodyVerdict();
        }
    }
    return BodyVerdict();
}

// ---- MP3: frame sync chain in every window after the ID3v2 tag ----

bool mp3WindowHasFrameChain(const QByteArray &window)
{
    const int limit = std::min<int>(static_cast<int>(window.size()) - 4, 2048);
    for (int pos = 0; pos < limit; ++pos) {
        const Mp3Frame frame = parseMp3Frame(window, pos);
        if (!frame.valid) {
            continue;
        }
        const int next = pos + frame.length;
        if (next + 4 <= window.size() && parseMp3Frame(window, next).valid) {
            return true;
        }
    }
    return false;
}

bool mp3TailHasKnownTag(const QByteArray &tail)
{
    const int n = tail.size();
    auto at = [&tail, n](int fromEnd, const char *marker) {
        const int length = static_cast<int>(strlen(marker));
        return n >= fromEnd && tail.mid(n - fromEnd, length) == marker;
    };
    return at(128, "TAG") || at(32, "APETAGEX") || at(160, "APETAGEX") || at(10, "3DI")
        || at(137, "LYRICS200") || at(9, "LYRICS200");
}

BodyVerdict mp3Body(BodyProbe &probe, const QByteArray &head)
{
    qint64 audioStart = 0;
    if (head.startsWith("ID3") && head.size() >= 10) {
        const qint64 tagSize = (static_cast<qint64>(byteAt(head, 6) & 0x7F) << 21) | ((byteAt(head, 7) & 0x7F) << 14)
            | ((byteAt(head, 8) & 0x7F) << 7) | (byteAt(head, 9) & 0x7F);
        audioStart = 10 + tagSize + ((byteAt(head, 5) & 0x10) ? 10 : 0);
    }
    const QVector<qint64> offsets = probe.windowOffsets();
    const qint64 tailOffset = offsets.last();
    int brokenWindows = 0;
    int checkedWindows = 0;
    qint64 firstBroken = -1;
    for (const qint64 offset : offsets) {
        if (offset < audioStart) {
            continue;
        }
        const QByteArray window = probe.window(offset);
        if (window.isEmpty()) {
            return BodyVerdict();
        }
        ++checkedWindows;
        if (mp3WindowHasFrameChain(window)) {
            continue;
        }
        if (offset == tailOffset) {
            // Tags (ID3v1, APE, Lyrics3, ID3v2 footer) legitimately end an MP3
            // without frames; random bytes with no tag at all do not.
            if (!mp3TailHasKnownTag(window) && looksRandom(window)) {
                return bodyFailure(QStringLiteral("MP3 tail at offset %1 holds neither audio frames nor a known tag (random data)").arg(offset));
            }
            continue;
        }
        if (firstBroken < 0) {
            firstBroken = offset;
        }
        ++brokenWindows;
    }
    // One window may sit in an embedded tag or picture (concatenated files); two cannot
    if (brokenWindows >= 2) {
        return bodyFailure(QStringLiteral("MP3 frame sync missing in %1 of %2 windows (first at offset %3)")
                               .arg(brokenWindows)
                               .arg(checkedWindows)
                               .arg(firstBroken));
    }
    return BodyVerdict();
}

// ---- Text: no window may be random bytes with NULs ----

BodyVerdict textBody(BodyProbe &probe)
{
    for (const qint64 offset : probe.windowOffsets()) {
        const QByteArray window = probe.window(offset);
        if (window.isEmpty()) {
            return BodyVerdict();
        }
        if (window.contains('\0') && looksRandom(window)) {
            return bodyFailure(QStringLiteral("text file holds NUL bytes and random data at offset %1").arg(offset));
        }
    }
    return BodyVerdict();
}

} // namespace

FormatSignatureDetector::FormatSignatureDetector()
{
}

double FormatSignatureDetector::headerEntropy(const QByteArray &data)
{
    return EntropyDetector::calculateEntropy(data);
}

quint32 FormatSignatureDetector::crc32(const QByteArray &data)
{
    static const std::array<quint32, 256> table = [] {
        std::array<quint32, 256> t{};
        for (quint32 n = 0; n < 256; ++n) {
            quint32 c = n;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            t[n] = c;
        }
        return t;
    }();

    quint32 crc = 0xFFFFFFFFu;
    for (char ch : data) {
        crc = table[(crc ^ static_cast<quint8>(ch)) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

bool FormatSignatureDetector::hasKnownSignature(const QString &fileName)
{
    const Spec *spec = specFor(fileName);
    return spec != nullptr && spec->family != Family::Skip;
}

bool FormatSignatureDetector::isTextExtension(const QString &fileName)
{
    const Spec *spec = specFor(fileName);
    return spec != nullptr && spec->family == Family::Text;
}

FormatSignatureDetector::Result FormatSignatureDetector::checkFile(const QString &localPath,
                                                                   const QString &nameForExtension) const
{
    Result result;

    const Spec *spec = specFor(nameForExtension);
    if (!spec || spec->family == Family::Skip) {
        result.reason = QStringLiteral("no reliable signature for this extension");
        return result;
    }
    result.expectedFormat = spec->format;

    QFile file(localPath);
    if (!file.open(QIODevice::ReadOnly)) {
        result.reason = QStringLiteral("cannot open file");
        return result;
    }

    const qint64 fileSize = file.size();
    if (fileSize < MIN_FILE_SIZE) {
        result.reason = QStringLiteral("file too small to judge");
        return result;
    }

    const QByteArray head = file.read(HEAD_SAMPLE_SIZE);
    if (head.isEmpty()) {
        result.reason = QStringLiteral("cannot read file");
        return result;
    }

    // Ciphertext is indistinguishable from random bytes. Very short samples
    // cannot reach 8 bits/byte, so scale the bar down for them.
    const double entropy = headerEntropy(head);
    const double randomBar = std::min(RANDOM_HEADER_ENTROPY, 0.85 * std::log2(static_cast<double>(head.size())));
    result.headerLooksRandom = entropy >= randomBar;

    auto readTail = [&file, fileSize](int wanted) {
        const qint64 length = std::min<qint64>(wanted, fileSize);
        if (!file.seek(fileSize - length)) {
            return QByteArray();
        }
        return file.read(length);
    };

    auto mismatch = [&result](const QString &reason) {
        result.verdict = Verdict::Mismatch;
        result.reason = reason;
        return result;
    };
    auto tailFailure = [&result](const QString &detail) {
        result.verdict = Verdict::Mismatch;
        result.tailCorrupted = true;
        result.reason = QStringLiteral("truncated/corrupted tail (%1)").arg(detail);
        return result;
    };
    // Header (and tail) are fine. For files large enough to have a body worth
    // sampling, run the format's structure walk before declaring a match.
    BodyProbe probe(file, fileSize);
    auto matchAfterBody = [&result, &probe, fileSize](const std::function<BodyVerdict(BodyProbe &)> &bodyCheck) {
        if (fileSize >= BODY_MIN_FILE_SIZE && bodyCheck) {
            const BodyVerdict body = bodyCheck(probe);
            if (body.corrupted) {
                result.verdict = Verdict::Mismatch;
                result.bodyCorrupted = true;
                result.reason = QStringLiteral("corrupted body (%1)").arg(body.reason);
                return result;
            }
        }
        result.verdict = Verdict::Match;
        result.reason = QStringLiteral("content matches the expected format");
        return result;
    };
    auto match = [&matchAfterBody]() {
        return matchAfterBody(nullptr);
    };
    const QString headerMismatch = QStringLiteral("header does not match the %1 signature").arg(spec->format);

    switch (spec->family) {
    case Family::Skip:
        return result;

    case Family::Generic:
        return matchesAny(head, spec->patterns) ? match() : mismatch(headerMismatch);

    case Family::Text: {
        // ".ts" is TypeScript but also an MPEG transport stream: 188-byte
        // packets that each start with the sync byte 0x47.
        if (extensionOf(nameForExtension) == QLatin1String("ts") && head.size() > 188
            && byteAt(head, 0) == 0x47 && byteAt(head, 188) == 0x47) {
            return match(); // compressed video: no text body check
        }
        if (head.startsWith("\xFF\xFE") || head.startsWith("\xFE\xFF")) {
            // UTF-16 BOM: NUL bytes are expected, so only the body's randomness is checked
            return matchAfterBody(textBody);
        }
        const QByteArray body = head.startsWith("\xEF\xBB\xBF") ? head.mid(3) : head;
        if (body.contains('\0')) {
            return mismatch(QStringLiteral("text file contains NUL bytes"));
        }
        const Utf8Status status = utf8Status(body);
        if (status == Utf8Status::Invalid
            || (status == Utf8Status::TruncatedAtEnd && head.size() < HEAD_SAMPLE_SIZE)) {
            return mismatch(QStringLiteral("text file is not valid UTF-8"));
        }
        return matchAfterBody(textBody);
    }

    case Family::Jpeg:
        if (!matchesAny(head, spec->patterns)) {
            return mismatch(headerMismatch);
        }
        if (!jpegSegmentsLookValid(head)) {
            return mismatch(QStringLiteral("corrupted JPEG segment structure"));
        }
        // No FFD9 trailer check: motion photos append data after the image
        return matchAfterBody([&head](BodyProbe &p) { return jpegBody(p, head); });

    case Family::Png: {
        if (!matchesAny(head, spec->patterns)) {
            return mismatch(headerMismatch);
        }
        // First chunk: length 13, type IHDR, CRC over type + data
        if (head.size() < 33 || u32be(head, 8) != 13 || head.mid(12, 4) != "IHDR"
            || u32be(head, 29) != crc32(head.mid(12, 17))) {
            return mismatch(QStringLiteral("corrupted PNG IHDR chunk"));
        }
        const QByteArray tail = readTail(PNG_TAIL_SIZE);
        static const QByteArray iend = QByteArray::fromHex("00000000" "49454E44" "AE426082");
        if (tail != iend) {
            return tailFailure(QStringLiteral("missing PNG IEND chunk"));
        }
        return matchAfterBody([&head](BodyProbe &p) { return pngBody(p, head); });
    }

    case Family::Zip: {
        if (!matchesAny(head, spec->patterns)) {
            return mismatch(headerMismatch);
        }
        const QByteArray tail = readTail(ZIP_TAIL_SIZE);
        if (tail.lastIndexOf("PK\x05\x06") < 0) {
            return tailFailure(QStringLiteral("missing ZIP end-of-central-directory record"));
        }
        const qint64 tailOffset = fileSize - tail.size();
        return matchAfterBody([&tail, tailOffset](BodyProbe &p) { return zipBody(p, tail, tailOffset); });
    }

    case Family::Pdf: {
        if (head.left(1024).indexOf("%PDF-") < 0) {
            return mismatch(headerMismatch);
        }
        const QByteArray tail = readTail(PDF_TAIL_SIZE);
        if (tail.lastIndexOf("%%EOF") < 0) {
            return tailFailure(QStringLiteral("missing PDF %%EOF marker"));
        }
        return matchAfterBody([&tail](BodyProbe &p) { return pdfBody(p, tail); });
    }

    case Family::IsoBmff:
        if (!isoBmffLooksValid(head)) {
            return mismatch(headerMismatch);
        }
        return matchAfterBody([&head](BodyProbe &p) { return isoBmffBody(p, head); });

    case Family::Mp3:
        if (!mp3LooksValid(head)) {
            return mismatch(headerMismatch);
        }
        return matchAfterBody([&head](BodyProbe &p) { return mp3Body(p, head); });

    case Family::Aac:
        return aacLooksValid(head) ? match() : mismatch(headerMismatch);

    case Family::Bmp:
        return bmpLooksValid(head) ? match() : mismatch(headerMismatch);

    case Family::Asn1:
        return derLooksValid(head, fileSize) ? match() : mismatch(headerMismatch);

    case Family::PemOrAsn1:
        return (pemLooksValid(head) || derLooksValid(head, fileSize)) ? match() : mismatch(headerMismatch);

    case Family::Pem:
        return pemLooksValid(head) ? match() : mismatch(headerMismatch);
    }

    return result;
}

ThreatInfo FormatSignatureDetector::analyze(const SyncFileItem &item,
                                             const QVector<struct KillSwitchManager::Event> &recentEvents,
                                             const AnalysisContext &context)
{
    Q_UNUSED(recentEvents)

    ThreatInfo result;
    result.level = ThreatLevel::None;
    result.detectorName = name();

    if (!m_enabled) {
        return result;
    }

    // Only content that was (re)written locally is worth validating
    if (item._instruction != CSYNC_INSTRUCTION_NEW
        && item._instruction != CSYNC_INSTRUCTION_SYNC
        && item._instruction != CSYNC_INSTRUCTION_CONFLICT) {
        return result;
    }
    if (item._type == ItemTypeDirectory) {
        return result;
    }
    // For a download the local file is either absent or still the previous version
    if (item._direction == SyncFileItem::Down) {
        return result;
    }

    const QString localPath = context.localPath(item._file);
    const Result check = checkFile(localPath, item._file);
    if (check.verdict != Verdict::Mismatch) {
        return result;
    }

    result.affectedFiles.append(localPath);

    const bool strong = check.headerLooksRandom || check.tailCorrupted || check.bodyCorrupted;
    if (!strong) {
        // Wrong extension, stray text, renamed file: worth a note, not an alarm
        result.level = ThreatLevel::Low;
        result.description = QStringLiteral("%1 is not a valid %2 (%3) but its content is not random; "
                                            "extension/content mismatch rather than encryption")
                                 .arg(item._file, check.expectedFormat, check.reason);
        return result;
    }

    const QDateTime now = QDateTime::currentDateTime();
    const bool existingFile = item._instruction != CSYNC_INSTRUCTION_NEW;
    const int hits = recordHit(now);

    if (existingFile && check.headerLooksRandom && !check.tailCorrupted && !check.bodyCorrupted) {
        // A file we already synced no longer carries its own signature and
        // starts with random bytes: that is exactly what in-place encryption
        // looks like. A corrupted tail with an intact header also happens to
        // archives still being written (compressed data looks random too),
        // so that case goes through the window counting below instead of
        // alarming on one file. The same goes for a corrupted body: the
        // header of a genuine JPEG or MP4 is itself high-entropy, so a
        // single file with damage inside is a hit, not an alarm.
        result.level = ThreatLevel::High;
    } else if (hits >= m_threshold * 2) {
        result.level = ThreatLevel::Critical;
    } else if (hits >= m_threshold) {
        result.level = ThreatLevel::High;
    } else {
        result.level = ThreatLevel::Medium;
    }

    result.description = QStringLiteral("%1 %2 is not a valid %3: %4; content looks random "
                                        "(%5 mismatching files in window)")
                             .arg(existingFile ? QStringLiteral("Modified file") : QStringLiteral("New file"),
                                  item._file, check.expectedFormat, check.reason)
                             .arg(hits);
    return result;
}

int FormatSignatureDetector::recordHit(const QDateTime &now)
{
    const QDateTime cutoff = now.addSecs(-m_windowSeconds);
    m_recentHits.erase(
        std::remove_if(m_recentHits.begin(), m_recentHits.end(),
                       [&cutoff](const QDateTime &t) { return t < cutoff; }),
        m_recentHits.end());
    m_recentHits.append(now);
    return m_recentHits.size();
}

} // namespace OCC

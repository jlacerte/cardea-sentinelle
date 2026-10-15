/*
 * Nextcloud Sentinel Edition - Format Signature Detector
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../threatdetector.h"
#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QVector>

namespace OCC {

/**
 * @brief Detects files whose content no longer matches their extension
 *
 * Ransomware that encrypts a file in place keeps the file name, so a
 * .jpg/.pdf/.docx/.zip/.mp4 turns into random bytes while still looking like
 * a photo or a document to every name-based check. Those formats are also
 * naturally high-entropy, which is why the EntropyDetector deliberately
 * skips them. This detector fills that gap with cheap structural checks:
 *
 * - a magic-number table (first 4 KB) for images, documents, archives,
 *   databases, media, fonts, executables and certificates;
 * - a "textness" check for text extensions (no NUL bytes, valid UTF-8 or
 *   a UTF-16 BOM);
 * - tail checks for formats that end with a known structure, which catch
 *   chunked/intermittent encryption that spared the header: ZIP-based files
 *   must carry an End-Of-Central-Directory record in the last 64 KB, PDFs a
 *   "%%EOF" in the last 2 KB, PNGs the IEND chunk as their last 12 bytes;
 * - a "structure walk" over sampled 4 KB windows (file start, file end and
 *   every 512 KiB, at most 16 windows) for files of 16 KB and more, which
 *   catches chunked encryption that spared both the header and the tail
 *   (Play/RansomHub/Conti style) and tail-only damage on formats without a
 *   trailer. Per format:
 *     JPEG  - marker grammar of the entropy-coded data (an FF byte may only
 *             be followed by 00, a RSTn or a real marker). Trailing data
 *             after the EOI marker (motion photos, MPF) is tolerated because
 *             the first corrupt window is bisected back to its start and
 *             excused when an FFD9 precedes it.
 *     ZIP   - up to 8 central-directory entries spread over the file must
 *             have their local file header (PK\3\4 + same name) at the
 *             recorded offset. A chunk that only overwrites compressed
 *             entry data is invisible.
 *     PDF   - the classic cross-reference table named by "startxref" is
 *             read and up to 12 in-use objects spread over the file must
 *             start with "N G obj" at their recorded offset. Damage counts
 *             only when the offset holds random bytes and an object later
 *             in the file is still intact (files mangled by CRLF conversion
 *             have shifted offsets but no later intact object). Files with
 *             a cross-reference stream (PDF 1.5+, compressed) get no body
 *             check; a chunk inside a large image stream is invisible.
 *     MP4/MOV/HEIC - the top-level atom chain (size + type) must link from
 *             offset 0 to EOF; a chunk that lands on an atom header breaks
 *             it. The content of mdat is compressed and not inspected, so a
 *             chunk inside a single big mdat is invisible.
 *     MP3   - every window after the ID3v2 tag must contain a frame header
 *             whose length lands on the next frame header; two broken
 *             windows (or a random tail without any known tag) are corrupt.
 *     PNG   - the chunk chain (length, type, CRC) of the first 64 KB; the
 *             middle of a PNG has no structure a sampled window can verify.
 *     text  - no window may contain NUL bytes together with random data.
 *   Formats with only a magic number (gif, webp, tiff, OLE2, gz, 7z, ...)
 *   get no body check.
 *
 * Nothing is decompressed. I/O per file is bounded: the 4 KB head, the
 * format's tail (at most 64 KB), at most 16 sampled windows of 4 KB, plus a
 * few small structure reads (up to 12 bisection windows for a JPEG, 8 ZIP
 * local headers, a 16 KB PDF cross-reference table, 64 MP4 atom headers),
 * all through one open file. Extensions without a reliable signature
 * (.bin, .dat, .tar, ...) and encrypted-by-design formats (.gpg, .pgp,
 * .asc) are left alone.
 *
 * Only local changes (direction Up) are analyzed: for a download the local
 * file is either missing or still the previous version.
 */
class OWNCLOUDSYNC_EXPORT FormatSignatureDetector : public ThreatDetector
{
public:
    enum class Verdict {
        Unknown,  ///< No reliable signature for this extension, or file unreadable/too small
        Match,    ///< Content is consistent with the extension
        Mismatch  ///< Content cannot be what the extension claims
    };

    struct Result {
        Verdict verdict = Verdict::Unknown;
        /// Human readable explanation ("header does not match ...", "truncated/corrupted tail", ...)
        QString reason;
        /// Shannon entropy of the first 4 KB is at ciphertext level (text wrongly named .jpg is not)
        bool headerLooksRandom = false;
        /// The header was fine but the structural tail check failed (chunked encryption)
        bool tailCorrupted = false;
        /// Header and tail were fine but a sampled window / structure walk inside the
        /// file failed (chunked encryption sparing both ends, or tail damage on a
        /// format without a trailer). Never set together with tailCorrupted.
        bool bodyCorrupted = false;
        /// Format the extension promised, e.g. "PNG image"
        QString expectedFormat;
    };

    FormatSignatureDetector();

    QString name() const override { return QStringLiteral("FormatSignatureDetector"); }

    using ThreatDetector::analyze;
    ThreatInfo analyze(const SyncFileItem &item,
                       const QVector<struct KillSwitchManager::Event> &recentEvents,
                       const AnalysisContext &context) override;

    /**
     * @brief Check a file on disk against the signature its name promises
     * @param localPath Absolute path of the file to read
     * @param nameForExtension Name (or relative path) whose extension selects the signature
     *
     * Reads the first 4 KB, the format's tail (at most 64 KB + 22) and, for
     * files of BODY_MIN_FILE_SIZE and more, up to BODY_MAX_WINDOWS sampled
     * windows of BODY_WINDOW_SIZE plus a few small structure reads, all
     * through a single open.
     */
    Result checkFile(const QString &localPath, const QString &nameForExtension) const;

    /**
     * @brief Whether the extension of fileName is in the signature table (text extensions included)
     */
    static bool hasKnownSignature(const QString &fileName);

    /**
     * @brief Whether the extension of fileName is checked with the text heuristic
     */
    static bool isTextExtension(const QString &fileName);

    /**
     * @brief Shannon entropy (bits/byte) of a header sample; delegates to EntropyDetector
     */
    static double headerEntropy(const QByteArray &data);

    /**
     * @brief Standard CRC-32 (IEEE 802.3, as used by PNG and ZIP)
     */
    static quint32 crc32(const QByteArray &data);

    /**
     * @brief Number of mismatching NEW files within the window needed for a High threat
     * (twice that for Critical). Default: 3.
     */
    void setThreshold(int count) { m_threshold = qMax(1, count); }
    int threshold() const { return m_threshold; }

    /**
     * @brief Time window (seconds) over which hits are counted. Default: 60.
     */
    void setWindowSeconds(int seconds) { m_windowSeconds = qMax(1, seconds); }

    static constexpr int HEAD_SAMPLE_SIZE = 4096;
    static constexpr int MIN_FILE_SIZE = 64;
    /// EOCD record (22 bytes) plus the maximum ZIP comment length (65535)
    static constexpr int ZIP_TAIL_SIZE = 65557;
    static constexpr int PDF_TAIL_SIZE = 2048;
    static constexpr int PNG_TAIL_SIZE = 12;
    static constexpr double RANDOM_HEADER_ENTROPY = 7.0;
    /// Body sampling: 4 KB windows at the start, the end and every BODY_WINDOW_STEP
    /// bytes (+ BODY_WINDOW_SKEW so a window never starts exactly on a boundary a
    /// chunking encryptor is likely to use), at most BODY_MAX_WINDOWS of them.
    static constexpr int BODY_WINDOW_SIZE = 4096;
    static constexpr int BODY_MIN_FILE_SIZE = 16384;
    static constexpr int BODY_MAX_WINDOWS = 16;
    static constexpr qint64 BODY_WINDOW_STEP = 512 * 1024;
    static constexpr int BODY_WINDOW_SKEW = 1024;
    /// PNG chunk chain is verified over this many leading bytes
    static constexpr int PNG_FRONT_SIZE = 65536;

private:
    int m_threshold = 3;
    int m_windowSeconds = 60;

    // Timestamps of recent mismatch hits (pruned to the window)
    QVector<QDateTime> m_recentHits;

    /**
     * @brief Record a mismatch hit and return the number of hits in the window
     */
    int recordHit(const QDateTime &now);
};

} // namespace OCC

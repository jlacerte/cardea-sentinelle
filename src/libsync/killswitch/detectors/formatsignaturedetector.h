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
 *   "%%EOF" in the last 2 KB, PNGs the IEND chunk as their last 12 bytes.
 *
 * Nothing is decompressed and at most two reads (head and tail) are issued
 * per file. Extensions without a reliable signature (.bin, .dat, .tar, ...)
 * and encrypted-by-design formats (.gpg, .pgp, .asc) are left alone.
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
     * Reads at most the first 4 KB and the last 64 KB (+22) of the file
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

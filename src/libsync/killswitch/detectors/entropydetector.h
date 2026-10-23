/*
 * Nextcloud Sentinel Edition - Entropy Detector
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../threatdetector.h"
#include <QDateTime>
#include <QHash>
#include <QVector>

#include <list>

namespace OCC {

/**
 * @brief Detects encrypted/ransomware files via entropy analysis
 *
 * Shannon entropy measures randomness in data (0-8 bits/byte).
 * Encrypted data has very high entropy (~7.9-8.0).
 * Normal files have lower entropy depending on type.
 *
 * Detection criteria:
 * - A text-like file (known extension) whose entropy is far above what its
 *   type can produce: High on its own (a .txt at 7.6 bits/byte is encrypted).
 * - Files of unknown type with very high entropy, or files whose entropy
 *   jumped since we last saw them: counted over the time window. One such
 *   file is Medium (password databases, disk images, proprietary formats are
 *   legitimately random); several within the window escalate to High and
 *   then Critical, which is what a running encryptor looks like.
 *
 * Only local changes (direction Up) are analyzed: for a download the local
 * file is either missing or still the previous version.
 */
class OWNCLOUDSYNC_EXPORT EntropyDetector : public ThreatDetector
{
public:
    EntropyDetector();

    QString name() const override { return QStringLiteral("EntropyDetector"); }

    using ThreatDetector::analyze;
    ThreatInfo analyze(const SyncFileItem &item,
                       const QVector<struct KillSwitchManager::Event> &recentEvents,
                       const AnalysisContext &context) override;

    /// Forget the high-entropy hits counted in the window (KillSwitchManager::reset()).
    /// The entropy cache is kept: it describes the files, not the attack.
    void reset() override { m_recentHits.clear(); }

    // Configuration
    void setHighEntropyThreshold(double threshold) { m_highThreshold = threshold; }
    void setSuspiciousEntropyThreshold(double threshold) { m_suspiciousThreshold = threshold; }
    void setSampleSize(int bytes) { m_sampleSize = bytes; }

    /**
     * @brief Number of high-entropy files within the window needed for a High threat
     * (twice that for Critical). Default: 3.
     */
    void setThreshold(int count) { m_threshold = qMax(1, count); }
    int threshold() const { return m_threshold; }

    /**
     * @brief Time window (seconds) over which high-entropy hits are counted. Default: 60.
     */
    void setWindowSeconds(int seconds) { m_windowSeconds = qMax(1, seconds); }

    // Cache control
    void setCacheEnabled(bool enabled) { m_cacheEnabled = enabled; }
    bool isCacheEnabled() const { return m_cacheEnabled; }
    void setMaxCacheSize(int size) { m_cacheMaxSize = size; }
    int maxCacheSize() const { return m_cacheMaxSize; }
    int cacheSize() const { return m_entropyCache.size(); }
    void clearCache()
    {
        m_entropyCache.clear();
        m_cachePositions.clear();
        m_cacheOrder.clear();
    }

    /**
     * @brief Calculate Shannon entropy of data
     * @param data The data to analyze
     * @return Entropy in bits per byte (0.0 - 8.0)
     */
    static double calculateEntropy(const QByteArray &data);

    /**
     * @brief Calculate entropy of a file using single sample
     * @param filePath Path to the file
     * @param sampleSize Number of bytes to sample (0 = entire file)
     * @return Entropy in bits per byte, or -1.0 on error
     */
    static double calculateFileEntropy(const QString &filePath, int sampleSize = 65536);

    /**
     * @brief Calculate entropy using multi-block sampling (more accurate)
     * @param filePath Path to the file
     * @return Entropy in bits per byte, or -1.0 on error
     *
     * Sampling strategy:
     * - Files < 64KB: Analyze entire file
     * - Files 64KB-1MB: 3 samples (beginning, middle, end)
     * - Files > 1MB: 5 samples distributed + random offset
     *
     * Benefits over single-sample:
     * - Detects partial encryption (only part of file encrypted)
     * - More representative of file content
     * - Early exit if first sample shows high entropy
     */
    double calculateMultiBlockEntropy(const QString &filePath) const;

    /**
     * @brief Check if file type normally has high entropy
     * @param filePath Path to the file (used to check extension)
     * @return true if the file extension indicates compressed/encrypted content
     *
     * High-entropy file types that should be whitelisted:
     * - Compressed formats: .zip, .7z, .rar, .gz, .bz2
     * - Media files: .jpg, .jpeg, .png, .gif, .mp3, .mp4, .avi
     * - Already encrypted: .pdf (often), .docx, .xlsx (ZIP-based)
     */
    bool isNormallyHighEntropy(const QString &filePath) const;

    /**
     * @brief Get expected entropy range for file type
     * @param filePath Path to the file (used to check extension)
     * @return Pair of (min, max) expected entropy for this file type
     *
     * Expected ranges by file type:
     * - Text files (.txt, .md): 3.0 - 5.5
     * - Source code (.cpp, .py): 4.0 - 6.0
     * - Config files (.json, .xml): 3.5 - 5.5
     * - Unknown types: 0.0 - 8.0
     */
    QPair<double, double> expectedEntropyRange(const QString &filePath) const;

private:

    double m_highThreshold = 7.9;       // Definitely encrypted
    double m_suspiciousThreshold = 7.5; // Suspicious
    int m_sampleSize = 65536;           // 64KB sample per block
    int m_cacheMaxSize = 10000;         // LRU cache limit
    bool m_cacheEnabled = true;         // Cache enabled by default
    int m_threshold = 3;                // High-entropy hits in window for High
    int m_windowSeconds = 60;           // Window for counting hits

    // Cache of known file entropies for comparison (with LRU eviction).
    // m_cacheOrder lists the keys least-recently-used first; m_cachePositions
    // maps each key to its node so a touch is an O(1) splice instead of an
    // O(n) QStringList::indexOf/removeAt.
    mutable QHash<QString, double> m_entropyCache;
    mutable std::list<QString> m_cacheOrder;
    mutable QHash<QString, std::list<QString>::iterator> m_cachePositions;

    // Timestamps of recent high-entropy hits (pruned to the window)
    QVector<QDateTime> m_recentHits;

    /**
     * @brief Update cache with O(1) LRU eviction
     */
    void updateCache(const QString &filePath, double entropy) const;

    /**
     * @brief Record a high-entropy hit and return the number of hits in the window
     */
    int recordHit(const QDateTime &now);

    // File extensions that normally have high entropy
    static const QStringList s_highEntropyExtensions;

    // Sampling constants
    static constexpr int SMALL_FILE_THRESHOLD = 65536;      // 64KB
    static constexpr int MEDIUM_FILE_THRESHOLD = 1048576;   // 1MB
    static constexpr int SAMPLE_BLOCK_SIZE = 32768;         // 32KB per block
};

} // namespace OCC

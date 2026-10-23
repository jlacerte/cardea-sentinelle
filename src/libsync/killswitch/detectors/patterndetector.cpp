/*
 * Nextcloud Sentinel Edition - Pattern Detector Implementation
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "patterndetector.h"
#include "syncfileitem.h"

#include <QFileInfo>
#include <algorithm>
#include <QLoggingCategory>

namespace OCC {

Q_LOGGING_CATEGORY(lcPatternDetector, "nextcloud.sync.killswitch.pattern", QtInfoMsg)

PatternDetector::PatternDetector()
{
    initializePatterns();
}

void PatternDetector::initializePatterns()
{
    // Known ransomware extensions - comprehensive list
    // Sources: Recorded Future, ID Ransomware, Malwarebytes threat intelligence
    m_ransomwareExtensions = {
        // Generic encryption extensions
        QStringLiteral(".locked"),
        QStringLiteral(".encrypted"),
        QStringLiteral(".enc"),
        QStringLiteral(".crypt"),
        QStringLiteral(".crypto"),
        QStringLiteral(".crypted"),
        QStringLiteral(".cry"),
        QStringLiteral(".crinf"),
        QStringLiteral(".r5a"),
        QStringLiteral(".xrnt"),
        QStringLiteral(".xtbl"),
        QStringLiteral(".crypz"),
        QStringLiteral(".xxx"),
        QStringLiteral(".aaa"),
        QStringLiteral(".abc"),
        QStringLiteral(".xyz"),
        QStringLiteral(".zzz"),
        QStringLiteral(".micro"),
        QStringLiteral(".ecc"),
        QStringLiteral(".ezz"),
        QStringLiteral(".exx"),
        QStringLiteral(".bleep"),

        // Named ransomware families
        QStringLiteral(".wannacry"),
        QStringLiteral(".wncry"),
        QStringLiteral(".wcry"),
        QStringLiteral(".wncryt"),
        QStringLiteral(".locky"),
        QStringLiteral(".odin"),
        QStringLiteral(".zepto"),
        QStringLiteral(".osiris"),
        QStringLiteral(".aesir"),
        QStringLiteral(".thor"),
        QStringLiteral(".cerber"),
        QStringLiteral(".cerber2"),
        QStringLiteral(".cerber3"),
        QStringLiteral(".petya"),
        QStringLiteral(".notpetya"),
        QStringLiteral(".goldeneye"),
        QStringLiteral(".conti"),
        QStringLiteral(".ryuk"),
        QStringLiteral(".maze"),
        QStringLiteral(".lockbit"),
        QStringLiteral(".revil"),
        QStringLiteral(".sodinokibi"),
        QStringLiteral(".darkside"),
        QStringLiteral(".ragnar"),
        QStringLiteral(".avaddon"),
        QStringLiteral(".babuk"),
        QStringLiteral(".clop"),
        QStringLiteral(".egregor"),
        QStringLiteral(".netwalker"),
        QStringLiteral(".phobos"),
        QStringLiteral(".dharma"),
        QStringLiteral(".crysis"),
        QStringLiteral(".globe"),
        QStringLiteral(".teslacrypt"),

        // STOP/Djvu family (very common)
        QStringLiteral(".stop"),
        QStringLiteral(".djvu"),
        QStringLiteral(".djvuq"),
        QStringLiteral(".djvur"),
        QStringLiteral(".djvus"),
        QStringLiteral(".djvut"),
        QStringLiteral(".pdff"),
        QStringLiteral(".pdfn"),
        QStringLiteral(".desu"),
        QStringLiteral(".boot"),
        QStringLiteral(".nood"),
        QStringLiteral(".kook"),
        QStringLiteral(".gero"),
        QStringLiteral(".hese"),
        QStringLiteral(".seto"),
        QStringLiteral(".mado"),
        QStringLiteral(".jope"),
        QStringLiteral(".nppp"),
        QStringLiteral(".remk"),
        QStringLiteral(".lmas"),
        QStringLiteral(".boza"),
        QStringLiteral(".boty"),
        QStringLiteral(".kiop"),

        // Other families
        QStringLiteral(".vvv"),
        QStringLiteral(".ccc"),
        QStringLiteral(".rrr"),
        QStringLiteral(".ttt"),
        QStringLiteral(".wallet"),
        QStringLiteral(".arena"),
        // Note: .java removed - too many false positives for Java developers
        QStringLiteral(".onion"),
        QStringLiteral(".btc"),
        QStringLiteral(".nochance"),
        QStringLiteral(".paycrypt"),
        QStringLiteral(".serpent"),
        QStringLiteral(".venom"),
        QStringLiteral(".damage"),
        QStringLiteral(".fucked"),
        QStringLiteral(".rip"),
        QStringLiteral(".rdmk"),
        QStringLiteral(".helpme"),
    };

    // Ransom note patterns (case insensitive)
    m_ransomNotePatterns = {
        // README-style notes must carry a ransom keyword: README.txt alone is in every software project.
        QRegularExpression(QStringLiteral("^readme.*(decrypt|restore|recover|unlock|ransom|encrypt|crypt|payment|bitcoin).*\\.(txt|html|hta)$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^how[_\\-\\s]?to[_\\-\\s]?decrypt.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^how[_\\-\\s]?to[_\\-\\s]?restore.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^how[_\\-\\s]?to[_\\-\\s]?recover.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^decrypt[_\\-\\s]?instructions.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^restore[_\\-\\s]?files.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^your[_\\-\\s]?files.*(encrypt|lock|decrypt|restore|recover|stolen|hack).*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^files[_\\-\\s]?encrypted.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^ransom.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^_readme[_\\-]?\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^!readme!?\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^read[_\\-\\s]?me[_\\-\\s]?now.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^warning.*(encrypt|decrypt|restore|recover|ransom|read[_\\-\\s]?me|files).*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^decrypt[_\\-]?all.*\\.(txt|html)$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^unlock[_\\-]?instructions.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("@please_read_me@\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // WannaCry specific
        QRegularExpression(QStringLiteral("@wannacry@\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("@wanadecryptor@\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Locky specific
        QRegularExpression(QStringLiteral("_locky_recover.*\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // LockBit specific
        QRegularExpression(QStringLiteral("restore-my-files\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Conti specific
        QRegularExpression(QStringLiteral("readme\\.conti\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // HTA (HTML Application) ransom notes - used by some ransomware families
        QRegularExpression(QStringLiteral("^how[_\\-\\s]?to[_\\-\\s]?decrypt.*\\.hta$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^how[_\\-\\s]?to[_\\-\\s]?restore.*\\.hta$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^decrypt[_\\-]?instructions.*\\.hta$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^read[_\\-\\s]?me.*\\.hta$"), QRegularExpression::CaseInsensitiveOption),
        // Modern RaaS families (2022-2026). LockBit 3.0's "<ID>.README.txt" is
        // handled separately in isRansomNote() because the ID must look random.
        // BlackCat/ALPHV: RECOVER-<ext>-FILES.txt
        QRegularExpression(QStringLiteral("^recover-[a-z0-9_\\-]{4,16}-files\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Qilin/Agenda: README-RECOVER-<ext>.txt
        QRegularExpression(QStringLiteral("^readme-recover-[a-z0-9_\\-]{4,16}\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Akira
        QRegularExpression(QStringLiteral("^akira_readme\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Medusa
        QRegularExpression(QStringLiteral("^!!!read_me_medusa!!!\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // RansomHub ("How To Restore Your Files.txt" is also covered by the how-to-restore rule above)
        QRegularExpression(QStringLiteral("^how to restore your files\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Clop
        QRegularExpression(QStringLiteral("^clopreadme\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(QStringLiteral("^readme_c_i_0p\\.txt$"), QRegularExpression::CaseInsensitiveOption),
        // Royal / BlackSuit
        QRegularExpression(QStringLiteral("^readme\\.blacksuit\\.txt$"), QRegularExpression::CaseInsensitiveOption),
    };

    // LockBit 3.0 drops "<ID>.README.txt" where <ID> is the same random
    // 9-character string it uses as extension. The ID is validated with
    // looksLikeRandomExtension() so that "project.readme.txt" stays harmless.
    m_lockBitNotePattern = QRegularExpression(QStringLiteral("^([A-Za-z0-9]{6,16})\\.readme\\.txt$"),
                                              QRegularExpression::CaseInsensitiveOption);

    // Normal file extensions (for double extension detection)
    m_normalExtensions = {
        QStringLiteral(".pdf"),
        QStringLiteral(".doc"),
        QStringLiteral(".docx"),
        QStringLiteral(".xls"),
        QStringLiteral(".xlsx"),
        QStringLiteral(".ppt"),
        QStringLiteral(".pptx"),
        QStringLiteral(".jpg"),
        QStringLiteral(".jpeg"),
        QStringLiteral(".png"),
        QStringLiteral(".gif"),
        QStringLiteral(".bmp"),
        QStringLiteral(".mp3"),
        QStringLiteral(".mp4"),
        QStringLiteral(".avi"),
        QStringLiteral(".mov"),
        QStringLiteral(".txt"),
        QStringLiteral(".zip"),
        QStringLiteral(".rar"),
        QStringLiteral(".7z"),
        QStringLiteral(".csv"),
        QStringLiteral(".html"),
        QStringLiteral(".xml"),
        QStringLiteral(".json"),
        QStringLiteral(".sql"),
        QStringLiteral(".db"),
        QStringLiteral(".psd"),
        QStringLiteral(".ai"),
        QStringLiteral(".odt"),
        QStringLiteral(".ods"),
        QStringLiteral(".odp"),
        QStringLiteral(".webp"),
        QStringLiteral(".heic"),
        QStringLiteral(".heif"),
        QStringLiteral(".tif"),
        QStringLiteral(".tiff"),
        QStringLiteral(".svg"),
        QStringLiteral(".raw"),
        QStringLiteral(".cr2"),
        QStringLiteral(".nef"),
        QStringLiteral(".dng"),
        QStringLiteral(".mkv"),
        QStringLiteral(".webm"),
        QStringLiteral(".wmv"),
        QStringLiteral(".m4v"),
        QStringLiteral(".m4a"),
        QStringLiteral(".wav"),
        QStringLiteral(".flac"),
        QStringLiteral(".ogg"),
        QStringLiteral(".aac"),
        QStringLiteral(".pages"),
        QStringLiteral(".numbers"),
        QStringLiteral(".key"),
        QStringLiteral(".rtf"),
        QStringLiteral(".md"),
        QStringLiteral(".tex"),
        QStringLiteral(".epub"),
        QStringLiteral(".mobi"),
        QStringLiteral(".py"),
        QStringLiteral(".js"),
        QStringLiteral(".ts"),
        QStringLiteral(".cpp"),
        QStringLiteral(".h"),
        QStringLiteral(".c"),
        QStringLiteral(".java"),
        QStringLiteral(".cs"),
        QStringLiteral(".php"),
        QStringLiteral(".rb"),
        QStringLiteral(".go"),
        QStringLiteral(".rs"),
        QStringLiteral(".yaml"),
        QStringLiteral(".yml"),
        QStringLiteral(".ini"),
        QStringLiteral(".cfg"),
        QStringLiteral(".conf"),
        QStringLiteral(".log"),
        QStringLiteral(".tar"),
        QStringLiteral(".gz"),
        QStringLiteral(".bz2"),
        QStringLiteral(".xz"),
        QStringLiteral(".iso"),
        QStringLiteral(".dmg"),
        QStringLiteral(".exe"),
        QStringLiteral(".dll"),
        QStringLiteral(".sqlite"),
        QStringLiteral(".sqlite3"),
        QStringLiteral(".mdb"),
        QStringLiteral(".accdb"),
        QStringLiteral(".bak"),
        QStringLiteral(".vmdk"),
        QStringLiteral(".vdi"),
        QStringLiteral(".ova"),
        QStringLiteral(".pst"),
        QStringLiteral(".eml"),
        QStringLiteral(".msg"),
        QStringLiteral(".xlsm"),
        QStringLiteral(".docm"),
        QStringLiteral(".pptm"),
        QStringLiteral(".dwg"),
        QStringLiteral(".dxf"),
        QStringLiteral(".indd"),
        QStringLiteral(".eps"),
    };

    // Real-world extensions of 6+ characters that contain digits or mixed
    // case and would otherwise look like a random ransomware suffix. Purely
    // lowercase words never look random, so most are listed for clarity and
    // for safety against future rule changes. Compared lowercase.
    m_knownExtensionAllowlist = {
        QStringLiteral("sqlite3"), QStringLiteral("sqlite"), QStringLiteral("sqlite-journal"),
        QStringLiteral("sqlite-wal"), QStringLiteral("sqlite-shm"), QStringLiteral("db-journal"),
        QStringLiteral("db-wal"), QStringLiteral("db-shm"),
        QStringLiteral("torrent"), QStringLiteral("backup"), QStringLiteral("crdownload"),
        QStringLiteral("download"), QStringLiteral("opdownload"), QStringLiteral("partial"),
        QStringLiteral("numbers"), QStringLiteral("keynote"), QStringLiteral("sketch"),
        QStringLiteral("markdown"), QStringLiteral("config"), QStringLiteral("logfile"),
        QStringLiteral("mp4"), QStringLiteral("mpeg4"), QStringLiteral("m4v"), QStringLiteral("mkv"),
        QStringLiteral("flatpak"), QStringLiteral("flatpakref"), QStringLiteral("flatpakrepo"),
        QStringLiteral("appimage"), QStringLiteral("pkpass"), QStringLiteral("webarchive"),
        QStringLiteral("textclipping"), QStringLiteral("conflicted"), QStringLiteral("sync-conflict"),
        QStringLiteral("orig"), QStringLiteral("swp"), QStringLiteral("encrypted"),
        QStringLiteral("ds_store"), QStringLiteral("localized"),
        QStringLiteral("sha256"), QStringLiteral("sha512"), QStringLiteral("sha384"),
        QStringLiteral("sha256sum"), QStringLiteral("sha1sum"), QStringLiteral("md5sum"),
        QStringLiteral("base64"), QStringLiteral("x86_64"), QStringLiteral("aarch64"),
        QStringLiteral("amd64"), QStringLiteral("arm64"), QStringLiteral("onetoc2"),
        QStringLiteral("iso9660"), QStringLiteral("utf-8"), QStringLiteral("iso-8859-1"),
        QStringLiteral("mpeg2"), QStringLiteral("h264"), QStringLiteral("h265"), QStringLiteral("mp4v"),
        QStringLiteral("jpeg2000"), QStringLiteral("python3"), QStringLiteral("gtk3"), QStringLiteral("qt5"), QStringLiteral("qt6"),
        QStringLiteral("part01"), QStringLiteral("part02"), QStringLiteral("part03"),
        QStringLiteral("woff2"), QStringLiteral("webloc"), QStringLiteral("mobileconfig"),
        QStringLiteral("sublime-project"), QStringLiteral("sublime-workspace"), QStringLiteral("code-workspace"),
        QStringLiteral("xcodeproj"), QStringLiteral("xcworkspace"), QStringLiteral("xcarchive"),
        QStringLiteral("tsbuildinfo"), QStringLiteral("profraw"), QStringLiteral("profdata"),
        QStringLiteral("gresource"), QStringLiteral("desktop"), QStringLiteral("service"),
        QStringLiteral("properties"), QStringLiteral("gradle"), QStringLiteral("csproj"),
        QStringLiteral("vcxproj"), QStringLiteral("filters"), QStringLiteral("nuspec"),
        QStringLiteral("nupkg"), QStringLiteral("snupkg"), QStringLiteral("vsix"),
        QStringLiteral("rproj"), QStringLiteral("rdata"), QStringLiteral("rhistory"),
        QStringLiteral("blend1"), QStringLiteral("blend2"), QStringLiteral("max2023"),
        QStringLiteral("tax2022"), QStringLiteral("tax2023"), QStringLiteral("tax2024"),
        QStringLiteral("tax2025"), QStringLiteral("tax2026"),
    };

    qCInfo(lcPatternDetector) << "Initialized with"
                              << m_ransomwareExtensions.size() << "ransomware extensions,"
                              << m_ransomNotePatterns.size() << "ransom note patterns";
}

ThreatInfo PatternDetector::analyze(const SyncFileItem &item,
                                    const QVector<struct KillSwitchManager::Event> &recentEvents,
                                    const AnalysisContext &context)
{
    ThreatInfo threat;
    threat.level = ThreatLevel::None;
    threat.detectorName = name();

    if (!m_enabled) {
        return threat;
    }

    // Only check new, modified or renamed files
    if (item._instruction != CSYNC_INSTRUCTION_NEW &&
        item._instruction != CSYNC_INSTRUCTION_SYNC &&
        item._instruction != CSYNC_INSTRUCTION_RENAME) {
        return threat;
    }

    const bool isRename = item._instruction == CSYNC_INSTRUCTION_RENAME && !item._renameTarget.isEmpty();

    // For a rename the suspicious name is the target
    const QString relativePath = isRename ? item._renameTarget : item._file;
    const QString filePath = context.localPath(relativePath);
    const QString fileName = QFileInfo(relativePath).fileName();

    // Check for ransom note - CRITICAL threat (immediate trigger)
    if (isRansomNote(fileName)) {
        threat.level = ThreatLevel::Critical;
        threat.description = QStringLiteral("Ransom note detected: %1").arg(fileName);
        threat.affectedFiles.append(filePath);
        qCWarning(lcPatternDetector) << "CRITICAL: Ransom note detected:" << fileName;
        return threat;
    }

    // Check for ransomware extension
    const bool hasRansomExt = hasRansomwareExtension(filePath);
    const bool hasDoubleExt = hasDoubleExtension(fileName);
    bool hasRandomExt = hasRandomExtensionAfterNormal(fileName);
    QString randomExt;

    // A rename that only appends an extension to the original name is the
    // in-place encryption signature, whatever the original extension was:
    // "Makefile" -> "Makefile.HLJkNskOq", "data.sqlite3" -> "data.sqlite3.a7Fk3Qz".
    if (isRename && !hasRansomExt && !hasDoubleExt && !hasRandomExt) {
        randomExt = renameAppendedSuspiciousExtension(item._file, item._renameTarget);
        hasRandomExt = !randomExt.isEmpty();
    }

    if (!hasRansomExt && !hasDoubleExt && !hasRandomExt) {
        return threat; // No suspicious pattern
    }

    // Count suspicious files in the time window. The manager records the
    // current item's event before running the detectors, so it is normally
    // already in recentEvents; only add it when it is not (direct calls).
    int suspiciousCount = countSuspiciousFiles(recentEvents);
    const bool currentAlreadyRecorded = std::any_of(recentEvents.cbegin(), recentEvents.cend(),
        [&relativePath](const KillSwitchManager::Event &event) { return event.path == relativePath; });
    if (!currentAlreadyRecorded) {
        suspiciousCount++;
    }

    // Determine threat level based on count
    if (suspiciousCount >= m_threshold * 2) {
        threat.level = ThreatLevel::Critical;
        threat.description = QStringLiteral("Mass ransomware encryption detected: %1 suspicious files")
                                 .arg(suspiciousCount);
    } else if (suspiciousCount >= m_threshold) {
        threat.level = ThreatLevel::High;
        threat.description = QStringLiteral("Multiple ransomware patterns detected: %1 suspicious files")
                                 .arg(suspiciousCount);
    } else if (hasDoubleExt) {
        threat.level = ThreatLevel::High;  // Double extension is a strong ransomware indicator
        threat.description = QStringLiteral("Suspicious double extension: %1").arg(fileName);
    } else if (hasRandomExt) {
        // Random per-victim extension (LockBit 3/4, BlackCat, Qilin, ...): a
        // single hit is less certain than the fixed list, so Medium only.
        threat.level = ThreatLevel::Medium;
        threat.description = QStringLiteral("Random-looking ransomware extension: %1").arg(fileName);
    } else {
        threat.level = ThreatLevel::Low;
        threat.description = QStringLiteral("Suspicious ransomware extension: %1").arg(fileName);
    }

    // Corroboration: "X.ext.SUFFIX" appears while "X.ext" was just deleted.
    // Encrypt-to-new-file-then-delete-original is how most families work
    // when they do not rename in place, so escalate one level.
    if (threat.level < ThreatLevel::Critical && originalWasDeleted(relativePath, recentEvents)) {
        threat.level = static_cast<ThreatLevel>(static_cast<int>(threat.level) + 1);
        threat.description += QStringLiteral(" (original file deleted)");
        qCWarning(lcPatternDetector) << "Original of" << relativePath
                                     << "was deleted in the window - escalating";
    }

    threat.affectedFiles.append(filePath);

    qCInfo(lcPatternDetector) << "Pattern detected:" << threat.description
                              << "- Level:" << static_cast<int>(threat.level);

    return threat;
}

bool PatternDetector::hasRansomwareExtension(const QString &filePath) const
{
    const QString extension = QFileInfo(filePath).suffix().toLower();
    if (extension.isEmpty()) {
        return false;
    }
    return m_ransomwareExtensions.contains(QStringLiteral(".") + extension);
}

bool PatternDetector::isRansomNote(const QString &fileName) const
{
    for (const auto &pattern : m_ransomNotePatterns) {
        if (pattern.match(fileName).hasMatch()) {
            return true;
        }
    }

    // LockBit 3.0: "<random ID>.README.txt" (e.g. HLJkNskOq.README.txt)
    const auto lockBitMatch = m_lockBitNotePattern.match(fileName);
    if (lockBitMatch.hasMatch() && looksLikeRandomExtension(lockBitMatch.captured(1))) {
        return true;
    }

    return false;
}

bool PatternDetector::hasDoubleExtension(const QString &fileName) const
{
    // Look for pattern like "document.pdf.locked"
    // Split on dots and check if second-to-last is a normal extension
    // and last is a ransomware extension

    const QStringList parts = fileName.split(QLatin1Char('.'));
    if (parts.size() < 3) {
        return false; // Need at least name.ext1.ext2
    }

    const QString lastExt = QStringLiteral(".") + parts.last().toLower();
    const QString secondLastExt = QStringLiteral(".") + parts[parts.size() - 2].toLower();

    // Check if last extension is ransomware and second-to-last is normal
    return m_ransomwareExtensions.contains(lastExt) &&
           m_normalExtensions.contains(secondLastExt);
}

bool PatternDetector::looksLikeRandomExtension(const QString &ext) const
{
    if (ext.size() < 6 || ext.size() > 16) {
        return false;
    }

    int digits = 0;
    int lower = 0;
    int upper = 0;
    int upperAfterFirst = 0;
    for (int i = 0; i < ext.size(); ++i) {
        const QChar c = ext.at(i);
        if (c >= QLatin1Char('0') && c <= QLatin1Char('9')) {
            ++digits;
        } else if (c >= QLatin1Char('a') && c <= QLatin1Char('z')) {
            ++lower;
        } else if (c >= QLatin1Char('A') && c <= QLatin1Char('Z')) {
            ++upper;
            if (i > 0) {
                ++upperAfterFirst;
            }
        } else if (c != QLatin1Char('_') && c != QLatin1Char('-')) {
            return false; // Anything outside [A-Za-z0-9_-] is not a ransomware suffix
        }
    }

    // Random suffixes are alphanumeric soup: require at least two letters
    // (dates and version numbers like "2024-01-15" are never random).
    if (lower + upper < 2) {
        return false;
    }

    // Either digits are mixed in, or the case changes beyond a leading
    // capital. Pure lowercase (.backup), pure uppercase (.TORRENT) and
    // capitalised words (.Backup) are ordinary extensions.
    const bool mixedCase = lower > 0 && upperAfterFirst > 0;
    if (digits == 0 && !mixedCase) {
        return false;
    }

    const QString lowerExt = ext.toLower();
    if (m_knownExtensionAllowlist.contains(lowerExt)) {
        return false;
    }

    // Versioned real formats: a lowercase word followed by up to four digits
    // (sqlite3, sha256, tax2024, onetoc2, python3, aarch64)
    static const QRegularExpression versionedWord(QStringLiteral("^[a-z]{2,}[0-9]{1,4}$"));
    if (versionedWord.match(lowerExt).hasMatch()) {
        return false;
    }

    return true;
}

bool PatternDetector::hasRandomExtensionAfterNormal(const QString &fileName) const
{
    // Look for "invoice.pdf.HLJkNskOq": a normal extension followed by a
    // random per-victim suffix. Hidden files are skipped: rsync and friends
    // write ".invoice.pdf.Xk3f9A" temporaries with exactly this shape.
    if (fileName.startsWith(QLatin1Char('.'))) {
        return false;
    }

    const QStringList parts = fileName.split(QLatin1Char('.'));
    if (parts.size() < 3) {
        return false; // Need at least name.ext1.ext2
    }

    const QString secondLastExt = QStringLiteral(".") + parts[parts.size() - 2].toLower();
    return m_normalExtensions.contains(secondLastExt) && looksLikeRandomExtension(parts.last());
}

QString PatternDetector::renameAppendedSuspiciousExtension(const QString &from, const QString &to) const
{
    if (from.isEmpty() || !to.startsWith(from + QLatin1Char('.'))) {
        return QString();
    }

    const QString appended = to.mid(from.size() + 1);
    if (appended.isEmpty() || appended.contains(QLatin1Char('.')) || appended.contains(QLatin1Char('/'))) {
        return QString();
    }

    if (looksLikeRandomExtension(appended) ||
        m_ransomwareExtensions.contains(QStringLiteral(".") + appended.toLower())) {
        return appended;
    }
    return QString();
}

bool PatternDetector::originalWasDeleted(const QString &relativePath,
                                         const QVector<struct KillSwitchManager::Event> &recentEvents)
{
    // "Documents/invoice.pdf.HLJkNskOq" -> "Documents/invoice.pdf"
    const int lastDot = relativePath.lastIndexOf(QLatin1Char('.'));
    const int lastSlash = relativePath.lastIndexOf(QLatin1Char('/'));
    if (lastDot <= 0 || lastDot < lastSlash || lastDot == lastSlash + 1) {
        return false;
    }
    const QString original = relativePath.left(lastDot);
    if (QFileInfo(original).fileName().isEmpty()) {
        return false;
    }

    for (const auto &event : recentEvents) {
        if (event.type == QStringLiteral("DELETE") && event.path == original) {
            return true;
        }
    }
    return false;
}

bool PatternDetector::isSuspiciousPath(const QString &path) const
{
    const QString fileName = QFileInfo(path).fileName();
    return hasRansomwareExtension(path) ||
           hasDoubleExtension(fileName) ||
           hasRandomExtensionAfterNormal(fileName) ||
           isRansomNote(fileName);
}

int PatternDetector::countSuspiciousFiles(const QVector<struct KillSwitchManager::Event> &recentEvents) const
{
    int count = 0;
    for (const auto &event : recentEvents) {
        if (event.type == QStringLiteral("CREATE") ||
            event.type == QStringLiteral("MODIFY") ||
            event.type == QStringLiteral("RENAME")) {
            if (isSuspiciousPath(event.path)) {
                count++;
            }
        }
    }
    return count;
}

void PatternDetector::addCustomExtension(const QString &extension)
{
    QString ext = extension.toLower();
    if (!ext.startsWith(QLatin1Char('.'))) {
        ext.prepend(QLatin1Char('.'));
    }
    m_ransomwareExtensions.insert(ext);
    qCInfo(lcPatternDetector) << "Added custom extension:" << ext;
}

void PatternDetector::addCustomPattern(const QString &pattern)
{
    QRegularExpression regex(pattern, QRegularExpression::CaseInsensitiveOption);
    if (regex.isValid()) {
        m_ransomNotePatterns.append(regex);
        qCInfo(lcPatternDetector) << "Added custom pattern:" << pattern;
    } else {
        qCWarning(lcPatternDetector) << "Invalid regex pattern:" << pattern;
    }
}

} // namespace OCC

/*
 * Nextcloud Sentinel Edition - Alert Throttle
 *
 * SPDX-FileCopyrightText: 2026 Nextcloud Sentinel Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDateTime>

namespace OCC {

/**
 * @brief Lets at most one alert through per interval and counts the rest
 *
 * In Audit mode nothing stops the analysis after a would-be trigger, so a
 * burst of encrypted files produces one High finding per file. The tray shows
 * the first one, then at most one per interval with the number of findings
 * it held back; every finding is still logged by ThreatLogger.
 */
class AlertThrottle
{
public:
    explicit AlertThrottle(int intervalSeconds = 30)
        : m_intervalSeconds(intervalSeconds)
    {
    }

    /**
     * @brief Whether an alert may be shown at @p now; a refused alert is counted
     */
    bool allow(const QDateTime &now)
    {
        if (m_lastShown.isValid() && m_lastShown.secsTo(now) < m_intervalSeconds) {
            ++m_suppressed;
            return false;
        }
        m_lastShown = now;
        return true;
    }

    /**
     * @brief Number of alerts refused since the last call, then reset to zero
     */
    int takeSuppressed()
    {
        const int count = m_suppressed;
        m_suppressed = 0;
        return count;
    }

    int intervalSeconds() const { return m_intervalSeconds; }

private:
    int m_intervalSeconds;
    QDateTime m_lastShown;
    int m_suppressed = 0;
};

} // namespace OCC

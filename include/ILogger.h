/**
 * ILogger.h
 * Abstract interface for all logging back-ends (file-based, MongoDB, etc.).
 * Both FileLogger and MongoLogger inherit from this interface so the rest of
 * the system can log and query without knowing which back-end is active.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "Packet.h"
#include "enums.h"
#include <string>
#include <vector>

class ILogger {
public:
    virtual ~ILogger() = default;

    // Log a firewall decision (ALLOW / BLOCK / LOG_ONLY) for one packet.
    // matchedRuleID = -1 when no specific rule matched (default policy applied).
    virtual void logEvent(const Packet& p, Action action, int matchedRuleID = -1) = 0;

    // Log a detected threat (SYN-flood, port-scan, etc.) against a source IP.
    virtual void logThreat(const std::string& ip, ThreatType t) = 0;

    // ─── Query helpers ───────────────────────────────────────────────────────
    // Each returns matching log lines (CSV format for file, BSON→string for Mongo).

    virtual std::vector<std::string> queryByIP(const std::string& ip) = 0;
    virtual std::vector<std::string> queryByAction(const std::string& action) = 0;
    virtual std::vector<std::string> queryLastN(int minutes) = 0;
};

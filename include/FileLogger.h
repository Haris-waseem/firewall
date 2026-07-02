/**
 * FileLogger.h
 * Flat-file logging back-end implementing ILogger.
 * Handles CSV log writing/reading and rules.conf persistence for rules,
 * blacklist, and whitelist sections.
 *
 * CSV log format (10 fields):
 *   timestamp,packetID,sourceIP,destIP,destPort,protocol,direction,
 *   action,matchedRuleID,threatType
 *
 * RAII: the log ofstream is kept open for performance and closed in the
 * destructor (or on explicit close).
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "ILogger.h"
#include "Rule.h"
#include "LinkedList.h"
#include "Packet.h"
#include "enums.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>

class FileLogger : public ILogger {
public:
    // ─── Construction / Destruction ──────────────────────────────────────────
    explicit FileLogger(const std::string& logPath    = "firewall.log",
                        const std::string& configPath = "rules.conf");
    ~FileLogger() override;

    // ─── ILogger overrides ───────────────────────────────────────────────────
    void logEvent(const Packet& p, Action action, int matchedRuleID = -1) override;
    void logThreat(const std::string& ip, ThreatType t) override;

    // Packet-aware threat logging (uses real packet metadata)
    void logThreat(const Packet& p, ThreatType t);

    std::vector<std::string> queryByIP(const std::string& ip) override;
    std::vector<std::string> queryByAction(const std::string& action) override;
    std::vector<std::string> queryLastN(int minutes) override;

    // Read the last N lines from the log file (no time filtering)
    std::vector<std::string> readLastLines(int count);

    // Session-only log: entries added during this session (not from file)
    std::vector<std::string> getSessionLog() const;

    // ─── Rule persistence ────────────────────────────────────────────────────
    void saveRules(const std::vector<Rule>& rules, Action defaultPolicy);
    std::vector<Rule> loadRules(Action& outDefaultPolicy);

    // ─── Blacklist / Whitelist persistence ───────────────────────────────────
    void saveBlacklist(const std::vector<std::string>& ips);
    void saveWhitelist(const std::vector<std::string>& ips);
    std::vector<std::string> loadBlacklist();
    std::vector<std::string> loadWhitelist();

private:
    std::string  logFilePath_;       // default "firewall.log"
    std::string  configFilePath_;    // default "rules.conf"
    std::ofstream logStream_;        // kept open for append-mode writes
    std::vector<std::string> sessionLog_;  // current session log entries

    // ─── Internal helpers ────────────────────────────────────────────────────
    // Parses an ISO-8601 timestamp string into a time_t for comparison
    static std::time_t parseTimestamp(const std::string& ts);
};


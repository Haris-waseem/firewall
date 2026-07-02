/**
 * MongoLogger.h
 * MongoDB persistence layer implementing ILogger.
 *
 * Compile-time control:
 *   - #define USE_MONGODB   → real mongocxx driver integration
 *   - (default)             → stub methods that print a warning and
 *                             return empty results (graceful degradation)
 *
 * Collections used (when MongoDB is active):
 *   trafficlog  — firewall event entries
 *   threats     — detected threat entries
 *   rules       — firewall rule documents
 *   blacklist   — blocked IPs
 *   whitelist   — trusted IPs
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "MongoConfig.h"
#include "ILogger.h"
#include "Packet.h"
#include "Rule.h"
#include "enums.h"
#include <string>
#include <vector>

#ifdef USE_MONGODB
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/collection.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#endif

class MongoLogger : public ILogger {
public:
    // ─── Construction / Destruction ──────────────────────────────────────────
    explicit MongoLogger(const MongoConfig& cfg = MongoConfig{});
    ~MongoLogger() override;

    // ─── Connection management ───────────────────────────────────────────────
    bool connect(const std::string& uri);
    void disconnect();
    bool isConnected() const;

    // ─── ILogger overrides ───────────────────────────────────────────────────
    void logEvent(const Packet& p, Action action, int matchedRuleID = -1) override;
    void logThreat(const std::string& ip, ThreatType t) override;

    // Packet-aware threat logging (uses real packet metadata)
    void logThreat(const Packet& p, ThreatType t);

    std::vector<std::string> queryByIP(const std::string& ip) override;
    std::vector<std::string> queryByAction(const std::string& action) override;
    std::vector<std::string> queryLastN(int minutes) override;

    // ─── Rule CRUD ───────────────────────────────────────────────────────────
    void saveRule(const Rule& r);
    void deleteRule(int ruleID);
    std::vector<Rule> loadRules();

    // Bulk operations for config persistence
    void saveRules(const std::vector<Rule>& rules);
    void saveBlacklist(const std::vector<std::string>& ips);
    void saveWhitelist(const std::vector<std::string>& ips);

    // ─── Blacklist CRUD ──────────────────────────────────────────────────────
    void saveBlacklistEntry(const std::string& ip);
    void deleteBlacklistEntry(const std::string& ip);
    std::vector<std::string> loadBlacklist();

    // ─── Whitelist CRUD ──────────────────────────────────────────────────────
    void saveWhitelistEntry(const std::string& ip);
    void deleteWhitelistEntry(const std::string& ip);
    std::vector<std::string> loadWhitelist();

    // ─── Analytics ───────────────────────────────────────────────────────────
    // Aggregation pipeline: $match BLOCK → $group by sourceIP → $sort desc → $limit n
    std::vector<std::string> topNBlockedIPs(int n);

private:
    MongoConfig config_;
    bool        connected_ = false;

#ifdef USE_MONGODB
    // The mongocxx::instance must be created exactly once per process.
    // We use a static helper to guarantee single-init.
    static mongocxx::instance& driverInstance();

    mongocxx::client     client_;
    mongocxx::database   db_;
#endif
};

/**
 * MongoLogger.cpp
 * MongoDB persistence layer implementation.
 * Connects to local MongoDB at mongodb://localhost:27017
 */
#include "../include/MongoLogger.h"
#include <iostream>
#include <chrono>
#include <ctime>

#ifdef USE_MONGODB

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/exception/exception.hpp>
#include <mongocxx/pipeline.hpp>
#include <mongocxx/options/find.hpp>

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_document;
using bsoncxx::builder::stream::close_document;

// ─── Static driver instance (must exist exactly once) ────────────────────────
mongocxx::instance& MongoLogger::driverInstance() {
    static mongocxx::instance inst{};
    return inst;
}

// ─── Constructor ─────────────────────────────────────────────────────────────
MongoLogger::MongoLogger(const MongoConfig& cfg) : config_(cfg) {
    driverInstance(); // ensure instance created
    connect(config_.mongoURI.empty() ? "mongodb://localhost:27017" : config_.mongoURI);
}

// ─── Destructor ──────────────────────────────────────────────────────────────
MongoLogger::~MongoLogger() {
    disconnect();
}

// ─── Connect ─────────────────────────────────────────────────────────────────
bool MongoLogger::connect(const std::string& uri) {
    try {
        mongocxx::uri mongo_uri(uri);
        client_ = mongocxx::client(mongo_uri);
        db_ = client_["firewall_db"];
        connected_ = true;
        std::cout << "[MongoLogger] Connected to MongoDB at: " << uri << "\n";
        std::cout << "[MongoLogger] Database: firewall_db\n";
        return true;
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] Connection error: " << e.what() << "\n";
        connected_ = false;
        return false;
    }
}

// ─── Disconnect ──────────────────────────────────────────────────────────────
void MongoLogger::disconnect() {
    connected_ = false;
}

// ─── isConnected ─────────────────────────────────────────────────────────────
bool MongoLogger::isConnected() const {
    return connected_;
}

// ─── Helper: current timestamp string ────────────────────────────────────────
static std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return std::string(buf);
}

// ─── Log packet event ────────────────────────────────────────────────────────
void MongoLogger::logEvent(const Packet& p, Action action, int matchedRuleID) {
    if (!connected_) return;
    try {
        auto col = db_["trafficlog"];
        auto doc = document{}
            << "timestamp"     << p.timestamp        // use packet's real timestamp
            << "packetID"      << p.packetID
            << "sourceIP"      << p.sourceIP
            << "destinationIP" << p.destIP
            << "port"          << p.destPort
            << "protocol"      << static_cast<int>(p.protocol)
            << "direction"     << static_cast<int>(p.direction)
            << "action"        << (action == Action::ALLOW ? "ALLOW" : "BLOCK")
            << "matchedRuleID" << matchedRuleID
            << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] logEvent error: " << e.what() << "\n";
    }
}

// ─── Log threat ──────────────────────────────────────────────────────────────
void MongoLogger::logThreat(const std::string& ip, ThreatType t) {
    if (!connected_) return;
    try {
        auto col = db_["threats"];
        auto doc = document{}
            << "timestamp"  << currentTimestamp()
            << "sourceIP"   << ip
            << "threatType" << static_cast<int>(t)
            << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] logThreat error: " << e.what() << "\n";
    }
}

// ─── Log threat with full packet context ──────────────────────────────────────
void MongoLogger::logThreat(const Packet& p, ThreatType t) {
    if (!connected_) return;
    try {
        auto col = db_["threats"];
        auto doc = document{}
            << "timestamp"      << p.timestamp
            << "packetID"       << p.packetID
            << "sourceIP"       << p.sourceIP
            << "destinationIP"  << p.destIP
            << "port"           << p.destPort
            << "protocol"       << protocolToStr(p.protocol)
            << "direction"      << directionToStr(p.direction)
            << "threatType"     << static_cast<int>(t)
            << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] logThreat error: " << e.what() << "\n";
    }
}

// ─── Query by IP ─────────────────────────────────────────────────────────────
std::vector<std::string> MongoLogger::queryByIP(const std::string& ip) {
    std::vector<std::string> results;
    if (!connected_) return results;
    try {
        auto col = db_["trafficlog"];
        auto filter = document{} << "sourceIP" << ip << finalize;
        auto cursor = col.find(filter.view());
        for (auto& doc : cursor) {
            results.push_back(bsoncxx::to_json(doc));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] queryByIP error: " << e.what() << "\n";
    }
    return results;
}

// ─── Query by action ─────────────────────────────────────────────────────────
std::vector<std::string> MongoLogger::queryByAction(const std::string& action) {
    std::vector<std::string> results;
    if (!connected_) return results;
    try {
        auto col = db_["trafficlog"];
        auto filter = document{} << "action" << action << finalize;
        auto cursor = col.find(filter.view());
        for (auto& doc : cursor) {
            results.push_back(bsoncxx::to_json(doc));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] queryByAction error: " << e.what() << "\n";
    }
    return results;
}

// ─── Query last N minutes ─────────────────────────────────────────────────────
std::vector<std::string> MongoLogger::queryLastN(int minutes) {
    std::vector<std::string> results;
    if (!connected_) return results;
    try {
        auto col = db_["trafficlog"];

        // Compute cutoff timestamp (N minutes ago)
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - std::chrono::minutes(minutes);
        std::time_t cutoff_t = std::chrono::system_clock::to_time_t(cutoff);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&cutoff_t));
        std::string cutoffStr(buf);

        // Filter: timestamp >= cutoff
        auto filter = document{} << "timestamp" << open_document
            << "$gte" << cutoffStr
            << close_document << finalize;

        auto opts = mongocxx::options::find{};
        opts.sort(document{} << "timestamp" << -1 << finalize); // newest first

        auto cursor = col.find(filter.view(), opts);
        for (auto& doc : cursor) {
            results.push_back(bsoncxx::to_json(doc));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] queryLastN error: " << e.what() << "\n";
    }
    return results;
}

// ─── Save rule ───────────────────────────────────────────────────────────────
void MongoLogger::saveRule(const Rule& r) {
    if (!connected_) return;
    try {
        auto col = db_["rules"];
        auto doc = document{}
            << "ruleID"     << r.ruleID
            << "action"     << static_cast<int>(r.action)
            << "direction"  << static_cast<int>(r.direction)
            << "protocol"   << static_cast<int>(r.protocol)
            << "sourceIP"   << r.sourceIP
            << "port"       << r.destPort
            << "priority"   << r.priority
            << "description"<< r.description
            << "enabled"    << (r.enabled ? 1 : 0)
            << "hitCount"   << r.hitCount
            << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveRule error: " << e.what() << "\n";
    }
}

// ─── Delete rule ─────────────────────────────────────────────────────────────
void MongoLogger::deleteRule(int ruleID) {
    if (!connected_) return;
    try {
        auto col = db_["rules"];
        auto filter = document{} << "ruleID" << ruleID << finalize;
        col.delete_one(filter.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] deleteRule error: " << e.what() << "\n";
    }
}

// ─── Load rules ──────────────────────────────────────────────────────────────
std::vector<Rule> MongoLogger::loadRules() {
    std::vector<Rule> rules;
    if (!connected_) return rules;
    try {
        auto col = db_["rules"];
        auto cursor = col.find({});
        for (auto& doc : cursor) {
            Rule r;
            if (doc["ruleID"] && doc["ruleID"].type() == bsoncxx::type::k_int32)
                r.ruleID     = doc["ruleID"].get_int32().value;
            if (doc["priority"] && doc["priority"].type() == bsoncxx::type::k_int32)
                r.priority   = doc["priority"].get_int32().value;
            if (doc["sourceIP"] && doc["sourceIP"].type() == bsoncxx::type::k_string)
                r.sourceIP   = std::string(doc["sourceIP"].get_string().value);
            if (doc["port"] && doc["port"].type() == bsoncxx::type::k_int32)
                r.destPort   = doc["port"].get_int32().value;
            if (doc["protocol"] && doc["protocol"].type() == bsoncxx::type::k_int32)
                r.protocol   = static_cast<Protocol>(doc["protocol"].get_int32().value);
            if (doc["direction"] && doc["direction"].type() == bsoncxx::type::k_int32)
                r.direction  = static_cast<Direction>(doc["direction"].get_int32().value);
            if (doc["action"] && doc["action"].type() == bsoncxx::type::k_int32)
                r.action     = static_cast<Action>(doc["action"].get_int32().value);
            if (doc["description"] && doc["description"].type() == bsoncxx::type::k_string)
                r.description = std::string(doc["description"].get_string().value);
            if (doc["enabled"] && doc["enabled"].type() == bsoncxx::type::k_int32)
                r.enabled    = (doc["enabled"].get_int32().value != 0);
            if (doc["hitCount"] && doc["hitCount"].type() == bsoncxx::type::k_int32)
                r.hitCount   = doc["hitCount"].get_int32().value;
            rules.push_back(r);
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] loadRules error: " << e.what() << "\n";
    }
    return rules;
}

// ─── Blacklist CRUD ──────────────────────────────────────────────────────────
void MongoLogger::saveBlacklistEntry(const std::string& ip) {
    if (!connected_) return;
    try {
        auto col = db_["blacklist"];
        auto doc = document{} << "ip" << ip << "timestamp" << currentTimestamp() << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveBlacklistEntry error: " << e.what() << "\n";
    }
}

void MongoLogger::deleteBlacklistEntry(const std::string& ip) {
    if (!connected_) return;
    try {
        auto col = db_["blacklist"];
        auto filter = document{} << "ip" << ip << finalize;
        col.delete_one(filter.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] deleteBlacklistEntry error: " << e.what() << "\n";
    }
}

std::vector<std::string> MongoLogger::loadBlacklist() {
    std::vector<std::string> ips;
    if (!connected_) return ips;
    try {
        auto col = db_["blacklist"];
        auto cursor = col.find({});
        for (auto& doc : cursor) {
            if (doc["ip"] && doc["ip"].type() == bsoncxx::type::k_string)
                ips.push_back(std::string(doc["ip"].get_string().value));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] loadBlacklist error: " << e.what() << "\n";
    }
    return ips;
}

// ─── Whitelist CRUD ──────────────────────────────────────────────────────────
void MongoLogger::saveWhitelistEntry(const std::string& ip) {
    if (!connected_) return;
    try {
        auto col = db_["whitelist"];
        auto doc = document{} << "ip" << ip << "timestamp" << currentTimestamp() << finalize;
        col.insert_one(doc.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveWhitelistEntry error: " << e.what() << "\n";
    }
}

void MongoLogger::deleteWhitelistEntry(const std::string& ip) {
    if (!connected_) return;
    try {
        auto col = db_["whitelist"];
        auto filter = document{} << "ip" << ip << finalize;
        col.delete_one(filter.view());
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] deleteWhitelistEntry error: " << e.what() << "\n";
    }
}

std::vector<std::string> MongoLogger::loadWhitelist() {
    std::vector<std::string> ips;
    if (!connected_) return ips;
    try {
        auto col = db_["whitelist"];
        auto cursor = col.find({});
        for (auto& doc : cursor) {
            if (doc["ip"] && doc["ip"].type() == bsoncxx::type::k_string)
                ips.push_back(std::string(doc["ip"].get_string().value));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] loadWhitelist error: " << e.what() << "\n";
    }
    return ips;
}

// ─── Bulk save rules ─────────────────────────────────────────────────────────
void MongoLogger::saveRules(const std::vector<Rule>& rules) {
    if (!connected_) return;
    try {
        auto col = db_["rules"];
        // Clear existing rules
        col.delete_many({});
        // Insert each rule
        for (const auto& r : rules) {
            auto doc = document{}
                << "ruleID"     << r.ruleID
                << "action"     << static_cast<int>(r.action)
                << "direction"  << static_cast<int>(r.direction)
                << "protocol"   << static_cast<int>(r.protocol)
                << "sourceIP"   << r.sourceIP
                << "port"       << r.destPort
                << "priority"   << r.priority
                << "description"<< r.description
                << "enabled"    << (r.enabled ? 1 : 0)
                << "hitCount"   << r.hitCount
                << finalize;
            col.insert_one(doc.view());
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveRules error: " << e.what() << "\n";
    }
}

// ─── Bulk save blacklist ─────────────────────────────────────────────────────
void MongoLogger::saveBlacklist(const std::vector<std::string>& ips) {
    if (!connected_) return;
    try {
        auto col = db_["blacklist"];
        col.delete_many({});
        for (const auto& ip : ips) {
            auto doc = document{} << "ip" << ip << "timestamp" << currentTimestamp() << finalize;
            col.insert_one(doc.view());
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveBlacklist error: " << e.what() << "\n";
    }
}

// ─── Bulk save whitelist ─────────────────────────────────────────────────────
void MongoLogger::saveWhitelist(const std::vector<std::string>& ips) {
    if (!connected_) return;
    try {
        auto col = db_["whitelist"];
        col.delete_many({});
        for (const auto& ip : ips) {
            auto doc = document{} << "ip" << ip << "timestamp" << currentTimestamp() << finalize;
            col.insert_one(doc.view());
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] saveWhitelist error: " << e.what() << "\n";
    }
}

// ─── Top N blocked IPs (using aggregation pipeline) ──────────────────────────
std::vector<std::string> MongoLogger::topNBlockedIPs(int n) {
    std::vector<std::string> results;
    if (!connected_) return results;
    try {
        auto col = db_["trafficlog"];

        // Aggregation pipeline: $match BLOCK → $group by sourceIP → $sort desc → $limit n
        mongocxx::pipeline p{};
        p.match(document{} << "action" << "BLOCK" << finalize);
        p.group(document{} << "_id" << "$sourceIP"
                           << "count" << open_document << "$sum" << 1 << close_document << finalize);
        p.sort(document{} << "count" << -1 << finalize);
        p.limit(n);

        auto cursor = col.aggregate(p);
        for (auto& doc : cursor) {
            if (doc["_id"] && doc["_id"].type() == bsoncxx::type::k_string)
                results.push_back(std::string(doc["_id"].get_string().value));
        }
    } catch (const mongocxx::exception& e) {
        std::cerr << "[MongoLogger] topNBlockedIPs error: " << e.what() << "\n";
    }
    return results;
}

#else

// ─── GRACEFUL DEGRADATION STUBS (with real TCP connection test) ───────────────
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

static bool tcpConnect(const std::string& host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string portStr = std::to_string(port);
    addrinfo* result = nullptr;

    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0 || !result) {
        return false;
    }

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        return false;
    }

    // Set 3-second timeout
    DWORD timeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    bool ok = (connect(sock, result->ai_addr, (int)result->ai_addrlen) == 0);
    closesocket(sock);
    freeaddrinfo(result);
    return ok;
}

static std::pair<std::string,int> parseUri(const std::string& uri) {
    std::string host = "127.0.0.1";
    int port = 27017;
    // Extract host:port from mongodb://host:port
    auto pos = uri.find("://");
    if (pos != std::string::npos) {
        std::string rest = uri.substr(pos + 3);
        auto slash = rest.find('/');
        std::string hp = (slash != std::string::npos) ? rest.substr(0, slash) : rest;
        auto colon = hp.find(':');
        if (colon != std::string::npos) {
            host = hp.substr(0, colon);
            port = std::stoi(hp.substr(colon + 1));
        } else {
            host = hp;
        }
    }
    return {host, port};
}

MongoLogger::MongoLogger(const MongoConfig& cfg) : config_(cfg) {
    std::cout << "[MongoLogger] Stub mode — TCP connection test available.\n";
}
MongoLogger::~MongoLogger() = default;

bool MongoLogger::connect(const std::string& uri) {
    auto [host, port] = parseUri(uri);
    std::cout << "[MongoLogger] Testing connection to " << host << ":" << port << " ...\n";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[MongoLogger] WSAStartup failed\n";
        return false;
    }

    bool ok = tcpConnect(host, port);
    WSACleanup();

    if (ok) {
        connected_ = true;
        config_.mongoURI = uri;
        std::cout << "[MongoLogger] MongoDB reachable at " << host << ":" << port << "\n";
    } else {
        connected_ = false;
        std::cerr << "[MongoLogger] Cannot reach MongoDB at " << host << ":" << port << "\n";
    }
    return ok;
}

void MongoLogger::disconnect() { connected_ = false; }
bool MongoLogger::isConnected() const { return connected_; }
void MongoLogger::logEvent(const Packet& p, Action action, int matchedRuleID) {}
void MongoLogger::logThreat(const std::string& ip, ThreatType t) {}
void MongoLogger::logThreat(const Packet& p, ThreatType t) {}
std::vector<std::string> MongoLogger::queryByIP(const std::string& ip) { return {}; }
std::vector<std::string> MongoLogger::queryByAction(const std::string& action) { return {}; }
std::vector<std::string> MongoLogger::queryLastN(int minutes) { return {}; }
void MongoLogger::saveRule(const Rule& r) {}
void MongoLogger::deleteRule(int ruleID) {}
std::vector<Rule> MongoLogger::loadRules() { return {}; }
void MongoLogger::saveRules(const std::vector<Rule>&) {}
void MongoLogger::saveBlacklist(const std::vector<std::string>&) {}
void MongoLogger::saveWhitelist(const std::vector<std::string>&) {}
void MongoLogger::saveBlacklistEntry(const std::string& ip) {}
void MongoLogger::deleteBlacklistEntry(const std::string& ip) {}
std::vector<std::string> MongoLogger::loadBlacklist() { return {}; }
void MongoLogger::saveWhitelistEntry(const std::string& ip) {}
void MongoLogger::deleteWhitelistEntry(const std::string& ip) {}
std::vector<std::string> MongoLogger::loadWhitelist() { return {}; }
std::vector<std::string> MongoLogger::topNBlockedIPs(int n) { return {}; }

#endif

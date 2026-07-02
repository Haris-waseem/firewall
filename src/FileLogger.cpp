/**
 * FileLogger.cpp
 * Flat-file logging and persistence implementation.
 */
#include "../include/FileLogger.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include <cstdio>
#include <algorithm>

// ─── Constructor ─────────────────────────────────────────────────────────────
FileLogger::FileLogger(const std::string& logPath, const std::string& configPath)
    : logFilePath_(logPath), configFilePath_(configPath) {
    // Open log file in append mode. Keep it open for performance.
    logStream_.open(logFilePath_, std::ios::out | std::ios::app);
    if (!logStream_.is_open()) {
        std::cerr << "[FileLogger] Warning: Could not open log file " << logFilePath_ << " for writing.\n";
    }
}

// ─── Destructor ──────────────────────────────────────────────────────────────
FileLogger::~FileLogger() {
    if (logStream_.is_open()) {
        logStream_.close();
    }
}

// ─── logEvent() — Overrides ILogger ──────────────────────────────────────────
void FileLogger::logEvent(const Packet& p, Action action, int matchedRuleID) {
    std::string entry = p.timestamp + ","
                      + std::to_string(p.packetID) + ","
                      + p.sourceIP + ","
                      + p.destIP + ","
                      + std::to_string(p.destPort) + ","
                      + protocolToStr(p.protocol) + ","
                      + directionToStr(p.direction) + ","
                      + actionToStr(action) + ","
                      + std::to_string(matchedRuleID) + ","
                      + "NONE";
    if (logStream_.is_open()) {
        logStream_ << entry << "\n";
        logStream_.flush();
    }
    sessionLog_.push_back(entry);
    if (sessionLog_.size() > 200) sessionLog_.erase(sessionLog_.begin());
}

// ─── logThreat() — Overrides ILogger ──────────────────────────────────────────
void FileLogger::logThreat(const std::string& ip, ThreatType t) {
    std::string entry = Packet::currentTimestamp() + ","
                      + "-1,"
                      + ip + ","
                      + "*,"
                      + "0,"
                      + "TCP,"
                      + "INBOUND,"
                      + "BLOCK,"
                      + "-2,"
                      + threatToStr(t);
    if (logStream_.is_open()) {
        logStream_ << entry << "\n";
        logStream_.flush();
    }
    sessionLog_.push_back(entry);
    if (sessionLog_.size() > 200) sessionLog_.erase(sessionLog_.begin());
}

// ─── logThreat() — Packet-aware overload using real metadata ──────────────────
void FileLogger::logThreat(const Packet& p, ThreatType t) {
    std::string entry = p.timestamp + ","
                      + std::to_string(p.packetID) + ","
                      + p.sourceIP + ","
                      + p.destIP + ","
                      + std::to_string(p.destPort) + ","
                      + protocolToStr(p.protocol) + ","
                      + directionToStr(p.direction) + ","
                      + "BLOCK,"
                      + "-2,"
                      + threatToStr(t);
    if (logStream_.is_open()) {
        logStream_ << entry << "\n";
        logStream_.flush();
    }
    sessionLog_.push_back(entry);
    if (sessionLog_.size() > 200) sessionLog_.erase(sessionLog_.begin());
}

// Helper to parse ISO 8601 string to time_t
std::time_t FileLogger::parseTimestamp(const std::string& ts) {
    std::tm tm{};
    int yr = 0, mon = 0, day = 0, hr = 0, min = 0, sec = 0;
#ifdef _WIN32
    if (sscanf_s(ts.c_str(), "%d-%d-%dT%d:%d:%dZ", &yr, &mon, &day, &hr, &min, &sec) == 6) {
#else
    if (sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%dZ", &yr, &mon, &day, &hr, &min, &sec) == 6) {
#endif
        tm.tm_year = yr - 1900;
        tm.tm_mon = mon - 1;
        tm.tm_mday = day;
        tm.tm_hour = hr;
        tm.tm_min = min;
        tm.tm_sec = sec;
        return std::mktime(&tm);
    }
    return 0;
}


// ─── queryByIP() ─────────────────────────────────────────────────────────────
std::vector<std::string> FileLogger::queryByIP(const std::string& ip) {
    std::vector<std::string> results;
    std::ifstream infile(logFilePath_);
    if (!infile.is_open()) return results;

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string field;
        std::vector<std::string> fields;
        while (std::getline(ss, field, ',')) {
            fields.push_back(field);
        }
        // Field index 2 is sourceIP
        if (fields.size() > 2 && fields[2] == ip) {
            results.push_back(line);
        }
    }
    return results;
}

// ─── queryByAction() ─────────────────────────────────────────────────────────
std::vector<std::string> FileLogger::queryByAction(const std::string& action) {
    std::vector<std::string> results;
    std::ifstream infile(logFilePath_);
    if (!infile.is_open()) return results;

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string field;
        std::vector<std::string> fields;
        while (std::getline(ss, field, ',')) {
            fields.push_back(field);
        }
        // Field index 7 is action (ALLOW / BLOCK / LOG_ONLY)
        if (fields.size() > 7 && fields[7] == action) {
            results.push_back(line);
        }
    }
    return results;
}

// ─── queryLastN() ────────────────────────────────────────────────────────────
std::vector<std::string> FileLogger::queryLastN(int minutes) {
    std::vector<std::pair<std::time_t, std::string>> timedResults;
    std::ifstream infile(logFilePath_);
    if (!infile.is_open()) return {};

    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string timestampStr;
        std::getline(ss, timestampStr, ','); // Field index 0 is timestamp

        std::time_t log_time = parseTimestamp(timestampStr);
        if (log_time != 0) {
            double diffSec = std::difftime(now_time, log_time);
            if (diffSec >= 0 && diffSec <= (minutes * 60)) {
                timedResults.push_back({log_time, line});
            }
        }
    }

    // Sort by timestamp (newest first) for chronologically ordered results
    std::sort(timedResults.begin(), timedResults.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    std::vector<std::string> results;
    results.reserve(timedResults.size());
    for (auto& p : timedResults) {
        results.push_back(p.second);
    }
    return results;
}

std::vector<std::string> FileLogger::readLastLines(int count) {
    std::vector<std::string> allLines;
    std::ifstream infile(logFilePath_);
    if (!infile.is_open()) return {};

    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty()) allLines.push_back(line);
    }

    int n = (int)allLines.size();
    int start = (n > count) ? n - count : 0;
    return std::vector<std::string>(allLines.begin() + start, allLines.end());
}

std::vector<std::string> FileLogger::getSessionLog() const {
    return sessionLog_;
}

// ─── saveRules() ─────────────────────────────────────────────────────────────
void FileLogger::saveRules(const std::vector<Rule>& rules, Action defaultPolicy) {
    // Read existing file to preserve user comments and ordering
    std::vector<std::string> fileLines;
    std::vector<std::string> bl = loadBlacklist();
    std::vector<std::string> wl = loadWhitelist();

    std::ifstream infile(configFilePath_);
    if (infile.is_open()) {
        std::string line;
        while (std::getline(infile, line)) {
            fileLines.push_back(line);
        }
    }
    infile.close();

    // Extract preamble comments (lines before [RULES] that are comments or blank)
    std::vector<std::string> preamble;
    for (const auto& l : fileLines) {
        if (l == "[RULES]") break;
        if (l.empty() || l[0] == '#') {
            preamble.push_back(l);
        }
    }

    // Extract inter-section comments (between [RULES] and [BLACKLIST])
    std::vector<std::string> interSectionRB; // RULES->BLACKLIST
    bool inRules = false;
    for (const auto& l : fileLines) {
        if (l == "[RULES]") { inRules = true; continue; }
        if (l == "[BLACKLIST]") { inRules = false; break; }
        if (inRules && (l.empty() || l[0] == '#')) {
            interSectionRB.push_back(l);
        }
    }

    // Write everything back
    std::ofstream outfile(configFilePath_, std::ios::out | std::ios::trunc);
    if (!outfile.is_open()) {
        std::cerr << "[FileLogger] Error: Could not open rules.conf for writing rules.\n";
        return;
    }

    // Preserved preamble
    if (preamble.empty()) {
        outfile << "# Rules Configuration File\n# Automatically generated by Firewall System\n\n";
    } else {
        for (const auto& l : preamble) outfile << l << "\n";
    }

    outfile << "[RULES]\n";
    for (const auto& l : interSectionRB) outfile << l << "\n";
    for (const auto& r : rules) {
        outfile << r.toConfigLine() << "\n";
    }
    outfile << "DEFAULT_POLICY " << actionToStr(defaultPolicy) << "\n\n";

    outfile << "[BLACKLIST]\n";
    for (const auto& ip : bl) {
        outfile << ip << "\n";
    }
    outfile << "\n";

    outfile << "[WHITELIST]\n";
    for (const auto& ip : wl) {
        outfile << ip << "\n";
    }
    outfile << "\n";
}

// ─── loadRules() ─────────────────────────────────────────────────────────────
std::vector<Rule> FileLogger::loadRules(Action& outDefaultPolicy) {
    std::vector<Rule> rules;
    outDefaultPolicy = Action::BLOCK; // default
    std::ifstream infile(configFilePath_);
    if (!infile.is_open()) {
        return rules;
    }

    std::string line;
    std::string currentSection = "NONE";

    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        if (line[0] == '#') continue;

        // Trim leading/trailing spaces
        size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t");
        line = line.substr(first, last - first + 1);

        if (line == "[RULES]") {
            currentSection = "RULES";
            continue;
        } else if (line == "[BLACKLIST]") {
            currentSection = "BLACKLIST";
            continue;
        } else if (line == "[WHITELIST]") {
            currentSection = "WHITELIST";
            continue;
        }

        if (currentSection == "RULES") {
            if (line.rfind("DEFAULT_POLICY", 0) == 0) {
                std::istringstream ss(line);
                std::string key, val;
                ss >> key >> val;
                outDefaultPolicy = strToAction(val);
            } else {
                try {
                    Rule r = Rule::fromConfigLine(line);
                    rules.push_back(r);
                } catch (...) {
                    // Ignore malformed rule lines
                }
            }
        }
    }
    return rules;
}

// ─── saveBlacklist() ─────────────────────────────────────────────────────────
void FileLogger::saveBlacklist(const std::vector<std::string>& ips) {
    // Read current state
    Action dp;
    std::vector<Rule> rules = loadRules(dp);
    std::vector<std::string> wl = loadWhitelist();

    std::ofstream outfile(configFilePath_, std::ios::out | std::ios::trunc);
    if (!outfile.is_open()) return;

    outfile << "# Rules Configuration File\n# Automatically generated by Firewall System\n\n";
    outfile << "[RULES]\n";
    for (const auto& r : rules) {
        outfile << r.toConfigLine() << "\n";
    }
    outfile << "DEFAULT_POLICY " << actionToStr(dp) << "\n\n";

    outfile << "[BLACKLIST]\n";
    for (const auto& ip : ips) {
        outfile << ip << "\n";
    }
    outfile << "\n";

    outfile << "[WHITELIST]\n";
    for (const auto& ip : wl) {
        outfile << ip << "\n";
    }
    outfile << "\n";
}

// ─── saveWhitelist() ─────────────────────────────────────────────────────────
void FileLogger::saveWhitelist(const std::vector<std::string>& ips) {
    Action dp;
    std::vector<Rule> rules = loadRules(dp);
    std::vector<std::string> bl = loadBlacklist();

    std::ofstream outfile(configFilePath_, std::ios::out | std::ios::trunc);
    if (!outfile.is_open()) return;

    outfile << "# Rules Configuration File\n# Automatically generated by Firewall System\n\n";
    outfile << "[RULES]\n";
    for (const auto& r : rules) {
        outfile << r.toConfigLine() << "\n";
    }
    outfile << "DEFAULT_POLICY " << actionToStr(dp) << "\n\n";

    outfile << "[BLACKLIST]\n";
    for (const auto& ip : bl) {
        outfile << ip << "\n";
    }
    outfile << "\n";

    outfile << "[WHITELIST]\n";
    for (const auto& ip : ips) {
        outfile << ip << "\n";
    }
    outfile << "\n";
}

// ─── loadBlacklist() ─────────────────────────────────────────────────────────
std::vector<std::string> FileLogger::loadBlacklist() {
    std::vector<std::string> ips;
    std::ifstream infile(configFilePath_);
    if (!infile.is_open()) return ips;

    std::string line;
    std::string currentSection = "NONE";

    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        if (line[0] == '#') continue;

        // Trim
        size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t");
        line = line.substr(first, last - first + 1);

        if (line == "[RULES]") {
            currentSection = "RULES";
            continue;
        } else if (line == "[BLACKLIST]") {
            currentSection = "BLACKLIST";
            continue;
        } else if (line == "[WHITELIST]") {
            currentSection = "WHITELIST";
            continue;
        }

        if (currentSection == "BLACKLIST") {
            ips.push_back(line);
        }
    }
    return ips;
}

// ─── loadWhitelist() ─────────────────────────────────────────────────────────
std::vector<std::string> FileLogger::loadWhitelist() {
    std::vector<std::string> ips;
    std::ifstream infile(configFilePath_);
    if (!infile.is_open()) return ips;

    std::string line;
    std::string currentSection = "NONE";

    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        if (line[0] == '#') continue;

        // Trim
        size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t");
        line = line.substr(first, last - first + 1);

        if (line == "[RULES]") {
            currentSection = "RULES";
            continue;
        } else if (line == "[BLACKLIST]") {
            currentSection = "BLACKLIST";
            continue;
        } else if (line == "[WHITELIST]") {
            currentSection = "WHITELIST";
            continue;
        }

        if (currentSection == "WHITELIST") {
            ips.push_back(line);
        }
    }
    return ips;
}

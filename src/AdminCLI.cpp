/**
 * AdminCLI.cpp
 * Administrator REPL (Read-Eval-Print Loop) controller logic.
 */
#include "../include/AdminCLI.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

// ─── Constructor ─────────────────────────────────────────────────────────────
AdminCLI::AdminCLI(RuleEngine& e, PacketProcessor& p, FirewallStats& s,
                   FileLogger& l, MongoLogger& ml, Stack& h, TrafficMonitor& m)
    : engine_(e), processor_(p), stats_(s), logger_(l), mongoLogger_(ml), history_(h), monitor_(m), running_(true) {}

// ─── run() REPL Loop ─────────────────────────────────────────────────────────
void AdminCLI::run() {
    std::string line;
    while (running_) {
        std::cout << "firewall> ";
        if (!std::getline(std::cin, line)) {
            break; // EOF or stream error
        }
        // Trim
        if (!line.empty()) {
            size_t first = line.find_first_not_of(" \t");
            if (first != std::string::npos) {
                size_t last = line.find_last_not_of(" \t");
                line = line.substr(first, last - first + 1);
            }
        }
        dispatch(line);
    }
}

// ─── dispatch() ──────────────────────────────────────────────────────────────
void AdminCLI::dispatch(const std::string& input) {
    if (input.empty()) return;
    auto tokens = tokenize(input);
    if (tokens.empty()) return;
    std::string cmd = tokens[0];
    // Remove the command token from args list
    std::vector<std::string> args(tokens.begin() + 1, tokens.end());

    if (cmd == "add-rule") cmdAddRule(args);
    else if (cmd == "del-rule") cmdDelRule(args);
    else if (cmd == "update-rule") cmdUpdateRule(args);
    else if (cmd == "enable-rule") cmdEnableRule(args);
    else if (cmd == "disable-rule") cmdDisableRule(args);
    else if (cmd == "list-rules") cmdListRules();
    else if (cmd == "block-ip") cmdBlockIP(args);
    else if (cmd == "allow-ip") cmdAllowIP(args);
    else if (cmd == "remove-block") cmdRemoveBlock(args);
    else if (cmd == "remove-allow") cmdRemoveAllow(args);
    else if (cmd == "set-policy") cmdSetPolicy(args);
    else if (cmd == "show-stats") cmdShowStats();
    else if (cmd == "show-history") cmdShowHistory(args);
    else if (cmd == "query") cmdQuery(args);
    else if (cmd == "send-packet") cmdSendPacket(args);
    else if (cmd == "save") cmdSave();
    else if (cmd == "load") cmdLoad();
    else if (cmd == "flush-rules") cmdFlushRules();
    else if (cmd == "set-threshold") cmdSetThreshold(args);
    else if (cmd == "reset-threats") cmdResetThreats();
    else if (cmd == "help") cmdHelp(args);
    else if (cmd == "exit") cmdExit();
    else {
        std::cout << "Unknown command. Type 'help' for available commands.\n";
    }
}

// ─── validateIP() ────────────────────────────────────────────────────────────
bool AdminCLI::validateIP(const std::string& ip) {
    if (ip == "*") return true;
    std::istringstream ss(ip);
    std::string token;
    int parts = 0;
    while (std::getline(ss, token, '.')) {
        parts++;
        if (parts > 4) return false;
        try {
            int val = std::stoi(token);
            if (val < 0 || val > 255) return false;
        } catch (...) {
            return false;
        }
    }
    return parts == 4;
}

// ─── validatePort() ──────────────────────────────────────────────────────────
bool AdminCLI::validatePort(const std::string& portStr) {
    if (portStr == "-1" || portStr == "*") return true;
    try {
        int val = std::stoi(portStr);
        return val >= 0 && val <= 65535;
    } catch (...) {
        return false;
    }
}


// ─── cmdAddRule() ────────────────────────────────────────────────────────────
// Format: add-rule <action> <dir> <proto> <ip> <port> [priority] [desc]
void AdminCLI::cmdAddRule(const std::vector<std::string>& args) {
    if (args.size() < 5) {
        std::cout << "Error: Invalid arguments. Format:\n"
                  << "  add-rule <action> <dir> <proto> <ip> <port> [priority] [desc]\n";
        return;
    }

    try {
        Rule r;
        r.action = strToAction(args[0]);
        r.direction = strToDirection(args[1]);
        r.protocol = strToProtocol(args[2]);

        std::string ip = args[3];
        if (!validateIP(ip)) {
            std::cout << "Error: Invalid IP format: " << ip << "\n";
            return;
        }
        r.sourceIP = ip;

        std::string portStr = args[4];
        if (!validatePort(portStr)) {
            std::cout << "Error: Invalid port: " << portStr << "\n";
            return;
        }
        r.destPort = (portStr == "*" || portStr == "-1") ? -1 : std::stoi(portStr);

        if (args.size() > 5) {
            try {
                r.priority = std::stoi(args[5]);
            } catch (...) {
                r.priority = 100;
            }
        }

        if (args.size() > 6) {
            std::string desc = "";
            for (size_t i = 6; i < args.size(); i++) {
                desc += args[i] + (i == args.size() - 1 ? "" : " ");
            }
            r.description = desc;
        } else {
            r.description = "Admin rule";
        }

        r.enabled = true;
        r.hitCount = 0;

        int assignedID = engine_.addRule(r);
        if (assignedID > 0) {
            std::cout << "Rule added successfully with ID: " << assignedID << "\n";
        } else {
            std::cout << "Error: Duplicate rule ID or rule could not be added.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error adding rule: " << e.what() << "\n";
    }
}

// ─── cmdDelRule() ────────────────────────────────────────────────────────────
void AdminCLI::cmdDelRule(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: del-rule requires <ruleID> argument.\n";
        return;
    }
    try {
        int id = std::stoi(args[0]);
        if (engine_.removeRule(id)) {
            std::cout << "Rule " << id << " deleted successfully.\n";
        } else {
            std::cout << "Rule " << id << " not found.\n";
        }
    } catch (...) {
        std::cout << "Error: Invalid rule ID format.\n";
    }
}

// ─── cmdUpdateRule() ─────────────────────────────────────────────────────────
void AdminCLI::cmdUpdateRule(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Error: update-rule requires <ruleID> <action>.\n";
        return;
    }
    try {
        int id = std::stoi(args[0]);
        Action a = strToAction(args[1]);
        if (engine_.updateRule(id, a)) {
            std::cout << "Rule " << id << " action updated to " << actionToStr(a) << ".\n";
        } else {
            std::cout << "Rule " << id << " not found.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error updating rule: " << e.what() << "\n";
    }
}

// ─── cmdEnableRule() ─────────────────────────────────────────────────────────
void AdminCLI::cmdEnableRule(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: enable-rule requires <ruleID>.\n";
        return;
    }
    try {
        int id = std::stoi(args[0]);
        if (engine_.enableRule(id)) {
            std::cout << "Rule " << id << " enabled.\n";
        } else {
            std::cout << "Rule " << id << " not found.\n";
        }
    } catch (...) {
        std::cout << "Error: Invalid rule ID format.\n";
    }
}

// ─── cmdDisableRule() ────────────────────────────────────────────────────────
void AdminCLI::cmdDisableRule(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: disable-rule requires <ruleID>.\n";
        return;
    }
    try {
        int id = std::stoi(args[0]);
        if (engine_.disableRule(id)) {
            std::cout << "Rule " << id << " disabled.\n";
        } else {
            std::cout << "Rule " << id << " not found.\n";
        }
    } catch (...) {
        std::cout << "Error: Invalid rule ID format.\n";
    }
}

// ─── cmdListRules() ──────────────────────────────────────────────────────────
void AdminCLI::cmdListRules() {
    engine_.listRules();
}

// ─── cmdBlockIP() ────────────────────────────────────────────────────────────
void AdminCLI::cmdBlockIP(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: block-ip requires <ip>.\n";
        return;
    }
    std::string ip = args[0];
    if (!validateIP(ip)) {
        std::cout << "Error: Invalid IP format.\n";
        return;
    }
    engine_.addToBlacklist(ip);
    std::cout << "IP " << ip << " blacklisted successfully.\n";
}

// ─── cmdAllowIP() ────────────────────────────────────────────────────────────
void AdminCLI::cmdAllowIP(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: allow-ip requires <ip>.\n";
        return;
    }
    std::string ip = args[0];
    if (!validateIP(ip)) {
        std::cout << "Error: Invalid IP format.\n";
        return;
    }
    engine_.addToWhitelist(ip);
    std::cout << "IP " << ip << " whitelisted successfully.\n";
}

// ─── cmdRemoveBlock() ────────────────────────────────────────────────────────
void AdminCLI::cmdRemoveBlock(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: remove-block requires <ip>.\n";
        return;
    }
    std::string ip = args[0];
    engine_.removeFromBlacklist(ip);
    std::cout << "IP " << ip << " removed from blacklist.\n";
}

// ─── cmdRemoveAllow() ────────────────────────────────────────────────────────
void AdminCLI::cmdRemoveAllow(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: remove-allow requires <ip>.\n";
        return;
    }
    std::string ip = args[0];
    engine_.removeFromWhitelist(ip);
    std::cout << "IP " << ip << " removed from whitelist.\n";
}

// ─── cmdSetPolicy() ──────────────────────────────────────────────────────────
void AdminCLI::cmdSetPolicy(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Error: set-policy requires <ALLOW|BLOCK>.\n";
        return;
    }
    try {
        Action a = strToAction(args[0]);
        if (a == Action::LOG_ONLY) {
            std::cout << "Error: LOG_ONLY cannot be a default policy.\n";
            return;
        }
        engine_.setDefaultPolicy(a);
        std::cout << "Default policy set to " << actionToStr(a) << ".\n";
    } catch (...) {
        std::cout << "Error: Invalid action. Choose ALLOW or BLOCK.\n";
    }
}

// ─── cmdShowStats() ──────────────────────────────────────────────────────────
void AdminCLI::cmdShowStats() {
    stats_.print();
    // Also display fast-lookup size tables
    std::cout << "  Active Blacklist Size: " << engine_.getBlacklistSize() << "\n";
    std::cout << "  Active Whitelist Size: " << engine_.getWhitelistSize() << "\n\n";
}

// ─── cmdShowHistory() ────────────────────────────────────────────────────────
void AdminCLI::cmdShowHistory(const std::vector<std::string>& args) {
    int n = 10;
    if (!args.empty()) {
        try {
            n = std::stoi(args[0]);
        } catch (...) {
            n = 10;
        }
    }
    std::cout << "\n================= ARCHIVED PACKET HISTORY (LIFO) =================\n";
    history_.printTop(n);
    std::cout << "==================================================================\n\n";
}

// ─── cmdQuery() ──────────────────────────────────────────────────────────────
void AdminCLI::cmdQuery(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Error: query requires options:\n"
                  << "  query --ip <ip>\n"
                  << "  query --action <action>\n"
                  << "  query --last <minutes>\n";
        return;
    }

    std::string opt = args[0];
    std::string val = args[1];
    std::vector<std::string> results;

    if (opt == "--ip") {
        results = logger_.queryByIP(val);
    } else if (opt == "--action") {
        results = logger_.queryByAction(val);
    } else if (opt == "--last") {
        try {
            int mins = std::stoi(val);
            results = logger_.queryLastN(mins);
        } catch (...) {
            std::cout << "Error: Last time must be an integer (minutes).\n";
            return;
        }
    } else {
        std::cout << "Error: Unknown query option: " << opt << "\n";
        return;
    }

    std::cout << "\n====================== LOG QUERY RESULTS ======================\n";
    if (results.empty()) {
        std::cout << "  No matching records found.\n";
    } else {
        for (const auto& logLine : results) {
            std::cout << "  " << logLine << "\n";
        }
        std::cout << "  Total Records Found: " << results.size() << "\n";
    }
    std::cout << "===============================================================\n\n";
}

// ─── cmdSendPacket() ─────────────────────────────────────────────────────────
void AdminCLI::cmdSendPacket(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "Error: send-packet requires <srcIP> <destPort> <protocol> [dir] [isSYN]\n";
        return;
    }

    std::string ip = args[0];
    if (!validateIP(ip)) {
        std::cout << "Error: Invalid IP format.\n";
        return;
    }

    int port = 0;
    try {
        port = std::stoi(args[1]);
    } catch (...) {
        std::cout << "Error: Invalid port number.\n";
        return;
    }

    Protocol proto;
    try {
        proto = strToProtocol(args[2]);
    } catch (...) {
        std::cout << "Error: Invalid protocol.\n";
        return;
    }

    Direction dir = Direction::INBOUND;
    if (args.size() > 3) {
        try {
            dir = strToDirection(args[3]);
        } catch (...) {}
    }

    bool isSYN = false;
    if (args.size() > 4) {
        isSYN = (args[4] == "true" || args[4] == "1" || args[4] == "SYN");
    }

    Packet p = simulator_.createPacket(ip, "10.0.0.1", port, proto, dir, isSYN, 512);
    std::cout << "Injecting: " << p.toString() << "\n";
    processor_.process(p);
}

// ─── cmdSave() ───────────────────────────────────────────────────────────────
void AdminCLI::cmdSave() {
    // Save to MongoDB (primary)
    mongoLogger_.saveRules(engine_.getAllRules());
    mongoLogger_.saveBlacklist(engine_.getBlacklistIPs());
    mongoLogger_.saveWhitelist(engine_.getWhitelistIPs());
    std::cout << "State saved to MongoDB.\n";

    // Also save to file as backup
    logger_.saveRules(engine_.getAllRules(), engine_.getDefaultPolicy());
    logger_.saveBlacklist(engine_.getBlacklistIPs());
    logger_.saveWhitelist(engine_.getWhitelistIPs());
    std::cout << "Backup saved to rules.conf.\n";
}

// ─── cmdLoad() ───────────────────────────────────────────────────────────────
void AdminCLI::cmdLoad() {
    try {
        bool loaded = false;

        // Try MongoDB first
        if (mongoLogger_.isConnected()) {
            auto mongoRules = mongoLogger_.loadRules();
            if (!mongoRules.empty()) {
                engine_.clearAll();
                for (const auto& r : mongoRules) engine_.addRule(r);
                engine_.setDefaultPolicy(Action::BLOCK);

                auto bl = mongoLogger_.loadBlacklist();
                for (const auto& ip : bl) engine_.addToBlacklist(ip);

                auto wl = mongoLogger_.loadWhitelist();
                for (const auto& ip : wl) engine_.addToWhitelist(ip);

                std::cout << "Successfully loaded configuration from MongoDB.\n";
                std::cout << "  Rules count    : " << engine_.getRuleCount() << "\n";
                std::cout << "  Blacklist size : " << engine_.getBlacklistSize() << "\n";
                std::cout << "  Whitelist size : " << engine_.getWhitelistSize() << "\n";
                loaded = true;
            }
        }

        // Fall back to file-based config
        if (!loaded) {
            Action dp;
            auto rules = logger_.loadRules(dp);
            engine_.clearAll();

            for (const auto& r : rules) {
                engine_.addRule(r);
            }
            engine_.setDefaultPolicy(dp);

            auto bl = logger_.loadBlacklist();
            for (const auto& ip : bl) {
                engine_.addToBlacklist(ip);
            }

            auto wl = logger_.loadWhitelist();
            for (const auto& ip : wl) {
                engine_.addToWhitelist(ip);
            }

            std::cout << "Successfully loaded configuration from rules.conf.\n";
            std::cout << "  Rules count    : " << engine_.getRuleCount() << "\n";
            std::cout << "  Blacklist size : " << engine_.getBlacklistSize() << "\n";
            std::cout << "  Whitelist size : " << engine_.getWhitelistSize() << "\n";
            std::cout << "  Default Policy : " << actionToStr(dp) << "\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error loading rules: " << e.what() << "\n";
    }
}

// ─── cmdFlushRules() ─────────────────────────────────────────────────────────
void AdminCLI::cmdFlushRules() {
    engine_.clearAll();
    std::cout << "Firewall flush complete: Rules, Whitelist, and Blacklist cleared.\n";
}

// ─── cmdSetThreshold() ───────────────────────────────────────────────────────
void AdminCLI::cmdSetThreshold(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Error: set-threshold requires <syn|portscan|window> <value>.\n";
        return;
    }
    std::string type = args[0];
    try {
        int val = std::stoi(args[1]);
        if (type == "syn") {
            monitor_.setSynThreshold(val);
            std::cout << "SYN Flood detection threshold set to " << val << " packets.\n";
        } else if (type == "portscan") {
            monitor_.setPortScanThreshold(val);
            std::cout << "Port Scan detection threshold set to " << val << " distinct ports.\n";
        } else if (type == "window") {
            monitor_.setWindowSeconds(val);
            std::cout << "Threat detection window set to " << val << " seconds.\n";
        } else {
            std::cout << "Error: Unknown threshold type: " << type << "\n";
        }
    } catch (...) {
        std::cout << "Error: Threshold value must be an integer.\n";
    }
}

// ─── cmdResetThreats() ───────────────────────────────────────────────────────
void AdminCLI::cmdResetThreats() {
    monitor_.resetWindow();
    std::cout << "Threat detection active monitoring window reset.\n";
}

// ─── cmdHelp() ───────────────────────────────────────────────────────────────
void AdminCLI::cmdHelp(const std::vector<std::string>& args) {
    std::cout << "\n=================== FIREWALL ADMIN HELP ===================\n";
    std::cout << "Category: Rule Management\n";
    std::cout << "  add-rule <action> <dir> <proto> <ip> <port> [priority] [desc]\n";
    std::cout << "         -> adds a new packet-filtering rule\n";
    std::cout << "         -> action: ALLOW, BLOCK, LOG_ONLY\n";
    std::cout << "         -> dir: INBOUND, OUTBOUND, BOTH\n";
    std::cout << "         -> proto: TCP, UDP, ICMP, ANY\n";
    std::cout << "         -> ip: standard IP (e.g. 192.168.1.5) or * for any\n";
    std::cout << "         -> port: port number (e.g. 80) or -1 for any\n";
    std::cout << "  del-rule <ruleID>           -> deletes rule by its ID\n";
    std::cout << "  update-rule <ruleID> <action> -> updates rule action\n";
    std::cout << "  enable-rule <ruleID>        -> enables a disabled rule\n";
    std::cout << "  disable-rule <ruleID>       -> disables an active rule\n";
    std::cout << "  list-rules                  -> shows all rules sorted by priority\n";
    std::cout << "  flush-rules                 -> deletes all rules, whitelist, blacklist\n";
    std::cout << "\nCategory: IP Whitelist/Blacklist\n";
    std::cout << "  block-ip <ip>               -> adds an IP to the fast O(1) blacklist\n";
    std::cout << "  allow-ip <ip>               -> adds an IP to the fast O(1) whitelist\n";
    std::cout << "  remove-block <ip>           -> removes an IP from blacklist\n";
    std::cout << "  remove-allow <ip>           -> removes an IP from whitelist\n";
    std::cout << "  set-policy <ALLOW|BLOCK>    -> changes default policy\n";
    std::cout << "\nCategory: Monitoring & Logs\n";
    std::cout << "  show-stats                  -> displays active runtime stat counters\n";
    std::cout << "  show-history [n]            -> shows top LIFO packet history (default 10)\n";
    std::cout << "  query --ip <ip>             -> queries logs matching source IP\n";
    std::cout << "  query --action <action>     -> queries logs matching action (ALLOW/BLOCK)\n";
    std::cout << "  query --last <minutes>      -> queries logs in last N minutes\n";
    std::cout << "  set-threshold syn|portscan|window <value>\n";
    std::cout << "                              -> configures threat thresholds\n";
    std::cout << "  reset-threats               -> resets detection counters window\n";
    std::cout << "\nCategory: Simulators & Config\n";
    std::cout << "  send-packet <srcIP> <port> <proto> [dir] [isSYN]\n";
    std::cout << "                              -> injects a test packet\n";
    std::cout << "  save                        -> writes rule config state to rules.conf\n";
    std::cout << "  load                        -> reads rule config state from rules.conf\n";
    std::cout << "  exit                        -> saves rules & exits CLI\n";
    std::cout << "============================================================\n\n";
}

// ─── cmdExit() ───────────────────────────────────────────────────────────────
void AdminCLI::cmdExit() {
    cmdSave();
    running_ = false;
}


// ─── Tokenize Helper ─────────────────────────────────────────────────────────
std::vector<std::string> AdminCLI::tokenize(const std::string& input) {
    std::vector<std::string> tokens;
    std::istringstream iss(input);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

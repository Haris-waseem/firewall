/**
 * AdminCLI.h
 * Administrator command-line interface (CLI) representing the controller in MVC.
 * Dispatches commands for managing rules, whitelists, blacklists, checking stats,
 * searching logs, and injecting simulated network traffic.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "RuleEngine.h"
#include "PacketProcessor.h"
#include "FirewallStats.h"
#include "FileLogger.h"
#include "MongoLogger.h"
#include "Stack.h"
#include "TrafficMonitor.h"
#include "PacketSimulator.h"
#include <string>
#include <vector>

class AdminCLI {
public:
    AdminCLI(RuleEngine& e, PacketProcessor& p, FirewallStats& s,
             FileLogger& l, MongoLogger& ml, Stack& h, TrafficMonitor& m);
    ~AdminCLI() = default;

    // Starts the read-eval-print loop (REPL). Blocks until 'exit' is entered.
    void run();

    // Command parser & dispatcher
    void dispatch(const std::string& input);

private:
    RuleEngine&     engine_;
    PacketProcessor& processor_;
    FirewallStats&  stats_;
    FileLogger&     logger_;
    MongoLogger&    mongoLogger_;
    Stack&          history_;
    TrafficMonitor& monitor_;
    PacketSimulator simulator_;
    bool            running_ = true;

    // ─── Command Handlers ────────────────────────────────────────────────────
    void cmdAddRule(const std::vector<std::string>& args);
    void cmdDelRule(const std::vector<std::string>& args);
    void cmdUpdateRule(const std::vector<std::string>& args);
    void cmdEnableRule(const std::vector<std::string>& args);
    void cmdDisableRule(const std::vector<std::string>& args);
    void cmdListRules();
    void cmdBlockIP(const std::vector<std::string>& args);
    void cmdAllowIP(const std::vector<std::string>& args);
    void cmdRemoveBlock(const std::vector<std::string>& args);
    void cmdRemoveAllow(const std::vector<std::string>& args);
    void cmdSetPolicy(const std::vector<std::string>& args);
    void cmdShowStats();
    void cmdShowHistory(const std::vector<std::string>& args);
    void cmdQuery(const std::vector<std::string>& args);
    void cmdSendPacket(const std::vector<std::string>& args);
    void cmdSave();
    void cmdLoad();
    void cmdFlushRules();
    void cmdSetThreshold(const std::vector<std::string>& args);
    void cmdResetThreats();
    void cmdHelp(const std::vector<std::string>& args);
    void cmdExit();

    // ─── Static Helpers ──────────────────────────────────────────────────────
    static bool validateIP(const std::string& ip);
    static bool validatePort(const std::string& portStr);
    static std::vector<std::string> tokenize(const std::string& input);
};

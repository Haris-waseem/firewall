/**
 * RuleEngine.h
 * Coordinates all packet-filtering rules, the IP blacklist, and the IP whitelist.
 * Owns three custom data structures to perform lookups:
 *   - LinkedList : Stores rules ordered by insertion/ID for management operations.
 *   - BST        : Binary Search Tree keyed on priority for fast O(log n) packet evaluations.
 *   - HashMaps   : Whitelist and Blacklist IP tables for O(1) checks.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "LinkedList.h"
#include "BST.h"
#include "HashMap.h"
#include "Packet.h"
#include "Rule.h"
#include "enums.h"
#include <string>
#include <vector>

class RuleEngine {
public:
    RuleEngine();
    ~RuleEngine() = default;

    // Evaluates a packet against the whitelist, blacklist, rules tree, and default policy.
    // Sets matchedRuleID:
    //   -1 if whitelisted
    //   -2 if blacklisted
    //   -3 if default policy applied
    //   ruleID of the matched rule otherwise
    Action evaluate(const Packet& p, int& matchedRuleID);

    // ─── Rule Management ─────────────────────────────────────────────────────
    // Returns assigned ruleID (>0) on success, 0 on failure (e.g. duplicate ID)
    int addRule(Rule r);
    bool removeRule(int ruleID);
    bool updateRule(int ruleID, Action newAction);
    bool updateRule(int ruleID, Action newAction, int newPriority,
                    Direction newDir, Protocol newProto,
                    const std::string& newSrcIP, int newDestPort);
    bool enableRule(int ruleID);
    bool disableRule(int ruleID);
    void listRules() const;
    std::string listRulesToString() const;

    // ─── Blacklist / Whitelist Management ────────────────────────────────────
    void addToBlacklist(const std::string& ip);
    void addToWhitelist(const std::string& ip);
    void removeFromBlacklist(const std::string& ip);
    void removeFromWhitelist(const std::string& ip);
    bool isBlacklisted(const std::string& ip) const;
    bool isWhitelisted(const std::string& ip) const;

    // ─── Getters / Setters ───────────────────────────────────────────────────
    void setDefaultPolicy(Action p) { defaultPolicy_ = p; }
    Action getDefaultPolicy() const { return defaultPolicy_; }

    int getRuleCount() const { return ruleList_.getSize(); }
    int getBlacklistSize() const { return blacklist_.size(); }
    int getWhitelistSize() const { return whitelist_.size(); }

    std::vector<std::string> getBlacklistIPs() const { return blacklist_.keys(); }
    std::vector<std::string> getWhitelistIPs() const { return whitelist_.keys(); }
    std::vector<Rule> getAllRules() const { return ruleList_.toVector(); }

    void clearAll();

private:
    LinkedList ruleList_;
    BST        ruleBST_;
    HashMap    blacklist_;
    HashMap    whitelist_;
    int        nextRuleID_    = 1;
    Action     defaultPolicy_ = Action::BLOCK; // DEFAULT_DENY policy by default

    // Helper to clear and rebuild the BST lookup index from the LinkedList ruleset.
    void rebuildBST();
};

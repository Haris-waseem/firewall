/**
 * RuleEngine.cpp
 * Coordinates Whitelist, Blacklist, BST index and LinkedList rule definitions.
 */
#include "../include/RuleEngine.h"
#include <iostream>
#include <sstream>
#include <iomanip>

// ─── Constructor ─────────────────────────────────────────────────────────────
RuleEngine::RuleEngine()
    : blacklist_(1024), whitelist_(1024), nextRuleID_(1), defaultPolicy_(Action::BLOCK) {}

// ─── evaluate() — Core O(log n) Evaluation Pipeline ──────────────────────────
Action RuleEngine::evaluate(const Packet& p, int& matchedRuleID) {
    // 1. Whitelist Check — O(1)
    if (whitelist_.contains(p.sourceIP)) {
        matchedRuleID = -1;
        return Action::ALLOW;
    }

    // 2. Blacklist Check — O(1)
    if (blacklist_.contains(p.sourceIP)) {
        matchedRuleID = -2;
        return Action::BLOCK;
    }

    // 3. Rules BST Matching — O(log n) average
    Rule* bstMatch = ruleBST_.findBestMatch(p);
    if (bstMatch) {
        matchedRuleID = bstMatch->ruleID;
        bstMatch->hitCount++;

        // Update the hit count in the LinkedList storage as well
        Rule* listMatch = ruleList_.find(bstMatch->ruleID);
        if (listMatch) {
            listMatch->hitCount++;
        }
        return bstMatch->action;
    }

    // 4. Default Policy — Fallback
    matchedRuleID = -3;
    return defaultPolicy_;
}

// ─── addRule() ───────────────────────────────────────────────────────────────
int RuleEngine::addRule(Rule r) {
    // Check for duplicate ruleID
    if (r.ruleID > 0 && ruleList_.find(r.ruleID) != nullptr) {
        return 0; // duplicate ID
    }

    if (r.ruleID <= 0) {
        r.ruleID = nextRuleID_++;
    } else if (r.ruleID >= nextRuleID_) {
        nextRuleID_ = r.ruleID + 1;
    }
    
    ruleList_.insertSorted(r);
    rebuildBST();
    return r.ruleID;
}

// ─── removeRule() ────────────────────────────────────────────────────────────
bool RuleEngine::removeRule(int ruleID) {
    bool found = ruleList_.remove(ruleID);
    if (found) {
        rebuildBST();
    }
    return found;
}

// ─── updateRule() ────────────────────────────────────────────────────────────
bool RuleEngine::updateRule(int ruleID, Action newAction) {
    Rule* r = ruleList_.find(ruleID);
    if (r) {
        r->action = newAction;
        rebuildBST();
        return true;
    }
    return false;
}

// Overloaded: update multiple fields at once
bool RuleEngine::updateRule(int ruleID, Action newAction, int newPriority,
                            Direction newDir, Protocol newProto,
                            const std::string& newSrcIP, int newDestPort) {
    Rule* r = ruleList_.find(ruleID);
    if (r) {
        r->action    = newAction;
        r->priority  = newPriority;
        r->direction = newDir;
        r->protocol  = newProto;
        r->sourceIP  = newSrcIP;
        r->destPort  = newDestPort;
        rebuildBST();
        return true;
    }
    return false;
}

// ─── enableRule() ────────────────────────────────────────────────────────────
bool RuleEngine::enableRule(int ruleID) {
    Rule* r = ruleList_.find(ruleID);
    if (r) {
        r->enabled = true;
        rebuildBST();
        return true;
    }
    return false;
}

// ─── disableRule() ───────────────────────────────────────────────────────────
bool RuleEngine::disableRule(int ruleID) {
    Rule* r = ruleList_.find(ruleID);
    if (r) {
        r->enabled = false;
        rebuildBST();
        return true;
    }
    return false;
}

// ─── listRules() ─────────────────────────────────────────────────────────────
void RuleEngine::listRules() const {
    ruleList_.printAll();
}

std::string RuleEngine::listRulesToString() const {
    std::ostringstream oss;
    std::vector<Rule> rules = ruleList_.toVector();
    if (rules.empty()) {
        oss << "  No active rules.\n";
        return oss.str();
    }
    oss << std::setw(4) << "ID" << " | " << std::setw(3) << "Pri"
        << " | " << std::setw(8) << "Action" << " | " << std::setw(8) << "Dir"
        << " | " << std::setw(5) << "Proto" << " | " << std::setw(18) << "Source IP"
        << " | " << std::setw(6) << "Port" << " | " << std::setw(6) << "Hits"
        << " | " << std::setw(8) << "Status" << " | Description\n";
    oss << std::string(100, '-') << "\n";
    for (const auto& r : rules) {
        oss << r.toString() << "\n";
    }
    oss << std::string(100, '-') << "\n";
    oss << "  Total: " << rules.size() << " rule(s)\n";
    return oss.str();
}

// ─── Blacklist / Whitelist Operations ────────────────────────────────────────
void RuleEngine::addToBlacklist(const std::string& ip) {
    blacklist_.insert(ip, 1);
}

void RuleEngine::addToWhitelist(const std::string& ip) {
    whitelist_.insert(ip, 1);
}

void RuleEngine::removeFromBlacklist(const std::string& ip) {
    blacklist_.remove(ip);
}

void RuleEngine::removeFromWhitelist(const std::string& ip) {
    whitelist_.remove(ip);
}

bool RuleEngine::isBlacklisted(const std::string& ip) const {
    return blacklist_.contains(ip);
}

bool RuleEngine::isWhitelisted(const std::string& ip) const {
    return whitelist_.contains(ip);
}

// ─── clearAll() ──────────────────────────────────────────────────────────────
void RuleEngine::clearAll() {
    ruleList_.clear();
    ruleBST_.clear();
    blacklist_.clear();
    whitelist_.clear();
    nextRuleID_ = 1;
    defaultPolicy_ = Action::BLOCK;
}

// ─── rebuildBST() — Sync tree view with list state ───────────────────────────
void RuleEngine::rebuildBST() {
    ruleBST_.clear();
    std::vector<Rule> rules = ruleList_.toVector();
    for (const auto& r : rules) {
        if (r.enabled) {
            ruleBST_.insert(r);
        }
    }
}

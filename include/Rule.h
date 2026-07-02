/**
 * Rule.h
 * Represents one firewall rule stored in the rule set.
 * Keyed by priority (lower number = higher precedence).
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <string>
#include "enums.h"
#include "Packet.h"

struct Rule {
    int         ruleID      = 0;
    int         priority    = 100;    // lower = higher precedence
    std::string sourceIP    = "*";    // "*" means any source IP
    int         destPort    = -1;     // -1 means any port (wildcard)
    Protocol    protocol    = Protocol::ANY;
    Direction   direction   = Direction::BOTH;
    Action      action      = Action::BLOCK;
    std::string description = "";
    bool        enabled     = true;
    int         hitCount    = 0;

    // Returns true if this rule matches the given packet (all non-wildcard fields)
    bool matches(const Packet& p) const;

    // Serialises the rule to one human-readable config-file line
    std::string toConfigLine() const;

    // Parses one config line (from rules.conf) into a Rule object
    static Rule fromConfigLine(const std::string& line);

    // Returns a formatted display string for list-rules output
    std::string toString() const;
};

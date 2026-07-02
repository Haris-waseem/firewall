/**
 * Rule.cpp
 * Implementation of Rule matching, serialisation, and parsing.
 */
#include "../include/Rule.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

// ─── matches() ───────────────────────────────────────────────────────────────
// Checks every non-wildcard field against the packet.
// Returns false immediately on any mismatch → fast short-circuit.
bool Rule::matches(const Packet& p) const {
    if (!enabled)                                         return false;
    if (sourceIP  != "*"         && sourceIP  != p.sourceIP)  return false;
    if (destPort  != -1          && destPort  != p.destPort)   return false;
    if (protocol  != Protocol::ANY  && protocol  != p.protocol)  return false;
    if (direction != Direction::BOTH && direction != p.direction) return false;
    return true;
}

// ─── toConfigLine() ──────────────────────────────────────────────────────────
// Format: ruleID priority action direction protocol sourceIP destPort hitCount enabled description
std::string Rule::toConfigLine() const {
    std::ostringstream oss;
    oss << std::setw(3) << std::setfill('0') << ruleID    << " "
        << std::setw(3) << std::setfill('0') << priority  << " "
        << std::setw(8) << std::setfill(' ') << actionToStr(action)    << " "
        << std::setw(8) << std::setfill(' ') << directionToStr(direction) << " "
        << std::setw(5) << std::setfill(' ') << protocolToStr(protocol) << " "
        << std::setw(18)<< std::setfill(' ') << sourceIP  << " "
        << std::setw(6) << std::setfill(' ') << destPort  << " "
        << std::setw(6) << std::setfill(' ') << hitCount  << " "
        << (enabled ? "1" : "0") << " "
        << description;
    return oss.str();
}

// ─── fromConfigLine() ────────────────────────────────────────────────────────
Rule Rule::fromConfigLine(const std::string& line) {
    if (line.empty() || line[0] == '#') throw std::invalid_argument("Comment or empty line");
    std::istringstream iss(line);
    Rule r;
    std::string actionStr, dirStr, protoStr, hitCountStr, enabledStr, descPart;

    if (!(iss >> r.ruleID >> r.priority >> actionStr >> dirStr >> protoStr >> r.sourceIP >> r.destPort))
        throw std::invalid_argument("Malformed rule line: " + line);

    r.action    = strToAction(actionStr);
    r.direction = strToDirection(dirStr);
    r.protocol  = strToProtocol(protoStr);

    // Try to parse hitCount and enabled (new format); fallback defaults for old format
    if (iss >> hitCountStr >> enabledStr) {
        try { r.hitCount = std::stoi(hitCountStr); } catch (...) { r.hitCount = 0; }
        r.enabled = (enabledStr == "1");
    } else {
        r.hitCount = 0;
        r.enabled  = true;
        iss.clear(); // clear eof/error for getline below
    }

    // Rest of line is description
    std::getline(iss, descPart);
    if (!descPart.empty() && descPart[0] == ' ') descPart = descPart.substr(1);
    r.description = descPart;
    return r;
}

// ─── toString() ──────────────────────────────────────────────────────────────
std::string Rule::toString() const {
    std::ostringstream oss;
    oss << std::setw(4)  << ruleID
        << " | " << std::setw(3)  << priority
        << " | " << std::setw(8)  << actionToStr(action)
        << " | " << std::setw(8)  << directionToStr(direction)
        << " | " << std::setw(5)  << protocolToStr(protocol)
        << " | " << std::setw(18) << sourceIP
        << " | " << std::setw(6)  << destPort
        << " | " << std::setw(6)  << hitCount
        << " | " << (enabled ? "ACTIVE  " : "DISABLED")
        << " | " << description;
    return oss.str();
}

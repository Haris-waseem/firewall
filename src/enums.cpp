/**
 * enums.cpp
 * String conversion implementations for all enumerations.
 * C++ Packet Filtering Firewall — DSA Major Project
 */
#include "../include/enums.h"
#include <stdexcept>
#include <algorithm>

// ─── Protocol ────────────────────────────────────────────────────────────────
std::string protocolToStr(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::ANY:  return "ANY";
        default:             return "UNKNOWN";
    }
}

Protocol strToProtocol(const std::string& s) {
    std::string upper = s;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper == "TCP")  return Protocol::TCP;
    if (upper == "UDP")  return Protocol::UDP;
    if (upper == "ICMP") return Protocol::ICMP;
    if (upper == "ANY")  return Protocol::ANY;
    throw std::invalid_argument("Unknown protocol: " + s);
}

// ─── Direction ───────────────────────────────────────────────────────────────
std::string directionToStr(Direction d) {
    switch (d) {
        case Direction::INBOUND:  return "INBOUND";
        case Direction::OUTBOUND: return "OUTBOUND";
        case Direction::BOTH:     return "BOTH";
        default:                  return "UNKNOWN";
    }
}

Direction strToDirection(const std::string& s) {
    std::string upper = s;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper == "INBOUND" || upper == "IN")  return Direction::INBOUND;
    if (upper == "OUTBOUND"|| upper == "OUT") return Direction::OUTBOUND;
    if (upper == "BOTH")                      return Direction::BOTH;
    throw std::invalid_argument("Unknown direction: " + s);
}

// ─── Action ──────────────────────────────────────────────────────────────────
std::string actionToStr(Action a) {
    switch (a) {
        case Action::ALLOW:    return "ALLOW";
        case Action::BLOCK:    return "BLOCK";
        case Action::LOG_ONLY: return "LOG_ONLY";
        default:               return "UNKNOWN";
    }
}

Action strToAction(const std::string& s) {
    std::string upper = s;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper == "ALLOW")    return Action::ALLOW;
    if (upper == "BLOCK")    return Action::BLOCK;
    if (upper == "LOG_ONLY" || upper == "LOG") return Action::LOG_ONLY;
    throw std::invalid_argument("Unknown action: " + s);
}

// ─── ThreatType ──────────────────────────────────────────────────────────────
std::string threatToStr(ThreatType t) {
    switch (t) {
        case ThreatType::NONE:           return "NONE";
        case ThreatType::SYN_FLOOD:      return "SYN_FLOOD";
        case ThreatType::PORT_SCAN:      return "PORT_SCAN";
        case ThreatType::BLACKLISTED_IP: return "BLACKLISTED_IP";
        case ThreatType::DANGEROUS_PORT: return "DANGEROUS_PORT";
        case ThreatType::IP_FLOOD:       return "IP_FLOOD";
        case ThreatType::BLOCKED_PACKET: return "BLOCKED_PACKET";
        default:                         return "NONE";
    }
}

ThreatType strToThreat(const std::string& s) {
    std::string upper = s;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper == "SYN_FLOOD")      return ThreatType::SYN_FLOOD;
    if (upper == "PORT_SCAN")      return ThreatType::PORT_SCAN;
    if (upper == "BLACKLISTED_IP") return ThreatType::BLACKLISTED_IP;
    if (upper == "DANGEROUS_PORT") return ThreatType::DANGEROUS_PORT;
    if (upper == "IP_FLOOD")       return ThreatType::IP_FLOOD;
    if (upper == "BLOCKED_PACKET") return ThreatType::BLOCKED_PACKET;
    return ThreatType::NONE;
}

/**
 * enums.h
 * All enumerations and their string conversion utilities used across the project.
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <string>

// =============================================================================
// Core Enumerations
// =============================================================================

enum class Protocol  { TCP, UDP, ICMP, ANY };
enum class Direction { INBOUND, OUTBOUND, BOTH };
enum class Action    { ALLOW, BLOCK, LOG_ONLY };
enum class ThreatType{ NONE, SYN_FLOOD, PORT_SCAN, BLACKLISTED_IP, DANGEROUS_PORT, IP_FLOOD, BLOCKED_PACKET };

// =============================================================================
// String Converters — declarations (implemented in enums.cpp)
// =============================================================================

std::string protocolToStr(Protocol p);
std::string directionToStr(Direction d);
std::string actionToStr(Action a);
std::string threatToStr(ThreatType t);

Protocol  strToProtocol(const std::string& s);
Direction strToDirection(const std::string& s);
Action    strToAction(const std::string& s);
ThreatType strToThreat(const std::string& s);

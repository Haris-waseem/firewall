/**
 * Packet.h
 * Represents one simulated network packet flowing through the firewall pipeline.
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <string>
#include "enums.h"

struct Packet {
    int       packetID    = 0;
    std::string sourceIP;
    std::string destIP;
    int       destPort    = 0;
    Protocol  protocol    = Protocol::TCP;
    Direction direction   = Direction::INBOUND;
    bool      isSYN       = false;
    int       payloadSize = 0;
    std::string timestamp;

    // Returns human-readable one-line summary for logging/display
    std::string toString() const;

    // Returns false if IP format is invalid or port is out of range
    bool isValid() const;

    // Generates an ISO 8601 timestamp string using current system time
    static std::string currentTimestamp();
};

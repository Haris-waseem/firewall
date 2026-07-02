/**
 * Packet.cpp
 * Implementation of Packet utility methods.
 */
#include "../include/Packet.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

// ─── isValid() ───────────────────────────────────────────────────────────────
// Validates: exactly 4 octets each 0-255, port in [0, 65535]
bool Packet::isValid() const {
    // Port check
    if (destPort < 0 || destPort > 65535) return false;

    // IP check — accepts "*" wildcard only for sourceIP in rules, but here it's a real packet
    auto checkIP = [](const std::string& ip) -> bool {
        if (ip.empty()) return false;
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
    };

    return checkIP(sourceIP) && checkIP(destIP);
}

// ─── toString() ──────────────────────────────────────────────────────────────
std::string Packet::toString() const {
    std::ostringstream oss;
    oss << "[Pkt#" << packetID << "] "
        << sourceIP << " -> " << destIP << ":" << destPort
        << " " << protocolToStr(protocol)
        << " " << directionToStr(direction)
        << (isSYN ? " SYN" : "")
        << " @ " << timestamp;
    return oss.str();
}

// ─── currentTimestamp() ──────────────────────────────────────────────────────
// Returns ISO 8601 UTC timestamp (no misleading Z with local time)
std::string Packet::currentTimestamp() {
    auto now  = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

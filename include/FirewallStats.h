/**
 * FirewallStats.h
 * Plain data struct holding all runtime statistics counters for the firewall.
 * Implemented as a header-only struct with an inline print() display method.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

struct ThreatAlert {
    std::string sourceIP;
    std::string threatType;
    std::string details;
    int severity;  // 1=CRITICAL, 2=WARNING, 3=INFO
    std::string timestamp;
};

struct ActivityEntry {
    std::string sourceIP;
    std::string description;
    std::string icon;
    int type;  // 1=allowed(green), 2=blocked(red), 3=threat(yellow), 4=info(cyan)
    std::string timestamp;
};

struct FirewallStats {
    int totalProcessed      = 0;
    int totalBlocked        = 0;
    int totalAllowed        = 0;
    int totalLogged         = 0;
    int synFloodsDetected   = 0;
    int portScansDetected   = 0;
    int queueOverflows      = 0;
    int threatsDetected     = 0;
    int criticalThreats     = 0;
    int activeConnections   = 0;
    int tcpPackets          = 0;
    int udpPackets          = 0;
    int icmpPackets         = 0;
    int inboundPackets      = 0;
    int outboundPackets     = 0;
    std::string startTime;
    std::vector<ThreatAlert> detectedThreats;
    std::vector<ActivityEntry> activityFeed;

    void addThreat(const ThreatAlert& t) {
        detectedThreats.push_back(t);
        threatsDetected++;
        if (t.severity == 1) criticalThreats++;
        if (detectedThreats.size() > 500) detectedThreats.erase(detectedThreats.begin());
    }

    void addActivity(const ActivityEntry& a) {
        activityFeed.insert(activityFeed.begin(), a);
        if (activityFeed.size() > 50) activityFeed.erase(activityFeed.begin() + 50);
    }

    // Prints a nicely formatted statistics summary box to stdout
    void print() const {
        std::cout << "\n";
        std::cout << "┌──────────────────────────────────────────────┐\n";
        std::cout << "│        FIREWALL STATISTICS SUMMARY           │\n";
        std::cout << "├──────────────────────────────────────────────┤\n";
        std::cout << "│  Start Time         : " << std::left << std::setw(22) << startTime << " │\n";
        std::cout << "│  Total Processed    : " << std::left << std::setw(22) << totalProcessed << " │\n";
        std::cout << "│  Total Allowed      : " << std::left << std::setw(22) << totalAllowed << " │\n";
        std::cout << "│  Total Blocked      : " << std::left << std::setw(22) << totalBlocked << " │\n";
        std::cout << "│  Total Logged       : " << std::left << std::setw(22) << totalLogged << " │\n";
        std::cout << "│  SYN Floods Blocked : " << std::left << std::setw(22) << synFloodsDetected << " │\n";
        std::cout << "│  Port Scans Blocked : " << std::left << std::setw(22) << portScansDetected << " │\n";
        std::cout << "│  Buffer Overflows   : " << std::left << std::setw(22) << queueOverflows << " │\n";
        std::cout << "└──────────────────────────────────────────────┘\n";
        std::cout << "\n";
    }
};

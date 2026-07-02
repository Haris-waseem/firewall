/**
 * TrafficMonitor.h
 * Inspects streaming packet patterns to detect SYN floods and port scanning.
 * Uses 3 HashMaps for tracking sliding time-window state:
 *   - synCounters_ : sourceIP -> count of SYN packets
 *   - portScanCounters_ : sourceIP + ":" + port -> 1 (to filter duplicate probes)
 *   - portCountPerIP_ : sourceIP -> count of distinct dest ports scanned
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "Packet.h"
#include "HashMap.h"
#include "enums.h"
#include <ctime>
#include <string>

class TrafficMonitor {
public:
    TrafficMonitor(int synThresh = 100, int portThresh = 20, int windowSec = 10);
    ~TrafficMonitor() = default;

    ThreatType inspect(const Packet& p);
    void resetWindow();

    bool isSYNFlood(const std::string& ip) const;
    bool isPortScan(const std::string& ip) const;
    bool isIPFlood(const std::string& ip) const;

    int  getSynThreshold() const { return synThreshold_; }
    void setSynThreshold(int t) { synThreshold_ = t; }

    int  getPortScanThreshold() const { return portScanThreshold_; }
    void setPortScanThreshold(int t) { portScanThreshold_ = t; }

    int  getWindowSeconds() const { return windowSeconds_; }
    void setWindowSeconds(int s) { windowSeconds_ = s; }

    int  getIPFloodThreshold() const { return ipFloodThreshold_; }
    void setIPFloodThreshold(int t) { ipFloodThreshold_ = t; }

private:
    HashMap synCounters_;
    HashMap portScanCounters_;
    HashMap portCountPerIP_;
    HashMap ipPacketCounters_;

    int synThreshold_;
    int portScanThreshold_;
    int ipFloodThreshold_;
    int windowSeconds_;
    std::time_t windowStart_;
};

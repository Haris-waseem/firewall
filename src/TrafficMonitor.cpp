/**
 * TrafficMonitor.cpp
 * Threat detection time-window sliding algorithms.
 */
#include "../include/TrafficMonitor.h"
#include <iostream>

// ─── Constructor ─────────────────────────────────────────────────────────────
TrafficMonitor::TrafficMonitor(int synThresh, int portThresh, int windowSec)
    : synThreshold_(synThresh),
      portScanThreshold_(portThresh),
      ipFloodThreshold_(5),
      windowSeconds_(windowSec),
      synCounters_(512),
      portScanCounters_(2048),
      portCountPerIP_(512),
      ipPacketCounters_(512) {
    windowStart_ = std::time(nullptr);
}

// ─── inspect() — Evaluates streaming packets for threat patterns ────────────
ThreatType TrafficMonitor::inspect(const Packet& p) {
    if (p.sourceIP.empty() || p.sourceIP == "*") {
        return ThreatType::NONE;
    }

    std::time_t now = std::time(nullptr);
    if (std::difftime(now, windowStart_) >= windowSeconds_) {
        resetWindow();
    }

    // Count all packets per IP for flood detection
    ipPacketCounters_.increment(p.sourceIP);

    // ─── SYN Flood Detection ───
    if (p.protocol == Protocol::TCP && p.isSYN) {
        synCounters_.increment(p.sourceIP);
        if (synCounters_.get(p.sourceIP) > synThreshold_) {
            return ThreatType::SYN_FLOOD;
        }
    }

    // ─── Port Scan Detection ───
    std::string key = p.sourceIP + ":" + std::to_string(p.destPort);
    if (!portScanCounters_.contains(key)) {
        portScanCounters_.insert(key, 1);
        portCountPerIP_.increment(p.sourceIP);
        if (portCountPerIP_.get(p.sourceIP) > portScanThreshold_) {
            return ThreatType::PORT_SCAN;
        }
    }

    return ThreatType::NONE;
}

// ─── resetWindow() ───────────────────────────────────────────────────────────
void TrafficMonitor::resetWindow() {
    synCounters_.clear();
    portScanCounters_.clear();
    portCountPerIP_.clear();
    ipPacketCounters_.clear();
    windowStart_ = std::time(nullptr);
}

bool TrafficMonitor::isSYNFlood(const std::string& ip) const {
    int val = synCounters_.get(ip);
    return val > synThreshold_;
}

bool TrafficMonitor::isPortScan(const std::string& ip) const {
    int val = portCountPerIP_.get(ip);
    return val > portScanThreshold_;
}

bool TrafficMonitor::isIPFlood(const std::string& ip) const {
    int val = ipPacketCounters_.get(ip);
    return val > ipFloodThreshold_;
}

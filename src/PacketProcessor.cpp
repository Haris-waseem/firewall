/**
 * PacketProcessor.cpp
 * Coordinates execution of enqueuing, threat evaluation, rule evaluation, logging, and history archiving.
 */
#include "../include/PacketProcessor.h"
#include "../include/IconsFontAwesome.h"
#include <iostream>

// ─── Constructor ─────────────────────────────────────────────────────────────
PacketProcessor::PacketProcessor(RuleEngine& e, TrafficMonitor& m, FileLogger& l,
                                 MongoLogger& ml, Stack& h, Queue& q, FirewallStats& s)
    : engine_(e), monitor_(m), logger_(l), mongoLogger_(ml), history_(h), packetQueue_(q), stats_(s),
      activeIPs_(512) {}

// ─── process() — Process a single packet from validation through logging ─────
void PacketProcessor::process(const Packet& p) {
    if (!p.isValid()) {
        logger_.logEvent(p, Action::BLOCK, -4);
        mongoLogger_.logEvent(p, Action::BLOCK, -4);
        stats_.totalBlocked++;
        stats_.totalLogged++;
        stats_.totalProcessed++;
        return;
    }

    // Track active connections
    activeIPs_.insert(p.sourceIP, 1);
    stats_.activeConnections = activeIPs_.size();

    bool threatDetected = false;

    // 1. Blacklisted IP → CRITICAL
    if (engine_.isBlacklisted(p.sourceIP)) {
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "Blacklisted IP";
        ta.details = "Packet from blacklisted IP on port " + std::to_string(p.destPort);
        ta.severity = 1;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, p.sourceIP + " blocked (blacklisted) on port " + std::to_string(p.destPort), ICON_FA_BAN, 2, p.timestamp});
        threatDetected = true;
    }

    // 2. Dangerous port → WARNING
    static const int dangerousPorts[] = {22, 23, 3389, 4444, 6666};
    for (int dp : dangerousPorts) {
        if (p.destPort == dp) {
            ThreatAlert ta;
            ta.sourceIP = p.sourceIP;
            ta.threatType = "Dangerous Port";
            ta.details = "Access attempt on port " + std::to_string(dp) + " (" + protocolToStr(p.protocol) + ")";
            ta.severity = 2;
            ta.timestamp = p.timestamp;
            stats_.addThreat(ta);
            stats_.addActivity({p.sourceIP, "Dangerous port " + std::to_string(dp) + " access from " + p.sourceIP, ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
            threatDetected = true;
            break;
        }
    }

    // 3. SYN flag set → WARNING
    if (p.protocol == Protocol::TCP && p.isSYN) {
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "SYN Packet";
        ta.details = "TCP SYN flag detected to port " + std::to_string(p.destPort);
        ta.severity = 2;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        if (!threatDetected) {
            stats_.addActivity({p.sourceIP, "SYN packet from " + p.sourceIP + " to port " + std::to_string(p.destPort), ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
        }
        threatDetected = true;
    }

    // 4. IP flood (>5 packets in window) → CRITICAL
    if (monitor_.isIPFlood(p.sourceIP)) {
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "IP Flood";
        ta.details = "More than 5 packets from " + p.sourceIP + " in monitoring window";
        ta.severity = 1;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "IP flood detected from " + p.sourceIP, ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
        threatDetected = true;
    }

    // 5. Pattern-based detection (SYN flood, port scan)
    ThreatType threat = monitor_.inspect(p);
    if (threat == ThreatType::SYN_FLOOD) {
        stats_.synFloodsDetected++;
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "SYN Flood";
        ta.details = "SYN flood threshold exceeded from " + p.sourceIP;
        ta.severity = 1;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "SYN flood from " + p.sourceIP + " — IP blacklisted", ICON_FA_BAN, 2, p.timestamp});
        engine_.addToBlacklist(p.sourceIP);
        logger_.logThreat(p, threat);
        mongoLogger_.logThreat(p, threat);
        threatDetected = true;
    } else if (threat == ThreatType::PORT_SCAN) {
        stats_.portScansDetected++;
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "Port Scan";
        ta.details = "Port scan detected from " + p.sourceIP;
        ta.severity = 1;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "Port scan from " + p.sourceIP + " — IP blacklisted", ICON_FA_BAN, 2, p.timestamp});
        engine_.addToBlacklist(p.sourceIP);
        logger_.logThreat(p, threat);
        mongoLogger_.logThreat(p, threat);
        threatDetected = true;
    }

    // 6. Evaluate packet against rules
    int matchedRuleID = -3;
    Action decision = engine_.evaluate(p, matchedRuleID);

    // 7. If BLOCKED → INFO threat
    if (decision == Action::BLOCK) {
        ThreatAlert ta;
        ta.sourceIP = p.sourceIP;
        ta.threatType = "Blocked Packet";
        ta.details = "Packet blocked by " + std::string(matchedRuleID == -2 ? "blacklist" : (matchedRuleID == -3 ? "default policy" : "rule R-" + std::to_string(matchedRuleID)));
        ta.severity = 3;
        ta.timestamp = p.timestamp;
        stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "Blocked " + protocolToStr(p.protocol) + " from " + p.sourceIP + " port " + std::to_string(p.destPort), ICON_FA_BAN, 2, p.timestamp});
    } else {
        // 8. Allowed — add green activity
        stats_.addActivity({p.sourceIP, "Allowed " + protocolToStr(p.protocol) + " from " + p.sourceIP + " port " + std::to_string(p.destPort), ICON_FA_CHECK_CIRCLE, 1, p.timestamp});
    }

    // 9. Log
    logger_.logEvent(p, decision, matchedRuleID);
    mongoLogger_.logEvent(p, decision, matchedRuleID);
    stats_.totalLogged++;

    // 10. Update counters
    if (decision == Action::BLOCK) {
        stats_.totalBlocked++;
    } else {
        stats_.totalAllowed++;
    }
    if (p.protocol == Protocol::TCP) stats_.tcpPackets++;
    else if (p.protocol == Protocol::UDP) stats_.udpPackets++;
    else if (p.protocol == Protocol::ICMP) stats_.icmpPackets++;
    if (p.direction == Direction::INBOUND) stats_.inboundPackets++;
    else if (p.direction == Direction::OUTBOUND) stats_.outboundPackets++;
    stats_.totalProcessed++;

    // 11. Archive in history stack
    history_.push(p);
}

// ─── drainQueue() ────────────────────────────────────────────────────────────
void PacketProcessor::drainQueue() {
    while (!packetQueue_.isEmpty()) {
        try {
            Packet p = packetQueue_.dequeue();

            if (!p.isValid()) {
                logger_.logEvent(p, Action::BLOCK, -4);
                mongoLogger_.logEvent(p, Action::BLOCK, -4);
                stats_.totalBlocked++;
                stats_.totalLogged++;
                stats_.totalProcessed++;
                continue;
            }

            activeIPs_.insert(p.sourceIP, 1);
            stats_.activeConnections = activeIPs_.size();

            bool threatDetected = false;

            if (engine_.isBlacklisted(p.sourceIP)) {
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "Blacklisted IP";
                ta.details = "Packet from blacklisted IP on port " + std::to_string(p.destPort);
                ta.severity = 1;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, p.sourceIP + " blocked (blacklisted) on port " + std::to_string(p.destPort), ICON_FA_BAN, 2, p.timestamp});
                threatDetected = true;
            }

            static const int dangerousPorts[] = {22, 23, 3389, 4444, 6666};
            for (int dp : dangerousPorts) {
                if (p.destPort == dp) {
                    ThreatAlert ta;
                    ta.sourceIP = p.sourceIP;
                    ta.threatType = "Dangerous Port";
                    ta.details = "Access attempt on port " + std::to_string(dp);
                    ta.severity = 2;
                    ta.timestamp = p.timestamp;
                    stats_.addThreat(ta);
            stats_.addActivity({p.sourceIP, "Dangerous port " + std::to_string(dp) + " access from " + p.sourceIP, ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
                    threatDetected = true;
                    break;
                }
            }

            if (p.protocol == Protocol::TCP && p.isSYN) {
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "SYN Packet";
                ta.details = "TCP SYN flag detected to port " + std::to_string(p.destPort);
                ta.severity = 2;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
                if (!threatDetected) {
                    stats_.addActivity({p.sourceIP, "SYN packet from " + p.sourceIP + " to port " + std::to_string(p.destPort), ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
                }
                threatDetected = true;
            }

            if (monitor_.isIPFlood(p.sourceIP)) {
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "IP Flood";
                ta.details = "More than 5 packets from " + p.sourceIP + " in monitoring window";
                ta.severity = 1;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "IP flood detected from " + p.sourceIP, ICON_FA_EXCLAMATION_TRIANGLE, 3, p.timestamp});
                threatDetected = true;
            }

            ThreatType threat = monitor_.inspect(p);
            if (threat == ThreatType::SYN_FLOOD) {
                stats_.synFloodsDetected++;
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "SYN Flood";
                ta.details = "SYN flood threshold exceeded from " + p.sourceIP;
                ta.severity = 1;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "SYN flood from " + p.sourceIP + " — IP blacklisted", ICON_FA_BAN, 2, p.timestamp});
                engine_.addToBlacklist(p.sourceIP);
                logger_.logThreat(p, threat);
                mongoLogger_.logThreat(p, threat);
                threatDetected = true;
            } else if (threat == ThreatType::PORT_SCAN) {
                stats_.portScansDetected++;
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "Port Scan";
                ta.details = "Port scan detected from " + p.sourceIP;
                ta.severity = 1;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "Port scan from " + p.sourceIP + " — IP blacklisted", ICON_FA_BAN, 2, p.timestamp});
                engine_.addToBlacklist(p.sourceIP);
                logger_.logThreat(p, threat);
                mongoLogger_.logThreat(p, threat);
                threatDetected = true;
            }

            int matchedRuleID = -3;
            Action decision = engine_.evaluate(p, matchedRuleID);

            if (decision == Action::BLOCK) {
                ThreatAlert ta;
                ta.sourceIP = p.sourceIP;
                ta.threatType = "Blocked Packet";
                ta.details = "Packet blocked by " + std::string(matchedRuleID == -2 ? "blacklist" : (matchedRuleID == -3 ? "default policy" : "rule R-" + std::to_string(matchedRuleID)));
                ta.severity = 3;
                ta.timestamp = p.timestamp;
                stats_.addThreat(ta);
        stats_.addActivity({p.sourceIP, "Blocked " + protocolToStr(p.protocol) + " from " + p.sourceIP + " port " + std::to_string(p.destPort), ICON_FA_BAN, 2, p.timestamp});
            } else {
        stats_.addActivity({p.sourceIP, "Allowed " + protocolToStr(p.protocol) + " from " + p.sourceIP + " port " + std::to_string(p.destPort), ICON_FA_CHECK_CIRCLE, 1, p.timestamp});
            }

            logger_.logEvent(p, decision, matchedRuleID);
            mongoLogger_.logEvent(p, decision, matchedRuleID);
            stats_.totalLogged++;
            if (decision == Action::BLOCK) {
                stats_.totalBlocked++;
            } else {
                stats_.totalAllowed++;
            }
            if (p.protocol == Protocol::TCP) stats_.tcpPackets++;
            else if (p.protocol == Protocol::UDP) stats_.udpPackets++;
            else if (p.protocol == Protocol::ICMP) stats_.icmpPackets++;
            if (p.direction == Direction::INBOUND) stats_.inboundPackets++;
            else if (p.direction == Direction::OUTBOUND) stats_.outboundPackets++;
            stats_.totalProcessed++;
            history_.push(p);
        } catch (...) {
            break;
        }
    }
}

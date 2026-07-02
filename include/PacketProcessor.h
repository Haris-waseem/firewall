/**
 * PacketProcessor.h
 * Main network packet inspection pipeline orchestrating the core logic.
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "RuleEngine.h"
#include "TrafficMonitor.h"
#include "FileLogger.h"
#include "MongoLogger.h"
#include "Stack.h"
#include "Queue.h"
#include "FirewallStats.h"
#include "Packet.h"
#include "HashMap.h"

class PacketProcessor {
public:
    PacketProcessor(RuleEngine& e, TrafficMonitor& m, FileLogger& l,
                    MongoLogger& ml, Stack& h, Queue& q, FirewallStats& s);
    ~PacketProcessor() = default;

    void process(const Packet& p);
    void drainQueue();

private:
    RuleEngine&     engine_;
    TrafficMonitor& monitor_;
    FileLogger&     logger_;
    MongoLogger&    mongoLogger_;
    Stack&          history_;
    Queue&          packetQueue_;
    FirewallStats&  stats_;
    HashMap         activeIPs_;
};

/**
 * PacketSimulator.h
 * Utility for generating simulated test packets.
 * Useful for debugging rules, SYN floods, and port scanning.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "Packet.h"
#include "enums.h"
#include <string>
#include <vector>

class PacketSimulator {
public:
    PacketSimulator();
    ~PacketSimulator() = default;

    // Creates a packet with auto-increment ID, current timestamp, and customized fields.
    Packet createPacket(const std::string& srcIP, const std::string& dstIP, int dstPort,
                        Protocol proto, Direction dir, bool isSYN = false, int payloadSize = 512);

    // Creates a TCP SYN packet from given source IP (useful for SYN-flood testing)
    Packet createSYNPacket(const std::string& srcIP, int dstPort);

    // Generates a burst of packets to sequential ports (useful for port-scan testing)
    std::vector<Packet> generateBurst(const std::string& srcIP, int count, int startPort = 80,
                                       Protocol proto = Protocol::TCP, Direction dir = Direction::INBOUND);

private:
    int nextPacketID_ = 1;
};

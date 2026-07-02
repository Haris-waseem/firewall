/**
 * PacketSimulator.cpp
 * Implementation of simulated test packet generators.
 */
#include "../include/PacketSimulator.h"

// ─── Constructor ─────────────────────────────────────────────────────────────
PacketSimulator::PacketSimulator() : nextPacketID_(1) {}

// ─── createPacket() ──────────────────────────────────────────────────────────
Packet PacketSimulator::createPacket(const std::string& srcIP, const std::string& dstIP, int dstPort,
                                     Protocol proto, Direction dir, bool isSYN, int payloadSize) {
    Packet p;
    p.packetID    = nextPacketID_++;
    p.sourceIP    = srcIP;
    p.destIP      = dstIP;
    p.destPort    = dstPort;
    p.protocol    = proto;
    p.direction   = dir;
    p.isSYN       = isSYN;
    p.payloadSize = payloadSize;
    p.timestamp   = Packet::currentTimestamp();
    return p;
}

// ─── createSYNPacket() ────────────────────────────────────────────────────────
Packet PacketSimulator::createSYNPacket(const std::string& srcIP, int dstPort) {
    return createPacket(srcIP, "10.0.0.1", dstPort, Protocol::TCP, Direction::INBOUND, true, 0);
}

// ─── generateBurst() — Port scan builder ──────────────────────────────────────
std::vector<Packet> PacketSimulator::generateBurst(const std::string& srcIP, int count, int startPort,
                                                     Protocol proto, Direction dir) {
    std::vector<Packet> burst;
    burst.reserve(count);
    for (int i = 0; i < count; i++) {
        burst.push_back(createPacket(srcIP, "10.0.0.1", startPort + i, proto, dir, false, 64));
    }
    return burst;
}

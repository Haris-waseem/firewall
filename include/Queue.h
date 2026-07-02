/**
 * Queue.h
 * Circular array-based FIFO queue for buffering network packets before processing.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "Packet.h"
#include <vector>

class Queue {
public:
    explicit Queue(int capacity = 1000);
    ~Queue() = default;

    // Enqueues a packet. Returns false and increments overflowCount_ if full.
    bool enqueue(const Packet& p);

    // Dequeues and returns the front packet. Throws std::runtime_error if empty.
    Packet dequeue();

    bool isEmpty() const { return count_ == 0; }
    bool isFull() const { return count_ == capacity_; }
    int  getCount() const { return count_; }
    int  getOverflowCount() const { return overflowCount_; }
    int  getCapacity() const { return capacity_; }

    // Resets the overflow counter to 0
    void resetOverflowCount() { overflowCount_ = 0; }

private:
    std::vector<Packet> items_;
    int front_          = 0;
    int rear_           = -1;
    int count_          = 0;
    int capacity_       = 1000;
    int overflowCount_  = 0; // Packets dropped due to queue overflow
};

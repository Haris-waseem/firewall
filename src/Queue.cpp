/**
 * Queue.cpp
 * Custom circular-array queue implementation for packet buffer.
 */
#include "../include/Queue.h"
#include <stdexcept>
#include <iostream>

// ─── Constructor ─────────────────────────────────────────────────────────────
Queue::Queue(int capacity)
    : capacity_(capacity), count_(0), front_(0), rear_(-1), overflowCount_(0) {
    if (capacity <= 0) {
        std::cerr << "[Queue] Warning: capacity=" << capacity
                  << " is invalid; defaulting to 1000\n";
        capacity_ = 1000;
    }
    items_.resize(capacity_);
}

// ─── enqueue() — O(1) circular enqueue ───────────────────────────────────────
bool Queue::enqueue(const Packet& p) {
    if (isFull()) {
        overflowCount_++;
        return false;
    }
    rear_ = (rear_ + 1) % capacity_;
    items_[rear_] = p;
    count_++;
    return true;
}

// ─── dequeue() — O(1) circular dequeue ───────────────────────────────────────
Packet Queue::dequeue() {
    if (isEmpty()) {
        throw std::runtime_error("Queue underflow: Buffer is empty.");
    }
    Packet p = items_[front_];
    front_ = (front_ + 1) % capacity_;
    count_--;
    return p;
}

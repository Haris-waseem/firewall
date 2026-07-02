/**
 * Stack.cpp
 * Custom circular-array stack implementation for packet history.
 */
#include "../include/Stack.h"
#include <iostream>
#include <stdexcept>

// ─── Constructor ─────────────────────────────────────────────────────────────
Stack::Stack(int capacity) : capacity_(capacity), count_(0), top_(-1) {
    if (capacity <= 0) {
        std::cerr << "[Stack] Warning: capacity=" << capacity
                  << " is invalid; defaulting to 100\n";
        capacity_ = 100;
    }
    items_.resize(capacity_);
}

// ─── push() — O(1) circular push ─────────────────────────────────────────────
void Stack::push(const Packet& p) {
    if (isFull()) {
        std::cerr << "[Stack] Warning: buffer full, overwriting oldest packet\n";
    }
    top_ = (top_ + 1) % capacity_;
    items_[top_] = p;
    if (count_ < capacity_) {
        count_++;
    }
}

// ─── pop() — O(1) circular pop ───────────────────────────────────────────────
Packet Stack::pop() {
    if (isEmpty()) {
        throw std::runtime_error("Stack underflow: History is empty.");
    }
    Packet p = items_[top_];
    top_ = (top_ - 1 + capacity_) % capacity_;
    count_--;
    return p;
}

// ─── peek() — O(1) ───────────────────────────────────────────────────────────
Packet Stack::peek() const {
    if (isEmpty()) {
        throw std::runtime_error("Stack empty: No packets in history.");
    }
    return items_[top_];
}

// ─── printTop() — O(n) display ───────────────────────────────────────────────
void Stack::printTop(int n) const {
    if (count_ == 0) {
        std::cout << "  No packet history recorded yet.\n";
        return;
    }
    int limit = (n < count_) ? n : count_;
    for (int i = 0; i < limit; i++) {
        int idx = (top_ - i + capacity_) % capacity_;
        std::cout << "  " << items_[idx].toString() << "\n";
    }
}

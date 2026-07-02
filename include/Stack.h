/**
 * Stack.h
 * Circular array-based LIFO buffer for storing firewall packet processing history.
 * If the stack is full, new items overwrite the oldest items.
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "Packet.h"
#include <vector>

class Stack {
public:
    explicit Stack(int capacity = 100);
    ~Stack() = default;

    // Adds a packet to the top of the stack.
    // If the stack is full, modular indexing is used to overwrite the oldest packet.
    void push(const Packet& p);

    // Removes and returns the top packet.
    // Throws std::runtime_error if the stack is empty.
    Packet pop();

    // Returns the top packet without removing it.
    // Throws std::runtime_error if the stack is empty.
    Packet peek() const;

    bool isEmpty() const { return count_ == 0; }
    bool isFull() const { return count_ == capacity_; }
    int  getCount() const { return count_; }
    int  getCapacity() const { return capacity_; }

    // Prints the top n items to stdout in LIFO order (most recent first)
    void printTop(int n) const;

private:
    std::vector<Packet> items_;
    int top_      = -1; // Index of the most recently pushed item
    int count_    = 0;  // Current number of items stored
    int capacity_ = 100;
};

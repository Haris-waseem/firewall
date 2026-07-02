/**
 * LinkedList.h
 * Singly-linked list of RuleNodes. Stores rules in insertion/priority order.
 *
 * Used for:
 *   - Ordered display of all rules (list-rules)
 *   - Sequential serialisation to rules.conf
 *   - Loading rules in bulk from file
 *
 * Complexity:
 *   insert (tail)  O(1) with tail pointer
 *   insertSorted   O(n) linear scan
 *   remove         O(n) linear scan
 *   find           O(n) linear scan
 *   printAll       O(n)
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "RuleNode.h"
#include <vector>

class LinkedList {
public:
    LinkedList();
    ~LinkedList();

    // Inserts at tail — O(1)
    void insert(const Rule& r);

    // Inserts maintaining ascending priority order — O(n)
    void insertSorted(const Rule& r);

    // Removes node with matching ruleID — O(n); returns true if found
    bool remove(int ruleID);

    // Returns pointer to Rule with matching ID; nullptr if not found — O(n)
    Rule* find(int ruleID);
    const Rule* find(int ruleID) const;

    // Prints formatted table of all rules to stdout
    void printAll() const;

    // Returns all rules as a vector (for file serialisation)
    std::vector<Rule> toVector() const;

    // Removes all nodes (frees memory)
    void clear();

    int  getSize() const { return size_; }
    bool isEmpty() const { return head_ == nullptr; }

    // Iterator support — returns head (for RuleEngine::loadFromFile)
    RuleNode* head() const { return head_; }

private:
    RuleNode* head_ = nullptr;
    RuleNode* tail_ = nullptr;
    int       size_ = 0;
};

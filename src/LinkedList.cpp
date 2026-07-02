/**
 * LinkedList.cpp
 * Custom singly-linked list implementation for firewall rule storage.
 */
#include "../include/LinkedList.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>

// ─── Constructor / Destructor ─────────────────────────────────────────────────
LinkedList::LinkedList() : head_(nullptr), tail_(nullptr), size_(0) {}

LinkedList::~LinkedList() { clear(); }

// ─── insert() — O(1) tail insertion ──────────────────────────────────────────
void LinkedList::insert(const Rule& r) {
    RuleNode* node = new RuleNode(r);
    if (!head_) {
        head_ = tail_ = node;
    } else {
        tail_->next = node;
        tail_ = node;
    }
    size_++;
}

// ─── insertSorted() — O(n) priority-ordered insertion ────────────────────────
// Inserts so that the list remains sorted by ascending priority number.
// Ties are broken by ruleID (lower ID first).
void LinkedList::insertSorted(const Rule& r) {
    RuleNode* node = new RuleNode(r);
    size_++;

    // Empty list or new node has higher priority (lower number) than head
    if (!head_ || r.priority < head_->rule.priority ||
        (r.priority == head_->rule.priority && r.ruleID < head_->rule.ruleID)) {
        node->next = head_;
        head_ = node;
        if (size_ == 1) tail_ = node;
        return;
    }

    RuleNode* prev = head_;
    RuleNode* curr = head_->next;
    while (curr) {
        if (r.priority < curr->rule.priority ||
            (r.priority == curr->rule.priority && r.ruleID < curr->rule.ruleID)) {
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    node->next = curr;
    prev->next = node;
    if (!curr) tail_ = node;  // inserted at tail
}

// ─── remove() — O(n) linear scan ─────────────────────────────────────────────
bool LinkedList::remove(int ruleID) {
    RuleNode* prev = nullptr;
    RuleNode* curr = head_;

    while (curr) {
        if (curr->rule.ruleID == ruleID) {
            if (prev) prev->next = curr->next;
            else      head_      = curr->next;
            if (curr == tail_) tail_ = prev;
            delete curr;
            size_--;
            return true;
        }
        prev = curr;
        curr = curr->next;
    }
    return false;  // not found
}

// ─── find() — O(n) linear scan ───────────────────────────────────────────────
Rule* LinkedList::find(int ruleID) {
    RuleNode* curr = head_;
    while (curr) {
        if (curr->rule.ruleID == ruleID) return &curr->rule;
        curr = curr->next;
    }
    return nullptr;
}

const Rule* LinkedList::find(int ruleID) const {
    const RuleNode* curr = head_;
    while (curr) {
        if (curr->rule.ruleID == ruleID) return &curr->rule;
        curr = curr->next;
    }
    return nullptr;
}

// ─── printAll() — O(n) formatted table ───────────────────────────────────────
void LinkedList::printAll() const {
    if (!head_) {
        std::cout << "  No active rules. Use 'add-rule' to add rules.\n";
        return;
    }
    // Table header
    std::cout << "\n"
              << std::setw(4)  << "ID"
              << " | " << std::setw(3)  << "Pri"
              << " | " << std::setw(8)  << "Action"
              << " | " << std::setw(8)  << "Dir"
              << " | " << std::setw(5)  << "Proto"
              << " | " << std::setw(18) << "Source IP"
              << " | " << std::setw(6)  << "Port"
              << " | " << std::setw(6)  << "Hits"
              << " | " << std::setw(8)  << "Status"
              << " | Description\n";
    std::cout << std::string(100, '-') << "\n";

    const RuleNode* curr = head_;
    while (curr) {
        std::cout << curr->rule.toString() << "\n";
        curr = curr->next;
    }
    std::cout << std::string(100, '-') << "\n";
    std::cout << "  Total: " << size_ << " rule(s)\n\n";
}

// ─── toVector() — O(n) ───────────────────────────────────────────────────────
std::vector<Rule> LinkedList::toVector() const {
    std::vector<Rule> vec;
    vec.reserve(size_);
    const RuleNode* curr = head_;
    while (curr) {
        vec.push_back(curr->rule);
        curr = curr->next;
    }
    return vec;
}

// ─── clear() — O(n) — frees all nodes ────────────────────────────────────────
void LinkedList::clear() {
    RuleNode* curr = head_;
    while (curr) {
        RuleNode* next = curr->next;
        delete curr;
        curr = next;
    }
    head_ = tail_ = nullptr;
    size_ = 0;
}

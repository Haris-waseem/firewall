/**
 * RuleNode.h
 * Internal node shared by both the LinkedList and BST.
 * Avoids duplicating the Rule object — single allocation, two logical uses.
 *
 * LinkedList uses: next pointer only
 * BST uses: left and right pointers only
 * C++ Packet Filtering Firewall — DSA Major Project
 */
#pragma once
#include "Rule.h"

struct RuleNode {
    Rule      rule;              // Owned Rule data (by value)
    RuleNode* next  = nullptr;   // LinkedList forward link
    RuleNode* left  = nullptr;   // BST left child
    RuleNode* right = nullptr;   // BST right child
    int       height = 1;        // AVL subtree height (leaf = 1)

    explicit RuleNode(const Rule& r) : rule(r) {}
};

/**
 * BST.h
 * Binary Search Tree keyed on Rule::priority for O(log n) rule matching.
 *
 * In-order traversal visits rules from lowest priority number to highest
 * (i.e., highest-precedence first). findBestMatch() returns the first
 * matching rule encountered in this traversal — the highest-priority match.
 *
 * Degenerate case: if rules inserted in sorted priority order, tree becomes
 * a right-skewed linked list → O(n) per lookup. Future enhancement: AVL tree.
 *
 * Complexity (average / worst):
 *   insert         O(log n) / O(n)
 *   findBestMatch  O(log n) / O(n)
 *   remove         O(log n) / O(n)
 *   inOrder        O(n)
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include "RuleNode.h"
#include "Packet.h"
#include <vector>

class BST {
public:
    BST();
    ~BST();

    // Insert rule keyed by priority; ties broken by ruleID
    void insert(const Rule& r);

    // In-order traversal: returns first Rule that matches packet p
    // Returns nullptr if no rule matches
    Rule* findBestMatch(const Packet& p);

    // Removes node with given ruleID; rebuilds using in-order successor
    bool remove(int ruleID);

    // Fills vector with all rules in priority order (ascending priority number)
    void inOrder(std::vector<Rule>& out) const;

    // Returns tree height (useful for DSA viva performance analysis)
    int height() const;

    // Checks if tree is balanced (max left/right height difference <= 1)
    bool isBalanced() const;

    // Removes all nodes (frees BST nodes; does NOT free shared RuleNode memory
    // since RuleNode is owned by LinkedList)
    void clear();

    bool isEmpty() const { return root_ == nullptr; }

private:
    RuleNode* root_ = nullptr;

    // Recursive helpers
    RuleNode* insertNode(RuleNode* node, const Rule& r);
    Rule*     findMatch(RuleNode* node, const Packet& p) const;
    RuleNode* removeNode(RuleNode* node, int ruleID, bool& found);
    RuleNode* minNode(RuleNode* node) const;
    void      inOrderHelper(RuleNode* node, std::vector<Rule>& out) const;
    int       heightHelper(RuleNode* node) const;
    bool      isBalancedHelper(RuleNode* node) const;
    void      clearHelper(RuleNode* node);

    // AVL balancing helpers
    int       getHeight(RuleNode* node) const;
    int       getBalance(RuleNode* node) const;
    RuleNode* rotateLeft(RuleNode* x);
    RuleNode* rotateRight(RuleNode* y);
    RuleNode* rebalance(RuleNode* node);
};

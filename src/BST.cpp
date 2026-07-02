/**
 * BST.cpp
 * Binary Search Tree implementation for priority-keyed firewall rule matching.
 *
 * Design notes:
 * - BST owns its own RuleNode objects (separate from LinkedList's nodes).
 * - Each BST node stores a COPY of the Rule (by value inside RuleNode).
 * - When a rule is updated via RuleEngine, BOTH the LinkedList node and
 *   the BST node must be updated independently.
 */
#include "../include/BST.h"
#include <algorithm>
#include <cmath>

// ─── Constructor / Destructor ─────────────────────────────────────────────────
BST::BST() : root_(nullptr) {}

BST::~BST() { clear(); }

// ─── insert() ────────────────────────────────────────────────────────────────
void BST::insert(const Rule& r) {
    root_ = insertNode(root_, r);
}

RuleNode* BST::insertNode(RuleNode* node, const Rule& r) {
    if (!node) return new RuleNode(r);

    // Key: priority — ties broken by ruleID
    if (r.priority < node->rule.priority)
        node->left  = insertNode(node->left,  r);
    else if (r.priority > node->rule.priority)
        node->right = insertNode(node->right, r);
    else {
        // Same priority — use ruleID as tie-breaker
        if (r.ruleID < node->rule.ruleID)
            node->left  = insertNode(node->left,  r);
        else
            node->right = insertNode(node->right, r);
    }
    return rebalance(node);
}

// ─── findBestMatch() — in-order traversal, first match wins ──────────────────
Rule* BST::findBestMatch(const Packet& p) {
    return findMatch(root_, p);
}

Rule* BST::findMatch(RuleNode* node, const Packet& p) const {
    if (!node) return nullptr;

    // Visit left subtree first (lower priority number = higher precedence)
    Rule* found = findMatch(node->left, p);
    if (found) return found;

    // Check this node
    if (node->rule.matches(p)) return &node->rule;

    // Visit right subtree (lower precedence)
    return findMatch(node->right, p);
}

// ─── remove() — in-order successor method ────────────────────────────────────
bool BST::remove(int ruleID) {
    bool found = false;
    root_ = removeNode(root_, ruleID, found);
    return found;
}

RuleNode* BST::removeNode(RuleNode* node, int ruleID, bool& found) {
    if (!node) return nullptr;

    // Search by ruleID (not priority, since we know ruleID but not priority)
    // We do a full tree traversal by ruleID — O(n) worst case but correct
    // Note: BST is keyed on priority, so ruleID search is not O(log n)
    // This is acceptable: removal is an admin operation (infrequent)
    node->left  = removeNode(node->left,  ruleID, found);
    node->right = removeNode(node->right, ruleID, found);

    if (!found && node->rule.ruleID == ruleID) {
        found = true;
        // Case 1: No children
        if (!node->left && !node->right) {
            delete node;
            return nullptr;
        }
        // Case 2: One child
        if (!node->left)  { RuleNode* r = node->right; delete node; return r; }
        if (!node->right) { RuleNode* l = node->left;  delete node; return l; }
        // Case 3: Two children — replace with in-order successor
        RuleNode* succ = minNode(node->right);
        node->rule     = succ->rule;  // copy successor's data up
        bool dummy = false;
        node->right = removeNode(node->right, succ->rule.ruleID, dummy);
    }
    return rebalance(node);
}

RuleNode* BST::minNode(RuleNode* node) const {
    while (node->left) node = node->left;
    return node;
}

// ─── inOrder() — fills vector in priority order ───────────────────────────────
void BST::inOrder(std::vector<Rule>& out) const {
    inOrderHelper(root_, out);
}

void BST::inOrderHelper(RuleNode* node, std::vector<Rule>& out) const {
    if (!node) return;
    inOrderHelper(node->left,  out);
    out.push_back(node->rule);
    inOrderHelper(node->right, out);
}

// ─── height() ────────────────────────────────────────────────────────────────
int BST::height() const { return heightHelper(root_); }

int BST::heightHelper(RuleNode* node) const {
    if (!node) return 0;
    return 1 + std::max(heightHelper(node->left), heightHelper(node->right));
}

// ─── isBalanced() ────────────────────────────────────────────────────────────
bool BST::isBalanced() const { return isBalancedHelper(root_); }

bool BST::isBalancedHelper(RuleNode* node) const {
    if (!node) return true;
    int lh = heightHelper(node->left);
    int rh = heightHelper(node->right);
    return std::abs(lh - rh) <= 1 &&
           isBalancedHelper(node->left) &&
           isBalancedHelper(node->right);
}

// ─── clear() — post-order delete ─────────────────────────────────────────────
void BST::clear() {
    clearHelper(root_);
    root_ = nullptr;
}

void BST::clearHelper(RuleNode* node) {
    if (!node) return;
    clearHelper(node->left);
    clearHelper(node->right);
    delete node;
}

// ─── AVL Balancing Helpers ────────────────────────────────────────────────────
int BST::getHeight(RuleNode* node) const {
    return node ? node->height : 0;
}

int BST::getBalance(RuleNode* node) const {
    return node ? getHeight(node->left) - getHeight(node->right) : 0;
}

RuleNode* BST::rotateLeft(RuleNode* x) {
    RuleNode* y  = x->right;
    RuleNode* T2 = y->left;
    y->left  = x;
    x->right = T2;
    x->height = 1 + std::max(getHeight(x->left), getHeight(x->right));
    y->height = 1 + std::max(getHeight(y->left), getHeight(y->right));
    return y;
}

RuleNode* BST::rotateRight(RuleNode* y) {
    RuleNode* x  = y->left;
    RuleNode* T2 = x->right;
    x->right = y;
    y->left  = T2;
    y->height = 1 + std::max(getHeight(y->left), getHeight(y->right));
    x->height = 1 + std::max(getHeight(x->left), getHeight(x->right));
    return x;
}

RuleNode* BST::rebalance(RuleNode* node) {
    if (!node) return nullptr;

    // Update height
    node->height = 1 + std::max(getHeight(node->left), getHeight(node->right));

    // Get balance factor
    int balance = getBalance(node);

    // Left Left Case
    if (balance > 1 && getBalance(node->left) >= 0)
        return rotateRight(node);

    // Left Right Case
    if (balance > 1 && getBalance(node->left) < 0) {
        node->left = rotateLeft(node->left);
        return rotateRight(node);
    }

    // Right Right Case
    if (balance < -1 && getBalance(node->right) <= 0)
        return rotateLeft(node);

    // Right Left Case
    if (balance < -1 && getBalance(node->right) > 0) {
        node->right = rotateRight(node->right);
        return rotateLeft(node);
    }

    return node;
}

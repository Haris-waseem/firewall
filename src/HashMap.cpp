/**
 * HashMap.cpp
 * Custom hash map implementation using djb2 hash + separate chaining.
 */
#include "../include/HashMap.h"
#include <algorithm>
#include <queue>
#include <stdexcept>
#include <iostream>

// ─── Constructor ──────────────────────────────────────────────────────────────
HashMap::HashMap(int initialBuckets)
    : bucketCount_(initialBuckets > 0 ? initialBuckets : 1024),
      buckets_(initialBuckets > 0 ? initialBuckets : 1024),
      count_(0)
{
    if (initialBuckets <= 0) {
        std::cerr << "[HashMap] Warning: initialBuckets=" << initialBuckets
                  << " clamped to " << bucketCount_ << "\n";
    }
}

// ─── hash() — djb2 algorithm ─────────────────────────────────────────────────
// hash = 5381; for each char c: hash = hash * 33 ^ c
// Excellent avalanche effect and uniform distribution for IP strings.
int HashMap::hash(const std::string& key) const {
    unsigned long h = 5381;
    for (unsigned char c : key)
        h = ((h << 5) + h) ^ c;   // h * 33 ^ c
    return static_cast<int>(h % static_cast<unsigned long>(bucketCount_));
}

// ─── insert() ────────────────────────────────────────────────────────────────
void HashMap::insert(const std::string& key, int value) {
    if (loadFactor() > 0.75f) rehash();
    int idx = hash(key);
    for (auto& pair : buckets_[idx]) {
        if (pair.first == key) { pair.second = value; return; }
    }
    buckets_[idx].push_back({key, value});
    count_++;
}

// ─── get() ───────────────────────────────────────────────────────────────────
int HashMap::get(const std::string& key) const {
    int idx = hash(key);
    for (const auto& pair : buckets_[idx])
        if (pair.first == key) return pair.second;
    return -1;
}

// ─── contains() ──────────────────────────────────────────────────────────────
bool HashMap::contains(const std::string& key) const {
    return get(key) != -1;
}

// ─── remove() ────────────────────────────────────────────────────────────────
bool HashMap::remove(const std::string& key) {
    int idx = hash(key);
    auto& bucket = buckets_[idx];
    for (auto it = bucket.begin(); it != bucket.end(); ++it) {
        if (it->first == key) {
            bucket.erase(it);
            count_--;
            return true;
        }
    }
    return false;
}

// ─── increment() ─────────────────────────────────────────────────────────────
void HashMap::increment(const std::string& key) {
    if (loadFactor() > 0.75f) rehash();
    int idx = hash(key);
    for (auto& pair : buckets_[idx]) {
        if (pair.first == key) { pair.second++; return; }
    }
    // Key not found — insert with value 1
    buckets_[idx].push_back({key, 1});
    count_++;
}

// ─── topN() — min-heap approach O(N log n) ───────────────────────────────────
std::vector<std::pair<std::string,int>> HashMap::topN(int n) const {
    if (n <= 0) return {};

    // Min-heap: keeps smallest of the top-n; we pop when size > n
    using Pair = std::pair<std::string,int>;
    auto cmp = [](const Pair& a, const Pair& b){ return a.second > b.second; };
    std::priority_queue<Pair, std::vector<Pair>, decltype(cmp)> minHeap(cmp);

    for (const auto& bucket : buckets_) {
        for (const auto& entry : bucket) {
            minHeap.push(entry);
            if (static_cast<int>(minHeap.size()) > n) minHeap.pop();
        }
    }

    // Extract and sort: highest value first; ties broken by key lexicographically
    std::vector<Pair> result;
    result.reserve(minHeap.size());
    while (!minHeap.empty()) { result.push_back(minHeap.top()); minHeap.pop(); }
    std::sort(result.begin(), result.end(),
              [](const Pair& a, const Pair& b){
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first; // deterministic tie-break
              });
    return result;
}

// ─── keys() ──────────────────────────────────────────────────────────────────
std::vector<std::string> HashMap::keys() const {
    std::vector<std::string> result;
    result.reserve(count_);
    for (const auto& bucket : buckets_)
        for (const auto& pair : bucket)
            result.push_back(pair.first);
    return result;
}

// ─── clear() ─────────────────────────────────────────────────────────────────
void HashMap::clear() {
    for (auto& bucket : buckets_) bucket.clear();
    count_ = 0;
}

// ─── rehash() — doubles bucket count, re-inserts all entries ─────────────────
void HashMap::rehash() {
    int newSize = bucketCount_ * 2;
    std::vector<std::list<std::pair<std::string,int>>> newBuckets(newSize);

    for (const auto& bucket : buckets_) {
        for (const auto& pair : bucket) {
            unsigned long h = 5381;
            for (unsigned char c : pair.first) h = ((h << 5) + h) ^ c;
            int idx = static_cast<int>(h % static_cast<unsigned long>(newSize));
            newBuckets[idx].push_back(pair);
        }
    }

    buckets_     = std::move(newBuckets);
    bucketCount_ = newSize;
}

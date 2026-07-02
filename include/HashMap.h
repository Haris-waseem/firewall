/**
 * HashMap.h
 * Custom hash map: string key → int value.
 * Used for: IP blacklist, IP whitelist, SYN counters, port-scan counters.
 *
 * Design:
 *   Hash function : djb2 (Dan Bernstein) — excellent distribution for IP strings
 *   Collision res : Separate chaining (each bucket = std::list of pairs)
 *   Load factor   : Rehash when count/buckets > 0.75
 *   Initial size  : 1024 buckets (power of 2 for fast modulo)
 *
 * Complexity:
 *   insert  O(1) avg | O(n) worst (all keys collide)
 *   get     O(1) avg | O(n) worst
 *   remove  O(1) avg | O(n) worst
 *   topN    O(N log n) where N=entries, n=requested count
 *
 * C++ Packet Filtering Firewall — DSA Major Project
 * Author: Haris | COMSATS University Islamabad
 */
#pragma once
#include <string>
#include <vector>
#include <list>
#include <utility>

class HashMap {
public:
    explicit HashMap(int initialBuckets = 1024);
    ~HashMap() = default;

    // Inserts key with given value (default 1). Updates if key exists.
    void insert(const std::string& key, int value = 1);

    // Returns value for key, -1 if not found
    int  get(const std::string& key) const;

    // Returns true if key is present
    bool contains(const std::string& key) const;

    // Removes key from map; returns true if found
    bool remove(const std::string& key);

    // Increments integer value for key (used for SYN/port-scan counters)
    // Creates entry with value 1 if key doesn't exist yet
    void increment(const std::string& key);

    // Returns N entries with the highest values (for top-N blocked IPs)
    // Uses a min-heap internally — O(N log n)
    std::vector<std::pair<std::string,int>> topN(int n) const;

    // Returns all keys (for listing blacklist/whitelist entries)
    std::vector<std::string> keys() const;

    float loadFactor()  const { return static_cast<float>(count_) / bucketCount_; }
    int   size()        const { return count_; }
    bool  empty()       const { return count_ == 0; }

    // Resets all entries (used for threat window reset)
    void clear();

private:
    using Bucket = std::list<std::pair<std::string, int>>;

    std::vector<Bucket> buckets_;
    int count_       = 0;
    int bucketCount_ = 1024;

    // djb2 hash function — hash = 5381; for each char: hash = hash*33 ^ char
    int  hash(const std::string& key) const;

    // Doubles bucket count and re-inserts all entries
    void rehash();
};
